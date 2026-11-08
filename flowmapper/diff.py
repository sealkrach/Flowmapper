"""Architecture diff between two periods (or two datasets).

The same flows are split by time window into two graphs, matched group by group, and
compared structurally: applications, workloads, roles, tiers, dependencies, services,
policy decisions and traffic volumes. The result renders as a deterministic Markdown
report; the agent turns it into a narrative ("what changed in CRM this month?").
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from .discovery import effective_connections
from .exports import find_group
from .graph import FlowGraph
from .knowledge import AGENT_SERVICES, INFRA_ROLE_CLASSES
from .models import Flow, PolicyDecision


# ------------------------------------------------------------------------ periods
def parse_date(value: Optional[str | datetime], default: Optional[datetime] = None) -> Optional[datetime]:
    if value is None or value == "":
        return default
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def filter_flows_by_period(flows: Iterable[Flow], start: datetime, end: datetime) -> list[Flow]:
    """Flows whose observation range intersects [start, end]. Undated flows are kept."""
    out = []
    for f in flows:
        first = f.first_seen or f.last_seen
        last = f.last_seen or f.first_seen
        if first is None:
            out.append(f)
            continue
        if last >= start and first <= end:
            out.append(f)
    return out


def default_periods(fg: FlowGraph, days: int = 30, split: Optional[datetime] = None) -> tuple[datetime, datetime, datetime, datetime]:
    """Period B = the last ``days`` days of the dataset, period A = the ``days`` before.
    With ``split``, A = everything before, B = everything from the split date."""
    end = fg.last_seen or datetime.now(timezone.utc)
    start = fg.first_seen or end - timedelta(days=2 * days)
    if split:
        return start, split, split, end
    span = (end - start).total_seconds() / 86400
    if days * 2 > span:  # dataset shorter than two periods: compare its two halves
        days = span / 2
    b_start = max(start, end - timedelta(days=days))
    a_end = b_start
    a_start = max(start, a_end - timedelta(days=days))
    return a_start, a_end, b_start, end


# ------------------------------------------------------------------------ matching
def match_groups(fg_a: FlowGraph, fg_b: FlowGraph) -> dict[str, Optional[str]]:
    """Map every group key of B to a group key of A. Labeled / unmanaged groups match by key,
    clusters by member overlap (Jaccard ≥ 0.5) because their numbering is unstable."""
    mapping: dict[str, Optional[str]] = {}
    used: set[str] = set()
    for key, gb in fg_b.groups.items():
        if gb.kind != "cluster":
            mapping[key] = key if key in fg_a.groups else None
            if mapping[key]:
                used.add(key)
    for key, gb in fg_b.groups.items():
        if gb.kind != "cluster":
            continue
        best, best_score = None, 0.0
        mb = set(gb.members)
        for ka, ga in fg_a.groups.items():
            if ga.kind != "cluster" or ka in used:
                continue
            ma = set(ga.members)
            score = len(ma & mb) / len(ma | mb) if (ma | mb) else 0
            if score > best_score:
                best, best_score = ka, score
        mapping[key] = best if best_score >= 0.5 else None
        if mapping[key]:
            used.add(mapping[key])
    return mapping


# ------------------------------------------------------------------------ diff model
@dataclass
class ArchDiff:
    app: Optional[str]
    period_a: tuple[datetime, datetime]
    period_b: tuple[datetime, datetime]
    stats_a: dict
    stats_b: dict
    apps_added: list[dict] = field(default_factory=list)
    apps_removed: list[dict] = field(default_factory=list)
    workloads_added: list[dict] = field(default_factory=list)
    workloads_removed: list[dict] = field(default_factory=list)
    workloads_moved: list[dict] = field(default_factory=list)
    role_changes: list[dict] = field(default_factory=list)
    tier_changes: list[dict] = field(default_factory=list)
    deps_added: list[dict] = field(default_factory=list)
    deps_removed: list[dict] = field(default_factory=list)
    services_added: list[dict] = field(default_factory=list)
    services_removed: list[dict] = field(default_factory=list)
    decision_changes: list[dict] = field(default_factory=list)
    volume_changes: list[dict] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return sum(len(getattr(self, f)) for f in ("apps_added", "apps_removed", "workloads_added", "workloads_removed", "workloads_moved", "role_changes", "tier_changes", "deps_added", "deps_removed", "services_added", "services_removed", "decision_changes", "volume_changes"))

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        d["period_a"] = [p.isoformat() if p else None for p in self.period_a]
        d["period_b"] = [p.isoformat() if p else None for p in self.period_b]
        d["total_changes"] = self.total_changes
        return d


def _group_name(fg: FlowGraph, key: Optional[str]) -> str:
    return fg.groups[key].name if key and key in fg.groups else (key or "?")


def _edge_summary(services: dict) -> dict:
    items = sorted(services.values(), key=lambda e: -e.connections)
    worst = PolicyDecision.ALLOWED
    for e in items:
        if e.worst_decision.severity > worst.severity:
            worst = e.worst_decision
    return {"services": [e.service_name if not e.service_name.startswith(("tcp/", "udp/")) else e.label for e in items[:6]], "connections": sum(e.connections for e in items), "decision": worst.value}


def diff_graphs(fg_a: FlowGraph, fg_b: FlowGraph, app: Optional[str] = None, period_a=None, period_b=None, volume_ratio: float = 2.0, min_volume: int = 20, min_service_connections: int = 10, top: int = 40) -> ArchDiff:
    period_a = period_a or (fg_a.first_seen, fg_a.last_seen)
    period_b = period_b or (fg_b.first_seen, fg_b.last_seen)
    diff = ArchDiff(app=app, period_a=period_a, period_b=period_b, stats_a=fg_a.stats(), stats_b=fg_b.stats())
    b_to_a = match_groups(fg_a, fg_b)
    a_to_b = {v: k for k, v in b_to_a.items() if v}

    focus_a = find_group(fg_a, app) if app else None
    focus_b = find_group(fg_b, app) if app else None
    if app and not focus_a and not focus_b:
        raise ValueError(f"Unknown application '{app}'")
    if app and focus_b and not focus_a:
        focus_a = b_to_a.get(focus_b)
    if app and focus_a and not focus_b:
        focus_b = a_to_b.get(focus_a)
    if app:
        diff.app = _group_name(fg_b, focus_b) if focus_b else _group_name(fg_a, focus_a)

    def in_scope_group(key_a: Optional[str], key_b: Optional[str]) -> bool:
        if not app:
            return True
        return (key_a is not None and key_a == focus_a) or (key_b is not None and key_b == focus_b)

    # -- applications
    for key, gb in fg_b.groups.items():
        if b_to_a.get(key) is None and gb.kind != "unmanaged" and (not app or key == focus_b):
            diff.apps_added.append({"name": gb.name, "kind": gb.kind, "env": gb.env, "workloads": len(gb.members)})
    for key, ga in fg_a.groups.items():
        if key not in a_to_b and ga.kind != "unmanaged" and (not app or key == focus_a):
            diff.apps_removed.append({"name": ga.name, "kind": ga.kind, "env": ga.env, "workloads": len(ga.members)})

    # -- workloads (managed only: external IPs come and go)
    def scoped_nodes(fg: FlowGraph, focus: Optional[str]):
        return {nid: n for nid, n in fg.nodes.items() if n.managed and (not app or n.group == focus)}

    nodes_a, nodes_b = scoped_nodes(fg_a, focus_a), scoped_nodes(fg_b, focus_b)
    for nid, n in nodes_b.items():
        if nid not in fg_a.nodes:
            diff.workloads_added.append({"workload": n.name, "id": nid, "app": _group_name(fg_b, n.group), "role": n.role_class, "tier": n.tier})
        elif nid not in nodes_a and app:
            diff.workloads_moved.append({"workload": n.name, "from": _group_name(fg_a, fg_a.nodes[nid].group), "to": _group_name(fg_b, n.group)})
    for nid, n in nodes_a.items():
        if nid not in fg_b.nodes:
            diff.workloads_removed.append({"workload": n.name, "id": nid, "app": _group_name(fg_a, n.group), "role": n.role_class, "tier": n.tier})
        elif nid not in nodes_b and app:
            diff.workloads_moved.append({"workload": n.name, "from": _group_name(fg_a, n.group), "to": _group_name(fg_b, fg_b.nodes[nid].group)})
    for nid in nodes_a.keys() & nodes_b.keys():
        na, nb = fg_a.nodes[nid], fg_b.nodes[nid]
        if na.role_class != nb.role_class and na.role_source != "label" and nb.role_source != "label":
            diff.role_changes.append({"workload": nb.name, "from": na.role_class, "to": nb.role_class})
        if na.tier != nb.tier and na.group == b_to_a.get(nb.group):
            diff.tier_changes.append({"workload": nb.name, "from": na.tier, "to": nb.tier})

    # -- application-level dependencies
    ag_a, ag_b = fg_a.app_graph(), fg_b.app_graph()
    edges_a = {(s, d): data for s, d, data in ag_a.edges(data=True)}
    edges_b = {(s, d): data for s, d, data in ag_b.edges(data=True)}
    days_a = max((period_a[1] - period_a[0]).total_seconds() / 86400, 1e-6) if period_a[0] and period_a[1] else 1
    days_b = max((period_b[1] - period_b[0]).total_seconds() / 86400, 1e-6) if period_b[0] and period_b[1] else 1
    def infra_edge(fg: FlowGraph, s: str, d: str, focus: Optional[str]) -> bool:
        """Edges towards shared infrastructure are noise unless that infrastructure is the focus."""
        for k in (s, d):
            g = fg.groups.get(k)
            if g and g.shared and k != focus:
                return True
        return False

    for (s, d), data in edges_b.items():
        sa, da = b_to_a.get(s), b_to_a.get(d)
        if not in_scope_group(sa, s) and not in_scope_group(da, d):
            continue
        if infra_edge(fg_b, s, d, focus_b):
            continue
        if effective_connections(data) == 0 and not any(e.worst_decision is PolicyDecision.BLOCKED for e in data["services"].values()):
            continue
        prev = edges_a.get((sa, da)) if sa and da else None
        summary = _edge_summary(data["services"])
        if prev is None:
            diff.deps_added.append({"source": _group_name(fg_b, s), "target": _group_name(fg_b, d), "source_key": s, "target_key": d, **summary})
        else:
            ca, cb = prev["connections"] / days_a, data["connections"] / days_b
            if max(prev["connections"], data["connections"]) >= min_volume and (cb >= volume_ratio * ca or ca >= volume_ratio * cb):
                diff.volume_changes.append({"source": _group_name(fg_b, s), "target": _group_name(fg_b, d), "source_key": s, "target_key": d, "connections_a": prev["connections"], "connections_b": data["connections"], "per_day_a": round(ca, 1), "per_day_b": round(cb, 1), "ratio": round(cb / ca, 2) if ca else None})
    for (s, d), data in edges_a.items():
        sb, db = a_to_b.get(s), a_to_b.get(d)
        if not in_scope_group(s, sb) and not in_scope_group(d, db):
            continue
        if infra_edge(fg_a, s, d, focus_a):
            continue
        if not (sb and db and (sb, db) in edges_b):
            diff.deps_removed.append({"source": _group_name(fg_a, s), "target": _group_name(fg_a, d), "source_key": s, "target_key": d, **_edge_summary(data["services"])})

    # -- workload-level services (pair + service), scoped, ignoring admin/agent services
    def scoped_services(fg: FlowGraph, focus: Optional[str]) -> dict:
        out = {}
        for s, d, data in fg.G.edges(data=True):
            if app and fg.nodes[s].group != focus and fg.nodes[d].group != focus:
                continue
            for key, e in data["services"].items():
                if e.service_name in AGENT_SERVICES or (e.role_class in INFRA_ROLE_CLASSES and e.worst_decision is PolicyDecision.ALLOWED):
                    continue  # ssh/agents and allowed dns/ldap/ntp/syslog are not architecture
                out[(s, d, key)] = e
        return out

    sv_a, sv_b = scoped_services(fg_a, focus_a), scoped_services(fg_b, focus_b)
    added = sorted((k for k in sv_b.keys() - sv_a.keys() if sv_b[k].connections >= min_service_connections or sv_b[k].worst_decision is not PolicyDecision.ALLOWED), key=lambda k: -sv_b[k].connections)
    removed = sorted((k for k in sv_a.keys() - sv_b.keys() if sv_a[k].connections >= min_service_connections), key=lambda k: -sv_a[k].connections)
    for s, d, key in added[:top]:
        e = sv_b[(s, d, key)]
        diff.services_added.append({"source": fg_b.nodes[s].name, "target": fg_b.nodes[d].name, "source_id": s, "target_id": d, "service": e.label, "name": e.service_name, "connections": e.connections, "decision": e.worst_decision.value})
    for s, d, key in removed[:top]:
        e = sv_a[(s, d, key)]
        diff.services_removed.append({"source": fg_a.nodes[s].name, "target": fg_a.nodes[d].name, "source_id": s, "target_id": d, "service": e.label, "name": e.service_name, "connections": e.connections, "decision": e.worst_decision.value})
    for k in sv_a.keys() & sv_b.keys():
        ea, eb = sv_a[k], sv_b[k]
        if ea.worst_decision != eb.worst_decision:
            s, d, _ = k
            diff.decision_changes.append({"source": fg_b.nodes[s].name, "target": fg_b.nodes[d].name, "source_id": s, "target_id": d, "service": eb.label, "name": eb.service_name, "from": ea.worst_decision.value, "to": eb.worst_decision.value, "connections": eb.connections})
    diff.decision_changes.sort(key=lambda c: -PolicyDecision(c["to"]).severity)
    return diff


def diff_periods(flows: Iterable[Flow], fg_full: FlowGraph, app: Optional[str] = None, a_start=None, a_end=None, b_start=None, b_end=None, days: int = 30, split=None, graph_options: Optional[dict] = None) -> ArchDiff:
    """Split ``flows`` into two periods and diff the resulting graphs."""
    flows = list(flows)
    d_a_start, d_a_end, d_b_start, d_b_end = default_periods(fg_full, days=days, split=parse_date(split))
    a_start, a_end = parse_date(a_start, d_a_start), parse_date(a_end, d_a_end)
    b_start, b_end = parse_date(b_start, d_b_start), parse_date(b_end, d_b_end)
    opts = graph_options or {}
    fg_a = FlowGraph.build(filter_flows_by_period(flows, a_start, a_end), **opts)
    fg_b = FlowGraph.build(filter_flows_by_period(flows, b_start, b_end), **opts)
    return diff_graphs(fg_a, fg_b, app=app, period_a=(a_start, a_end), period_b=(b_start, b_end))


# ------------------------------------------------------------------------ rendering
def _fmt_period(p: tuple[datetime, datetime]) -> str:
    a, b = p
    return f"{a.strftime('%Y-%m-%d') if a else '?'} → {b.strftime('%Y-%m-%d') if b else '?'}"


def diff_to_markdown(diff: ArchDiff) -> str:
    scope = f"de l'application **{diff.app}**" if diff.app else "de l'ensemble du parc"
    out = [f"# Changements {scope}", f"Période A : {_fmt_period(diff.period_a)} ({diff.stats_a['flows']} flux) · Période B : {_fmt_period(diff.period_b)} ({diff.stats_b['flows']} flux)", ""]
    if diff.total_changes == 0:
        out.append("Aucun changement structurel détecté entre les deux périodes.")
        return "\n".join(out)
    out.append(f"**{diff.total_changes} changements** détectés.")

    def section(title: str, rows: list[str]):
        if rows:
            out.append("")
            out.append(f"## {title} ({len(rows)})")
            out.extend(f"- {r}" for r in rows)

    section("Applications apparues", [f"{a['name']} ({a['kind']}, {a['env'] or 'sans env'}, {a['workloads']} workloads)" for a in diff.apps_added])
    section("Applications disparues", [f"{a['name']} ({a['kind']}, {a['env'] or 'sans env'}, {a['workloads']} workloads)" for a in diff.apps_removed])
    section("Nouveaux workloads", [f"{w['workload']} — {w['app']}, rôle {w['role']}, tier {w['tier']}" for w in diff.workloads_added])
    section("Workloads disparus", [f"{w['workload']} — {w['app']}, rôle {w['role']}" for w in diff.workloads_removed])
    section("Workloads ayant changé d'application", [f"{w['workload']} : {w['from']} → {w['to']}" for w in diff.workloads_moved])
    section("Nouvelles dépendances applicatives", [f"{d['source']} → {d['target']} : {', '.join(d['services'])} ({d['connections']} conn., {d['decision']})" for d in diff.deps_added])
    section("Dépendances applicatives disparues", [f"{d['source']} → {d['target']} : {', '.join(d['services'])} ({d['connections']} conn.)" for d in diff.deps_removed])
    section("Changements de décision de policy", [f"{c['source']} → {c['target']} {c['name']} ({c['service']}) : {c['from']} → **{c['to']}** ({c['connections']} conn.)" for c in diff.decision_changes])
    section("Variations de volume (×2 ou ÷2)", [f"{v['source']} → {v['target']} : {v['per_day_a']} → {v['per_day_b']} conn./jour (×{v['ratio']})" for v in diff.volume_changes])
    section("Nouveaux flux (workload → workload)", [f"{s['source']} → {s['target']} {s['name']} ({s['service']}), {s['connections']} conn., {s['decision']}" for s in diff.services_added])
    section("Flux disparus (workload → workload)", [f"{s['source']} → {s['target']} {s['name']} ({s['service']}), {s['connections']} conn." for s in diff.services_removed])
    section("Changements de rôle déduit", [f"{r['workload']} : {r['from']} → {r['to']}" for r in diff.role_changes])
    section("Changements de tier", [f"{t['workload']} : tier {t['from']} → {t['to']}" for t in diff.tier_changes])
    return "\n".join(out)
