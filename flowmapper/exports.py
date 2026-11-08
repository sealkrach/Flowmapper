"""Exports: Cytoscape elements for the UI, Mermaid / Markdown for documentation, GraphML
for Gephi / yEd, and a JSON dump of the whole model."""
from __future__ import annotations

import io
import json
import math
import re
from collections import defaultdict
from typing import Iterable, Optional

import networkx as nx

from .graph import AppGroup, FlowGraph, ServiceEdge
from .models import PolicyDecision

ENV_UNLABELED = "unlabeled"
ENV_UNMANAGED = "external"


def _env_of(group: AppGroup) -> str:
    if group.kind == "unmanaged":
        return ENV_UNMANAGED
    return group.env or ENV_UNLABELED


def _edge_width(connections: int) -> float:
    return round(1 + math.log10(max(connections, 1)), 2)


def _services_summary(services: Iterable[ServiceEdge], limit: int = 3) -> str:
    items = sorted(services, key=lambda e: -e.connections)
    names = [e.service_name if not e.service_name.startswith(("tcp/", "udp/")) else e.label for e in items[:limit]]
    extra = len(items) - limit
    return ", ".join(names) + (f" +{extra}" if extra > 0 else "")


def _worst(services: Iterable[ServiceEdge]) -> str:
    worst = PolicyDecision.ALLOWED
    for e in services:
        if e.worst_decision.severity > worst.severity:
            worst = e.worst_decision
    return worst.value


class GraphFilter:
    """Filtering options shared by the API and the exports."""

    def __init__(
        self,
        env: Optional[str] = None,
        app: Optional[str] = None,
        hide_shared: bool = False,
        hide_infra: bool = True,
        hide_unmanaged: bool = False,
        min_connections: int = 1,
        decisions: Optional[set[str]] = None,
        ports: Optional[set[int]] = None,
        search: Optional[str] = None,
    ):
        self.env = env
        self.app = app
        self.hide_shared = hide_shared
        self.hide_infra = hide_infra
        self.hide_unmanaged = hide_unmanaged
        self.min_connections = max(1, min_connections)
        self.decisions = decisions
        self.ports = ports
        self.search = search.lower() if search else None

    def keep_group(self, fg: FlowGraph, group: AppGroup) -> bool:
        if self.env and _env_of(group) != self.env and group.kind == "labeled":
            return False
        if self.hide_unmanaged and group.kind == "unmanaged":
            return False
        if group.shared:
            if self.hide_shared:
                return False
            if self.hide_infra and all(fg.nodes[m].shared_kind == "infra" for m in group.members if fg.nodes[m].shared):
                return False
        return True

    def keep_services(self, services: dict) -> list[ServiceEdge]:
        kept = []
        for edge in services.values():
            if self.decisions and edge.worst_decision.value not in self.decisions:
                continue
            if self.ports and edge.port not in self.ports:
                continue
            kept.append(edge)
        return kept


def _group_shared_kind(fg: FlowGraph, group: AppGroup) -> Optional[str]:
    if not group.shared:
        return None
    kinds = {fg.nodes[m].shared_kind for m in group.members if fg.nodes[m].shared}
    return "infra" if kinds == {"infra"} else "service"


def to_cytoscape(fg: FlowGraph, level: str = "app", flt: Optional[GraphFilter] = None) -> dict:
    flt = flt or GraphFilter()
    nodes: list[dict] = []
    edges: list[dict] = []
    envs: set[str] = set()

    groups = {k: g for k, g in fg.groups.items() if flt.keep_group(fg, g)}
    if flt.app:
        focus = {k for k, g in groups.items() if g.name == flt.app or g.app == flt.app or k == flt.app}
        AG = fg.app_graph()
        neighbours = set(focus)
        for k in focus:
            neighbours |= set(AG.predecessors(k)) | set(AG.successors(k))
        groups = {k: g for k, g in groups.items() if k in neighbours}
        focus_keys = focus
    else:
        focus_keys = set()

    for key, group in groups.items():
        env = _env_of(group)
        envs.add(env)
        nodes.append(
            {
                "data": {
                    "id": f"g:{key}",
                    "label": group.name,
                    "type": "app",
                    "kind": group.kind,
                    "env": env,
                    "parent": f"env:{env}",
                    "group": key,
                    "members": len(group.members),
                    "shared": group.shared,
                    "shared_kind": _group_shared_kind(fg, group),
                    "focus": key in focus_keys,
                    "suggested": group.suggested_name,
                }
            }
        )

    if level == "workload":
        for key, group in groups.items():
            for m in group.members:
                node = fg.nodes[m]
                nodes.append(
                    {
                        "data": {
                            "id": f"w:{m}",
                            "label": node.name,
                            "type": "workload",
                            "parent": f"g:{key}",
                            "group": key,
                            "role": node.role_class,
                            "role_source": node.role_source,
                            "managed": node.managed,
                            "shared": node.shared,
                            "shared_kind": node.shared_kind,
                            "tier": node.tier,
                            "ips": sorted(node.ips)[:5],
                            "labels": node.labels,
                            "served": node.top_served,
                            "in": node.in_connections,
                            "out": node.out_connections,
                        }
                    }
                )
        for s, d, data in fg.G.edges(data=True):
            gs, gd = fg.nodes[s].group, fg.nodes[d].group
            if gs not in groups or gd not in groups or s == d:
                continue
            services = flt.keep_services(data["services"])
            conns = sum(e.connections for e in services)
            if not services or conns < flt.min_connections:
                continue
            eid = f"e:{s}->{d}"
            edges.append(
                {
                    "data": {
                        "id": eid,
                        "source": f"w:{s}",
                        "target": f"w:{d}",
                        "label": _services_summary(services),
                        "connections": conns,
                        "width": _edge_width(conns),
                        "decision": _worst(services),
                        "internal": gs == gd,
                        "services": [e.to_dict() for e in sorted(services, key=lambda e: -e.connections)[:15]],
                    }
                }
            )
    else:
        AG = fg.app_graph()
        for s, d, data in AG.edges(data=True):
            if s not in groups or d not in groups:
                continue
            services = flt.keep_services(data["services"])
            conns = sum(e.connections for e in services)
            if not services or conns < flt.min_connections:
                continue
            edges.append(
                {
                    "data": {
                        "id": f"e:{s}->{d}",
                        "source": f"g:{s}",
                        "target": f"g:{d}",
                        "label": _services_summary(services),
                        "connections": conns,
                        "width": _edge_width(conns),
                        "decision": _worst(services),
                        "pairs": data["pairs"],
                        "services": [e.to_dict() for e in sorted(services, key=lambda e: -e.connections)[:15]],
                    }
                }
            )

    env_nodes = [{"data": {"id": f"env:{e}", "label": e, "type": "env"}} for e in sorted(envs)]
    return {"elements": {"nodes": env_nodes + nodes, "edges": edges}, "meta": {"level": level, "envs": sorted(envs), "stats": fg.stats()}}


# ---------------------------------------------------------------------------- Mermaid
def _mid(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


def _mtext(text) -> str:
    """Escape a value inserted inside a Mermaid quoted label."""
    return str(text).replace('"', "#quot;")


def to_mermaid(fg: FlowGraph, app: Optional[str] = None, flt: Optional[GraphFilter] = None, direction: str = "LR") -> str:
    flt = flt or GraphFilter()
    lines = [f"flowchart {direction}"]
    if app:
        return _mermaid_app(fg, app, flt, direction)
    AG = fg.app_graph()
    groups = {k: g for k, g in fg.groups.items() if flt.keep_group(fg, g)}
    by_env: dict[str, list[str]] = defaultdict(list)
    for k, g in groups.items():
        by_env[_env_of(g)].append(k)
    for env, keys in sorted(by_env.items()):
        lines.append(f'  subgraph {_mid("env_" + env)}["{_mtext(env)}"]')
        for k in keys:
            lines.append(f'    {_mid(k)}["{_mtext(groups[k].name)}"]')
        lines.append("  end")
    for s, d, data in AG.edges(data=True):
        if s in groups and d in groups:
            services = flt.keep_services(data["services"])
            if services:
                lines.append(f'  {_mid(s)} -->|"{_mtext(_services_summary(services))}"| {_mid(d)}')
    return "\n".join(lines)


def _mermaid_app(fg: FlowGraph, app: str, flt: GraphFilter, direction: str) -> str:
    key = find_group(fg, app)
    if key is None:
        return f"%% application not found: {app}"
    group = fg.groups[key]
    lines = [f"flowchart {direction}", f'  subgraph {_mid(key)}["{_mtext(group.name)}"]']
    tiers: dict[int, list[str]] = defaultdict(list)
    for m in group.members:
        tiers[fg.nodes[m].tier or 0].append(m)
    for t in sorted(tiers):
        lines.append(f'    subgraph {_mid(key)}_t{t}["tier {t}"]')
        for m in tiers[t]:
            n = fg.nodes[m]
            lines.append(f'      {_mid(m)}["{_mtext(n.name)}<br/>{n.role_class}"]')
        lines.append("    end")
    lines.append("  end")
    for s, d, data in fg.internal_edges(key):
        services = flt.keep_services(data["services"])
        if services:
            lines.append(f'  {_mid(s)} -->|"{_mtext(_services_summary(services))}"| {_mid(d)}')
    deps = fg.dependencies(key, include_shared=not flt.hide_shared)
    for dep in deps["outbound"]:
        lines.append(f'  {_mid(dep["group"])}["{_mtext(dep["name"])}"]')
        lines.append(f'  {_mid(key)} -->|"{_mtext(", ".join(s["name"] for s in dep["services"][:3]))}"| {_mid(dep["group"])}')
    for dep in deps["inbound"]:
        lines.append(f'  {_mid(dep["group"])}["{_mtext(dep["name"])}"]')
        lines.append(f'  {_mid(dep["group"])} -->|"{_mtext(", ".join(s["name"] for s in dep["services"][:3]))}"| {_mid(key)}')
    return "\n".join(lines)


def find_group(fg: FlowGraph, name: str) -> Optional[str]:
    """Resolve a user-supplied application name to a group key (exact key, name, app label, case-insensitive)."""
    if name in fg.groups:
        return name
    low = name.lower()
    for k, g in fg.groups.items():
        if g.name.lower() == low or (g.app or "").lower() == low:
            return k
    for k, g in fg.groups.items():
        if low in g.name.lower() or low in k.lower():
            return k
    return None


# --------------------------------------------------------------------------- Markdown
def to_markdown(fg: FlowGraph, app: Optional[str] = None, flt: Optional[GraphFilter] = None) -> str:
    flt = flt or GraphFilter()
    if app:
        key = find_group(fg, app)
        return _markdown_app(fg, key, flt) if key else f"Application not found: {app}"
    stats = fg.stats()
    out = ["# Application architecture report", ""]
    out.append(f"- Flows: {stats['flows']} · workloads: {stats['workloads']} ({stats['managed_workloads']} managed) · applications: {stats['groups']}")
    out.append(f"- Period: {stats['first_seen']} → {stats['last_seen']}")
    out.append(f"- Connections by policy decision: {stats['connections_by_decision']}")
    out.append("")
    for key, group in sorted(fg.groups.items(), key=lambda kv: (kv[1].kind != "labeled", kv[1].name)):
        if not flt.keep_group(fg, group):
            continue
        out.append(_markdown_app(fg, key, flt, heading="## "))
        out.append("")
    return "\n".join(out)


def _markdown_app(fg: FlowGraph, key: str, flt: GraphFilter, heading: str = "# ") -> str:
    group = fg.groups[key]
    out = [f"{heading}{group.name}" + (f" — {group.env}" if group.env else "")]
    out.append(f"Kind: {group.kind}" + (" (shared service)" if group.shared else "") + f" · {len(group.members)} workloads")
    if group.kind == "cluster" and group.evidence:
        out.append(f"Suggested name: **{group.suggested_name}** · evidence: {json.dumps(group.evidence, ensure_ascii=False)}")
    out.append("")
    out.append("| Tier | Workload | Role | Top services served | IPs |")
    out.append("|---|---|---|---|---|")
    for m in sorted(group.members, key=lambda m: (fg.nodes[m].tier or 0, fg.nodes[m].name)):
        n = fg.nodes[m]
        served = ", ".join(f"{s} ({c})" for s, c in n.top_served[:3])
        out.append(f"| {n.tier} | {n.name}{' ⚠shared' if n.shared else ''} | {n.role_class} | {served} | {', '.join(sorted(n.ips)[:3])} |")
    internal = fg.internal_edges(key)
    if internal:
        out.append("")
        out.append("Internal flows:")
        for s, d, data in internal:
            services = flt.keep_services(data["services"])
            if services:
                out.append(f"- {fg.nodes[s].name} → {fg.nodes[d].name}: {_services_summary(services, 5)} ({_worst(services)})")
    deps = fg.dependencies(key, include_shared=not flt.hide_shared)
    if deps["outbound"]:
        out.append("")
        out.append("Depends on (outbound):")
        for dep in deps["outbound"]:
            out.append(f"- {dep['name']}{' [shared]' if dep['shared'] else ''}: {', '.join(s['name'] for s in dep['services'][:5])} — {dep['connections']} connections, {dep['decision']}")
    if deps["inbound"]:
        out.append("")
        out.append("Consumed by (inbound):")
        for dep in deps["inbound"]:
            out.append(f"- {dep['name']}{' [shared]' if dep['shared'] else ''}: {', '.join(s['name'] for s in dep['services'][:5])} — {dep['connections']} connections, {dep['decision']}")
    blocked = []
    for s, d, data in fg.G.edges(data=True):
        if fg.nodes[s].group == key or fg.nodes[d].group == key:
            for e in data["services"].values():
                if e.worst_decision in (PolicyDecision.BLOCKED, PolicyDecision.POTENTIALLY_BLOCKED):
                    blocked.append(f"- {fg.nodes[s].name} → {fg.nodes[d].name} {e.label} ({e.worst_decision.value}, {e.connections})")
    if blocked:
        out.append("")
        out.append("Blocked / potentially blocked:")
        out.extend(blocked[:30])
    return "\n".join(out)


# ---------------------------------------------------------------------------- GraphML
def to_graphml(fg: FlowGraph, level: str = "workload") -> str:
    G = nx.DiGraph()
    if level == "app":
        for k, data in fg.app_graph().nodes(data=True):
            g = data["group"]
            G.add_node(k, name=g.name, kind=g.kind, env=g.env or "", shared=str(g.shared), members=len(g.members))
        for s, d, data in fg.app_graph().edges(data=True):
            G.add_edge(s, d, services=_services_summary(data["services"].values(), 10), connections=data["connections"], decision=_worst(data["services"].values()))
    else:
        for n in fg.nodes.values():
            G.add_node(n.id, name=n.name, group=n.group or "", role=n.role_class, managed=str(n.managed), shared=str(n.shared), tier=n.tier if n.tier is not None else -1, ips=",".join(sorted(n.ips)))
        for s, d, data in fg.G.edges(data=True):
            G.add_edge(s, d, services=_services_summary(data["services"].values(), 10), connections=sum(e.connections for e in data["services"].values()), decision=_worst(data["services"].values()))
    buf = io.BytesIO()
    nx.write_graphml(G, buf)
    return buf.getvalue().decode("utf-8")


# ------------------------------------------------------------------------------- JSON
def to_json(fg: FlowGraph) -> dict:
    return {
        "stats": fg.stats(),
        "groups": [g.to_dict() for g in fg.groups.values()],
        "workloads": [n.to_dict() for n in fg.nodes.values()],
        "edges": [
            {"source": s, "target": d, "services": [e.to_dict() for e in data["services"].values()]}
            for s, d, data in fg.G.edges(data=True)
        ],
        "app_edges": [
            {"source": s, "target": d, "connections": data["connections"], "services": [e.to_dict() for e in data["services"].values()]}
            for s, d, data in fg.app_graph().edges(data=True)
        ],
    }
