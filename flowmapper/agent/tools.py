"""LangChain tools exposing the flow graph to the agent. Every tool reads the *current*
graph held by the :class:`~flowmapper.store.Store`, so a re-ingest is picked up instantly."""
from __future__ import annotations

import json
from itertools import islice
from typing import Optional

import networkx as nx
from langchain.tools import tool

from ..discovery import effective_connections
from ..exports import GraphFilter, find_group, to_markdown, to_mermaid
from ..models import PolicyDecision
from ..store import Store


def _j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _resolve_node(fg, name: str) -> Optional[str]:
    low = name.strip().lower()
    if low in fg.nodes:
        return low
    for nid, n in fg.nodes.items():
        if n.name.lower() == low or low in n.ips:
            return nid
    for nid, n in fg.nodes.items():
        if low in n.name.lower():
            return nid
    return None


def make_tools(store: Store) -> list:
    """Build the tool list bound to ``store``."""

    @tool
    def graph_overview() -> str:
        """Summary of the loaded Illumio dataset: flow counts, period, policy decisions and the
        list of applications discovered (labeled apps, unlabeled clusters, external IP lists)
        with their size, environment and whether they are shared infrastructure. Call this first."""
        fg = store.require_graph()
        groups = [
            {
                "key": g.key,
                "name": g.name,
                "env": g.env,
                "kind": g.kind,
                "workloads": len(g.members),
                "shared_service": g.shared,
                "suggested_name": g.suggested_name,
                "candidate_app": g.evidence.get("candidate_app") if g.evidence else None,
            }
            for g in sorted(fg.groups.values(), key=lambda g: (g.kind != "labeled", -len(g.members)))
        ]
        return _j({"stats": fg.stats(), "applications": groups, "files": store.files})

    @tool
    def describe_application(name: str, include_shared_infra: bool = False) -> str:
        """Full architecture of one application: workloads by tier with their role and served
        services, internal flows, outbound dependencies (what it relies on), inbound consumers,
        and blocked/potentially blocked flows. `name` is the application name, Illumio app
        label or group key (e.g. "E-Commerce" or "E-Commerce|Production")."""
        fg = store.require_graph()
        key = find_group(fg, name)
        if not key:
            return f"Unknown application '{name}'. Known: {', '.join(sorted({g.name for g in fg.groups.values()}))}"
        return to_markdown(fg, app=key, flt=GraphFilter(hide_shared=not include_shared_infra))

    @tool
    def get_dependencies(name: str, direction: str = "both", include_shared: bool = False) -> str:
        """Application-level dependencies of `name`. direction: "outbound" (providers this app
        calls), "inbound" (consumers calling this app) or "both". include_shared adds shared
        infrastructure such as AD/DNS/NTP/monitoring."""
        fg = store.require_graph()
        key = find_group(fg, name)
        if not key:
            return f"Unknown application '{name}'"
        return _j(fg.dependencies(key, direction=direction, include_shared=include_shared))

    @tool
    def search_flows(source: str = "", destination: str = "", port: int = 0, decision: str = "", limit: int = 40) -> str:
        """Search aggregated workload-to-workload flows. `source`/`destination` match a hostname,
        an IP or an application name (partial, case-insensitive). `port` filters the destination
        port, `decision` one of allowed / potentially_blocked / blocked / unknown. Returns the
        heaviest matches with service, process names and connection counts."""
        fg = store.require_graph()

        def matches(node_id: str, query: str) -> bool:
            if not query:
                return True
            q = query.lower()
            n = fg.nodes[node_id]
            g = fg.groups.get(n.group) if n.group else None
            return q in n.name.lower() or any(q in ip for ip in n.ips) or (g is not None and (q in g.name.lower() or q in g.key.lower()))

        rows = []
        for s, d, data in fg.G.edges(data=True):
            if not matches(s, source) or not matches(d, destination):
                continue
            for e in data["services"].values():
                if port and e.port != port:
                    continue
                if decision and e.worst_decision.value != decision:
                    continue
                rows.append(
                    {
                        "source": fg.nodes[s].name,
                        "source_app": fg.groups[fg.nodes[s].group].name if fg.nodes[s].group else None,
                        "destination": fg.nodes[d].name,
                        "destination_app": fg.groups[fg.nodes[d].group].name if fg.nodes[d].group else None,
                        "service": e.label,
                        "service_name": e.service_name,
                        "processes": sorted(e.processes),
                        "connections": e.connections,
                        "decision": e.worst_decision.value,
                        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                    }
                )
        rows.sort(key=lambda r: -r["connections"])
        return _j({"matches": len(rows), "flows": rows[: max(1, min(limit, 200))]})

    @tool
    def find_path(source: str, target: str, max_paths: int = 3) -> str:
        """Shortest dependency paths between two applications (or two workloads) following the
        direction of the flows: who calls whom to get from `source` to `target`."""
        fg = store.require_graph()
        AG = fg.app_graph()
        ks, kt = find_group(fg, source), find_group(fg, target)
        if ks and kt:
            # Shared infrastructure never acts as an intermediate hop (everything talks to AD/DNS).
            G = AG.subgraph([k for k in AG if not fg.groups[k].shared or k in (ks, kt)])
            label = lambda k: fg.groups[k].name
        else:
            ns, nt = _resolve_node(fg, source), _resolve_node(fg, target)
            if not (ns and nt):
                return f"Could not resolve '{source}' or '{target}' to an application or workload"
            ks, kt = ns, nt
            G = fg.G.subgraph([n for n in fg.G if not fg.nodes[n].shared or n in (ks, kt)])
            label = lambda k: fg.nodes[k].name
        try:
            paths = list(islice(nx.shortest_simple_paths(G, ks, kt), max_paths))
        except nx.NetworkXNoPath:
            return f"No directed path from {label(ks)} to {label(kt)}"
        out = []
        for p in paths:
            hops = []
            for a, b in zip(p, p[1:]):
                services = sorted(G[a][b]["services"].values(), key=lambda e: -e.connections)[:3]
                hops.append(f"{label(a)} -[{', '.join(e.service_name for e in services)}]-> {label(b)}")
            out.append(" ; ".join(hops))
        return _j(out)

    @tool
    def list_unlabeled_clusters() -> str:
        """Groups of VEN-managed workloads that have no Illumio application label, with the
        evidence gathered for each (hostnames, services served, labeled applications they talk
        to, candidate parent app). Use this to propose application names and labels."""
        fg = store.require_graph()
        clusters = [g.to_dict() for g in fg.groups.values() if g.kind == "cluster"]
        attached = [
            {"workload": n.name, "ips": sorted(n.ips), "attached_to": fg.groups[n.group].name, "role": n.role_class}
            for n in fg.nodes.values()
            if n.group_source == "attached"
        ]
        return _j({"clusters": clusters, "attached_workloads": attached})

    @tool
    def rename_application(key_or_name: str, new_name: str, app_label: str = "", env_label: str = "") -> str:
        """Give a discovered cluster (or any application) a human name for the visualization
        and record the Illumio labels (app / env) to propose for its workloads. This only
        changes the local model: nothing is written to the PCE."""
        fg = store.require_graph()
        key = find_group(fg, key_or_name)
        if not key:
            return f"Unknown application '{key_or_name}'"
        group = store.rename_group(key, new_name, app_label or None, env_label or None)
        proposal = [{"workload": fg.nodes[m].name, "app": app_label or new_name, "env": env_label or group.get("env"), "role_guess": fg.nodes[m].role_class} for m in group["members"]]
        return _j({"renamed": group["key"], "name": new_name, "label_proposal": proposal})

    @tool
    def blocked_flows(application: str = "", limit: int = 50) -> str:
        """Blocked and potentially-blocked flows, optionally restricted to one application
        (as source or destination). Useful to spot policy gaps before enforcement."""
        fg = store.require_graph()
        key = find_group(fg, application) if application else None
        rows = []
        for s, d, data in fg.G.edges(data=True):
            if key and fg.nodes[s].group != key and fg.nodes[d].group != key:
                continue
            for e in data["services"].values():
                if e.worst_decision in (PolicyDecision.BLOCKED, PolicyDecision.POTENTIALLY_BLOCKED):
                    rows.append(
                        {
                            "source": fg.nodes[s].name,
                            "source_app": fg.groups[fg.nodes[s].group].name if fg.nodes[s].group else None,
                            "destination": fg.nodes[d].name,
                            "destination_app": fg.groups[fg.nodes[d].group].name if fg.nodes[d].group else None,
                            "service": e.label,
                            "service_name": e.service_name,
                            "decision": e.worst_decision.value,
                            "connections": e.connections,
                        }
                    )
        rows.sort(key=lambda r: (r["decision"] != "blocked", -r["connections"]))
        return _j({"count": len(rows), "flows": rows[:limit]})

    @tool
    def workload_details(name_or_ip: str) -> str:
        """Everything known about one workload: labels, inferred role, application, tier,
        services served and consumed, peers."""
        fg = store.require_graph()
        nid = _resolve_node(fg, name_or_ip)
        if not nid:
            return f"Unknown workload '{name_or_ip}'"
        n = fg.nodes[nid]
        peers_out = [{"to": fg.nodes[d].name, "services": [e.label for e in fg.G[nid][d]["services"].values()][:5]} for d in fg.G.successors(nid)]
        peers_in = [{"from": fg.nodes[s].name, "services": [e.label for e in fg.G[s][nid]["services"].values()][:5]} for s in fg.G.predecessors(nid)]
        info = n.to_dict()
        info["application"] = fg.groups[n.group].name if n.group else None
        info["talks_to"] = peers_out[:30]
        info["called_by"] = peers_in[:30]
        return _j(info)

    @tool
    def export_architecture(application: str = "", format: str = "mermaid") -> str:
        """Export the architecture as text: format "mermaid" (flowchart) or "markdown" (report).
        Without `application`, exports the application-level map of the whole estate."""
        fg = store.require_graph()
        flt = GraphFilter(hide_infra=True)
        if format == "markdown":
            return to_markdown(fg, app=application or None, flt=flt)
        return to_mermaid(fg, app=application or None, flt=flt)

    @tool
    def compare_periods(application: str = "", days: int = 30, split_date: str = "", a_start: str = "", a_end: str = "", b_start: str = "", b_end: str = "", against_baseline: bool = False) -> str:
        """What changed in the architecture between two periods. By default period B is the
        last `days` days of the dataset and period A the `days` before (clamped to the dataset's
        range: see graph_overview for first_seen/last_seen). Alternatives: `split_date` (A =
        before, B = after), explicit ISO dates, or `against_baseline` to compare an older export
        loaded as baseline. Restrict to one application with `application`. Returns a structured
        Markdown diff: new/removed workloads, dependencies, services, policy decision changes
        (e.g. potentially_blocked → blocked), volume variations, role/tier changes. Turn it into
        a narrative for the user, leading with the most significant changes and risks."""
        from ..diff import diff_to_markdown

        try:
            if against_baseline:
                d = store.diff(app=application or None, mode="baseline")
            else:
                d = store.diff(app=application or None, mode="period", days=days, split=split_date or None, a_start=a_start or None, a_end=a_end or None, b_start=b_start or None, b_end=b_end or None)
        except (ValueError, RuntimeError) as exc:
            return f"Cannot compute diff: {exc}"
        return diff_to_markdown(d)

    @tool
    def run_ai_enrichment(auto_apply: bool = False, min_confidence: float = 0.7) -> str:
        """Run the batch AI enrichment: propose names and Illumio labels for every unlabeled
        cluster and a role for every workload whose role is unknown. Proposals stay pending for
        human review unless auto_apply is true (then those above min_confidence are applied)."""
        from ..enrich import Enricher, enrichment_available

        ok, detail = enrichment_available()
        if not ok:
            return f"Enrichment unavailable: {detail}"
        return _j(Enricher().run(store, auto_apply=auto_apply, min_confidence=min_confidence))

    @tool
    def list_proposals(status: str = "pending") -> str:
        """AI proposals (cluster names/labels, workload roles) with their status: pending,
        accepted or rejected. Use review_proposal to accept or reject one."""
        out = []
        for kind, items in store.proposals.items():
            for pid, p in items.items():
                if status in ("all", p["status"]):
                    out.append({"kind": kind, **{k: v for k, v in p.items() if k != "workload_roles"}, "workload_roles": len(p.get("workload_roles", []))})
        return _j(out)

    @tool
    def review_proposal(kind: str, proposal_id: str, action: str) -> str:
        """Accept or reject an AI proposal. kind is "clusters" or "workloads", proposal_id the
        cluster key (e.g. "cluster:1") or workload id, action "accept" or "reject". Only do this
        when the user explicitly asked to apply or discard a proposal."""
        if kind not in store.proposals or proposal_id not in store.proposals[kind]:
            return f"Unknown proposal {kind}/{proposal_id}"
        return _j(store.review_proposal(kind, proposal_id, action))

    return [
        graph_overview,
        describe_application,
        get_dependencies,
        search_flows,
        find_path,
        list_unlabeled_clusters,
        rename_application,
        blocked_flows,
        workload_details,
        export_architecture,
        compare_periods,
        run_ai_enrichment,
        list_proposals,
        review_proposal,
    ]
