"""Core graph model: workloads (nodes) linked by aggregated services (edges), grouped into
applications.

Build it once from the normalised flows, then query it from the CLI, the API or the agent::

    fg = FlowGraph.build(flows)
    fg.groups["Shop|Production"].members
    fg.app_graph().edges(data=True)
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional

import networkx as nx

from .knowledge import AGENT_SERVICES, INFRA_ROLE_CLASSES, TIER_ORDER, role_from_hostname, role_from_label, service_info
from .models import Flow, PolicyDecision, proto_name


@dataclass
class ServiceEdge:
    """Aggregate of every flow between two nodes on one (proto, port)."""

    proto: int
    port: Optional[int]
    connections: int = 0
    flows: int = 0
    decisions: Counter = field(default_factory=Counter)  # decision value -> connections
    processes: set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    @property
    def label(self) -> str:
        return f"{proto_name(self.proto)}/{self.port}" if self.port is not None else proto_name(self.proto)

    @property
    def service_name(self) -> str:
        return service_info(self.proto, self.port)[0]

    @property
    def role_class(self) -> str:
        return service_info(self.proto, self.port)[1]

    @property
    def worst_decision(self) -> PolicyDecision:
        worst = PolicyDecision.ALLOWED
        for value in self.decisions:
            pd = PolicyDecision(value)
            if pd.severity > worst.severity:
                worst = pd
        return worst

    def add(self, flow: Flow) -> None:
        self.connections += flow.connections
        self.flows += 1
        self.decisions[flow.policy_decision.value] += flow.connections
        if flow.process_name:
            self.processes.add(flow.process_name)
        if flow.first_seen and (self.first_seen is None or flow.first_seen < self.first_seen):
            self.first_seen = flow.first_seen
        if flow.last_seen and (self.last_seen is None or flow.last_seen > self.last_seen):
            self.last_seen = flow.last_seen

    def to_dict(self) -> dict:
        return {
            "service": self.label,
            "name": self.service_name,
            "role_class": self.role_class,
            "connections": self.connections,
            "flows": self.flows,
            "decision": self.worst_decision.value,
            "decisions": dict(self.decisions),
            "processes": sorted(self.processes),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass
class Workload:
    id: str
    name: str
    managed: bool
    ips: set[str] = field(default_factory=set)
    labels: dict[str, str] = field(default_factory=dict)
    hrefs: set[str] = field(default_factory=set)
    ip_list_names: set[str] = field(default_factory=set)
    served: Counter = field(default_factory=Counter)  # (proto, port) -> connections received
    consumed: Counter = field(default_factory=Counter)  # (proto, port) -> connections initiated
    in_connections: int = 0
    out_connections: int = 0
    role_class: str = "unknown"
    role_source: str = "none"
    role_label: Optional[str] = None  # human label proposed by the AI enrichment
    group: Optional[str] = None
    group_source: str = "none"  # labels | cluster | attached | unmanaged
    shared: bool = False
    shared_kind: Optional[str] = None  # infra | service
    consumer_groups: set[str] = field(default_factory=set)
    tier: Optional[int] = None

    @property
    def app(self) -> Optional[str]:
        return self.labels.get("app")

    @property
    def env(self) -> Optional[str]:
        return self.labels.get("env")

    @property
    def top_served(self) -> list[tuple[str, int]]:
        return [(f"{proto_name(p)}/{port}" if port is not None else proto_name(p), c) for (p, port), c in self.served.most_common(5)]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "managed": self.managed,
            "ips": sorted(self.ips),
            "labels": self.labels,
            "role_class": self.role_class,
            "role_source": self.role_source,
            "role_label": self.role_label or self.labels.get("role"),
            "group": self.group,
            "group_source": self.group_source,
            "shared": self.shared,
            "shared_kind": self.shared_kind,
            "consumer_groups": sorted(self.consumer_groups),
            "tier": self.tier,
            "served": [{"service": s, "connections": c} for s, c in self.top_served],
            "consumed": [
                {"service": f"{proto_name(p)}/{port}" if port is not None else proto_name(p), "connections": c}
                for (p, port), c in self.consumed.most_common(5)
            ],
            "in_connections": self.in_connections,
            "out_connections": self.out_connections,
            "ip_lists": sorted(self.ip_list_names),
        }


@dataclass
class AppGroup:
    key: str
    name: str
    kind: str  # labeled | cluster | attached | unmanaged
    app: Optional[str] = None
    env: Optional[str] = None
    loc: Optional[str] = None
    members: list[str] = field(default_factory=list)
    suggested_name: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    shared: bool = False

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "kind": self.kind,
            "app": self.app,
            "env": self.env,
            "loc": self.loc,
            "members": self.members,
            "member_count": len(self.members),
            "suggested_name": self.suggested_name,
            "evidence": self.evidence,
            "shared": self.shared,
        }


class FlowGraph:
    """Workload-level directed graph plus application groups derived from it."""

    def __init__(
        self,
        group_by: tuple[str, ...] = ("app", "env"),
        unmanaged_grouping: str = "iplist",  # iplist | subnet | ip
        shared_min_consumers: int = 3,
        subnet_prefix: int = 24,
        attach_unmanaged: bool = True,
        ip_lists: Optional[dict[str, list[str]]] = None,
        role_overrides: Optional[dict[str, dict]] = None,
    ):
        import ipaddress

        # node id -> {"role_class": ..., "role_label": ...}, accepted AI proposals (role_source="ai")
        self.role_overrides = dict(role_overrides or {})
        self.group_by = tuple(group_by)
        self.unmanaged_grouping = unmanaged_grouping
        self.shared_min_consumers = shared_min_consumers
        self.subnet_prefix = subnet_prefix
        self.attach_unmanaged = attach_unmanaged
        # name -> list of ip_network, used to name unmanaged IPs when the source has no IP-list info
        self.ip_lists = {
            name: [ipaddress.ip_network(c, strict=False) for c in cidrs] for name, cidrs in (ip_lists or {}).items()
        }
        self.G: nx.DiGraph = nx.DiGraph()
        self.nodes: dict[str, Workload] = {}
        self.groups: dict[str, AppGroup] = {}
        self.flow_count = 0
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.sources: Counter = Counter()
        self._app_graph: Optional[nx.DiGraph] = None

    # ------------------------------------------------------------------ build
    @classmethod
    def build(cls, flows: Iterable[Flow], **kwargs) -> "FlowGraph":
        fg = cls(**kwargs)
        for flow in flows:
            fg.add_flow(flow)
        fg.finalise()
        return fg

    def add_flow(self, flow: Flow) -> None:
        src = self._node(flow.src.identity, flow)
        dst = self._node(flow.dst.identity, flow)
        self._merge_endpoint(src, flow.src)
        self._merge_endpoint(dst, flow.dst)
        key = (flow.proto, flow.port)
        src.consumed[key] += flow.connections
        dst.served[key] += flow.connections
        src.out_connections += flow.connections
        dst.in_connections += flow.connections
        if not self.G.has_edge(src.id, dst.id):
            self.G.add_edge(src.id, dst.id, services={})
        services: dict = self.G[src.id][dst.id]["services"]
        edge = services.get(key)
        if edge is None:
            edge = services[key] = ServiceEdge(proto=flow.proto, port=flow.port)
        edge.add(flow)
        self.flow_count += 1
        self.sources[flow.source_format] += 1
        if flow.first_seen and (self.first_seen is None or flow.first_seen < self.first_seen):
            self.first_seen = flow.first_seen
        if flow.last_seen and (self.last_seen is None or flow.last_seen > self.last_seen):
            self.last_seen = flow.last_seen

    def _node(self, node_id: str, flow: Flow) -> Workload:
        node = self.nodes.get(node_id)
        if node is None:
            node = Workload(id=node_id, name=node_id, managed=False)
            self.nodes[node_id] = node
            self.G.add_node(node_id)
        return node

    @staticmethod
    def _merge_endpoint(node: Workload, ep) -> None:
        if ep.ip:
            node.ips.add(ep.ip)
        if ep.hostname:
            node.name = ep.hostname
        if ep.href:
            node.hrefs.add(ep.href)
        if ep.managed:
            node.managed = True
        for k, v in ep.labels.items():
            node.labels.setdefault(k, v)
        node.ip_list_names.update(ep.ip_list_names)

    def finalise(self) -> None:
        from . import discovery  # local import to avoid a cycle

        for node in self.nodes.values():
            self._infer_role(node)
            override = self.role_overrides.get(node.id)
            if override and override.get("role_class"):
                node.role_class, node.role_source = override["role_class"], "ai"
                if override.get("role_label"):
                    node.role_label = override["role_label"]
        discovery.assign_labeled_groups(self)
        discovery.detect_shared_services(self)  # pass 1: labeled consumers only
        discovery.cluster_unlabeled(self)  # attach / Louvain, ignoring shared peers
        discovery.detect_shared_services(self)  # pass 2: clusters now count as consumers
        discovery.compute_tiers(self)
        self._app_graph = None

    # ------------------------------------------------------------- inference
    def _infer_role(self, node: Workload) -> None:
        cls = role_from_label(node.labels.get("role"))
        if cls:
            node.role_class, node.role_source = cls, "label"
            return
        scores: Counter = Counter()
        real_served = False
        for (proto, port), conns in node.served.items():
            name, role = service_info(proto, port)
            if name in AGENT_SERVICES:
                continue
            real_served = True
            if role in ("unknown", "admin"):
                continue
            scores[role] += math.log1p(conns) + (1.0 if role not in INFRA_ROLE_CLASSES else 0.0)
        if scores:
            node.role_class, node.role_source = scores.most_common(1)[0][0], "ports"
            return
        cls = role_from_hostname(node.name) if node.managed else None
        if cls:
            node.role_class, node.role_source = cls, "hostname"
            return
        if real_served:
            node.role_class, node.role_source = "unknown", "none"
        elif node.consumed:
            node.role_class, node.role_source = "client", "none"

    # ---------------------------------------------------------------- queries
    def group_of(self, node_id: str) -> Optional[AppGroup]:
        node = self.nodes.get(node_id)
        return self.groups.get(node.group) if node and node.group else None

    def edge_services(self, src: str, dst: str) -> dict[tuple[int, Optional[int]], ServiceEdge]:
        if self.G.has_edge(src, dst):
            return self.G[src][dst]["services"]
        return {}

    def app_graph(self, rebuild: bool = False) -> nx.DiGraph:
        """Application-level graph: one node per group, edges aggregated per service."""
        if self._app_graph is not None and not rebuild:
            return self._app_graph
        AG = nx.DiGraph()
        for key, group in self.groups.items():
            AG.add_node(key, group=group)
        for src, dst, data in self.G.edges(data=True):
            gs, gd = self.nodes[src].group, self.nodes[dst].group
            if gs is None or gd is None or gs == gd:
                continue
            if not AG.has_edge(gs, gd):
                AG.add_edge(gs, gd, services={}, connections=0, pairs=0)
            agg = AG[gs][gd]
            agg["pairs"] += 1
            for key, edge in data["services"].items():
                target = agg["services"].get(key)
                if target is None:
                    target = agg["services"][key] = ServiceEdge(proto=edge.proto, port=edge.port)
                target.connections += edge.connections
                target.flows += edge.flows
                target.decisions.update(edge.decisions)
                target.processes.update(edge.processes)
                if edge.first_seen and (target.first_seen is None or edge.first_seen < target.first_seen):
                    target.first_seen = edge.first_seen
                if edge.last_seen and (target.last_seen is None or edge.last_seen > target.last_seen):
                    target.last_seen = edge.last_seen
                agg["connections"] += edge.connections
        self._app_graph = AG
        return AG

    def internal_edges(self, group_key: str) -> list[tuple[str, str, dict]]:
        members = set(self.groups[group_key].members)
        return [(s, d, data) for s, d, data in self.G.edges(data=True) if s in members and d in members]

    def dependencies(self, group_key: str, direction: str = "both", include_shared: bool = True) -> dict[str, list[dict]]:
        """Inbound (consumers of this app) and outbound (providers it relies on) dependencies."""
        AG = self.app_graph()
        out: dict[str, list[dict]] = {"outbound": [], "inbound": []}
        if group_key not in AG:
            return out
        if direction in ("both", "outbound"):
            for _, dst, data in AG.out_edges(group_key, data=True):
                g = self.groups[dst]
                if not include_shared and g.shared:
                    continue
                out["outbound"].append(self._dep_dict(g, data))
        if direction in ("both", "inbound"):
            for src, _, data in AG.in_edges(group_key, data=True):
                g = self.groups[src]
                if not include_shared and g.shared:
                    continue
                out["inbound"].append(self._dep_dict(g, data))
        for lst in out.values():
            lst.sort(key=lambda d: -d["connections"])
        return out

    @staticmethod
    def _dep_dict(group: AppGroup, data: dict) -> dict:
        services = sorted(data["services"].values(), key=lambda e: -e.connections)
        return {
            "group": group.key,
            "name": group.name,
            "env": group.env,
            "kind": group.kind,
            "shared": group.shared,
            "connections": data["connections"],
            "services": [e.to_dict() for e in services[:10]],
            "decision": max((e.worst_decision for e in services), key=lambda d: d.severity).value if services else "unknown",
        }

    def stats(self) -> dict:
        decisions: Counter = Counter()
        for _, _, data in self.G.edges(data=True):
            for edge in data["services"].values():
                decisions.update(edge.decisions)
        kinds = Counter(g.kind for g in self.groups.values())
        return {
            "flows": self.flow_count,
            "sources": dict(self.sources),
            "workloads": len(self.nodes),
            "managed_workloads": sum(1 for n in self.nodes.values() if n.managed),
            "edges": self.G.number_of_edges(),
            "services": sum(len(d["services"]) for _, _, d in self.G.edges(data=True)),
            "groups": len(self.groups),
            "groups_by_kind": dict(kinds),
            "shared_nodes": sum(1 for n in self.nodes.values() if n.shared),
            "connections_by_decision": dict(decisions),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "envs": sorted({g.env for g in self.groups.values() if g.env}),
        }

    def rename_group(self, key: str, name: str, app: Optional[str] = None, env: Optional[str] = None) -> AppGroup:
        group = self.groups[key]
        group.name = name
        if app:
            group.app = app
        if env:
            group.env = env
        return group

    # --------------------------------------------------------------- helpers
    def tier_order(self, node: Workload) -> int:
        return TIER_ORDER.get(node.role_class, TIER_ORDER["unknown"])
