"""Application discovery on top of :class:`flowmapper.graph.FlowGraph`.

1. ``assign_labeled_groups`` – workloads carrying an Illumio ``app`` label form a group per
   ``group_by`` tuple (default ``(app, env)``); unmanaged IPs are grouped by IP list / subnet.
2. ``cluster_unlabeled`` – unlabeled managed workloads are first clustered among themselves
   (Louvain communities on the traffic they exchange); cohesive communities become candidate
   applications with a suggested name. Isolated workloads (and VEN-less IPs outside any IP
   list) are *attached* to the only application they talk to.
3. ``detect_shared_services`` – nodes consumed by many applications are flagged shared
   (``infra`` when they serve DNS/AD/monitoring-like services, ``service`` otherwise).
4. ``compute_tiers`` – inside each application, workloads are layered by their distance to
   the data tier (front → middle → data).

Only *effective* traffic (allowed / potentially blocked / unknown) drives these decisions:
blocked attempts are kept in the graph for display but never shape the architecture.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from os.path import commonprefix
from typing import TYPE_CHECKING

import networkx as nx

from .knowledge import AGENT_SERVICES, INFRA_ROLE_CLASSES, TIER_ORDER, service_info

if TYPE_CHECKING:
    from .graph import AppGroup, FlowGraph, Workload

CLUSTER_PREFIX = "cluster"
UNCLASSIFIED = "cluster:unclassified"


# ----------------------------------------------------------------------------- helpers
def effective_connections(data: dict, ignore_agents: bool = True) -> int:
    """Connections that actually flowed (everything but ``blocked``), ignoring management
    services (ssh, monitoring agents...) that every host exposes and that carry no
    architectural meaning."""
    total = 0
    for edge in data["services"].values():
        if ignore_agents and edge.service_name in AGENT_SERVICES:
            continue
        total += sum(c for pd, c in edge.decisions.items() if pd != "blocked")
    return total


def _group_key(labels: dict[str, str], group_by: tuple[str, ...]) -> str:
    return "|".join(labels.get(k, "-") for k in group_by)


def _group_name(labels: dict[str, str], group_by: tuple[str, ...]) -> str:
    app = labels.get("app")
    extra = [labels[k] for k in group_by if k not in ("app", "env") and labels.get(k)]
    return f"{app} ({', '.join(extra)})" if extra else (app or _group_key(labels, group_by))


def _labeled_peers(fg: "FlowGraph", node: "Workload", as_provider_only: bool = False) -> Counter:
    """Labeled, non-shared application groups this node exchanges effective traffic with.

    With ``as_provider_only`` only the traffic *received* by the node counts: a VEN-less IP
    is a component of an application when the application calls it, not when it merely
    browses the application (Internet clients, office users)."""
    peers: Counter = Counter()
    for nb in set(fg.G.predecessors(node.id)) | set(fg.G.successors(node.id)):
        other = fg.nodes[nb]
        if other.shared or other.id == node.id:
            continue
        g = other.group
        if not (g and fg.groups[g].kind == "labeled" and not fg.groups[g].shared):
            continue
        conns = 0
        if fg.G.has_edge(node.id, nb) and not as_provider_only:
            conns += effective_connections(fg.G[node.id][nb])
        if fg.G.has_edge(nb, node.id):
            conns += effective_connections(fg.G[nb][node.id])
        if conns:
            peers[g] += conns
    return peers


def _is_private(node: "Workload") -> bool:
    import ipaddress

    for ip in node.ips:
        try:
            if not ipaddress.ip_address(ip).is_private:
                return False
        except ValueError:
            return False
    return bool(node.ips)


# ------------------------------------------------------------------- labeled groups
def assign_labeled_groups(fg: "FlowGraph") -> None:
    from .graph import AppGroup

    for node in fg.nodes.values():
        if node.managed and node.labels.get("app"):
            key = _group_key(node.labels, fg.group_by)
            group = fg.groups.get(key)
            if group is None:
                group = fg.groups[key] = AppGroup(
                    key=key,
                    name=_group_name(node.labels, fg.group_by),
                    kind="labeled",
                    app=node.labels.get("app"),
                    env=node.labels.get("env"),
                    loc=node.labels.get("loc"),
                )
            group.members.append(node.id)
            node.group, node.group_source = key, "labels"
        elif not node.managed:
            _group_unmanaged(fg, node)


def _group_unmanaged(fg: "FlowGraph", node: "Workload") -> None:
    from .graph import AppGroup

    if not node.ip_list_names and fg.ip_lists:
        # Syslog summaries carry no IP-list names: resolve them from the configured CIDRs.
        import ipaddress

        for ip in node.ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for name, nets in fg.ip_lists.items():
                if any(addr in net for net in nets):
                    node.ip_list_names.add(name)
                    break
    if fg.unmanaged_grouping == "ip":
        key, name = f"unmanaged:{node.id}", node.name
    elif fg.unmanaged_grouping == "iplist" and node.ip_list_names:
        name = sorted(node.ip_list_names)[0]
        key = f"unmanaged:iplist:{name}"
    else:
        from .models import Endpoint

        ip = next(iter(node.ips), node.id)
        subnet = Endpoint(ip=ip).subnet(fg.subnet_prefix)
        key, name = f"unmanaged:net:{subnet}", f"Unmanaged {subnet}"
    group = fg.groups.get(key)
    if group is None:
        group = fg.groups[key] = AppGroup(key=key, name=name, kind="unmanaged")
    group.members.append(node.id)
    node.group, node.group_source = key, "unmanaged"


# --------------------------------------------------------------------- clustering
def cluster_unlabeled(fg: "FlowGraph", attach: bool = True, min_cluster_size: int = 2) -> None:
    from .graph import AppGroup

    pending = [n for n in fg.nodes.values() if n.managed and n.group is None]
    ids = {n.id for n in pending}

    # Step 1 – communities among unlabeled workloads, weighted by effective traffic.
    H = nx.Graph()
    H.add_nodes_from(ids)
    for s, d, data in fg.G.subgraph(ids).edges(data=True):
        conns = effective_connections(data)
        if s == d or not conns:
            continue
        w = math.log1p(conns)
        if H.has_edge(s, d):
            H[s][d]["weight"] += w
        else:
            H.add_edge(s, d, weight=w)
    communities = nx.community.louvain_communities(H, weight="weight", seed=42) if H.number_of_edges() else [{n} for n in ids]
    clusters = sorted((sorted(c) for c in communities if len(c) >= max(2, min_cluster_size)), key=lambda c: (-len(c), c[0]))
    singletons = sorted(n for c in communities if len(c) < max(2, min_cluster_size) for n in c)

    # Step 2 – attach isolated workloads (and VEN-less IPs outside any IP list) to the only
    # application they exchange traffic with. Shared infrastructure never counts as a peer.
    remaining: list[str] = []
    if attach:
        candidates = [fg.nodes[n] for n in singletons]
        if fg.attach_unmanaged:
            # VEN-less private IPs outside any IP list, only when they *serve* an application
            candidates += [n for n in fg.nodes.values() if not n.managed and not n.ip_list_names and not n.shared and _is_private(n) and n.served]
        for node in candidates:
            peers = _labeled_peers(fg, node, as_provider_only=not node.managed)
            if len(peers) == 1:
                key = next(iter(peers))
                _move_node(fg, node, key, "attached")
            elif node.managed:
                remaining.append(node.id)
    else:
        remaining = singletons

    # Step 3 – materialise clusters.
    for i, members in enumerate(clusters, start=1):
        key = f"{CLUSTER_PREFIX}:{i}"
        group = AppGroup(key=key, name=key, kind="cluster", members=list(members))
        fg.groups[key] = group
        for m in members:
            fg.nodes[m].group, fg.nodes[m].group_source = key, "cluster"
        _describe_cluster(fg, group)
    if remaining:
        group = fg.groups.get(UNCLASSIFIED) or AppGroup(key=UNCLASSIFIED, name="Unclassified workloads", kind="cluster")
        group.members.extend(remaining)
        fg.groups[UNCLASSIFIED] = group
        for m in remaining:
            fg.nodes[m].group, fg.nodes[m].group_source = UNCLASSIFIED, "cluster"
        _describe_cluster(fg, group, name=False)


def _move_node(fg: "FlowGraph", node: "Workload", key: str, source: str) -> None:
    if node.group and node.group != key:
        old = fg.groups[node.group]
        if node.id in old.members:
            old.members.remove(node.id)
        if not old.members:
            del fg.groups[node.group]
    fg.groups[key].members.append(node.id)
    node.group, node.group_source = key, source


def _describe_cluster(fg: "FlowGraph", group: "AppGroup", name: bool = True) -> None:
    nodes = [fg.nodes[m] for m in group.members]
    hostnames = sorted(n.name for n in nodes if n.managed)
    served: Counter = Counter()
    for n in nodes:
        for (proto, port), c in n.served.items():
            svc = service_info(proto, port)[0]
            if svc not in AGENT_SERVICES:
                served[svc] += c
    envs = Counter(n.labels.get("env") for n in nodes if n.labels.get("env"))
    locs = Counter(n.labels.get("loc") for n in nodes if n.labels.get("loc"))
    roles = Counter(n.role_class for n in nodes)
    peers: Counter = Counter()
    for n in nodes:
        for g, conns in _labeled_peers(fg, n).items():
            peers[g] += conns
    group.env = envs.most_common(1)[0][0] if envs else None
    group.loc = locs.most_common(1)[0][0] if locs else None
    group.evidence = {
        "hostnames": hostnames[:25],
        "served_services": [s for s, _ in served.most_common(8)],
        "role_classes": dict(roles),
        "envs": dict(envs),
        "peer_groups": [fg.groups[g].name for g, _ in peers.most_common(8)],
    }
    if len(peers) == 1:
        # The whole community only talks to one labeled application: probably its unlabeled part.
        group.evidence["candidate_app"] = fg.groups[next(iter(peers))].name
    if name:
        group.suggested_name = _suggest_name(hostnames, served)
        group.name = group.suggested_name


STOP_TOKENS = {"web", "app", "api", "srv", "prod", "prd", "dev", "test", "tst", "uat", "node", "host", "vm", "server", "db", "lb"}


def _suggest_name(hostnames: list[str], served: Counter) -> str:
    prefix = commonprefix(hostnames) if hostnames else ""
    prefix = re.sub(r"[\d\-_.]+$", "", prefix)
    prefix = re.sub(r"(?i)(web|app|db|api|srv|lb|prd|prod|uat|dev|tst|test)$", "", prefix).strip("-_.")
    if len(prefix) >= 3:
        return prefix
    tokens: Counter = Counter()
    for h in hostnames:
        for tok in re.split(r"[\-_.\d]+", h.lower()):
            if len(tok) >= 3 and tok not in STOP_TOKENS:
                tokens[tok] += 1
    if tokens and tokens.most_common(1)[0][1] >= max(2, len(hostnames) // 2):
        return tokens.most_common(1)[0][0]
    top = [s for s, _ in served.most_common(2)]
    return "cluster (" + ", ".join(top) + ")" if top else "cluster"


# ----------------------------------------------------------------- shared services
def detect_shared_services(fg: "FlowGraph") -> None:
    counted_kinds = {"labeled", "cluster"}
    for node in fg.nodes.values():
        consumers = set()
        for pred in fg.G.predecessors(node.id):
            g = fg.nodes[pred].group
            if g and g != node.group and fg.groups[g].kind in counted_kinds and effective_connections(fg.G[pred][node.id]):
                consumers.add(g)
        node.consumer_groups = consumers
        if len(consumers) >= fg.shared_min_consumers:
            node.shared = True
            infra_conns = sum(c for (p, port), c in node.served.items() if service_info(p, port)[1] in INFRA_ROLE_CLASSES)
            node.shared_kind = "infra" if (node.role_class in INFRA_ROLE_CLASSES or infra_conns > node.in_connections / 2) else "service"
        else:
            node.shared, node.shared_kind = False, None
    for group in fg.groups.values():
        if not group.members:
            continue
        shared = sum(1 for m in group.members if fg.nodes[m].shared)
        group.shared = shared * 2 >= len(group.members)


# -------------------------------------------------------------------------- tiers
def compute_tiers(fg: "FlowGraph") -> None:
    for group in fg.groups.values():
        members = set(group.members)
        if not members:
            continue
        sub = nx.DiGraph()
        sub.add_nodes_from(members)
        for s, d, data in fg.G.subgraph(members).edges(data=True):
            if s != d and effective_connections(data):
                sub.add_edge(s, d)
        if sub.number_of_edges() == 0:
            for m in members:
                fg.nodes[m].tier = _role_rank(fg, m)
            continue
        cond = nx.condensation(sub)
        depth: dict[int, int] = {}
        for c in reversed(list(nx.topological_sort(cond))):
            succ = list(cond.successors(c))
            depth[c] = 0 if not succ else 1 + max(depth[s] for s in succ)
        max_depth = max(depth.values())
        mapping = cond.graph["mapping"]
        for m in members:
            fg.nodes[m].tier = max_depth - depth[mapping[m]]


def _role_rank(fg: "FlowGraph", node_id: str) -> int:
    return min(TIER_ORDER.get(fg.nodes[node_id].role_class, 5), 3)
