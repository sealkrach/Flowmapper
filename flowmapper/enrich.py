"""AI enrichment of the discovered model, with human-in-the-loop validation.

Two batch jobs run against the LLM (structured output, a few calls for a whole estate):

* **clusters** – every unlabeled cluster gets a proposed application name, Illumio
  ``app`` / ``env`` labels and a role per workload, justified by the evidence gathered
  by :mod:`flowmapper.discovery` (hostnames, services served, neighbouring applications).
* **roles** – managed workloads whose role could not be inferred from labels or ports
  get a proposed role class and label (from hostname, processes, services consumed...).

Nothing is applied automatically unless asked: proposals are stored as *pending* in the
:class:`~flowmapper.store.Store`, reviewed in the UI / API / agent, and only accepted ones
change the model (``role_source = "ai"``, cluster renamed, labels recorded). Nothing is ever
written to the PCE.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from .knowledge import AGENT_SERVICES, service_info
from .models import proto_name

log = logging.getLogger("flowmapper.enrich")

ROLE_CLASSES = Literal[
    "edge", "web", "api", "app", "worker", "database", "cache", "messaging", "search", "coordination",
    "storage", "directory", "infra", "monitoring", "security", "platform", "admin", "mail", "client", "unknown",
]


class WorkloadRoleProposal(BaseModel):
    workload: str = Field(description="workload id exactly as given")
    role_class: ROLE_CLASSES
    role_label: str = Field(description="short human label for the Illumio role label, e.g. 'Reporting Server'")
    confidence: float = Field(ge=0, le=1)
    rationale: str = Field(description="one sentence, grounded in the evidence")


class RoleBatch(BaseModel):
    proposals: list[WorkloadRoleProposal]


class ClusterProposal(BaseModel):
    cluster: str = Field(description="cluster key exactly as given")
    name: str = Field(description="human application name")
    app_label: str = Field(description="value to use for the Illumio 'app' label")
    env_label: Optional[str] = Field(default=None, description="value for the Illumio 'env' label, if it can be inferred")
    confidence: float = Field(ge=0, le=1)
    rationale: str
    workload_roles: list[WorkloadRoleProposal] = Field(default_factory=list)


class ClusterBatch(BaseModel):
    proposals: list[ClusterProposal]


SYSTEM_CLUSTERS = """You are an application architect labeling workloads in an Illumio deployment.
You receive clusters of VEN-managed servers that have no Illumio application label. For each
cluster, propose a human application name, the values for the Illumio `app` and `env` labels,
and a role per workload. Ground every proposal in the evidence (hostnames, services served,
processes, applications they talk to, environment labels seen). If the evidence says the
cluster is probably the unlabeled part of an existing application ("candidate_app"), reuse that
application's name and say so. Use the existing naming conventions visible in the known
application names. Be conservative with confidence: 0.9+ only when hostnames are explicit.
Write rationale and labels in {language}; keep hostnames and service names unchanged."""

SYSTEM_ROLES = """You are an application architect labeling workloads in an Illumio deployment.
For each workload below the role could not be inferred from Illumio labels or from well-known
ports. Propose a role class (one of the allowed values) and a short human role label from the
evidence: hostname, application, services served with their connection counts, processes seen,
services consumed, callers. A workload that only consumes services is usually a 'client',
'worker' or 'app' depending on what it consumes; one that serves an unknown TCP port with a
Java/.NET process is usually 'app' or 'api'. Keep 'unknown' when evidence is insufficient.
Write rationale and labels in {language}."""


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Enricher:
    def __init__(self, llm: Any = None, model: Optional[str] = None, language: Optional[str] = None, batch_size: int = 25):
        self.model_name = model or os.getenv("FLOWMAPPER_MODEL", "anthropic:claude-sonnet-5-5")
        self.language = language or os.getenv("FLOWMAPPER_LANGUAGE", "fr")
        self.batch_size = batch_size
        self._llm = llm

    # ----------------------------------------------------------------- LLM access
    @property
    def llm(self):
        if self._llm is None:
            from langchain.chat_models import init_chat_model

            self._llm = init_chat_model(self.model_name)
        return self._llm

    def _call(self, schema: type[BaseModel], system: str, payload: dict) -> BaseModel:
        """One structured LLM call. Tests replace this method."""
        from langchain_core.messages import HumanMessage, SystemMessage

        structured = self.llm.with_structured_output(schema)
        return structured.invoke([SystemMessage(content=system.format(language=self.language)), HumanMessage(content=json.dumps(payload, ensure_ascii=False))])

    # ----------------------------------------------------------------- evidence
    @staticmethod
    def _workload_evidence(fg, node) -> dict:
        served = [
            {"service": f"{proto_name(p)}/{port}" if port is not None else proto_name(p), "name": service_info(p, port)[0], "connections": c}
            for (p, port), c in node.served.most_common(8)
            if service_info(p, port)[0] not in AGENT_SERVICES
        ]
        consumed = [
            {"service": f"{proto_name(p)}/{port}" if port is not None else proto_name(p), "name": service_info(p, port)[0], "connections": c}
            for (p, port), c in node.consumed.most_common(8)
            if service_info(p, port)[0] not in AGENT_SERVICES
        ]
        processes: set[str] = set()
        callers: set[str] = set()
        callees: set[str] = set()
        for pred in fg.G.predecessors(node.id):
            for e in fg.G[pred][node.id]["services"].values():
                processes.update(e.processes)
            g = fg.nodes[pred].group
            callers.add(fg.groups[g].name if g else fg.nodes[pred].name)
        for succ in fg.G.successors(node.id):
            g = fg.nodes[succ].group
            callees.add(fg.groups[g].name if g else fg.nodes[succ].name)
        return {
            "workload": node.id,
            "hostname": node.name,
            "ips": sorted(node.ips)[:3],
            "labels": node.labels,
            "application": fg.groups[node.group].name if node.group else None,
            "current_role_class": node.role_class,
            "serves": served,
            "processes_serving": sorted(processes)[:10],
            "consumes": consumed,
            "called_by": sorted(callers)[:10],
            "calls": sorted(callees)[:10],
        }

    def _cluster_evidence(self, fg, group) -> dict:
        return {
            "cluster": group.key,
            "current_suggested_name": group.suggested_name,
            "evidence": group.evidence,
            "workloads": [self._workload_evidence(fg, fg.nodes[m]) for m in group.members[:40]],
        }

    # ----------------------------------------------------------------- jobs
    def propose_clusters(self, fg) -> list[ClusterProposal]:
        clusters = [g for g in fg.groups.values() if g.kind == "cluster" and g.key != "cluster:unclassified"]
        if not clusters:
            return []
        known_apps = sorted({g.name for g in fg.groups.values() if g.kind == "labeled"})
        envs = sorted({g.env for g in fg.groups.values() if g.env})
        out: list[ClusterProposal] = []
        for i in range(0, len(clusters), 5):
            batch = clusters[i : i + 5]
            payload = {"known_applications": known_apps, "known_environments": envs, "clusters": [self._cluster_evidence(fg, g) for g in batch]}
            result = self._call(ClusterBatch, SYSTEM_CLUSTERS, payload)
            valid = {g.key for g in batch}
            out.extend(p for p in result.proposals if p.cluster in valid)
        return out

    def propose_roles(self, fg) -> list[WorkloadRoleProposal]:
        targets = [n for n in fg.nodes.values() if n.managed and n.role_class in ("unknown", "client") and n.role_source != "ai"]
        if not targets:
            return []
        out: list[WorkloadRoleProposal] = []
        for i in range(0, len(targets), self.batch_size):
            batch = targets[i : i + self.batch_size]
            payload = {"allowed_role_classes": list(ROLE_CLASSES.__args__), "workloads": [self._workload_evidence(fg, n) for n in batch]}
            result = self._call(RoleBatch, SYSTEM_ROLES, payload)
            valid = {n.id for n in batch}
            out.extend(p for p in result.proposals if p.workload in valid)
        return out

    def run(self, store, clusters: bool = True, roles: bool = True, auto_apply: bool = False, min_confidence: float = 0.7) -> dict:
        """Run the enabled jobs against ``store.graph`` and record proposals in the store."""
        fg = store.require_graph()
        created = {"clusters": 0, "workloads": 0, "applied": 0}
        if clusters:
            for p in self.propose_clusters(fg):
                store.add_proposal("clusters", p.cluster, {"name": p.name, "app": p.app_label, "env": p.env_label, "confidence": p.confidence, "rationale": p.rationale, "workload_roles": [r.model_dump() for r in p.workload_roles]})
                created["clusters"] += 1
        if roles:
            for p in self.propose_roles(fg):
                store.add_proposal("workloads", p.workload, {"role_class": p.role_class, "role_label": p.role_label, "confidence": p.confidence, "rationale": p.rationale})
                created["workloads"] += 1
        if auto_apply:
            for kind in ("clusters", "workloads"):
                for pid, prop in list(store.proposals[kind].items()):
                    if prop["status"] == "pending" and prop["confidence"] >= min_confidence:
                        store.review_proposal(kind, pid, "accept")
                        created["applied"] += 1
        created["pending"] = store.pending_proposals()
        return created


def enrichment_available() -> tuple[bool, str]:
    from .agent.agent import agent_available

    return agent_available()
