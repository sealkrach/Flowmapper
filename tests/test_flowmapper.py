"""End-to-end tests on the synthetic dataset (parsers, discovery, exports, API)."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from flowmapper import FlowGraph, detect_format, load_flows
from flowmapper.exports import GraphFilter, to_cytoscape, to_graphml, to_markdown, to_mermaid
from flowmapper.models import PolicyDecision
from flowmapper.parsers.explorer_csv import parse_explorer_csv
from flowmapper.parsers.syslog_json import iter_json_objects, parse_syslog_records
from flowmapper.sample import generate


@pytest.fixture(scope="session")
def samples(tmp_path_factory) -> dict[str, Path]:
    return generate(tmp_path_factory.mktemp("samples"))


@pytest.fixture(scope="session")
def graph(samples) -> FlowGraph:
    return FlowGraph.build(load_flows(samples["api_json"]))


def test_formats_are_detected(samples):
    for fmt, path in samples.items():
        assert detect_format(path) == fmt


def test_three_sources_give_the_same_graph(samples):
    stats = [FlowGraph.build(load_flows(p)).stats() for p in samples.values()]
    for key in ("flows", "workloads", "managed_workloads", "edges", "services", "connections_by_decision"):
        assert len({json.dumps(s[key], sort_keys=True) for s in stats}) == 1, key


def test_old_style_explorer_header():
    csv = io.StringIO(
        "Consumer IP,Consumer Name,Consumer Role,Consumer Application,Consumer Environment,Provider IP,Provider Name,Provider Application,Port,Protocol,Reported Policy,Connections\n"
        "10.0.0.1,web01,Web,Shop,Prod,10.0.0.2,db01,Shop,5432,TCP,Allowed,12\n"
    )
    flows = list(parse_explorer_csv(csv))
    assert len(flows) == 1
    f = flows[0]
    assert f.src.labels == {"role": "Web", "app": "Shop", "env": "Prod"}
    assert f.dst.identity == "db01" and f.port == 5432 and f.proto == 6
    assert f.policy_decision is PolicyDecision.ALLOWED and f.connections == 12


def test_syslog_prefix_and_pd_mapping():
    line = '<14>1 2026-11-01T10:00:00Z pce illumio_pce/collector 1 - - {"src_ip":"10.1.1.1","dst_ip":"10.1.1.2","dst_port":443,"proto":6,"pd":2,"dir":"I","count":3,"dst_labels":[{"key":"app","value":"X"}]}'
    flows = list(parse_syslog_records(iter_json_objects([line])))
    assert flows[0].policy_decision is PolicyDecision.BLOCKED
    assert flows[0].dst.labels == {"app": "X"}
    assert flows[0].connections == 3


def test_labeled_groups_and_tiers(graph):
    ecom = graph.groups["E-Commerce|Production"]
    assert ecom.kind == "labeled" and len(ecom.members) == 11
    tiers = {graph.nodes[m].name: graph.nodes[m].tier for m in ecom.members}
    assert tiers["ecom-lb01"] < tiers["ecom-web01"] < tiers["ecom-api01"] < tiers["ecom-pg01"]
    assert tiers["ecom-worker01"] == tiers["ecom-api01"]


def test_shared_infra_detected(graph):
    core = graph.groups["Core Infra|Production"]
    assert core.shared
    assert graph.nodes["dc01"].shared_kind == "infra"
    assert not graph.nodes["ecom-pg01"].shared  # only two other apps consume it


def test_unlabeled_cluster_and_attachments(graph):
    clusters = [g for g in graph.groups.values() if g.kind == "cluster"]
    assert len(clusters) == 1
    erp = clusters[0]
    assert sorted(erp.members) == ["erp-app01", "erp-db01", "erp-web01"]
    assert erp.suggested_name == "erp"
    assert graph.nodes["rpt01"].group == "CRM|Production" and graph.nodes["rpt01"].group_source == "attached"
    assert graph.nodes["10.20.9.10"].group == "Payments|Production"  # VEN-less HSM appliance


def test_roles(graph):
    assert graph.nodes["ecom-lb01"].role_class == "edge"
    assert graph.nodes["erp-db01"].role_class == "database" and graph.nodes["erp-db01"].role_source == "ports"
    assert graph.nodes["rpt01"].role_class == "worker"


def test_dependencies(graph):
    deps = graph.dependencies("E-Commerce|Production", include_shared=False)
    assert {d["name"] for d in deps["outbound"]} == {"Search Platform", "Payments"}
    assert "CRM" in {d["name"] for d in deps["inbound"]}


def test_exports(graph):
    cy = to_cytoscape(graph, "workload", GraphFilter(hide_infra=True))
    ids = {n["data"]["id"] for n in cy["elements"]["nodes"]}
    assert "g:Core Infra|Production" not in ids and "w:ecom-api01" in ids
    assert "flowchart" in to_mermaid(graph, app="CRM")
    assert "| Tier |" in to_markdown(graph, app="E-Commerce")
    assert to_graphml(graph).startswith("<?xml")


def test_api(samples):
    from fastapi.testclient import TestClient

    from flowmapper.api import main as api

    api.store.clear()
    with TestClient(api.app) as client:
        with open(samples["explorer_csv"], "rb") as fh:
            r = client.post("/api/ingest", files=[("files", ("x.csv", fh, "text/csv"))])
        assert r.status_code == 200 and r.json()["stats"]["flows"] == len(load_flows(samples["explorer_csv"]))
        assert client.get("/api/graph?level=app").status_code == 200
        assert client.get("/api/apps/Payments").json()["group"]["member_count"] == 4
        d = client.get("/api/diff?app=CRM&days=3").json()
        assert d["markdown"].startswith("# Changements") and any(x["target"] == "Payments" for x in d["diff"]["deps_added"])
        assert client.post("/api/apps/cluster:1/rename", json={"name": "Legacy ERP"}).json()["name"] == "Legacy ERP"
        assert client.get("/api/export?format=mermaid").text.startswith("flowchart")


# ----------------------------------------------------------------------------- AI enrichment
class FakeEnricher:
    """Replaces the LLM call with canned structured answers derived from the evidence."""

    @staticmethod
    def call(schema, system, payload):
        from flowmapper.enrich import ClusterBatch, ClusterProposal, RoleBatch, WorkloadRoleProposal

        if schema is ClusterBatch:
            props = []
            for c in payload["clusters"]:
                roles = [WorkloadRoleProposal(workload=w["workload"], role_class="database" if "db" in w["hostname"] else "app", role_label="Serveur", confidence=0.8, rationale="hostname") for w in c["workloads"]]
                props.append(ClusterProposal(cluster=c["cluster"], name="Legacy ERP", app_label="Legacy ERP", env_label="Production", confidence=0.85, rationale="hostnames erp-*", workload_roles=roles))
            return ClusterBatch(proposals=props)
        return RoleBatch(proposals=[WorkloadRoleProposal(workload=w["workload"], role_class="worker", role_label="Serveur de reporting", confidence=0.6, rationale="consomme mssql") for w in payload["workloads"]])


def test_enrichment_proposals_and_hitl(samples, monkeypatch):
    from flowmapper.enrich import Enricher
    from flowmapper.store import Store

    monkeypatch.setattr(Enricher, "_call", staticmethod(FakeEnricher.call))
    store = Store(graph_options={})
    store.ingest_file(samples["api_json"])
    # make one role unknown on purpose so the role job has a target
    assert store.graph.nodes["rpt01"].role_class == "worker"
    result = Enricher(llm=object()).run(store)
    assert result["clusters"] == 1 and result["pending"] >= 1
    prop = store.proposals["clusters"]["cluster:1"]
    assert prop["status"] == "pending" and store.graph.groups["cluster:1"].name == "erp"  # nothing applied yet
    store.review_proposal("clusters", "cluster:1", "accept")
    assert store.graph.groups["cluster:1"].name == "Legacy ERP" and store.graph.groups["cluster:1"].app == "Legacy ERP"
    assert store.graph.nodes["erp-db01"].role_source == "ai" and store.graph.nodes["erp-db01"].role_class == "database"
    # overrides survive a rebuild (new ingest without replace)
    store.ingest_file(samples["explorer_csv"], replace=False)
    assert store.graph.groups["cluster:1"].name == "Legacy ERP" and store.graph.nodes["erp-db01"].role_source == "ai"
    # auto-apply with threshold
    store2 = Store(graph_options={})
    store2.ingest_file(samples["api_json"])
    out = Enricher(llm=object()).run(store2, auto_apply=True, min_confidence=0.8)
    assert store2.graph.groups["cluster:1"].name == "Legacy ERP" and out["applied"] >= 1


def test_enrichment_api(samples, monkeypatch):
    from fastapi.testclient import TestClient

    from flowmapper import enrich
    from flowmapper.api import main as api

    monkeypatch.setattr(enrich.Enricher, "_call", staticmethod(FakeEnricher.call))
    monkeypatch.setattr(enrich, "enrichment_available", lambda: (True, "fake"))
    monkeypatch.setattr(enrich.Enricher, "llm", property(lambda self: object()))
    api.store.clear()
    with TestClient(api.app) as client:
        with open(samples["api_json"], "rb") as fh:
            client.post("/api/ingest", files=[("files", ("x.json", fh, "application/json"))])
        r = client.post("/api/enrich", json={"clusters": True, "roles": True})
        assert r.status_code == 200 and r.json()["clusters"] == 1
        props = client.get("/api/proposals").json()
        assert props["pending"] >= 1 and props["clusters"][0]["name"] == "Legacy ERP"
        node = next(n for n in client.get("/api/graph?level=app").json()["elements"]["nodes"] if n["data"]["id"] == "g:cluster:1")
        assert node["data"]["ai"] == "pending"
        r = client.post("/api/proposals/clusters/cluster:1", json={"action": "accept"})
        assert r.status_code == 200 and r.json()["status"] == "accepted"
        assert client.get("/api/apps/cluster:1").json()["group"]["name"] == "Legacy ERP"
        assert client.get("/api/health").json()["pending_proposals"] == props["pending"] - 1


# ----------------------------------------------------------------------------- period diff
def test_period_diff_finds_planted_changes(samples):
    from flowmapper.diff import diff_periods, diff_to_markdown

    flows = load_flows(samples["api_json"])
    fg = FlowGraph.build(flows)
    d = diff_periods(flows, fg, app="CRM", days=3)
    assert [w["workload"] for w in d.workloads_added] == ["crm-app02"]
    assert {(x["source"], x["target"]) for x in d.deps_added} == {("CRM", "Payments")}
    assert {(x["source"], x["target"]) for x in d.deps_removed} == {("CRM", "Search Platform")}
    assert d.decision_changes[0]["to"] == "blocked" and d.decision_changes[0]["target"] == "ecom-pg01"
    assert any(v["source"] == "Corporate Users" and v["ratio"] > 2 for v in d.volume_changes)
    assert not d.apps_added and not d.apps_removed and not d.workloads_removed
    md = diff_to_markdown(d)
    assert "crm-app02" in md and "Payments" in md
    # a window larger than the dataset falls back to its two halves
    d2 = diff_periods(flows, fg, days=365)
    assert d2.period_a[0] < d2.period_a[1] <= d2.period_b[0] < d2.period_b[1]
    # whole-estate diff stays quiet apart from the planted changes
    assert d2.total_changes <= 20
