"""Parser for the PCE REST API traffic query download.

Each record looks like::

    {
      "src": {"ip": "10.0.1.10", "workload": {"hostname": "web01", "href": "/orgs/1/workloads/...",
                                             "labels": [{"href": "...", "key": "app", "value": "Shop"}]}},
      "dst": {"ip": "10.0.2.20", "workload": {...}, "ip_lists": [{"name": "Internet", ...}]},
      "service": {"port": 443, "proto": 6, "process_name": "nginx", "service_name": null, "user_name": null},
      "num_connections": 42,
      "policy_decision": "allowed",
      "draft_policy_decision": "allowed",
      "flow_direction": "inbound",
      "timestamp_range": {"first_detected": "...", "last_detected": "..."}
    }
"""
from __future__ import annotations

from typing import Any, Iterable, Iterator

from ..models import Endpoint, Flow, PolicyDecision, normalise_labels, parse_proto, parse_timestamp


def _endpoint(raw: dict[str, Any]) -> Endpoint:
    raw = raw or {}
    workload = raw.get("workload") or raw.get("virtual_service") or raw.get("virtual_server") or {}
    hostname = workload.get("hostname") or workload.get("name") or None
    labels = normalise_labels(workload.get("labels"))
    if not labels and raw.get("labels"):
        labels = normalise_labels(raw.get("labels"))
    ip_lists = [il.get("name") for il in (raw.get("ip_lists") or []) if isinstance(il, dict) and il.get("name")]
    return Endpoint(
        ip=str(raw.get("ip") or ""),
        hostname=hostname,
        href=workload.get("href"),
        labels=labels,
        ip_list_names=ip_lists,
        fqdn=raw.get("fqdn") or (raw.get("domain") or {}).get("name") if isinstance(raw.get("domain"), dict) else raw.get("fqdn"),
    )


def parse_api_record(rec: dict[str, Any]) -> Flow:
    service = rec.get("service") or {}
    ts = rec.get("timestamp_range") or {}
    direction = rec.get("flow_direction")
    return Flow(
        src=_endpoint(rec.get("src") or {}),
        dst=_endpoint(rec.get("dst") or {}),
        port=service.get("port"),
        proto=parse_proto(service.get("proto")),
        policy_decision=PolicyDecision.parse(rec.get("policy_decision")),
        draft_policy_decision=PolicyDecision.parse(rec["draft_policy_decision"]) if rec.get("draft_policy_decision") else None,
        connections=int(rec.get("num_connections") or 1),
        process_name=service.get("process_name") or None,
        service_name=service.get("service_name") or service.get("windows_service_name") or None,
        user_name=service.get("user_name") or None,
        first_seen=parse_timestamp(ts.get("first_detected")),
        last_seen=parse_timestamp(ts.get("last_detected")),
        direction="I" if str(direction or "").lower().startswith("in") else ("O" if direction else None),
        source_format="api_json",
    )


def parse_api_records(records: Iterable[dict[str, Any]]) -> Iterator[Flow]:
    for rec in records:
        if isinstance(rec, dict) and ("src" in rec or "dst" in rec):
            yield parse_api_record(rec)
