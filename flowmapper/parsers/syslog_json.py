"""Parser for VEN traffic-flow summaries forwarded by the PCE to syslog / Fluentd.

Reference (Illumio Core "Manage Traffic Flows Using REST API"):

* ``pd``: 0 allowed, 1 potentially blocked, 2 blocked, 3 unknown
* ``dir``: ``I`` / ``O`` direction of the first packet
* ``proto`` (int), ``dst_port`` (older schema: ``dst_prt``), ``count``, ``state`` (A/C/T/S/N)
* ``pn`` process name, ``sn`` service name, ``un`` user name
* ``src_ip``/``dst_ip``, ``src_hostname``/``dst_hostname``, ``src_href``/``dst_href``
* ``src_labels``/``dst_labels``: ``{"app": .., "env": .., "loc": .., "role": ..}``
* ``timestamp`` RFC3339, ``interval_sec``

Lines may carry a syslog header (``<14>1 2024-... pce illumio_pce/collector ... {json}``);
only the JSON object is parsed.
"""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Iterable, Iterator

from ..models import Endpoint, Flow, PolicyDecision, normalise_labels, parse_proto, parse_timestamp


def iter_json_objects(source: Iterable[str] | str) -> Iterator[dict[str, Any]]:
    """Yield every JSON object found in the lines of ``source`` (string or file-like)."""
    lines = source.splitlines() if isinstance(source, str) else source
    for line in lines:
        line = line.strip()
        if not line:
            continue
        start = line.find("{")
        if start < 0:
            continue
        candidate = line[start:]
        if candidate.endswith(","):
            candidate = candidate[:-1]
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            # Some collectors escape the payload inside a "message" field
            try:
                outer = json.loads(line)
                inner = outer.get("message") or outer.get("msg") or outer.get("log")
                obj = json.loads(inner) if isinstance(inner, str) else inner
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue
        if isinstance(obj, dict):
            # Fluentd / Sentinel wrappers nest the flow under a key
            for key in ("flow", "event", "illumio"):
                if isinstance(obj.get(key), dict) and "src_ip" in obj[key]:
                    obj = obj[key]
                    break
            yield obj


def parse_syslog_record(rec: dict[str, Any]) -> Flow:
    ts = parse_timestamp(rec.get("timestamp"))
    interval = rec.get("interval_sec")
    last = ts + timedelta(seconds=int(interval)) if (ts and interval) else ts
    return Flow(
        src=Endpoint(
            ip=str(rec.get("src_ip") or ""),
            hostname=rec.get("src_hostname") or None,
            href=rec.get("src_href") or None,
            labels=normalise_labels(rec.get("src_labels")),
        ),
        dst=Endpoint(
            ip=str(rec.get("dst_ip") or ""),
            hostname=rec.get("dst_hostname") or None,
            href=rec.get("dst_href") or None,
            labels=normalise_labels(rec.get("dst_labels")),
            fqdn=rec.get("fqdn") or None,
        ),
        port=_port(rec),
        proto=parse_proto(rec.get("proto")),
        policy_decision=PolicyDecision.parse(rec.get("pd")),
        connections=int(rec.get("count") or rec.get("flow_count") or 1),
        process_name=rec.get("pn") or None,
        service_name=rec.get("sn") or None,
        user_name=rec.get("un") or None,
        first_seen=ts,
        last_seen=last,
        direction=rec.get("dir") or None,
        source_format="syslog_json",
    )


def _port(rec: dict[str, Any]):
    for key in ("dst_port", "dst_prt", "port"):
        if rec.get(key) not in (None, ""):
            try:
                return int(rec[key])
            except (TypeError, ValueError):
                return None
    return None


def parse_syslog_records(records: Iterable[dict[str, Any]]) -> Iterator[Flow]:
    for rec in records:
        if "src_ip" in rec or "dst_ip" in rec:
            yield parse_syslog_record(rec)
