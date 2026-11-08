"""Parser for the Explorer CSV export.

Column names vary between PCE releases (``Consumer``/``Provider`` before 22.x,
``Source``/``Destination`` afterwards, label types spelled ``Application`` or ``App``,
custom label types added by the customer...). The parser therefore matches columns by
prefix and keeps every ``<side> <label type>`` column as a label.
"""
from __future__ import annotations

import csv
import re
from typing import Iterable, Iterator, Optional, TextIO

from ..models import Endpoint, Flow, PolicyDecision, canonical_label_key, parse_proto, parse_timestamp

SRC_PREFIXES = ("consumer", "source", "src")
DST_PREFIXES = ("provider", "destination", "dst")

# Columns on each side that are *not* labels.
NON_LABEL_SUFFIXES = {
    "ip", "ip address", "name", "hostname", "host name", "href", "enforcement", "enforcement mode",
    "ip list", "ip lists", "iplist", "fqdn", "workload", "managed", "virtual service", "virtual server",
    "transmission", "type", "os", "status", "cloud", "network", "process", "process name", "username", "user name",
}

PORT_COLUMNS = ("port", "destination port", "dst port", "provider port")
PROTO_COLUMNS = ("protocol", "proto")
PROCESS_COLUMNS = ("process name", "process", "provider process", "destination process")
SERVICE_COLUMNS = ("service name", "service", "windows service")
USER_COLUMNS = ("user name", "username", "user")
POLICY_COLUMNS = ("reported policy", "reported policy decision", "policy decision", "policy", "decision")
DRAFT_POLICY_COLUMNS = ("draft policy", "draft policy decision")
CONNECTIONS_COLUMNS = ("connections", "num connections", "number of connections", "flows", "count", "connection count")
FIRST_COLUMNS = ("first detected", "first seen", "first")
LAST_COLUMNS = ("last detected", "last seen", "last")
DIRECTION_COLUMNS = ("flow direction", "direction")


def _norm(name: str) -> str:
    return re.sub(r"[\s_\-]+", " ", name.strip().lower().lstrip("﻿"))


def _find(columns: dict[str, str], candidates: Iterable[str]) -> Optional[str]:
    for cand in candidates:
        if cand in columns:
            return columns[cand]
    return None


def _side_columns(columns: dict[str, str], prefixes: tuple[str, ...]) -> dict[str, str]:
    """Map ``suffix → original column`` for every column starting with one of the prefixes."""
    out: dict[str, str] = {}
    for norm, original in columns.items():
        for prefix in prefixes:
            if norm.startswith(prefix + " "):
                out[norm[len(prefix) + 1:]] = original
                break
    return out


def _to_int(value: Optional[str], default: int = 1) -> int:
    if value is None or value == "":
        return default
    try:
        return int(float(str(value).replace(",", "").replace(" ", "")))
    except ValueError:
        return default


def _endpoint(row: dict[str, str], side: dict[str, str]) -> Endpoint:
    ip = (row.get(side.get("ip", ""), "") or row.get(side.get("ip address", ""), "") or "").strip()
    hostname = (
        row.get(side.get("hostname", ""), "") or row.get(side.get("host name", ""), "") or row.get(side.get("name", ""), "") or ""
    ).strip() or None
    href = (row.get(side.get("href", ""), "") or "").strip() or None
    fqdn = (row.get(side.get("fqdn", ""), "") or "").strip() or None
    ip_lists = (row.get(side.get("ip list", ""), "") or row.get(side.get("ip lists", ""), "") or "").strip()
    labels: dict[str, str] = {}
    for suffix, original in side.items():
        if suffix in NON_LABEL_SUFFIXES:
            continue
        value = (row.get(original) or "").strip()
        if value and value.lower() not in ("-", "n/a", "none", "null"):
            labels[canonical_label_key(suffix)] = value
    # Explorer prints the IP in the name column when the endpoint is unmanaged.
    if hostname and hostname == ip:
        hostname = None
    return Endpoint(
        ip=ip,
        hostname=hostname,
        href=href,
        labels=labels,
        fqdn=fqdn,
        ip_list_names=[s.strip() for s in re.split(r"[;|]", ip_lists) if s.strip()] if ip_lists else [],
    )


def parse_explorer_csv(fh: TextIO) -> Iterator[Flow]:
    reader = csv.DictReader(fh)
    if not reader.fieldnames:
        return
    columns = {_norm(c): c for c in reader.fieldnames}
    src_cols = _side_columns(columns, SRC_PREFIXES)
    dst_cols = _side_columns(columns, DST_PREFIXES)
    if "ip" not in src_cols and "ip address" not in src_cols:
        raise ValueError(f"No consumer/source IP column found in CSV header: {reader.fieldnames}")

    port_col = _find(columns, PORT_COLUMNS)
    proto_col = _find(columns, PROTO_COLUMNS)
    process_col = _find(columns, PROCESS_COLUMNS)
    service_col = _find(columns, SERVICE_COLUMNS)
    user_col = _find(columns, USER_COLUMNS)
    policy_col = _find(columns, POLICY_COLUMNS)
    draft_col = _find(columns, DRAFT_POLICY_COLUMNS)
    conn_col = _find(columns, CONNECTIONS_COLUMNS)
    first_col = _find(columns, FIRST_COLUMNS)
    last_col = _find(columns, LAST_COLUMNS)
    dir_col = _find(columns, DIRECTION_COLUMNS)

    for row in reader:
        if not row:
            continue
        src = _endpoint(row, src_cols)
        dst = _endpoint(row, dst_cols)
        if not src.ip and not dst.ip:
            continue
        port_raw = (row.get(port_col) or "").strip() if port_col else ""
        port = int(float(port_raw)) if port_raw and port_raw.replace(".", "", 1).isdigit() else None
        proto = parse_proto(row.get(proto_col)) if proto_col else (6 if port else 0)
        yield Flow(
            src=src,
            dst=dst,
            port=port,
            proto=proto,
            policy_decision=PolicyDecision.parse(row.get(policy_col)) if policy_col else PolicyDecision.UNKNOWN,
            draft_policy_decision=PolicyDecision.parse(row.get(draft_col)) if draft_col and row.get(draft_col) else None,
            connections=_to_int(row.get(conn_col)) if conn_col else 1,
            process_name=(row.get(process_col) or "").strip() or None if process_col else None,
            service_name=(row.get(service_col) or "").strip() or None if service_col else None,
            user_name=(row.get(user_col) or "").strip() or None if user_col else None,
            first_seen=parse_timestamp(row.get(first_col)) if first_col else None,
            last_seen=parse_timestamp(row.get(last_col)) if last_col else None,
            direction=_direction(row.get(dir_col)) if dir_col else None,
            source_format="explorer_csv",
        )


def _direction(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip().lower()
    if v.startswith("i"):
        return "I"
    if v.startswith("o"):
        return "O"
    return None
