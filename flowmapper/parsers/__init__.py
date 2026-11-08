"""Auto-detecting loaders for the three Illumio traffic sources.

* Explorer CSV export (PCE UI → Explorer → Export)
* PCE REST API ``GET /orgs/:id/traffic_flows/async_queries/:uuid/download`` (JSON list)
* Syslog / Fluentd traffic-flow summaries (one JSON object per line, optional syslog prefix)
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Iterator, Union

from ..models import Flow
from .api_json import parse_api_records
from .explorer_csv import parse_explorer_csv
from .syslog_json import iter_json_objects, parse_syslog_records

PathLike = Union[str, os.PathLike]


def detect_format(path: PathLike, sample_bytes: int = 65536) -> str:
    """Return ``"explorer_csv"``, ``"api_json"`` or ``"syslog_json"``."""
    p = Path(path)
    with open(p, "rb") as fh:
        head = fh.read(sample_bytes).decode("utf-8", errors="replace")
    stripped = head.lstrip("﻿ \t\r\n")
    if p.suffix.lower() == ".csv" or (stripped and stripped[0] not in "[{<" and "," in stripped.splitlines()[0]):
        return "explorer_csv"
    # JSON array → almost certainly an async-query download
    if stripped.startswith("["):
        try:
            first = json.loads(stripped)[0] if stripped.rstrip().endswith("]") else None
        except (json.JSONDecodeError, IndexError):
            first = None
        if first is None:
            # Large file: peek at the first object
            first = next(iter_json_objects(stripped[1:]), None)
        if isinstance(first, dict):
            return _classify_record(first)
        return "api_json"
    # NDJSON / syslog lines
    first = next(iter_json_objects(stripped), None)
    if isinstance(first, dict):
        return _classify_record(first)
    raise ValueError(f"Unrecognised Illumio flow file: {p}")


def _classify_record(rec: dict) -> str:
    if "src_ip" in rec and ("pd" in rec or "dst_port" in rec or "dst_prt" in rec):
        return "syslog_json"
    if isinstance(rec.get("src"), dict) and isinstance(rec.get("dst"), dict):
        return "api_json"
    if "src" in rec and "dst" in rec:
        return "api_json"
    return "syslog_json"


def load_flows(path: PathLike, fmt: str | None = None) -> list[Flow]:
    fmt = fmt or detect_format(path)
    p = Path(path)
    if fmt == "explorer_csv":
        with open(p, newline="", encoding="utf-8-sig") as fh:
            return list(parse_explorer_csv(fh))
    if fmt == "api_json":
        with open(p, encoding="utf-8") as fh:
            text = fh.read()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = list(iter_json_objects(text))
        if isinstance(data, dict):
            data = data.get("flows") or data.get("results") or data.get("data") or [data]
        return list(parse_api_records(data))
    if fmt == "syslog_json":
        with open(p, encoding="utf-8", errors="replace") as fh:
            return list(parse_syslog_records(iter_json_objects(fh)))
    raise ValueError(f"Unknown format: {fmt}")


def load_many(paths: Iterable[PathLike]) -> list[Flow]:
    flows: list[Flow] = []
    for p in paths:
        flows.extend(load_flows(p))
    return flows


__all__ = ["detect_format", "load_flows", "load_many", "parse_api_records", "parse_explorer_csv", "parse_syslog_records"]
