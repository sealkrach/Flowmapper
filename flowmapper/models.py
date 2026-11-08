"""Normalised data model shared by every Illumio flow source.

Whatever the source (Explorer CSV export, PCE REST ``traffic_flows/async_queries``
download, syslog/Fluentd traffic-flow summaries), each record is normalised into a
:class:`Flow` made of two :class:`Endpoint` objects plus the service and policy facts.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class PolicyDecision(str, Enum):
    ALLOWED = "allowed"
    POTENTIALLY_BLOCKED = "potentially_blocked"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: Any) -> "PolicyDecision":
        """Accept the integer ``pd`` of syslog summaries or the API/CSV strings."""
        if value is None:
            return cls.UNKNOWN
        if isinstance(value, bool):
            return cls.UNKNOWN
        if isinstance(value, (int, float)):
            return {0: cls.ALLOWED, 1: cls.POTENTIALLY_BLOCKED, 2: cls.BLOCKED}.get(int(value), cls.UNKNOWN)
        text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
        try:  # numeric spellings: "2", "2.0"
            return cls.parse(int(float(text)))
        except (ValueError, OverflowError):
            pass
        if text in ("allowed", "allow"):
            return cls.ALLOWED
        if text.startswith("potentially"):
            return cls.POTENTIALLY_BLOCKED
        if text in ("blocked", "block", "denied", "deny"):
            return cls.BLOCKED
        return cls.UNKNOWN

    @property
    def severity(self) -> int:
        return {"allowed": 0, "unknown": 1, "potentially_blocked": 2, "blocked": 3}[self.value]


PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6", 132: "sctp"}
PROTO_NUMBERS = {v: k for k, v in PROTO_NAMES.items()}

# Illumio exports sometimes spell the four canonical label types in full.
LABEL_ALIASES = {
    "application": "app",
    "app": "app",
    "environment": "env",
    "env": "env",
    "location": "loc",
    "loc": "loc",
    "role": "role",
}


def canonical_label_key(key: str) -> str:
    k = key.strip().lower().replace(" ", "_")
    return LABEL_ALIASES.get(k, k)


def parse_proto(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().lower()
    if text.isdigit():
        return int(text)
    return PROTO_NUMBERS.get(text, 0)


def proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, str(proto))


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse the various timestamp spellings; naive values (Explorer CSV) are assumed UTC so
    that files from different sources can be merged."""
    if not value:
        return None
    if isinstance(value, datetime):
        return _aware(value)
    text = str(value).strip()
    for candidate in (text, text.replace("Z", "+00:00")):
        try:
            return _aware(datetime.fromisoformat(candidate))
        except ValueError:
            pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d"):
        try:
            return _aware(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@dataclass
class Endpoint:
    """One side of a flow. ``hostname`` / ``href`` / ``labels`` only exist for managed workloads."""

    ip: str = ""
    hostname: Optional[str] = None
    href: Optional[str] = None
    labels: dict[str, str] = field(default_factory=dict)
    ip_list_names: list[str] = field(default_factory=list)
    fqdn: Optional[str] = None

    @property
    def managed(self) -> bool:
        return bool(self.hostname or self.href or self.labels)

    @property
    def identity(self) -> str:
        """Stable node identifier: hostname when known, else the IP."""
        if self.hostname:
            return self.hostname.strip().lower()
        if self.fqdn:
            return self.fqdn.strip().lower()
        return self.ip

    @property
    def display_name(self) -> str:
        return self.hostname or self.fqdn or self.ip

    def label(self, key: str) -> Optional[str]:
        return self.labels.get(canonical_label_key(key))

    def subnet(self, prefix: int = 24) -> str:
        try:
            net = ipaddress.ip_network(f"{self.ip}/{prefix}", strict=False)
            return str(net)
        except ValueError:
            return "unknown"


@dataclass
class Flow:
    src: Endpoint
    dst: Endpoint
    port: Optional[int]
    proto: int
    policy_decision: PolicyDecision = PolicyDecision.UNKNOWN
    connections: int = 1
    process_name: Optional[str] = None
    service_name: Optional[str] = None
    user_name: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    direction: Optional[str] = None  # "I" (inbound) or "O" (outbound) as reported by the VEN
    draft_policy_decision: Optional[PolicyDecision] = None
    source_format: str = "unknown"

    @property
    def service_key(self) -> tuple[int, Optional[int]]:
        return (self.proto, self.port)

    @property
    def service_label(self) -> str:
        if self.port is None:
            return proto_name(self.proto)
        return f"{proto_name(self.proto)}/{self.port}"


def normalise_labels(raw: Any) -> dict[str, str]:
    """Accept ``{"app": "X"}``, ``[{"key": "app", "value": "X"}]`` or ``[{"href":..,"key":..,"value":..}]``."""
    labels: dict[str, str] = {}
    if not raw:
        return labels
    if isinstance(raw, dict):
        for k, v in raw.items():
            if v is None or v == "":
                continue
            if isinstance(v, dict):  # {"app": {"value": "X"}}
                v = v.get("value")
            if v:
                labels[canonical_label_key(str(k))] = str(v)
        return labels
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("key") and item.get("value"):
                labels[canonical_label_key(str(item["key"]))] = str(item["value"])
    return labels
