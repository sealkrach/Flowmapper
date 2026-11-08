"""Minimal PCE REST client: run an Explorer *async* traffic query and download the flows.

Environment variables (or constructor arguments)::

    ILLUMIO_PCE_URL=https://pce.corp.example:8443
    ILLUMIO_ORG_ID=1
    ILLUMIO_API_KEY=api_1195cf055cf8a834c
    ILLUMIO_API_SECRET=148afd87...
    ILLUMIO_VERIFY_SSL=true            # or a path to a CA bundle

Usage::

    client = PCEClient.from_env()
    flows = client.fetch_flows(start="2026-10-01T00:00:00Z", end="2026-11-01T00:00:00Z")
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx

from .models import Flow
from .parsers.api_json import parse_api_records


class PCEClient:
    def __init__(self, base_url: str, org_id: int, api_key: str, api_secret: str, verify: bool | str = True, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.org_id = int(org_id)
        self._client = httpx.Client(
            base_url=f"{self.base_url}/api/v2",
            auth=(api_key, api_secret),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            verify=verify,
            timeout=timeout,
        )

    @classmethod
    def from_env(cls) -> "PCEClient":
        missing = [v for v in ("ILLUMIO_PCE_URL", "ILLUMIO_ORG_ID", "ILLUMIO_API_KEY", "ILLUMIO_API_SECRET") if not os.getenv(v)]
        if missing:
            raise RuntimeError(f"Missing PCE settings: {', '.join(missing)}")
        verify_raw = os.getenv("ILLUMIO_VERIFY_SSL", "true")
        verify: bool | str = verify_raw if os.path.exists(verify_raw) else verify_raw.lower() not in ("0", "false", "no")
        return cls(os.environ["ILLUMIO_PCE_URL"], int(os.environ["ILLUMIO_ORG_ID"]), os.environ["ILLUMIO_API_KEY"], os.environ["ILLUMIO_API_SECRET"], verify=verify)

    @property
    def org_href(self) -> str:
        return f"/orgs/{self.org_id}"

    # ------------------------------------------------------------------ queries
    def create_query(
        self,
        start: str | datetime,
        end: str | datetime,
        policy_decisions: Optional[list[str]] = None,
        max_results: int = 200000,
        query_name: str = "flowmapper",
        sources: Optional[dict] = None,
        destinations: Optional[dict] = None,
        services: Optional[dict] = None,
    ) -> dict[str, Any]:
        body = {
            "query_name": query_name,
            "start_date": _iso(start),
            "end_date": _iso(end),
            "sources": sources or {"include": [[]], "exclude": []},
            "destinations": destinations or {"include": [[]], "exclude": []},
            "services": services or {"include": [], "exclude": []},
            "policy_decisions": policy_decisions or ["allowed", "potentially_blocked", "blocked", "unknown"],
            "max_results": max_results,
            "sources_destinations_query_op": "and",
        }
        resp = self._client.post(f"{self.org_href}/traffic_flows/async_queries", json=body)
        resp.raise_for_status()
        return resp.json()

    def get_query(self, href: str) -> dict[str, Any]:
        resp = self._client.get(href)
        resp.raise_for_status()
        return resp.json()

    def wait(self, href: str, poll_seconds: float = 3.0, timeout_seconds: float = 1800.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            info = self.get_query(href)
            status = info.get("status")
            if status == "completed":
                return info
            if status in ("failed", "killed", "cancelled"):
                raise RuntimeError(f"PCE async query {href} ended with status {status}: {info}")
            if time.monotonic() > deadline:
                raise TimeoutError(f"PCE async query {href} still {status} after {timeout_seconds}s")
            time.sleep(poll_seconds)

    def download(self, info: dict[str, Any]) -> list[dict[str, Any]]:
        result_href = info.get("result") or f"{info['href']}/download"
        resp = self._client.get(result_href)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("flows", [])

    def fetch_records(self, start=None, end=None, **kwargs) -> list[dict[str, Any]]:
        end = end or datetime.now(timezone.utc)
        start = start or (_as_dt(end) - timedelta(days=7))
        created = self.create_query(start, end, **kwargs)
        info = self.wait(created["href"])
        return self.download(info)

    def fetch_flows(self, start=None, end=None, **kwargs) -> list[Flow]:
        return list(parse_api_records(self.fetch_records(start, end, **kwargs)))

    def close(self) -> None:
        self._client.close()


def _as_dt(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(value: str | datetime) -> str:
    dt = _as_dt(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
