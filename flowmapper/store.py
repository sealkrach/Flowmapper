"""In-memory store holding the current dataset (flows + graph) shared by the API, the CLI
and the agent tools. Rebuilding the graph after each ingest keeps everything consistent."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Iterable, Optional

from .graph import FlowGraph
from .models import Flow
from .parsers import detect_format, load_flows


def graph_options_from_env() -> dict:
    """Read FlowGraph tuning from the environment (see README)."""
    opts: dict = {}
    if os.getenv("FLOWMAPPER_GROUP_BY"):
        opts["group_by"] = tuple(k.strip() for k in os.environ["FLOWMAPPER_GROUP_BY"].split(",") if k.strip())
    if os.getenv("FLOWMAPPER_UNMANAGED_GROUPING"):
        opts["unmanaged_grouping"] = os.environ["FLOWMAPPER_UNMANAGED_GROUPING"]
    if os.getenv("FLOWMAPPER_SHARED_MIN_CONSUMERS"):
        opts["shared_min_consumers"] = int(os.environ["FLOWMAPPER_SHARED_MIN_CONSUMERS"])
    if os.getenv("FLOWMAPPER_SUBNET_PREFIX"):
        opts["subnet_prefix"] = int(os.environ["FLOWMAPPER_SUBNET_PREFIX"])
    if os.getenv("FLOWMAPPER_ATTACH_UNMANAGED"):
        opts["attach_unmanaged"] = os.environ["FLOWMAPPER_ATTACH_UNMANAGED"].lower() not in ("0", "false", "no")
    if os.getenv("FLOWMAPPER_IP_LISTS"):
        raw = os.environ["FLOWMAPPER_IP_LISTS"]
        opts["ip_lists"] = json.loads(Path(raw).read_text()) if os.path.exists(raw) else json.loads(raw)
    return opts


class Store:
    def __init__(self, graph_options: Optional[dict] = None):
        self.graph_options = graph_options if graph_options is not None else graph_options_from_env()
        self.flows: list[Flow] = []
        self.files: list[dict] = []
        self.graph: Optional[FlowGraph] = None
        self.renames: dict[str, dict] = {}  # group key -> {"name":..., "app":..., "env":...}
        self.role_overrides: dict[str, dict] = {}  # node id -> {"role_class":..., "role_label":...}
        self.proposals: dict[str, dict[str, dict]] = {"clusters": {}, "workloads": {}}
        self.baseline: Optional[FlowGraph] = None  # an older dataset to diff against
        self.baseline_files: list[dict] = []
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- ingest
    def ingest_file(self, path: str | os.PathLike, replace: bool = False, label: Optional[str] = None) -> dict:
        fmt = detect_format(path)
        flows = load_flows(path, fmt)
        return self.ingest_flows(flows, source=label or Path(path).name, fmt=fmt, replace=replace)

    def ingest_flows(self, flows: Iterable[Flow], source: str = "api", fmt: str = "api_json", replace: bool = False) -> dict:
        flows = list(flows)
        with self._lock:
            if replace:
                self.flows, self.files, self.renames, self.role_overrides = [], [], {}, {}
                self.proposals = {"clusters": {}, "workloads": {}}
            self.flows.extend(flows)
            self.files.append({"source": source, "format": fmt, "flows": len(flows)})
            self._rebuild()
            stats = self.graph.stats()
        return {"source": source, "format": fmt, "flows": len(flows), "stats": stats}

    def clear(self) -> None:
        with self._lock:
            self.flows, self.files, self.renames, self.graph = [], [], {}, None
            self.role_overrides, self.proposals = {}, {"clusters": {}, "workloads": {}}

    def set_options(self, **options) -> None:
        with self._lock:
            self.graph_options.update(options)
            if self.flows:
                self._rebuild()

    def _rebuild(self) -> None:
        self.graph = FlowGraph.build(self.flows, role_overrides=self.role_overrides, **self.graph_options)
        for key, r in self.renames.items():
            if key in self.graph.groups:
                self.graph.rename_group(key, r["name"], r.get("app"), r.get("env"))

    # ---------------------------------------------------------------- helpers
    def require_graph(self) -> FlowGraph:
        if self.graph is None:
            raise RuntimeError("No flows loaded yet. Ingest an Illumio export first.")
        return self.graph

    def rename_group(self, key: str, name: str, app: Optional[str] = None, env: Optional[str] = None) -> dict:
        fg = self.require_graph()
        with self._lock:
            group = fg.rename_group(key, name, app, env)
            self.renames[key] = {"name": name, "app": app, "env": env}
            return group.to_dict()

    # ------------------------------------------------------------ baseline / diff
    def ingest_baseline(self, paths: Iterable[str | os.PathLike]) -> dict:
        flows: list[Flow] = []
        files = []
        for p in paths:
            fmt = detect_format(p)
            part = load_flows(p, fmt)
            flows.extend(part)
            files.append({"source": Path(p).name, "format": fmt, "flows": len(part)})
        with self._lock:
            self.baseline = FlowGraph.build(flows, role_overrides=self.role_overrides, **self.graph_options)
            self.baseline_files = files
        return {"files": files, "stats": self.baseline.stats()}

    def diff(self, app: Optional[str] = None, mode: str = "period", **periods):
        from .diff import diff_graphs, diff_periods

        fg = self.require_graph()
        if mode == "baseline":
            if self.baseline is None:
                raise RuntimeError("No baseline dataset loaded (POST /api/baseline or `flowmapper diff --baseline`).")
            return diff_graphs(self.baseline, fg, app=app)
        return diff_periods(self.flows, fg, app=app, graph_options=self.graph_options, **periods)

    # ------------------------------------------------------------ AI proposals
    def add_proposal(self, kind: str, pid: str, data: dict) -> dict:
        from datetime import datetime, timezone

        prop = {**data, "id": pid, "kind": kind, "status": "pending", "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.proposals[kind][pid] = prop
        return prop

    def pending_proposals(self) -> int:
        return sum(1 for kind in self.proposals.values() for p in kind.values() if p["status"] == "pending")

    def review_proposal(self, kind: str, pid: str, action: str) -> dict:
        """Accept or reject a proposal. Accepting applies it to the model (rebuild included)."""
        prop = self.proposals[kind][pid]
        if action == "reject":
            prop["status"] = "rejected"
            return prop
        if action != "accept":
            raise ValueError("action must be accept or reject")
        fg = self.require_graph()
        with self._lock:
            if kind == "clusters":
                if pid in fg.groups:
                    self.renames[pid] = {"name": prop["name"], "app": prop.get("app"), "env": prop.get("env")}
                for r in prop.get("workload_roles", []):
                    if r.get("workload") in fg.nodes and r.get("role_class") not in (None, "unknown"):
                        self.role_overrides[r["workload"]] = {"role_class": r["role_class"], "role_label": r.get("role_label")}
            else:
                self.role_overrides[pid] = {"role_class": prop["role_class"], "role_label": prop.get("role_label")}
            prop["status"] = "accepted"
            self._rebuild()
        return prop

    def proposal_state(self, kind: str, pid: str) -> Optional[str]:
        prop = self.proposals.get(kind, {}).get(pid)
        return prop["status"] if prop else None

    @property
    def loaded(self) -> bool:
        return self.graph is not None
