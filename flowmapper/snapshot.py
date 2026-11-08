"""Export a fully static, offline copy of the UI with the current dataset embedded.

Useful to share an architecture map with people who do not run the backend (the agent chat
and the upload are disabled in a snapshot)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .exports import GraphFilter, to_cytoscape, to_markdown, to_mermaid
from .graph import FlowGraph

STATIC_DIR = Path(__file__).parent / "api" / "static"


def build_payload(fg: FlowGraph) -> dict:
    full = GraphFilter(hide_infra=False, hide_shared=False, hide_unmanaged=False)
    app_details = {}
    for key, group in fg.groups.items():
        members = sorted((fg.nodes[m] for m in group.members), key=lambda n: (n.tier or 0, n.name))
        app_details[key] = {
            "group": group.to_dict(),
            "workloads": [n.to_dict() for n in members],
            "dependencies": fg.dependencies(key),
            "markdown": to_markdown(fg, app=key, flt=GraphFilter(hide_infra=True)),
            "mermaid": to_mermaid(fg, app=key, flt=GraphFilter(hide_infra=True)),
        }
    workloads = {}
    for nid, n in fg.nodes.items():
        workloads[nid] = {
            **n.to_dict(),
            "application": fg.groups[n.group].name if n.group else None,
            "talks_to": [{"to": fg.nodes[d].name, "services": [e.to_dict() for e in fg.G[nid][d]["services"].values()]} for d in fg.G.successors(nid)],
            "called_by": [{"from": fg.nodes[s].name, "services": [e.to_dict() for e in fg.G[s][nid]["services"].values()]} for s in fg.G.predecessors(nid)],
        }
    return {
        "graphs": {"app": to_cytoscape(fg, "app", full), "workload": to_cytoscape(fg, "workload", full)},
        "apps": [g.to_dict() for g in sorted(fg.groups.values(), key=lambda g: (g.kind != "labeled", g.name))],
        "appDetails": app_details,
        "workloads": workloads,
        "exports": {"mermaid": to_mermaid(fg, flt=GraphFilter(hide_infra=True)), "markdown": to_markdown(fg, flt=GraphFilter(hide_infra=True))},
    }


def write_snapshot(fg: FlowGraph, out_dir: Path, title: str | None = None) -> Path:
    out_dir = Path(out_dir)
    (out_dir / "static" / "vendor").mkdir(parents=True, exist_ok=True)
    for name in ("style.css", "app.js"):
        shutil.copy(STATIC_DIR / name, out_dir / "static" / name)
    shutil.copy(STATIC_DIR / "vendor" / "graph-vendor.js", out_dir / "static" / "vendor" / "graph-vendor.js")
    payload = json.dumps(build_payload(fg), ensure_ascii=False, default=str).replace("</", "<\\/")
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    if title:
        html = html.replace("<title>FlowMapper — application architectures from Illumio flows</title>", f"<title>{title}</title>")
    html = html.replace('<script src="static/vendor/graph-vendor.js"></script>', f"<script>window.FLOWMAPPER_EMBEDDED = {payload};</script>\n<script src=\"static/vendor/graph-vendor.js\"></script>")
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    return out_dir / "index.html"
