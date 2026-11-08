"""FastAPI application: ingestion, graph queries, exports and the agent chat.

Run with ``flowmapper serve samples/*.csv`` or ``uvicorn flowmapper.api.main:app``.
"""
from __future__ import annotations

import logging
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..exports import GraphFilter, find_group, to_cytoscape, to_graphml, to_json, to_markdown, to_mermaid
from ..store import Store

log = logging.getLogger("flowmapper")
STATIC_DIR = Path(__file__).parent / "static"

store = Store()
_agent = None
_agent_error: Optional[str] = None


def get_store() -> Store:
    return store


def get_agent():
    """Lazily build the LangGraph agent so the UI works without an LLM configured.
    Failures are not cached: a transient error (network, import) is retried on the next call."""
    global _agent, _agent_error
    if _agent is None:
        from ..agent import FlowAgent, agent_available

        ok, detail = agent_available()
        if not ok:
            _agent_error = detail
        else:
            try:
                _agent = FlowAgent(store)
                _agent_error = None
            except Exception as exc:  # noqa: BLE001
                _agent_error = f"{type(exc).__name__}: {exc}"
    return _agent


@asynccontextmanager
async def lifespan(app: FastAPI):
    files = [f for f in os.getenv("FLOWMAPPER_FILES", "").split(",") if f.strip()]
    for f in files:
        try:
            info = store.ingest_file(f.strip())
            log.info("Loaded %s (%s flows)", f, info["flows"])
        except Exception as exc:  # noqa: BLE001
            log.error("Could not load %s: %s", f, exc)
    if files and os.getenv("FLOWMAPPER_AUTO_ENRICH", "").lower() in ("1", "true", "yes"):
        _auto_enrich()
    yield


def _auto_enrich() -> None:
    from ..enrich import Enricher, enrichment_available

    ok, detail = enrichment_available()
    if not ok:
        log.warning("FLOWMAPPER_AUTO_ENRICH set but %s", detail)
        return
    try:
        result = Enricher().run(store, auto_apply=os.getenv("FLOWMAPPER_AUTO_APPLY", "").lower() in ("1", "true", "yes"))
        log.info("AI enrichment: %s", result)
    except Exception as exc:  # noqa: BLE001
        log.error("AI enrichment failed: %s", exc)


app = FastAPI(title="FlowMapper", version=__version__, description="Illumio flows → application architecture graphs", lifespan=lifespan)


# -------------------------------------------------------------------------- models
class IngestPCERequest(BaseModel):
    start: Optional[str] = Field(None, description="ISO date, default now-7d")
    end: Optional[str] = None
    max_results: int = 200000
    policy_decisions: list[str] = ["allowed", "potentially_blocked", "blocked", "unknown"]
    replace: bool = True


class RenameRequest(BaseModel):
    name: str
    app: Optional[str] = None
    env: Optional[str] = None


class OptionsRequest(BaseModel):
    group_by: Optional[list[str]] = None
    unmanaged_grouping: Optional[str] = None
    shared_min_consumers: Optional[int] = None
    subnet_prefix: Optional[int] = None
    attach_unmanaged: Optional[bool] = None
    ip_lists: Optional[dict[str, list[str]]] = None


class ChatRequest(BaseModel):
    message: str
    thread_id: Optional[str] = None


class EnrichRequest(BaseModel):
    clusters: bool = True
    roles: bool = True
    auto_apply: bool = False
    min_confidence: float = 0.7


class ReviewRequest(BaseModel):
    action: str = Field(pattern="^(accept|reject)$")


# ------------------------------------------------------------------------- helpers
def _require(st: Store):
    if not st.loaded:
        raise HTTPException(status_code=409, detail="No flows loaded. Upload an Illumio export first (POST /api/ingest).")
    return st.graph


def _filter(
    env: Optional[str] = None,
    app: Optional[str] = None,
    hide_shared: bool = False,
    hide_infra: bool = True,
    hide_unmanaged: bool = False,
    min_connections: int = 1,
    decisions: Optional[str] = Query(None, description="comma separated: allowed,potentially_blocked,blocked,unknown"),
    ports: Optional[str] = Query(None, description="comma separated destination ports"),
) -> GraphFilter:
    return GraphFilter(
        env=env or None,
        app=app or None,
        hide_shared=hide_shared,
        hide_infra=hide_infra,
        hide_unmanaged=hide_unmanaged,
        min_connections=min_connections,
        decisions={d.strip() for d in decisions.split(",") if d.strip()} if decisions else None,
        ports={int(p) for p in ports.split(",") if p.strip().isdigit()} if ports else None,
    )


# ------------------------------------------------------------------------- routes
@app.get("/api/health")
def health(st: Store = Depends(get_store)):
    from ..agent import agent_available

    ok, detail = agent_available()
    return {"version": __version__, "loaded": st.loaded, "files": st.files, "agent": {"available": ok, "detail": detail}, "pending_proposals": st.pending_proposals()}


@app.post("/api/ingest")
async def ingest(files: list[UploadFile] = File(...), replace: bool = Query(True), st: Store = Depends(get_store)):
    results = []
    first = True
    for upload in files:
        suffix = Path(upload.filename or "flows").suffix or ".txt"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(await upload.read())
            tmp_path = tmp.name
        try:
            results.append(st.ingest_file(tmp_path, replace=replace and first, label=upload.filename))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"{upload.filename}: {exc}") from exc
        finally:
            os.unlink(tmp_path)
        first = False
    if os.getenv("FLOWMAPPER_AUTO_ENRICH", "").lower() in ("1", "true", "yes"):
        _auto_enrich()
    return {"ingested": results, "stats": st.graph.stats(), "pending_proposals": st.pending_proposals()}


@app.post("/api/ingest/pce")
def ingest_pce(req: IngestPCERequest, st: Store = Depends(get_store)):
    from ..pce_client import PCEClient

    try:
        client = PCEClient.from_env()
        flows = client.fetch_flows(req.start, req.end, policy_decisions=req.policy_decisions, max_results=req.max_results)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return st.ingest_flows(flows, source=f"PCE {os.getenv('ILLUMIO_PCE_URL')}", replace=req.replace)


@app.delete("/api/dataset")
def clear(st: Store = Depends(get_store)):
    st.clear()
    return {"cleared": True}


@app.get("/api/stats")
def stats(st: Store = Depends(get_store)):
    return _require(st).stats()


@app.post("/api/options")
def set_options(req: OptionsRequest, st: Store = Depends(get_store)):
    opts = {k: v for k, v in req.model_dump().items() if v is not None}
    if "group_by" in opts:
        opts["group_by"] = tuple(opts["group_by"])
    st.set_options(**opts)
    return {"options": {k: (list(v) if isinstance(v, tuple) else v) for k, v in st.graph_options.items()}, "stats": st.graph.stats() if st.loaded else None}


def _annotate_ai(payload: dict, st: Store) -> dict:
    """Flag nodes that carry a pending / accepted AI proposal so the UI can mark them."""
    for n in payload["elements"]["nodes"]:
        d = n["data"]
        if d.get("type") == "app":
            d["ai"] = st.proposal_state("clusters", d["group"])
        elif d.get("type") == "workload":
            d["ai"] = st.proposal_state("workloads", d["id"][2:]) or ("accepted" if d.get("role_source") == "ai" else None)
    return payload


@app.get("/api/graph")
def graph(level: str = Query("app", pattern="^(app|workload)$"), flt: GraphFilter = Depends(_filter), st: Store = Depends(get_store)):
    return _annotate_ai(to_cytoscape(_require(st), level=level, flt=flt), st)


@app.post("/api/enrich")
def enrich(req: EnrichRequest, st: Store = Depends(get_store)):
    from ..enrich import Enricher, enrichment_available

    _require(st)
    ok, detail = enrichment_available()
    if not ok:
        raise HTTPException(status_code=503, detail=f"Enrichment unavailable: {detail}")
    try:
        return Enricher().run(st, clusters=req.clusters, roles=req.roles, auto_apply=req.auto_apply, min_confidence=req.min_confidence)
    except Exception as exc:  # noqa: BLE001
        log.exception("enrichment error")
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc


@app.get("/api/proposals")
def proposals(st: Store = Depends(get_store)):
    fg = _require(st)
    out = {"pending": st.pending_proposals(), "clusters": [], "workloads": []}
    for pid, p in st.proposals["clusters"].items():
        g = fg.groups.get(pid)
        out["clusters"].append({**p, "current_name": g.name if g else None, "members": g.members if g else []})
    for pid, p in st.proposals["workloads"].items():
        n = fg.nodes.get(pid)
        out["workloads"].append({**p, "hostname": n.name if n else pid, "application": fg.groups[n.group].name if n and n.group else None, "current_role": n.role_class if n else None})
    return out


@app.post("/api/proposals/{kind}/{pid:path}")
def review(kind: str, pid: str, req: ReviewRequest, st: Store = Depends(get_store)):
    _require(st)
    if kind not in st.proposals or pid not in st.proposals[kind]:
        raise HTTPException(status_code=404, detail=f"Unknown proposal {kind}/{pid}")
    return st.review_proposal(kind, pid, req.action)


@app.get("/api/apps")
def apps(st: Store = Depends(get_store)):
    fg = _require(st)
    return [g.to_dict() for g in sorted(fg.groups.values(), key=lambda g: (g.kind != "labeled", g.name))]


@app.get("/api/apps/{name}")
def app_detail(name: str, st: Store = Depends(get_store)):
    fg = _require(st)
    key = find_group(fg, name)
    if not key:
        raise HTTPException(status_code=404, detail=f"Unknown application {name}")
    group = fg.groups[key]
    members = sorted((fg.nodes[m] for m in group.members), key=lambda n: (n.tier or 0, n.name))
    return {
        "group": group.to_dict(),
        "workloads": [n.to_dict() for n in members],
        "internal_flows": [
            {"source": fg.nodes[s].name, "target": fg.nodes[d].name, "services": [e.to_dict() for e in data["services"].values()]}
            for s, d, data in fg.internal_edges(key)
        ],
        "dependencies": fg.dependencies(key),
        "markdown": to_markdown(fg, app=key, flt=GraphFilter(hide_infra=True)),
        "mermaid": to_mermaid(fg, app=key, flt=GraphFilter(hide_infra=True)),
        "proposal": st.proposals["clusters"].get(key),
    }


@app.post("/api/apps/{key}/rename")
def rename(key: str, req: RenameRequest, st: Store = Depends(get_store)):
    fg = _require(st)
    resolved = find_group(fg, key)
    if not resolved:
        raise HTTPException(status_code=404, detail=f"Unknown application {key}")
    return st.rename_group(resolved, req.name, req.app, req.env)


@app.get("/api/workloads/{name}")
def workload(name: str, st: Store = Depends(get_store)):
    fg = _require(st)
    from ..agent.tools import _resolve_node

    nid = _resolve_node(fg, name)
    if not nid:
        raise HTTPException(status_code=404, detail=f"Unknown workload {name}")
    n = fg.nodes[nid]
    return {
        **n.to_dict(),
        "application": fg.groups[n.group].name if n.group else None,
        "proposal": st.proposals["workloads"].get(nid),
        "talks_to": [{"to": fg.nodes[d].name, "services": [e.to_dict() for e in fg.G[nid][d]["services"].values()]} for d in fg.G.successors(nid)],
        "called_by": [{"from": fg.nodes[s].name, "services": [e.to_dict() for e in fg.G[s][nid]["services"].values()]} for s in fg.G.predecessors(nid)],
    }


@app.get("/api/export")
def export(format: str = Query("mermaid", pattern="^(mermaid|markdown|graphml|json)$"), app: Optional[str] = None, level: str = "app", flt: GraphFilter = Depends(_filter), st: Store = Depends(get_store)):
    fg = _require(st)
    if format == "mermaid":
        return PlainTextResponse(to_mermaid(fg, app=app, flt=flt))
    if format == "markdown":
        return PlainTextResponse(to_markdown(fg, app=app, flt=flt), media_type="text/markdown")
    if format == "graphml":
        return Response(to_graphml(fg, level=level), media_type="application/xml", headers={"Content-Disposition": "attachment; filename=flowmapper.graphml"})
    return to_json(fg)


@app.get("/api/diff")
def diff(
    app_name: Optional[str] = Query(None, alias="app"),
    mode: str = Query("period", pattern="^(period|baseline)$"),
    days: int = 30,
    split: Optional[str] = None,
    a_start: Optional[str] = None,
    a_end: Optional[str] = None,
    b_start: Optional[str] = None,
    b_end: Optional[str] = None,
    st: Store = Depends(get_store),
):
    """Structural diff between two periods of the loaded flows (or against the baseline dataset)."""
    from ..diff import diff_to_markdown

    _require(st)
    try:
        d = st.diff(app=app_name, mode=mode, days=days, split=split, a_start=a_start, a_end=a_end, b_start=b_start, b_end=b_end) if mode == "period" else st.diff(app=app_name, mode=mode)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"diff": d.to_dict(), "markdown": diff_to_markdown(d)}


@app.post("/api/baseline")
async def baseline(files: list[UploadFile] = File(...), st: Store = Depends(get_store)):
    """Load an older export as the baseline for GET /api/diff?mode=baseline."""
    paths = []
    try:
        for upload in files:
            suffix = Path(upload.filename or "flows").suffix or ".txt"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(await upload.read())
                paths.append(tmp.name)
        return st.ingest_baseline(paths)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        for p in paths:
            os.unlink(p)


@app.post("/api/chat")
def chat(req: ChatRequest, st: Store = Depends(get_store)):
    _require(st)
    agent = get_agent()
    if agent is None:
        raise HTTPException(status_code=503, detail=f"Agent unavailable: {_agent_error}")
    try:
        return agent.ask(req.message, req.thread_id)
    except Exception as exc:  # noqa: BLE001
        log.exception("agent error")
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
