"""Command line entry point: ``flowmapper <command>``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _build_store(paths: list[str]):
    from .store import Store

    store = Store()
    for p in paths:
        info = store.ingest_file(p)
        print(f"loaded {p}: {info['format']}, {info['flows']} flows", file=sys.stderr)
    return store


def cmd_ingest(args) -> None:
    from .exports import to_json

    store = _build_store(args.files)
    out = to_json(store.require_graph())
    text = json.dumps(out, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)


def cmd_report(args) -> None:
    from .exports import GraphFilter, to_graphml, to_markdown, to_mermaid

    store = _build_store(args.files)
    fg = store.require_graph()
    flt = GraphFilter(hide_infra=not args.show_infra, hide_shared=args.hide_shared, env=args.env)
    if args.format == "mermaid":
        text = to_mermaid(fg, app=args.app, flt=flt)
    elif args.format == "graphml":
        text = to_graphml(fg, level=args.level)
    else:
        text = to_markdown(fg, app=args.app, flt=flt)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)


def cmd_stats(args) -> None:
    store = _build_store(args.files)
    fg = store.require_graph()
    print(json.dumps(fg.stats(), indent=2))
    for g in sorted(fg.groups.values(), key=lambda g: (g.kind != "labeled", g.name)):
        flag = " [shared]" if g.shared else ""
        print(f"- {g.name:<32} {g.kind:<9} env={g.env or '-':<12} workloads={len(g.members)}{flag}")


def cmd_serve(args) -> None:
    import uvicorn

    if args.files:
        os.environ["FLOWMAPPER_FILES"] = ",".join(args.files)
    uvicorn.run("flowmapper.api.main:app", host=args.host, port=args.port, reload=args.reload, log_level="info")


def cmd_fetch(args) -> None:
    from .pce_client import PCEClient

    client = PCEClient.from_env()
    records = client.fetch_records(args.start, args.end, max_results=args.max_results)
    Path(args.output).write_text(json.dumps(records), encoding="utf-8")
    print(f"wrote {len(records)} flows to {args.output}", file=sys.stderr)


def cmd_demo(args) -> None:
    from .sample import generate

    paths = generate(Path(args.dir))
    print("sample files:", ", ".join(str(p) for p in paths.values()), file=sys.stderr)
    if not args.no_serve:
        args.files = [str(paths["api_json"])]
        cmd_serve(args)


def cmd_enrich(args) -> None:
    from .enrich import Enricher

    store = _build_store(args.files)
    result = Enricher().run(store, clusters=not args.no_clusters, roles=not args.no_roles, auto_apply=args.apply, min_confidence=args.min_confidence)
    print(json.dumps(result), file=sys.stderr)
    for kind, items in store.proposals.items():
        for pid, p in items.items():
            if kind == "clusters":
                print(f"[{p['status']:<8}] cluster {pid}: {p['name']} (app={p['app']}, env={p.get('env')}, {p['confidence']:.2f}) — {p['rationale']}")
                for r in p.get("workload_roles", []):
                    print(f"             · {r['workload']}: {r['role_class']} / {r['role_label']} ({r['confidence']:.2f})")
            else:
                print(f"[{p['status']:<8}] {pid}: {p['role_class']} / {p['role_label']} ({p['confidence']:.2f}) — {p['rationale']}")
    if args.output:
        Path(args.output).write_text(json.dumps(store.proposals, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)


def cmd_diff(args) -> None:
    from .diff import diff_to_markdown

    store = _build_store(args.files)
    if args.baseline:
        store.ingest_baseline(args.baseline)
        d = store.diff(app=args.app, mode="baseline")
    else:
        d = store.diff(app=args.app, mode="period", days=args.days, split=args.split, a_start=args.a_start, a_end=args.a_end, b_start=args.b_start, b_end=args.b_end)
    text = diff_to_markdown(d) if args.format == "markdown" else json.dumps(d.to_dict(), indent=2, ensure_ascii=False, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)


def cmd_snapshot(args) -> None:
    from .snapshot import write_snapshot

    store = _build_store(args.files)
    path = write_snapshot(store.require_graph(), Path(args.output), title=args.title)
    print(f"static snapshot written to {path}", file=sys.stderr)


def cmd_chat(args) -> None:
    from .agent import FlowAgent

    store = _build_store(args.files)
    agent = FlowAgent(store)
    print(f"model: {agent.model_name} — type 'exit' to quit", file=sys.stderr)
    thread = "cli"
    while True:
        try:
            q = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if q in ("exit", "quit", ""):
            if q:
                break
            continue
        out = agent.ask(q, thread)
        for tc in out["tool_calls"]:
            if "tool" in tc:
                print(f"  ⚙ {tc['tool']}({json.dumps(tc['args'], ensure_ascii=False)})", file=sys.stderr)
        print(out["reply"])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="flowmapper", description="Illumio flows → application architecture graphs")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="parse files and dump the graph model as JSON")
    p.add_argument("files", nargs="+")
    p.add_argument("-o", "--output")
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("report", help="markdown / mermaid / graphml export")
    p.add_argument("files", nargs="+")
    p.add_argument("--app", help="restrict to one application")
    p.add_argument("--format", choices=["markdown", "mermaid", "graphml"], default="markdown")
    p.add_argument("--level", choices=["app", "workload"], default="app")
    p.add_argument("--env")
    p.add_argument("--show-infra", action="store_true", help="keep shared infrastructure (AD, DNS...)")
    p.add_argument("--hide-shared", action="store_true", help="hide every shared service")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("stats", help="dataset summary and discovered applications")
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("serve", help="start the web UI + API")
    p.add_argument("files", nargs="*")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("fetch", help="download flows from the PCE (async Explorer query)")
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--max-results", type=int, default=200000)
    p.add_argument("-o", "--output", default="pce_flows.json")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("demo", help="generate the synthetic dataset and serve it")
    p.add_argument("--dir", default="samples")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")
    p.add_argument("--no-serve", action="store_true")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("enrich", help="AI enrichment: name unlabeled clusters, qualify unknown roles (proposals, HITL)")
    p.add_argument("files", nargs="+")
    p.add_argument("--apply", action="store_true", help="apply proposals above --min-confidence instead of leaving them pending")
    p.add_argument("--min-confidence", type=float, default=0.7)
    p.add_argument("--no-clusters", action="store_true")
    p.add_argument("--no-roles", action="store_true")
    p.add_argument("-o", "--output", help="write proposals as JSON")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("diff", help="what changed between two periods (or against an older export)")
    p.add_argument("files", nargs="+", help="current export(s)")
    p.add_argument("--baseline", nargs="+", help="older export(s) to compare against instead of splitting by time")
    p.add_argument("--app", help="restrict to one application")
    p.add_argument("--days", type=int, default=30, help="period length (B = last N days, A = the N days before)")
    p.add_argument("--split", help="ISO date: A = before, B = after")
    p.add_argument("--a-start"), p.add_argument("--a-end"), p.add_argument("--b-start"), p.add_argument("--b-end")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("snapshot", help="export a static, offline copy of the UI with the dataset embedded")
    p.add_argument("files", nargs="+")
    p.add_argument("-o", "--output", default="snapshot")
    p.add_argument("--title")
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("chat", help="talk to the agent from the terminal")
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_chat)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
