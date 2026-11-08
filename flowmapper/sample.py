"""Synthetic but realistic Illumio dataset, emitted in the three supported formats.

Topology: an e-commerce stack, a payments API, a CRM, a search platform, an analytics
cluster, a preprod copy, shared core infrastructure (AD/DNS/NTP/syslog/Zabbix), a legacy ERP
with VENs but no labels, a reporting box attached to the CRM, Internet / corporate IP lists
and a handful of blocked flows.
"""
from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

PROD, PRE = "Production", "Preprod"
LOC = "DC-Paris"


@dataclass
class Host:
    name: str
    ip: str
    app: Optional[str] = None
    env: Optional[str] = None
    role: Optional[str] = None
    loc: Optional[str] = LOC
    managed: bool = True
    ip_list: Optional[str] = None

    @property
    def labels(self) -> dict:
        if not self.managed:
            return {}
        return {k: v for k, v in (("app", self.app), ("env", self.env), ("loc", self.loc), ("role", self.role)) if v}

    @property
    def href(self) -> Optional[str]:
        return f"/orgs/1/workloads/{abs(hash(self.name)) % 10**12:012x}" if self.managed else None


H: dict[str, Host] = {}


def h(name, ip, app=None, env=None, role=None, managed=True, ip_list=None, loc=LOC):
    H[name] = Host(name, ip, app, env, role, loc, managed, ip_list)
    return name


# --- E-Commerce (prod)
for i in (1, 2):
    h(f"ecom-lb0{i}", f"10.10.1.{i}", "E-Commerce", PROD, "Load Balancer")
for i in (1, 2, 3):
    h(f"ecom-web0{i}", f"10.10.2.{i}", "E-Commerce", PROD, "Web Server")
for i in (1, 2):
    h(f"ecom-api0{i}", f"10.10.3.{i}", "E-Commerce", PROD, "API Server")
h("ecom-worker01", "10.10.3.10", "E-Commerce", PROD, "Batch Worker")
h("ecom-pg01", "10.10.4.1", "E-Commerce", PROD, "Database")
h("ecom-redis01", "10.10.4.5", "E-Commerce", PROD, "Cache")
h("ecom-mq01", "10.10.4.8", "E-Commerce", PROD, "Message Broker")
# --- Payments (prod)
for i in (1, 2):
    h(f"pay-api0{i}", f"10.20.1.{i}", "Payments", PROD, "API Server")
h("pay-db01", "10.20.2.1", "Payments", PROD, "Database")
h("hsm-appliance", "10.20.9.10", managed=False)  # unmanaged appliance used only by Payments
# --- CRM (prod)
h("crm-web01", "10.30.1.1", "CRM", PROD, "Web Server")
h("crm-app01", "10.30.2.1", "CRM", PROD, "Application Server")
h("crm-db01", "10.30.3.1", "CRM", PROD, "Database")
# --- Search platform (prod, consumed by 3 apps)
for i in (1, 2, 3):
    h(f"es0{i}", f"10.40.1.{i}", "Search Platform", PROD, "Search Node")
h("kibana01", "10.40.2.1", "Search Platform", PROD, "Web Server")
# --- Analytics (prod)
h("spark-master01", "10.45.1.1", "Analytics", PROD, "Cluster Master")
for i in (1, 2):
    h(f"spark-worker0{i}", f"10.45.2.{i}", "Analytics", PROD, "Worker")
# --- Preprod copy of e-commerce
h("ecom-web01p", "10.110.2.1", "E-Commerce", PRE, "Web Server")
h("ecom-api01p", "10.110.3.1", "E-Commerce", PRE, "API Server")
h("ecom-pg01p", "10.110.4.1", "E-Commerce", PRE, "Database")
# --- Core infrastructure (labeled, shared by everybody)
h("dc01", "10.0.0.11", "Core Infra", PROD, "Domain Controller")
h("dc02", "10.0.0.12", "Core Infra", PROD, "Domain Controller")
h("ntp01", "10.0.0.20", "Core Infra", PROD, "NTP")
h("syslog01", "10.0.0.30", "Core Infra", PROD, "Log Collector")
h("zabbix01", "10.0.0.40", "Core Infra", PROD, "Monitoring")
# --- Legacy ERP: VENs installed, no labels at all
h("erp-web01", "10.60.1.1")
h("erp-app01", "10.60.2.1")
h("erp-db01", "10.60.3.1")
# --- Reporting server: unlabeled, only talks to CRM DB
h("rpt01", "10.30.9.1")
# --- Unmanaged
h("internet-1", "203.0.113.10", managed=False, ip_list="Internet")
h("internet-2", "198.51.100.25", managed=False, ip_list="Internet")
h("internet-3", "192.0.2.77", managed=False, ip_list="Internet")
h("user-1", "10.200.1.15", managed=False, ip_list="Corporate Users")
h("user-2", "10.200.1.42", managed=False, ip_list="Corporate Users")
h("user-3", "10.200.2.8", managed=False, ip_list="Corporate Users")
h("scanner", "10.200.5.77", managed=False, ip_list="Corporate Users")

# (src, dst, port, proto, process, decision, connections, since_day, until_day)
# since/until restrict the link to a sub-window of the dataset (days from its start) so that
# a period diff has real changes to find.
LINKS: list[tuple] = []


def link(src, dst, port, proto=6, process=None, decision="allowed", conns=100, since=None, until=None):
    LINKS.append((src, dst, port, proto, process, decision, conns, since, until))


# Internet → load balancers → web → api → data
for src in ("internet-1", "internet-2", "internet-3"):
    for lb in ("ecom-lb01", "ecom-lb02"):
        link(src, lb, 443, process="haproxy", conns=5000)
        link(src, lb, 80, process="haproxy", conns=800)
for lb in ("ecom-lb01", "ecom-lb02"):
    for web in ("ecom-web01", "ecom-web02", "ecom-web03"):
        link(lb, web, 443, process="nginx", conns=4000)
for web in ("ecom-web01", "ecom-web02", "ecom-web03"):
    for api in ("ecom-api01", "ecom-api02"):
        link(web, api, 8080, process="java", conns=3000)
    link(web, "ecom-redis01", 6379, process="redis-server", conns=2500)
for api in ("ecom-api01", "ecom-api02", "ecom-worker01"):
    link(api, "ecom-pg01", 5432, process="postgres", conns=1500)
    link(api, "ecom-redis01", 6379, process="redis-server", conns=900)
    link(api, "ecom-mq01", 5672, process="beam.smp", conns=400)
    link(api, "es01", 9200, process="java", conns=600)
    link(api, "es02", 9200, process="java", conns=600)
for api in ("ecom-api01", "ecom-api02"):
    link(api, "pay-api01", 8443, process="java", conns=700)
    link(api, "pay-api02", 8443, process="java", conns=700)
# Payments
for api in ("pay-api01", "pay-api02"):
    link(api, "pay-db01", 1521, process="tnslsnr", conns=900)
    link(api, "hsm-appliance", 1792, conns=300)
# CRM
for u in ("user-1", "user-2", "user-3"):
    link(u, "crm-web01", 443, process="httpd", conns=300)
    link(u, "kibana01", 5601, process="node", conns=40)
link("crm-web01", "crm-app01", 8009, process="java", conns=1200)
link("crm-app01", "crm-db01", 1433, process="sqlservr.exe", conns=1500)
link("crm-app01", "ecom-api01", 8080, process="java", conns=200)
link("crm-app01", "es01", 9200, process="java", conns=150)
link("crm-app01", "ecom-pg01", 5432, process="postgres", decision="potentially_blocked", conns=20)
# Reporting server only talks to the CRM database
link("rpt01", "crm-db01", 1433, process="sqlservr.exe", conns=80)
# Search platform internals + kibana
for a in ("es01", "es02", "es03"):
    for b in ("es01", "es02", "es03"):
        if a != b:
            link(a, b, 9300, process="java", conns=2000)
link("kibana01", "es01", 9200, process="java", conns=500)
# Analytics
for w in ("spark-worker01", "spark-worker02"):
    link(w, "spark-master01", 7077, process="java", conns=800)
    link("spark-master01", w, 7078, process="java", conns=300)
    link(w, "ecom-pg01", 5432, process="postgres", conns=200)
    link(w, "es03", 9200, process="java", conns=250)
# Preprod
link("ecom-web01p", "ecom-api01p", 8080, process="java", conns=200)
link("ecom-api01p", "ecom-pg01p", 5432, process="postgres", conns=150)
link("user-1", "ecom-web01p", 443, process="nginx", conns=30)
# Legacy ERP (unlabeled)
link("erp-web01", "erp-app01", 8000, process="python", conns=600)
link("erp-app01", "erp-db01", 3306, process="mysqld", conns=700)
for u in ("user-2", "user-3"):
    link(u, "erp-web01", 443, process="httpd", conns=120)
link("erp-app01", "crm-app01", 8009, process="java", conns=50)
# Shared infrastructure: everybody → AD/DNS/NTP/syslog, Zabbix → everybody
for name, host in H.items():
    if not host.managed or host.app == "Core Infra":
        continue
    for dc in ("dc01", "dc02"):
        link(name, dc, 53, 17, process="named", conns=400)
        link(name, dc, 389, process="lsass.exe", conns=60)
        link(name, dc, 88, process="lsass.exe", conns=40)
    link(name, "ntp01", 123, 17, process="chronyd", conns=50)
    link(name, "syslog01", 514, 17, process="rsyslogd", conns=200)
    link("zabbix01", name, 10050, process="zabbix_agentd", conns=300)
# --- Changes that only exist in part of the window (for the period diff) ----------------
# CRM gains a second app server and a new dependency on Payments during the last 3 days
h("crm-app02", "10.30.2.2", "CRM", PROD, "Application Server")
link("crm-web01", "crm-app02", 8009, process="java", conns=900, since=4)
link("crm-app02", "crm-db01", 1433, process="sqlservr.exe", conns=1100, since=4)
link("crm-app01", "pay-api01", 8443, process="java", conns=350, since=4)
link("crm-app02", "pay-api01", 8443, process="java", conns=300, since=4)
# CRM stops using the search platform after day 4
LINKS[:] = [l for l in LINKS if not (l[0] == "crm-app01" and l[1] == "es01")]
link("crm-app01", "es01", 9200, process="java", conns=150, until=4)
# The CRM → ecom-pg01 flow gets enforced: potentially blocked before, blocked after
LINKS[:] = [l for l in LINKS if not (l[0] == "crm-app01" and l[1] == "ecom-pg01")]
link("crm-app01", "ecom-pg01", 5432, process="postgres", decision="potentially_blocked", conns=20, until=4)
link("crm-app01", "ecom-pg01", 5432, process="postgres", decision="blocked", conns=18, since=4)
# Traffic from corporate users to the CRM triples in the last 3 days
link("user-1", "crm-web01", 443, process="httpd", conns=1800, since=4)
# Blocked flows
link("internet-3", "ecom-web01", 22, process="sshd", decision="blocked", conns=35)
link("internet-2", "ecom-lb01", 8080, decision="blocked", conns=12)
for port in (22, 445, 3389, 5432, 1433, 8080):
    link("scanner", "ecom-api01", port, decision="blocked", conns=3)
    link("scanner", "pay-db01", port, decision="blocked", conns=3)
link("user-3", "pay-db01", 1521, decision="blocked", conns=5)
link("erp-app01", "ecom-pg01", 5432, process="postgres", decision="blocked", conns=8)

PROCESS_DEFAULT = {443: "nginx", 80: "nginx", 8080: "java", 5432: "postgres", 1521: "tnslsnr", 1433: "sqlservr.exe"}


def generate(out_dir: Path, days: int = 7, seed: int = 7) -> dict[str, Path]:
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    end = datetime(2026, 11, 6, 18, 0, tzinfo=timezone.utc)
    start = end - timedelta(days=days)
    records = []
    for src, dst, port, proto, process, decision, conns, since, until in LINKS:
        lo = int((since or 0) * 86400)
        hi = int((until if until is not None else days) * 86400) - 1
        window_days = max((hi - lo) / 86400, 0.5)
        # steady flows report roughly twice a day, rare ones a few times in the window
        n_buckets = max(2, int(window_days * 2)) if conns > 20 else rng.randint(1, 3)
        for _ in range(n_buckets):
            t = start + timedelta(seconds=rng.randint(lo, hi))
            c = max(1, int(conns / n_buckets * rng.uniform(0.6, 1.4)))
            records.append((H[src], H[dst], port, proto, process or PROCESS_DEFAULT.get(port), decision, c, t))
    records.sort(key=lambda r: r[7])

    csv_path = out_dir / "explorer_export.csv"
    _write_csv(csv_path, records)
    api_path = out_dir / "api_traffic_flows.json"
    _write_api(api_path, records)
    syslog_path = out_dir / "syslog_flow_summaries.log"
    _write_syslog(syslog_path, records, rng)
    return {"explorer_csv": csv_path, "api_json": api_path, "syslog_json": syslog_path}


PD_TEXT = {"allowed": "Allowed", "potentially_blocked": "Potentially Blocked", "blocked": "Blocked"}
PD_INT = {"allowed": 0, "potentially_blocked": 1, "blocked": 2}
PROTO_TEXT = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _write_csv(path: Path, records) -> None:
    cols = [
        "Source IP", "Source Name", "Source Role", "Source Application", "Source Environment", "Source Location", "Source IP List",
        "Destination IP", "Destination Name", "Destination Role", "Destination Application", "Destination Environment",
        "Destination Location", "Destination IP List", "Port", "Protocol", "Process Name", "Service Name", "User Name",
        "Reported Policy", "Draft Policy", "Connections", "First Detected", "Last Detected", "Flow Direction",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for src, dst, port, proto, process, decision, c, t in records:
            w.writerow(
                [
                    src.ip, src.name if src.managed else src.ip, src.role or "", src.app or "", src.env or "", src.loc if src.managed else "", src.ip_list or "",
                    dst.ip, dst.name if dst.managed else dst.ip, dst.role or "", dst.app or "", dst.env or "", dst.loc if dst.managed else "", dst.ip_list or "",
                    port, PROTO_TEXT.get(proto, proto), process or "", "", "", PD_TEXT[decision], PD_TEXT[decision], c,
                    t.strftime("%Y-%m-%d %H:%M:%S"), (t + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
                    "Inbound" if dst.managed else "Outbound",
                ]
            )


def _api_endpoint(host: Host) -> dict:
    ep: dict = {"ip": host.ip}
    if host.managed:
        ep["workload"] = {
            "href": host.href,
            "hostname": host.name,
            "name": host.name,
            "labels": [{"href": f"/orgs/1/labels/{abs(hash(k + v)) % 1000}", "key": k, "value": v} for k, v in host.labels.items()],
        }
    elif host.ip_list:
        ep["ip_lists"] = [{"href": f"/orgs/1/sec_policy/draft/ip_lists/{abs(hash(host.ip_list)) % 100}", "name": host.ip_list}]
    return ep


def _write_api(path: Path, records) -> None:
    out = []
    for src, dst, port, proto, process, decision, c, t in records:
        out.append(
            {
                "src": _api_endpoint(src),
                "dst": _api_endpoint(dst),
                "service": {"port": port, "proto": proto, "process_name": process, "service_name": None, "user_name": None},
                "num_connections": c,
                "policy_decision": decision,
                "draft_policy_decision": decision,
                "flow_direction": "inbound" if dst.managed else "outbound",
                "state": "closed",
                "timestamp_range": {"first_detected": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "last_detected": (t + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")},
            }
        )
    path.write_text(json.dumps(out, indent=1), encoding="utf-8")


def _write_syslog(path: Path, records, rng: random.Random) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for src, dst, port, proto, process, decision, c, t in records:
            rec = {
                "version": 4,
                "interval_sec": 600,
                "count": c,
                "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
                "dir": "I" if dst.managed else "O",
                "src_ip": src.ip,
                "dst_ip": dst.ip,
                "proto": proto,
                "dst_port": port,
                "state": "C" if decision == "allowed" else "N",
                "pd": PD_INT[decision],
                "class": "U" if decision == "allowed" else "B",
            }
            if process and decision != "blocked":
                rec["pn"] = process
            if src.managed:
                rec["src_hostname"], rec["src_href"], rec["src_labels"] = src.name, src.href, src.labels
            if dst.managed:
                rec["dst_hostname"], rec["dst_href"], rec["dst_labels"] = dst.name, dst.href, dst.labels
            reporter = dst.name if dst.managed else src.name
            prefix = f"<14>1 {t.strftime('%Y-%m-%dT%H:%M:%SZ')} pce.corp.example illumio_pce/collector 3412 - [meta sequenceId=\"{rng.randint(1, 10**6)}\"] "
            fh.write((prefix if rng.random() < 0.5 else "") + json.dumps(rec, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import sys

    paths = generate(Path(sys.argv[1] if len(sys.argv) > 1 else "samples"))
    for k, p in paths.items():
        print(f"{k}: {p}")
