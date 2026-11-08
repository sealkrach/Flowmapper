"""Port/protocol knowledge used to name services and infer workload roles.

Everything here is a heuristic: Illumio labels always win when present. The table is
deliberately a plain dict so a customer can extend it from ``flowmapper.yaml``.
"""
from __future__ import annotations

import re
from typing import Optional

# (proto, port) -> (service name, role class)
# Role classes: web, api, app, database, cache, messaging, directory, infra, monitoring,
#               storage, mail, security, platform, admin, search, coordination
KNOWN_SERVICES: dict[tuple[int, int], tuple[str, str]] = {
    (6, 22): ("ssh", "admin"),
    (6, 23): ("telnet", "admin"),
    (6, 3389): ("rdp", "admin"),
    (6, 5985): ("winrm", "admin"),
    (6, 5986): ("winrm-https", "admin"),
    (6, 5900): ("vnc", "admin"),
    (6, 80): ("http", "web"),
    (6, 443): ("https", "web"),
    (6, 8080): ("http-alt", "web"),
    (6, 8443): ("https-alt", "web"),
    (6, 8000): ("http-8000", "app"),
    (6, 8008): ("http-alt", "web"),
    (6, 8888): ("http-alt", "web"),
    (6, 9443): ("https-alt", "web"),
    (6, 3000): ("node/grafana", "web"),
    (6, 4200): ("angular-dev", "web"),
    (6, 5000): ("flask/registry", "api"),
    (6, 5001): ("api", "api"),
    (6, 8081): ("api", "api"),
    (6, 8082): ("api", "api"),
    (6, 8090): ("api", "api"),
    (6, 9000): ("php-fpm/minio", "api"),
    (6, 50051): ("grpc", "api"),
    (6, 7001): ("weblogic", "app"),
    (6, 7002): ("weblogic-ssl", "app"),
    (6, 9080): ("websphere", "app"),
    (6, 9043): ("websphere-admin", "app"),
    (6, 8009): ("ajp", "app"),
    (6, 1099): ("jmx/rmi", "app"),
    (6, 3306): ("mysql", "database"),
    (6, 33060): ("mysqlx", "database"),
    (6, 5432): ("postgresql", "database"),
    (6, 1521): ("oracle", "database"),
    (6, 1433): ("mssql", "database"),
    (6, 1434): ("mssql-browser", "database"),
    (6, 27017): ("mongodb", "database"),
    (6, 27018): ("mongodb", "database"),
    (6, 9042): ("cassandra", "database"),
    (6, 5984): ("couchdb", "database"),
    (6, 50000): ("db2", "database"),
    (6, 8529): ("arangodb", "database"),
    (6, 7687): ("neo4j", "database"),
    (6, 8086): ("influxdb", "database"),
    (6, 6379): ("redis", "cache"),
    (6, 6380): ("redis-tls", "cache"),
    (6, 11211): ("memcached", "cache"),
    (6, 5672): ("amqp", "messaging"),
    (6, 5671): ("amqps", "messaging"),
    (6, 15672): ("rabbitmq-mgmt", "messaging"),
    (6, 9092): ("kafka", "messaging"),
    (6, 9093): ("kafka-tls", "messaging"),
    (6, 61616): ("activemq", "messaging"),
    (6, 1883): ("mqtt", "messaging"),
    (6, 8883): ("mqtts", "messaging"),
    (6, 4222): ("nats", "messaging"),
    (6, 1414): ("ibm-mq", "messaging"),
    (6, 389): ("ldap", "directory"),
    (6, 636): ("ldaps", "directory"),
    (6, 3268): ("ldap-gc", "directory"),
    (6, 3269): ("ldaps-gc", "directory"),
    (6, 88): ("kerberos", "directory"),
    (17, 88): ("kerberos", "directory"),
    (6, 464): ("kpasswd", "directory"),
    (17, 464): ("kpasswd", "directory"),
    (6, 135): ("msrpc", "directory"),
    (6, 445): ("smb", "storage"),
    (6, 139): ("netbios-ssn", "storage"),
    (17, 137): ("netbios-ns", "infra"),
    (17, 138): ("netbios-dgm", "infra"),
    (6, 2049): ("nfs", "storage"),
    (17, 2049): ("nfs", "storage"),
    (6, 111): ("rpcbind", "storage"),
    (17, 111): ("rpcbind", "storage"),
    (6, 3260): ("iscsi", "storage"),
    (6, 873): ("rsync", "storage"),
    (6, 21): ("ftp", "storage"),
    (6, 990): ("ftps", "storage"),
    (17, 53): ("dns", "infra"),
    (6, 53): ("dns", "infra"),
    (17, 123): ("ntp", "infra"),
    (17, 67): ("dhcp", "infra"),
    (17, 68): ("dhcp", "infra"),
    (17, 514): ("syslog", "infra"),
    (6, 514): ("syslog", "infra"),
    (6, 6514): ("syslog-tls", "infra"),
    (17, 161): ("snmp", "monitoring"),
    (17, 162): ("snmp-trap", "monitoring"),
    (6, 10050): ("zabbix-agent", "monitoring"),
    (6, 10051): ("zabbix-server", "monitoring"),
    (6, 9100): ("node-exporter", "monitoring"),
    (6, 9090): ("prometheus", "monitoring"),
    (6, 5666): ("nrpe", "monitoring"),
    (6, 4317): ("otlp-grpc", "monitoring"),
    (6, 4318): ("otlp-http", "monitoring"),
    (6, 24224): ("fluentd", "monitoring"),
    (6, 5044): ("beats", "monitoring"),
    (6, 9997): ("splunk-fwd", "monitoring"),
    (6, 8089): ("splunk-mgmt", "monitoring"),
    (6, 9200): ("elasticsearch", "search"),
    (6, 9300): ("elasticsearch-transport", "search"),
    (6, 5601): ("kibana", "web"),
    (6, 8983): ("solr", "search"),
    (6, 25): ("smtp", "mail"),
    (6, 465): ("smtps", "mail"),
    (6, 587): ("submission", "mail"),
    (6, 110): ("pop3", "mail"),
    (6, 143): ("imap", "mail"),
    (6, 993): ("imaps", "mail"),
    (6, 8200): ("vault", "security"),
    (6, 1812): ("radius", "security"),
    (17, 1812): ("radius", "security"),
    (17, 1813): ("radius-acct", "security"),
    (6, 49): ("tacacs", "security"),
    (6, 8834): ("nessus", "security"),
    (6, 2181): ("zookeeper", "coordination"),
    (6, 2379): ("etcd", "coordination"),
    (6, 2380): ("etcd-peer", "coordination"),
    (6, 8500): ("consul", "coordination"),
    (6, 6443): ("kube-apiserver", "platform"),
    (6, 10250): ("kubelet", "platform"),
    (6, 10256): ("kube-proxy", "platform"),
    (6, 2375): ("docker", "platform"),
    (6, 2376): ("docker-tls", "platform"),
    (6, 5555): ("registry", "platform"),
    (17, 8472): ("flannel-vxlan", "platform"),
    (17, 4789): ("vxlan", "platform"),
    (6, 902): ("vmware-esxi", "platform"),
    (6, 9001): ("supervisor/tor", "platform"),
    (6, 8140): ("puppet", "platform"),
    (6, 4505): ("salt", "platform"),
    (6, 4506): ("salt", "platform"),
    (6, 9418): ("git", "platform"),
    (6, 10000): ("webmin/ndmp", "admin"),
    (17, 1194): ("openvpn", "security"),
    (6, 1194): ("openvpn", "security"),
    (17, 500): ("isakmp", "security"),
    (17, 4500): ("ipsec-nat-t", "security"),
    (17, 51820): ("wireguard", "security"),
    (1, 0): ("icmp", "infra"),
}

# Role classes whose providers are typically shared infrastructure rather than an app tier.
INFRA_ROLE_CLASSES = {"infra", "directory", "monitoring", "security", "admin", "platform", "mail"}

# Ordering used to place workloads in tiers when the flow DAG is ambiguous.
TIER_ORDER = {
    "edge": 0, "web": 0, "api": 1, "app": 1, "worker": 1, "search": 2, "messaging": 2, "cache": 2,
    "database": 3, "storage": 3, "coordination": 2, "directory": 9, "infra": 9, "monitoring": 9,
    "security": 9, "platform": 9, "admin": 9, "mail": 9, "unknown": 5,
}

# Services every host exposes to management tooling; they say nothing about the host's role.
AGENT_SERVICES = {
    "ssh", "rdp", "winrm", "winrm-https", "vnc", "telnet", "zabbix-agent", "node-exporter", "nrpe", "msrpc",
    "netbios-ns", "netbios-dgm", "netbios-ssn", "icmp", "snmp", "kubelet", "kube-proxy", "webmin/ndmp",
}

# (hint, role class). Short hints (<= 3 chars) must match a whole token of the label/hostname,
# longer hints match as substrings. Order matters: first match wins.
ROLE_LABEL_HINTS = [
    ("load balancer", "edge"), ("loadbalancer", "edge"), ("balancer", "edge"), ("haproxy", "edge"), ("proxy", "edge"),
    ("lb", "edge"), ("f5", "edge"), ("ingress", "edge"), ("waf", "edge"),
    ("database", "database"), ("postgres", "database"), ("oracle", "database"), ("mongo", "database"), ("mysql", "database"),
    ("mssql", "database"), ("sql", "database"), ("db", "database"), ("rds", "database"),
    ("redis", "cache"), ("memcache", "cache"), ("cache", "cache"),
    ("kafka", "messaging"), ("rabbit", "messaging"), ("broker", "messaging"), ("queue", "messaging"), ("mq", "messaging"),
    ("elastic", "search"), ("opensearch", "search"), ("solr", "search"), ("search", "search"), ("es", "search"),
    ("domain controller", "directory"), ("ldap", "directory"), ("active directory", "directory"), ("dc", "directory"), ("ad", "directory"),
    ("dns", "infra"), ("ntp", "infra"), ("dhcp", "infra"), ("syslog", "infra"), ("log collector", "infra"), ("log", "infra"),
    ("monitor", "monitoring"), ("zabbix", "monitoring"), ("prometheus", "monitoring"), ("grafana", "monitoring"), ("nagios", "monitoring"),
    ("backup", "storage"), ("nas", "storage"), ("nfs", "storage"), ("file", "storage"), ("storage", "storage"),
    ("vault", "security"), ("hsm", "security"), ("pki", "security"), ("bastion", "admin"), ("jump", "admin"),
    ("k8s", "platform"), ("kube", "platform"), ("openshift", "platform"), ("ocp", "platform"), ("esx", "platform"), ("vcenter", "platform"),
    ("mail", "mail"), ("smtp", "mail"), ("exchange", "mail"),
    ("web", "web"), ("front", "web"), ("nginx", "web"), ("apache", "web"), ("www", "web"), ("ui", "web"), ("portal", "web"),
    ("api", "api"), ("gateway", "api"), ("rest", "api"),
    ("worker", "worker"), ("batch", "worker"), ("job", "worker"), ("etl", "worker"), ("report", "worker"), ("rpt", "worker"),
    ("spark", "worker"), ("scheduler", "worker"), ("cron", "worker"),
    ("master", "app"), ("application", "app"), ("backend", "app"), ("app", "app"), ("srv", "app"), ("service", "app"),
]


def _match_hint(text: str) -> Optional[str]:
    low = text.lower()
    tokens = set(re.split(r"[^a-z0-9]+", low))
    # also split trailing digits: "web01" -> "web"
    tokens |= {re.sub(r"\d+$", "", t) for t in tokens}
    for hint, cls in ROLE_LABEL_HINTS:
        if len(hint) <= 3:
            if hint in tokens:
                return cls
        elif hint in low:
            return cls
    return None


def service_info(proto: int, port: Optional[int]) -> tuple[str, str]:
    """Return ``(service_name, role_class)`` for a port/proto; falls back to a generic name."""
    if proto == 1 or proto == 58:
        return ("icmp", "infra")
    if port is None:
        return (str(proto), "unknown")
    info = KNOWN_SERVICES.get((proto, port))
    if info:
        return info
    if proto == 6:
        if 8000 <= port <= 8999:
            return (f"tcp/{port}", "api")
        if port >= 49152:
            return (f"tcp/{port}", "unknown")  # ephemeral ports: reversed flow or RPC
        return (f"tcp/{port}", "unknown")
    if proto == 17:
        return (f"udp/{port}", "unknown")
    return (f"{proto}/{port}", "unknown")


def role_from_label(role_label: Optional[str]) -> Optional[str]:
    """Map a free-text Illumio ``role`` label to a role class (``Web Server`` → ``web``)."""
    return _match_hint(role_label) if role_label else None


def role_from_hostname(hostname: Optional[str]) -> Optional[str]:
    return _match_hint(hostname) if hostname else None
