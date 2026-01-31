from __future__ import annotations

import os
from pathlib import Path
from typing import List

from models import Node, RunConfig

DEFAULT_SUDO_PASS = os.environ.get("SUDO_PASS")
DEFAULT_CERT_PASS = os.environ.get("ELK_CERT_PASS")
DEFAULT_SSH_USER = os.environ.get("SSH_USER", "cft")
DEFAULT_SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
DEFAULT_SET_HOSTNAMES = os.environ.get("SET_HOSTNAMES", "true").lower() == "true"
DEFAULT_DOMAIN = os.environ.get("DOMAIN", "cft.net")
DEFAULT_CERTUTIL_BIN = os.environ.get(
    "CERTUTIL_BIN", "/usr/share/elasticsearch/bin/elasticsearch-certutil"
)
DEFAULT_CONNECT_VIA = os.environ.get("CONNECT_VIA", "ip")
DEFAULT_HOSTNAME_FQDN = os.environ.get("HOSTNAME_FQDN", "false").lower() == "true"
DEFAULT_DEBUG_SSH = os.environ.get("DEBUG_SSH", "false").lower() == "true"

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CERTS_OUT = SCRIPT_DIR / "elk-certs.zip"

CERT_WORKDIR = "/tmp/elkcerts"
CERT_DESTINATIONS = {
    "es1": "/etc/elasticsearch/certs",
    "es2": "/etc/elasticsearch/certs",
    "es3": "/etc/elasticsearch/certs",
    "kibana": "/etc/kibana/certs",
    "fleet": "/etc/elastic-agent/certs",
    "logstash": "/etc/logstash/certs",
}
CA_DESTINATIONS = {
    "kibana": "/etc/kibana/elasticsearch-ca.pem",
    "fleet": "/etc/elastic-agent/ca.pem",
    "fleet_alt": "/etc/elastic-agent/certs/ca.pem",
    "logstash": "/etc/logstash/certs/ca.pem",
}
SERVICE_NAME_BY_NODE = {
    "es1": "elasticsearch",
    "es2": "elasticsearch",
    "es3": "elasticsearch",
    "kibana": "kibana",
    "fleet": "elastic-agent",
    "logstash": "logstash",
}
SERVICE_RESTART_ORDER = ("es1", "es2", "es3", "kibana", "fleet", "logstash")

CA_DIR = "/etc/elasticsearch/certs/ca"
CA_CERT = f"{CA_DIR}/ca.crt"
CA_KEY = f"{CA_DIR}/ca.key"

MARK_BEGIN = "# >>> SIEM HOSTS (managed by siem_hosts_push_interactive.sh) >>>"
MARK_END = "# <<< SIEM HOSTS (managed by siem_hosts_push_interactive.sh) <<<"


def build_default_nodes(domain: str) -> List[Node]:
    return [
        Node("kibana", "kibana", f"kibana.{domain}", "192.168.2.20"),
        Node("es", "es1", f"es1.{domain}", "192.168.2.21"),
        Node("es", "es2", f"es2.{domain}", "192.168.2.22"),
        Node("es", "es3", f"es3.{domain}", "192.168.2.23"),
        Node("ml", "ml1", f"ml1.{domain}", "192.168.2.24"),
        Node("ml", "ml2", f"ml2.{domain}", "192.168.2.25"),
        Node("logstash", "logstash", f"logstash.{domain}", "192.168.2.26"),
        Node("fleet", "fleet", f"fleet.{domain}", "192.168.2.27"),
    ]


def load_config() -> RunConfig:
    nodes = build_default_nodes(DEFAULT_DOMAIN)
    resolved_cert_pass = DEFAULT_CERT_PASS or DEFAULT_SUDO_PASS or ""
    return RunConfig(
        sudo_pass=DEFAULT_SUDO_PASS or "",
        cert_pass=resolved_cert_pass,
        ssh_user=DEFAULT_SSH_USER,
        ssh_port=DEFAULT_SSH_PORT,
        connect_via=DEFAULT_CONNECT_VIA,
        set_hostnames=DEFAULT_SET_HOSTNAMES,
        hostname_fqdn=DEFAULT_HOSTNAME_FQDN,
        domain=DEFAULT_DOMAIN,
        nodes=nodes,
        certutil_bin=DEFAULT_CERTUTIL_BIN,
        certs_out=DEFAULT_CERTS_OUT,
        cert_workdir=CERT_WORKDIR,
        cert_destinations=CERT_DESTINATIONS,
        service_name_by_node=SERVICE_NAME_BY_NODE,
        service_restart_order=SERVICE_RESTART_ORDER,
        mark_begin=MARK_BEGIN,
        mark_end=MARK_END,
        ca_dir=CA_DIR,
        ca_cert=CA_CERT,
        ca_key=CA_KEY,
        purge_ca=True,
        purge_node_certs=True,
        debug_ssh=DEFAULT_DEBUG_SSH,
    )
