from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class Node:
    role: str
    short: str
    fqdn: str
    ip: str


@dataclass(frozen=True)
class Target:
    node: Node
    dest: str


@dataclass(frozen=True)
class RemoteResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass
class RunConfig:
    sudo_pass: str
    ssh_user: str
    ssh_port: int
    connect_via: str
    set_hostnames: bool
    hostname_fqdn: bool
    domain: str
    nodes: Sequence[Node]
    certutil_bin: str
    certs_out: Path
    cert_workdir: str
    cert_destinations: Mapping[str, str]
    service_name_by_node: Mapping[str, str]
    service_restart_order: Sequence[str]
    mark_begin: str
    mark_end: str
    ca_dir: str
    ca_cert: str
    ca_key: str
    purge_ca: bool
    purge_node_certs: bool
    debug_ssh: bool
