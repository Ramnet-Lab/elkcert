from __future__ import annotations

import shlex
from typing import Sequence

from log import info, warn
from models import Node, RunConfig
from ssh import run_script


def _connect_host(node: Node, connect_via: str) -> str:
    return node.ip if connect_via == "ip" else node.fqdn


def build_restart_script(*, sudo_pass: str, service_name: str) -> str:
    return "\n".join(
        [
            "set -euo pipefail",
            f"SUDO_PASS={shlex.quote(sudo_pass)}",
            'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
            f"run_sudo systemctl restart {shlex.quote(service_name)}",
        ]
    )


def restart_services(config: RunConfig) -> None:
    info("Restarting services after cert distribution")
    nodes_by_short = {node.short: node for node in config.nodes}

    for short in config.service_restart_order:
        node = nodes_by_short.get(short)
        if node is None:
            raise RuntimeError(f"Missing node definition for restart target: {short}")
        service_name = config.service_name_by_node.get(short)
        if service_name is None:
            raise RuntimeError(f"Missing service mapping for restart target: {short}")

        connect_host = _connect_host(node, config.connect_via)
        info(f"Restarting {service_name} on {node.short}")
        restart_script = build_restart_script(
            sudo_pass=config.sudo_pass,
            service_name=service_name,
        )

        result = run_script(
            connect_host,
            restart_script,
            ssh_user=config.ssh_user,
            ssh_port=config.ssh_port,
            debug_ssh=config.debug_ssh,
        )

        if result.returncode == 0:
            continue

        stderr_lower = result.stderr.lower()
        if (
            result.returncode == 5
            and "unit" in stderr_lower
            and "not found" in stderr_lower
        ):
            warn(
                f"systemd unit not found for {service_name} on {node.short}; skipping."
            )
            if result.stderr.strip():
                warn(f"Details: {result.stderr.strip()}")
            continue

        if config.debug_ssh:
            if result.stdout.strip():
                warn(f"STDOUT:\n{result.stdout.strip()}")
            if result.stderr.strip():
                warn(f"STDERR:\n{result.stderr.strip()}")

        raise RuntimeError(
            f"Service restart failed for {service_name} on {node.short} "
            f"with exit code {result.returncode}"
            + (f"\n{result.stderr.strip()}" if result.stderr.strip() else "")
        )
