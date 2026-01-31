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


def build_elasticsearch_keystore_script(*, sudo_pass: str) -> str:
    return "\n".join(
        [
            "set -euo pipefail",
            f"SUDO_PASS={shlex.quote(sudo_pass)}",
            "KEYSTORE_PASS=\"$SUDO_PASS\"",
            'run_sudo_keystore() { printf "%s\\n%s\\n" "$SUDO_PASS" "$KEYSTORE_PASS" | sudo -S -p "" "$@"; }',
            'add_secret() { run_sudo_keystore /usr/share/elasticsearch/bin/elasticsearch-keystore add -xf "$1"; }',
            "add_secret xpack.security.http.ssl.keystore.secure_password",
            "add_secret xpack.security.transport.ssl.keystore.secure_password",
            "add_secret xpack.security.transport.ssl.truststore.secure_password",
        ]
    )


def _log_command_output(label: str, stdout: str, stderr: str) -> None:
    stdout_text = stdout.strip() or "<empty>"
    stderr_text = stderr.strip() or "<empty>"
    warn(f"{label} STDOUT:\n{stdout_text}")
    warn(f"{label} STDERR:\n{stderr_text}")


def _collect_failure_logs(
    *,
    connect_host: str,
    service_name: str,
    config: RunConfig,
) -> None:
    status_script = "\n".join(
        [
            "set -euo pipefail",
            f"systemctl status {shlex.quote(service_name)} --no-pager -l",
        ]
    )
    journal_script = "\n".join(
        [
            "set -euo pipefail",
            f"journalctl -xeu {shlex.quote(service_name)} --no-pager -n 200",
        ]
    )

    status_result = run_script(
        connect_host,
        status_script,
        ssh_user=config.ssh_user,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _log_command_output(
        f"systemctl status {service_name} on {connect_host}",
        status_result.stdout,
        status_result.stderr,
    )

    journal_result = run_script(
        connect_host,
        journal_script,
        ssh_user=config.ssh_user,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _log_command_output(
        f"journalctl -xeu {service_name} on {connect_host}",
        journal_result.stdout,
        journal_result.stderr,
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

        if short.startswith("es"):
            info(f"Setting Elasticsearch keystore passwords on {node.short}")
            keystore_script = build_elasticsearch_keystore_script(
                sudo_pass=config.sudo_pass,
            )
            keystore_result = run_script(
                connect_host,
                keystore_script,
                ssh_user=config.ssh_user,
                ssh_port=config.ssh_port,
                debug_ssh=config.debug_ssh,
            )
            if keystore_result.returncode != 0:
                _log_command_output(
                    f"elasticsearch-keystore setup on {node.short}",
                    keystore_result.stdout,
                    keystore_result.stderr,
                )
                raise RuntimeError(
                    f"Elasticsearch keystore setup failed on {node.short} "
                    f"with exit code {keystore_result.returncode}"
                    + (
                        f"\n{keystore_result.stderr.strip()}"
                        if keystore_result.stderr.strip()
                        else ""
                    )
                )

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

        _collect_failure_logs(
            connect_host=connect_host,
            service_name=service_name,
            config=config,
        )

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
