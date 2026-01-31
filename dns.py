from __future__ import annotations

import shlex
import sys
from typing import Sequence

from log import info
from models import Node, RunConfig
from ssh import run_script


def build_hosts_block(nodes: Sequence[Node], *, mark_begin: str, mark_end: str) -> str:
    lines = [mark_begin]
    for node in nodes:
        lines.append(f"{node.ip}    {node.fqdn}    {node.short}")
    lines.append(mark_end)
    return "\n".join(lines) + "\n"


def _connect_host(node: Node, connect_via: str) -> str:
    return node.ip if connect_via == "ip" else node.fqdn


def build_remote_script(
    node: Node,
    hosts_block: str,
    *,
    set_hostnames: bool,
    hostname_fqdn: bool,
    sudo_pass: str,
    mark_begin: str,
    mark_end: str,
) -> str:
    set_hostnames_str = "true" if set_hostnames else "false"
    hostname_target = node.fqdn if hostname_fqdn else node.short

    lines = [
        "set -euo pipefail",
        "",
        f"SET_HOSTNAMES={shlex.quote(set_hostnames_str)}",
        f"SHORTNAME={shlex.quote(node.short)}",
        f"FQDN={shlex.quote(node.fqdn)}",
        f"HOSTNAME_TARGET={shlex.quote(hostname_target)}",
        f"MARK_BEGIN={shlex.quote(mark_begin)}",
        f"MARK_END={shlex.quote(mark_end)}",
        "",
        "HOSTS_BLOCK=$(cat <<'EOF'",
        hosts_block.rstrip("\n"),
        "EOF",
        ")",
        "",
        f"SUDO_PASS={shlex.quote(sudo_pass)}",
        'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
        "",
        "# Ensure sudo works non-interactively",
        "run_sudo true",
        "",
        'if [[ "$SET_HOSTNAMES" == "true" ]]; then',
        '  run_sudo hostnamectl set-hostname "$HOSTNAME_TARGET"',
        "fi",
        "",
        'tmp=$(mktemp)',
        'cp /etc/hosts "$tmp"',
        "",
        "# Remove prior managed block if present (fixed-string match)",
        'if grep -qF "$MARK_BEGIN" "$tmp"; then',
        '  tmp_cleaned="${tmp}.clean"',
        "  awk -v begin=\"$MARK_BEGIN\" -v end=\"$MARK_END\" '",
        "    $0 == begin { in_block=1; next }",
        "    $0 == end { in_block=0; next }",
        "    in_block != 1 { print }",
        "  ' \"$tmp\" > \"$tmp_cleaned\"",
        '  mv -f "$tmp_cleaned" "$tmp"',
        "fi",
        "",
        "# Append fresh block",
        'printf "\\n%s\\n" "$HOSTS_BLOCK" >> "$tmp"',
        "",
        'run_sudo install -m 644 "$tmp" /etc/hosts',
        'rm -f "$tmp"',
        "",
        'echo "Resolution check:"',
        'getent hosts "$FQDN" || true',
        'getent hosts "$SHORTNAME" || true',
        "",
    ]
    return "\n".join(lines)


def _raise_on_failure(host: str, result_stdout: str, result_stderr: str, returncode: int, *, debug_ssh: bool) -> None:
    if returncode == 0:
        return
    stdout_trimmed = result_stdout.strip()
    stderr_trimmed = result_stderr.strip()
    details = []
    if debug_ssh:
        details.append(
            "STDOUT:\n" + (stdout_trimmed if stdout_trimmed else "(empty)")
        )
        details.append(
            "STDERR:\n" + (stderr_trimmed if stderr_trimmed else "(empty)")
        )
    else:
        if stdout_trimmed:
            details.append(f"STDOUT:\n{stdout_trimmed}")
        if stderr_trimmed:
            details.append(f"STDERR:\n{stderr_trimmed}")
    detail_text = "\n".join(details)
    raise RuntimeError(
        f"Remote command failed on {host} with exit code {returncode}"
        + (f"\n{detail_text}" if detail_text else "")
    )


def apply_hosts(config: RunConfig) -> None:
    info("Starting ELK DNS/hosts update")
    info(
        f"Domain: {config.domain}; set_hostnames={config.set_hostnames}; "
        f"hostname_fqdn={config.hostname_fqdn}"
    )

    hosts_block = build_hosts_block(
        config.nodes,
        mark_begin=config.mark_begin,
        mark_end=config.mark_end,
    )

    for node in config.nodes:
        info(f"Configuring {node.fqdn} ({node.ip})")
        info(f"Using non-interactive sudo for {config.ssh_user} on that host.")
        remote_script = build_remote_script(
            node=node,
            hosts_block=hosts_block,
            set_hostnames=config.set_hostnames,
            hostname_fqdn=config.hostname_fqdn,
            sudo_pass=config.sudo_pass,
            mark_begin=config.mark_begin,
            mark_end=config.mark_end,
        )
        connect_host = _connect_host(node, config.connect_via)
        result = run_script(
            connect_host,
            remote_script,
            ssh_user=config.ssh_user,
            ssh_port=config.ssh_port,
            debug_ssh=config.debug_ssh,
        )
        _raise_on_failure(
            connect_host,
            result.stdout,
            result.stderr,
            result.returncode,
            debug_ssh=config.debug_ssh,
        )
        if result.stdout:
            sys.stdout.write(result.stdout)
            sys.stdout.flush()
        if result.stderr:
            sys.stderr.write(result.stderr)
            sys.stderr.flush()

    info("Done. All nodes updated with *.cft.net host mappings.")
    info("Safe to re-run any time.")
