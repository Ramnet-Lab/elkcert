from __future__ import annotations

import shlex
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Sequence

from log import info
from models import Node, RunConfig, Target
from ssh import run_script, upload


def _connect_host(node: Node, connect_via: str) -> str:
    return node.ip if connect_via == "ip" else node.fqdn


def _raise_on_failure(host: str, action: str, returncode: int, stdout: str, stderr: str, *, debug_ssh: bool) -> None:
    if returncode == 0:
        return
    stdout_trimmed = stdout.strip()
    stderr_trimmed = stderr.strip()
    details = []
    if debug_ssh:
        details.append("STDOUT:\n" + (stdout_trimmed if stdout_trimmed else "(empty)"))
        details.append("STDERR:\n" + (stderr_trimmed if stderr_trimmed else "(empty)"))
    else:
        if stdout_trimmed:
            details.append(f"STDOUT:\n{stdout_trimmed}")
        if stderr_trimmed:
            details.append(f"STDERR:\n{stderr_trimmed}")
    detail_text = "\n".join(details)
    raise RuntimeError(
        f"Remote command failed during {action} on {host} with exit code {returncode}"
        + (f"\n{detail_text}" if detail_text else "")
    )


def build_distribution_targets(config: RunConfig) -> list[Target]:
    targets: list[Target] = []
    for node in config.nodes:
        dest = config.cert_destinations.get(node.short)
        if dest:
            targets.append(Target(node=node, dest=dest))
    return targets


def distribute_certs(*, config: RunConfig, archive_path: Path) -> None:
    info("Distributing certs to nodes")

    targets = build_distribution_targets(config)
    if not targets:
        raise RuntimeError("No distribution targets found")

    es_nodes = {"es1", "es2", "es3"}

    with tempfile.TemporaryDirectory(prefix="elkcerts-unzip-") as tmp:
        tmp_path = Path(tmp)
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            zip_ref.extractall(tmp_path)

        ca_bundle_candidates = list(tmp_path.rglob("elastic-stack-ca.p12"))

        for target in targets:
            node = target.node
            dest = target.dest
            instance_dir = tmp_path / node.short
            if not instance_dir.exists():
                raise RuntimeError(f"Missing certs for {node.short} in archive")

            if node.short in es_nodes and ca_bundle_candidates:
                ca_bundle_source = ca_bundle_candidates[0]
                ca_bundle_dest = instance_dir / "elastic-stack-ca.p12"
                if ca_bundle_source != ca_bundle_dest:
                    shutil.copy2(ca_bundle_source, ca_bundle_dest)

            stage_parent = f"{config.cert_workdir}/stage"
            stage_dir = f"{stage_parent}/{node.short}"
            stage_parent_quoted = shlex.quote(stage_parent)
            stage_dir_quoted = shlex.quote(stage_dir)
            connect_host = _connect_host(node, config.connect_via)

            prep_script = "\n".join(
                [
                    "set -euo pipefail",
                    f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
                    'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
                    f"run_sudo mkdir -p {stage_parent_quoted}",
                    f"run_sudo rm -rf {stage_dir_quoted}",
                    f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {stage_parent_quoted}",
                ]
            )

            result = run_script(
                connect_host,
                prep_script,
                ssh_user=config.ssh_user,
                ssh_port=config.ssh_port,
                debug_ssh=config.debug_ssh,
            )
            _raise_on_failure(
                connect_host,
                "stage prep",
                result.returncode,
                result.stdout,
                result.stderr,
                debug_ssh=config.debug_ssh,
            )

            upload_result = upload(
                str(instance_dir),
                stage_parent,
                ssh_user=config.ssh_user,
                host=connect_host,
                ssh_port=config.ssh_port,
                recursive=True,
                debug_ssh=config.debug_ssh,
            )
            _raise_on_failure(
                connect_host,
                "stage upload",
                upload_result.returncode,
                upload_result.stdout,
                upload_result.stderr,
                debug_ssh=config.debug_ssh,
            )

            dest_quoted = shlex.quote(dest)
            purge_line = f"run_sudo rm -rf {dest_quoted}" if config.purge_node_certs else ""
            install_lines = [
                "set -euo pipefail",
                f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
                'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
                purge_line,
                f"run_sudo mkdir -p {dest_quoted}",
                f"run_sudo cp -af {stage_dir_quoted}/. {dest_quoted}/",
            ]
            if node.short in es_nodes:
                p12_source = f"{stage_dir}/{node.short}.p12"
                http_p12_dest = f"{dest}/http.p12"
                ca_p12_dest = f"{dest}/elastic-stack-ca.p12"
                install_lines.extend(
                    [
                        f"if run_sudo test -f {shlex.quote(p12_source)}; then",
                        f"  run_sudo cp -af {shlex.quote(p12_source)} {shlex.quote(http_p12_dest)}",
                        "fi",
                        f"CA_P12_SRC=$(find {stage_dir_quoted} -type f -name elastic-stack-ca.p12 -print -quit || true)",
                        "if [ -n \"$CA_P12_SRC\" ]; then",
                        f"  run_sudo cp -af \"$CA_P12_SRC\" {shlex.quote(ca_p12_dest)}",
                        "fi",
                    ]
                )
            install_script = "\n".join(install_lines)

            result = run_script(
                connect_host,
                install_script,
                ssh_user=config.ssh_user,
                ssh_port=config.ssh_port,
                debug_ssh=config.debug_ssh,
            )
            _raise_on_failure(
                connect_host,
                "install certs",
                result.returncode,
                result.stdout,
                result.stderr,
                debug_ssh=config.debug_ssh,
            )
