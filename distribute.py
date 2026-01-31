from __future__ import annotations

import shlex
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Sequence

from config import CA_DESTINATIONS
from log import info
from models import Node, RunConfig, Target
from ssh import download, run_script, upload


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


def _require_node(config: RunConfig, short: str) -> Node:
    node = next((item for item in config.nodes if item.short == short), None)
    if node is None:
        raise RuntimeError(f"Unable to resolve {short} node definition")
    return node


def build_distribution_targets(config: RunConfig) -> list[Target]:
    targets: list[Target] = []
    for node in config.nodes:
        dest = config.cert_destinations.get(node.short)
        if dest:
            targets.append(Target(node=node, dest=dest))
    return targets


def _ca_destination_for_node(node: Node) -> str | None:
    if node.short == "fleet":
        return CA_DESTINATIONS.get("fleet") or CA_DESTINATIONS.get("fleet_alt")
    return CA_DESTINATIONS.get(node.short)


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
                elastic_certs_dest = f"{dest}/elastic-certificates.p12"
                ca_p12_dest = f"{dest}/elastic-stack-ca.p12"
                install_lines.extend(
                    [
                        f"if run_sudo test -f {shlex.quote(p12_source)}; then",
                        f"  run_sudo cp -af {shlex.quote(p12_source)} {shlex.quote(http_p12_dest)}",
                        f"  run_sudo cp -af {shlex.quote(p12_source)} {shlex.quote(elastic_certs_dest)}",
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


def distribute_fleet_http_ca(*, config: RunConfig, remote_ca_path: str) -> None:
    info("Distributing ES HTTP CA to Fleet")

    try:
        es1_node = _require_node(config, "es1")
        fleet_node = _require_node(config, "fleet")
    except RuntimeError:
        info("Fleet node not defined; skipping Fleet CA distribution")
        return

    es1_host = _connect_host(es1_node, config.connect_via)
    fleet_host = _connect_host(fleet_node, config.connect_via)

    temp_dir = Path(tempfile.mkdtemp(prefix="elkcerts-fleet-ca-"))
    local_ca = temp_dir / "elasticsearch-http-ca.crt"

    download_result = download(
        remote_ca_path,
        str(local_ca),
        ssh_user=config.ssh_user,
        host=es1_host,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        es1_host,
        "Fleet CA download",
        download_result.returncode,
        download_result.stdout,
        download_result.stderr,
        debug_ssh=config.debug_ssh,
    )

    stage_parent = f"{config.cert_workdir}/stage-fleet-ca"
    stage_dir = f"{stage_parent}/fleet"
    stage_file = f"{stage_dir}/elasticsearch-http-ca.crt"

    prep_script = "\n".join(
        [
            "set -euo pipefail",
            f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
            'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
            f"run_sudo mkdir -p {shlex.quote(stage_parent)}",
            f"run_sudo rm -rf {shlex.quote(stage_dir)}",
            f"run_sudo mkdir -p {shlex.quote(stage_dir)}",
            f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {shlex.quote(stage_parent)}",
            f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {shlex.quote(stage_dir)}",
        ]
    )

    result = run_script(
        fleet_host,
        prep_script,
        ssh_user=config.ssh_user,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        fleet_host,
        "Fleet CA stage prep",
        result.returncode,
        result.stdout,
        result.stderr,
        debug_ssh=config.debug_ssh,
    )

    upload_result = upload(
        str(local_ca),
        stage_file,
        ssh_user=config.ssh_user,
        host=fleet_host,
        ssh_port=config.ssh_port,
        recursive=False,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        fleet_host,
        "Fleet CA stage upload",
        upload_result.returncode,
        upload_result.stdout,
        upload_result.stderr,
        debug_ssh=config.debug_ssh,
    )

    group = config.service_name_by_node.get("fleet", "fleet")
    fleet_alt_dir = "/etc/elastic-agent/certs"
    fleet_alt_dest = f"{fleet_alt_dir}/elasticsearch-http-ca.crt"
    fleet_primary = config.fleet_http_ca_dest

    install_script = "\n".join(
        [
            "set -euo pipefail",
            f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
            'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
            f"STAGE_FILE={shlex.quote(stage_file)}",
            f"FLEET_PRIMARY={shlex.quote(fleet_primary)}",
            f"FLEET_ALT_DIR={shlex.quote(fleet_alt_dir)}",
            f"FLEET_ALT_DEST={shlex.quote(fleet_alt_dest)}",
            "if [ -d \"$FLEET_ALT_DIR\" ]; then",
            "  CA_DEST=\"$FLEET_ALT_DEST\"",
            "else",
            "  CA_DEST=\"$FLEET_PRIMARY\"",
            "fi",
            "run_sudo mkdir -p \"$(dirname \"$CA_DEST\")\"",
            "run_sudo cp -af \"$STAGE_FILE\" \"$CA_DEST\"",
            f"if getent group {shlex.quote(group)} >/dev/null 2>&1; then",
            f"  run_sudo chown root:{shlex.quote(group)} \"$CA_DEST\" || run_sudo chown root:root \"$CA_DEST\"",
            "else",
            "  run_sudo chown root:root \"$CA_DEST\"",
            "fi",
            "run_sudo chmod 644 \"$CA_DEST\"",
        ]
    )

    result = run_script(
        fleet_host,
        install_script,
        ssh_user=config.ssh_user,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        fleet_host,
        "Fleet CA install",
        result.returncode,
        result.stdout,
        result.stderr,
        debug_ssh=config.debug_ssh,
    )


def distribute_es_http_ca(*, config: RunConfig, ca_path: Path) -> None:
    info("Distributing ES HTTP CA to non-ES nodes")

    targets: list[Target] = []
    for node in config.nodes:
        if node.short in {"kibana", "fleet", "logstash"}:
            dest = _ca_destination_for_node(node)
            if dest:
                targets.append(Target(node=node, dest=dest))

    if not targets:
        info("No ES HTTP CA distribution targets found")
        return

    stage_parent = f"{config.cert_workdir}/stage-ca"

    for target in targets:
        node = target.node
        dest = target.dest
        connect_host = _connect_host(node, config.connect_via)
        stage_dir = f"{stage_parent}/{node.short}"
        stage_file = f"{stage_dir}/es-http-ca.pem"

        prep_script = "\n".join(
            [
                "set -euo pipefail",
                f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
                'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
                f"run_sudo mkdir -p {shlex.quote(stage_parent)}",
                f"run_sudo rm -rf {shlex.quote(stage_dir)}",
                f"run_sudo mkdir -p {shlex.quote(stage_dir)}",
                f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {shlex.quote(stage_parent)}",
                f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {shlex.quote(stage_dir)}",
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
            "CA stage prep",
            result.returncode,
            result.stdout,
            result.stderr,
            debug_ssh=config.debug_ssh,
        )

        upload_result = upload(
            str(ca_path),
            stage_file,
            ssh_user=config.ssh_user,
            host=connect_host,
            ssh_port=config.ssh_port,
            recursive=False,
            debug_ssh=config.debug_ssh,
        )
        _raise_on_failure(
            connect_host,
            "CA stage upload",
            upload_result.returncode,
            upload_result.stdout,
            upload_result.stderr,
            debug_ssh=config.debug_ssh,
        )

        group = config.service_name_by_node.get(node.short, node.short)
        dest_parent = str(Path(dest).parent)

        if node.short == "fleet":
            fleet_primary = CA_DESTINATIONS.get("fleet", dest)
            fleet_alt = CA_DESTINATIONS.get("fleet_alt", dest)
            dest_selector = "\n".join(
                [
                    f"FLEET_PRIMARY={shlex.quote(fleet_primary)}",
                    f"FLEET_ALT={shlex.quote(fleet_alt)}",
                    "if [ -d \"$(dirname \"$FLEET_ALT\")\" ]; then",
                    "  CA_DEST=\"$FLEET_ALT\"",
                    "else",
                    "  CA_DEST=\"$FLEET_PRIMARY\"",
                    "fi",
                ]
            )
        else:
            dest_selector = f"CA_DEST={shlex.quote(dest)}"

        if node.short == "fleet":
            chown_line = "\n".join(
                [
                    f"if getent group {shlex.quote(group)} >/dev/null 2>&1; then",
                    f"  run_sudo chown root:{shlex.quote(group)} \"$CA_DEST\" || run_sudo chown root:root \"$CA_DEST\"",
                    "else",
                    "  run_sudo chown root:root \"$CA_DEST\"",
                    "fi",
                ]
            )
        else:
            chown_line = f"run_sudo chown root:{shlex.quote(group)} \"$CA_DEST\""

        install_script = "\n".join(
            [
                "set -euo pipefail",
                f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
                'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
                f"STAGE_FILE={shlex.quote(stage_file)}",
                dest_selector,
                "run_sudo mkdir -p \"$(dirname \"$CA_DEST\")\"",
                "run_sudo cp -af \"$STAGE_FILE\" \"$CA_DEST\"",
                chown_line,
                "run_sudo chmod 640 \"$CA_DEST\"",
            ]
        )

        result = run_script(
            connect_host,
            install_script,
            ssh_user=config.ssh_user,
            ssh_port=config.ssh_port,
            debug_ssh=config.debug_ssh,
        )
        _raise_on_failure(
            connect_host,
            "CA install",
            result.returncode,
            result.stdout,
            result.stderr,
            debug_ssh=config.debug_ssh,
        )
