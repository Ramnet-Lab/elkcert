from __future__ import annotations

import shlex
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Sequence

from log import info
from models import Node, RunConfig
from ssh import download, run_script, upload


def select_cert_nodes(nodes: Sequence[Node]) -> list[Node]:
    wanted = {"es1", "es2", "es3", "kibana", "fleet", "logstash"}
    return [node for node in nodes if node.short in wanted]


def build_instances_yaml(nodes: Sequence[Node]) -> str:
    lines = ["instances:"]
    for node in nodes:
        lines.append(f"  - name: {node.short}")
        lines.append("    dns:")
        lines.append(f"      - {node.fqdn}")
        if node.short != node.fqdn:
            lines.append(f"      - {node.short}")
    return "\n".join(lines) + "\n"


def _write_instances_yaml(path: Path, nodes: Sequence[Node]) -> None:
    contents = build_instances_yaml(nodes)
    path.write_text(contents, encoding="utf-8")


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


def verify_dns(names: Sequence[str]) -> None:
    info("Verifying DNS resolution via getent hosts")
    for name in names:
        result = subprocess.run(["getent", "hosts", name], check=False)
        if result.returncode != 0:
            raise RuntimeError(f"DNS verification failed for {name}")


def build_es1_ca_bootstrap_script(config: RunConfig) -> str:
    ca_parent = str(Path(config.ca_dir).parent)
    purge_lines = [
        'echo "==> purging CA directory"',
        'run_sudo rm -rf "$CA_DIR"',
    ] if config.purge_ca else []
    lines = [
        "set -euxo pipefail",
        f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
        'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
        f"CERT_WORKDIR={shlex.quote(config.cert_workdir)}",
        f"CA_PARENT={shlex.quote(ca_parent)}",
        f"CA_DIR={shlex.quote(config.ca_dir)}",
        f"CA_CERT={shlex.quote(config.ca_cert)}",
        f"CA_KEY={shlex.quote(config.ca_key)}",
        f"CA_ZIP={shlex.quote(f'{config.cert_workdir}/ca.zip')}",
        f"CA_STAGE={shlex.quote(f'{config.cert_workdir}/ca-stage')}",
        "",
        "run_sudo true",
        'echo "==> ensuring cert workdir"',
        "run_sudo mkdir -p \"$CERT_WORKDIR\"",
        f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} \"$CERT_WORKDIR\"",
        'echo "==> ensuring CA parent directory"',
        "run_sudo mkdir -p \"$CA_PARENT\"",
        *purge_lines,
        'echo "==> ensuring CA directory"',
        "run_sudo mkdir -p \"$CA_DIR\"",
        f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} \"$CA_DIR\"",
        'echo "==> generating CA zip via certutil"',
        "run_sudo rm -f \"$CA_ZIP\"",
        "run_sudo "
        + shlex.quote(config.certutil_bin)
        + " ca --silent --pem --out \"$CA_ZIP\"",
        f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} \"$CA_ZIP\"",
        'echo "==> staging CA zip"',
        "run_sudo rm -rf \"$CA_STAGE\"",
        "run_sudo mkdir -p \"$CA_STAGE\"",
        f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} \"$CA_STAGE\"",
        "env CA_ZIP=\"$CA_ZIP\" CA_STAGE=\"$CA_STAGE\" python3 - <<'PY'",
        "import os",
        "import zipfile",
        "zip_path = os.environ['CA_ZIP']",
        "dest = os.environ['CA_STAGE']",
        "with zipfile.ZipFile(zip_path, 'r') as zf:",
        "    zf.extractall(dest)",
        "PY",
        'echo "==> installing CA material"',
        "run_sudo mkdir -p \"$CA_DIR\"",
        "if [ -s \"$CA_STAGE/ca/ca.crt\" ]; then",
        "  run_sudo cp -af \"$CA_STAGE/ca/.\" \"$CA_DIR/\"",
        "else",
        "  run_sudo cp -af \"$CA_STAGE/.\" \"$CA_DIR/\"",
        "fi",
        "run_sudo test -s \"$CA_CERT\"",
        "run_sudo test -s \"$CA_KEY\"",
        f"run_sudo chown -R {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} \"$CA_DIR\"",
        "",
    ]
    return "\n".join(line for line in lines if line)


def purge_and_bootstrap_ca(config: RunConfig, es1_host: str) -> None:
    info("Ensuring PEM CA exists on es1")
    script = build_es1_ca_bootstrap_script(config)
    result = run_script(
        es1_host,
        script,
        ssh_user=config.ssh_user,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        es1_host,
        "CA bootstrap",
        result.returncode,
        result.stdout,
        result.stderr,
        debug_ssh=config.debug_ssh,
    )


def generate_certs(config: RunConfig) -> Path:
    cert_nodes = select_cert_nodes(config.nodes)

    if config.connect_via == "fqdn":
        required_dns = sorted(
            {node.fqdn for node in cert_nodes} | {f"es1.{config.domain}", f"kibana.{config.domain}"}
        )
        verify_dns(required_dns)

    es1_node = next((node for node in config.nodes if node.short == "es1"), None)
    if es1_node is None:
        raise RuntimeError("Unable to resolve es1 node definition")
    es1_host = _connect_host(es1_node, config.connect_via)

    output_path = config.certs_out
    output_path.parent.mkdir(parents=True, exist_ok=True)
    info(f"Cert bundle output path: {output_path}")

    temp_dir = Path(tempfile.mkdtemp(prefix="elkcerts-"))
    instances_path = temp_dir / "instances.yml"
    _write_instances_yaml(instances_path, cert_nodes)

    remote_instances = f"{config.cert_workdir}/instances.yml"
    remote_zip = f"{config.cert_workdir}/certs.zip"

    prep_script = "\n".join(
        [
            "set -euo pipefail",
            f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
            'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
            f"run_sudo mkdir -p {config.cert_workdir}",
            f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {config.cert_workdir}",
        ]
    )

    info(f"Ensuring {config.cert_workdir} exists on {es1_host}")
    result = run_script(
        es1_host,
        prep_script,
        ssh_user=config.ssh_user,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        es1_host,
        "cert workdir prep",
        result.returncode,
        result.stdout,
        result.stderr,
        debug_ssh=config.debug_ssh,
    )

    purge_and_bootstrap_ca(config, es1_host)

    info(f"Uploading instances.yml to {es1_host}")
    upload_result = upload(
        str(instances_path),
        remote_instances,
        ssh_user=config.ssh_user,
        host=es1_host,
        ssh_port=config.ssh_port,
        recursive=False,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        es1_host,
        "instances.yml upload",
        upload_result.returncode,
        upload_result.stdout,
        upload_result.stderr,
        debug_ssh=config.debug_ssh,
    )

    remote_script = "\n".join(
        [
            "set -euo pipefail",
            f"SUDO_PASS={shlex.quote(config.sudo_pass)}",
            f"CERT_PASS={shlex.quote(config.cert_pass)}",
            f"CERT_WORKDIR={shlex.quote(config.cert_workdir)}",
            f"CA_CERT={shlex.quote(config.ca_cert)}",
            f"CA_KEY={shlex.quote(config.ca_key)}",
            f"CA_P12={shlex.quote(f'{config.cert_workdir}/elastic-stack-ca.p12')}",
            f"ZIP_STAGE_DIR={shlex.quote(f'{config.cert_workdir}/certs-stage')}",
            f"ZIP_STAGE={shlex.quote(f'{config.cert_workdir}/certs-stage/certs.zip')}",
            'run_sudo() { echo "$SUDO_PASS" | sudo -S -p "" "$@"; }',
            f"run_sudo rm -f {remote_zip}",
            "run_sudo "
            + shlex.quote(config.certutil_bin)
            + " cert --silent --in "
            + remote_instances
            + " --out "
            + remote_zip
            + " --ca-cert "
            + config.ca_cert
            + " --ca-key "
            + config.ca_key
            + " --pass \"$CERT_PASS\"",
            f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {remote_zip}",
            f"run_sudo rm -f \"$CA_P12\"",
            "run_sudo keytool -importcert -alias ca -file \"$CA_CERT\" -keystore \"$CA_P12\" -storetype PKCS12 -storepass \"$CERT_PASS\" -noprompt",
            f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} \"$CA_P12\"",
            "run_sudo test -s \"$CA_P12\"",
            "run_sudo rm -rf \"$ZIP_STAGE_DIR\"",
            "run_sudo mkdir -p \"$ZIP_STAGE_DIR\"",
            f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} \"$ZIP_STAGE_DIR\"",
            "cp \"" + remote_zip + "\" \"$ZIP_STAGE\"",
            "env ZIP_PATH=\"$ZIP_STAGE\" CA_P12=\"$CA_P12\" python3 - <<'PY'",
            "import os",
            "import zipfile",
            "zip_path = os.environ['ZIP_PATH']",
            "p12_path = os.environ['CA_P12']",
            "with zipfile.ZipFile(zip_path, 'a') as zf:",
            "    zf.write(p12_path, arcname='elastic-stack-ca.p12')",
            "PY",
            "run_sudo mv \"$ZIP_STAGE\" \"" + remote_zip + "\"",
            f"run_sudo chown {shlex.quote(config.ssh_user)}:{shlex.quote(config.ssh_user)} {remote_zip}",
        ]
    )

    info("Generating PKCS#12 HTTP layer TLS certs (xpack.security.http.ssl)")
    info("Running elasticsearch-certutil on es1")
    result = run_script(
        es1_host,
        remote_script,
        ssh_user=config.ssh_user,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        es1_host,
        "certutil",
        result.returncode,
        result.stdout,
        result.stderr,
        debug_ssh=config.debug_ssh,
    )

    local_zip = temp_dir / "certs.zip"
    info("Downloading cert bundle back to Kibana")
    download_result = download(
        remote_zip,
        str(local_zip),
        ssh_user=config.ssh_user,
        host=es1_host,
        ssh_port=config.ssh_port,
        debug_ssh=config.debug_ssh,
    )
    _raise_on_failure(
        es1_host,
        "cert download",
        download_result.returncode,
        download_result.stdout,
        download_result.stderr,
        debug_ssh=config.debug_ssh,
    )

    shutil.move(str(local_zip), str(output_path))
    info(f"Cert bundle written to: {output_path}")
    return output_path
