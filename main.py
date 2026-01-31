from __future__ import annotations

from pathlib import Path

from certs import extract_es_http_ca, generate_certs
from config import load_config
from distribute import distribute_certs, distribute_es_http_ca
from dns import apply_hosts
from log import info
from restart import restart_services


def _require_sudo_pass(sudo_pass: str) -> None:
    if sudo_pass:
        return
    raise RuntimeError("sudo password required. Set SUDO_PASS in environment.")


def run() -> int:
    config = load_config()
    _require_sudo_pass(config.sudo_pass)

    apply_hosts(config)

    archive_path = generate_certs(config)
    if not isinstance(archive_path, Path):
        raise RuntimeError("Cert generation did not return an archive path")

    distribute_certs(config=config, archive_path=archive_path)

    ca_path = extract_es_http_ca(config)
    distribute_es_http_ca(config=config, ca_path=ca_path)

    restart_services(config)

    info("Completed full ELK cert rebuild flow")
    return 0
