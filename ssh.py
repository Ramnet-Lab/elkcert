from __future__ import annotations

import os
import shlex
import subprocess
from typing import List

from log import info
from models import RemoteResult


def ssh_args(ssh_port: int) -> List[str]:
    return [
        "ssh",
        "-p",
        str(ssh_port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={os.path.expanduser('~/.ssh/known_hosts')}",
        "-o",
        "ConnectTimeout=5",
    ]


def scp_args(ssh_port: int) -> List[str]:
    return [
        "scp",
        "-P",
        str(ssh_port),
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={os.path.expanduser('~/.ssh/known_hosts')}",
        "-o",
        "ConnectTimeout=5",
    ]


def run_script(
    host: str,
    script: str,
    *,
    ssh_user: str,
    ssh_port: int,
    debug_ssh: bool,
) -> RemoteResult:
    args = ssh_args(ssh_port) + [f"{ssh_user}@{host}", "bash", "-s"]

    if debug_ssh:
        info(
            f"\n----- BEGIN REMOTE SCRIPT ({host}) -----\n{script}\n"
            f"----- END REMOTE SCRIPT ({host}) -----"
        )

    proc = subprocess.run(
        args,
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    if debug_ssh and (stdout or stderr):
        if stdout:
            info(f"STDOUT:\n{stdout.strip()}")
        if stderr:
            info(f"STDERR:\n{stderr.strip()}")

    return RemoteResult(stdout=stdout, stderr=stderr, returncode=proc.returncode)


def upload(
    local_path: str,
    remote_path: str,
    *,
    ssh_user: str,
    host: str,
    ssh_port: int,
    recursive: bool,
    debug_ssh: bool,
) -> RemoteResult:
    args = scp_args(ssh_port)
    if recursive:
        args.append("-r")
    args += [local_path, f"{ssh_user}@{host}:{remote_path}"]

    if debug_ssh:
        info(f"SCP upload: {shlex.join(args)}")

    proc = subprocess.run(
        args,
        text=True,
        capture_output=True,
        check=False,
    )
    return RemoteResult(
        stdout=proc.stdout or "", stderr=proc.stderr or "", returncode=proc.returncode
    )


def download(
    remote_path: str,
    local_path: str,
    *,
    ssh_user: str,
    host: str,
    ssh_port: int,
    debug_ssh: bool,
) -> RemoteResult:
    args = scp_args(ssh_port) + [
        f"{ssh_user}@{host}:{remote_path}",
        local_path,
    ]

    if debug_ssh:
        info(f"SCP download: {shlex.join(args)}")

    proc = subprocess.run(
        args,
        text=True,
        capture_output=True,
        check=False,
    )
    return RemoteResult(
        stdout=proc.stdout or "", stderr=proc.stderr or "", returncode=proc.returncode
    )
