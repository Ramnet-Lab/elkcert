from __future__ import annotations

from datetime import datetime
import sys


def info(message: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"\n[{now}] {message}\n")
    sys.stdout.flush()


def warn(message: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"\n[{now}] WARNING: {message}\n")
    sys.stdout.flush()


def error(message: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    sys.stderr.write(f"\n[{now}] ERROR: {message}\n")
    sys.stderr.flush()
