#!/usr/bin/env python3
from __future__ import annotations

import sys

import main


def main_entry() -> int:
    return main.run()


if __name__ == "__main__":
    raise SystemExit(main_entry())
