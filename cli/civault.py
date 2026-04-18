#!/usr/bin/env python3
"""Backward-compatible launcher for civault packaged CLI.

Preferred usage after install:
    civault <command>
"""

from civault_cli.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
