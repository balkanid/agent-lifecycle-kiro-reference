#!/usr/bin/env python3
"""Import every script module to catch broken cross-module imports (py_compile misses these)."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

MODULES = (
    "balkanid_api",
    "kiro_config",
    "guardrails",
    "kiro_hook",
    "register_agent",
    "service_account_gate",
    "setup_agent_profile",
    "agent_credentials",
    "trigger_sync",
    "preflight",
)


def main() -> int:
    scripts = Path(__file__).resolve().parent
    sys.path.insert(0, str(scripts))
    for name in MODULES:
        importlib.import_module(name)
    print(f"imported {len(MODULES)} modules ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
