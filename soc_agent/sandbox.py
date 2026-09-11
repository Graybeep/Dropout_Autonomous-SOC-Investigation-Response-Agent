"""Sandbox filesystem layer.

CLAUDE.md 5.2: fixtures/seed is pristine and committed; fixtures/run is the
working copy and is gitignored. Every tool reads and writes the run copy only.
reset_sandbox() restores run/ from seed/ and is called before every scenario.

There is no hidden global state here: each read hits the JSON file on disk and
each write lands on disk immediately. That is what makes the block_ip ->
check_firewall_state verification loop real rather than theatre (guardrail 4).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from . import config


def reset_sandbox() -> Path:
    """rm -rf fixtures/run && cp -r fixtures/seed fixtures/run."""
    if config.RUN_DIR.exists():
        shutil.rmtree(config.RUN_DIR)
    shutil.copytree(config.SEED_DIR, config.RUN_DIR)
    # Case store is runtime-only; it is never seeded.
    write_json(config.CASES, {})
    return config.RUN_DIR


def _path(name: str) -> Path:
    return config.RUN_DIR / name


def read_json(name: str) -> Any:
    """Read a run-copy fixture from disk. Always hits the filesystem."""
    p = _path(name)
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)


def write_json(name: str, data: Any) -> None:
    """Write a run-copy fixture to disk immediately."""
    config.RUN_DIR.mkdir(parents=True, exist_ok=True)
    with _path(name).open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def ensure_ready() -> None:
    """Guard against tools being called before reset_sandbox()."""
    if not config.RUN_DIR.exists():
        raise RuntimeError(
            "fixtures/run does not exist. Call sandbox.reset_sandbox() before "
            "running a scenario."
        )
