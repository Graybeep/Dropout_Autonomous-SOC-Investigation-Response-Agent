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
import os
import shutil
import time
from pathlib import Path
from typing import Any

from . import config


LOCK = "_run.lock"


class SandboxBusy(RuntimeError):
    """Another process is mid-run against fixtures/run."""


def _lock_path() -> Path:
    return config.RUN_DIR / LOCK


def acquire(owner: str) -> None:
    """Mark fixtures/run as in use by a live run.

    fixtures/run is a single shared directory. Without this, running
    selfcheck.py (which resets the sandbox) while run_all.py is mid-scenario
    silently deletes the firewall state the running scenario is about to
    verify - the block succeeds, the verification then reads an empty file,
    and the scenario fails for a reason that has nothing to do with the agent.
    That happened during a live run; hence the guard.
    """
    config.RUN_DIR.mkdir(parents=True, exist_ok=True)
    _lock_path().write_text(
        json.dumps({"owner": owner, "pid": os.getpid(),
                    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}),
        encoding="utf-8")


def release() -> None:
    p = _lock_path()
    if p.exists():
        p.unlink()


def _check_free(force: bool) -> None:
    p = _lock_path()
    if not p.exists() or force:
        return
    try:
        info = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if info.get("pid") == os.getpid():
        return
    if _pid_alive(info.get("pid")):
        raise SandboxBusy(
            f"fixtures/run is in use by {info.get('owner')} (pid {info.get('pid')}, "
            f"started {info.get('started')}). Resetting it now would delete state "
            f"that run is about to verify. Wait for it to finish, or pass "
            f"force=True if you are certain it is dead."
        )
    p.unlink()  # stale lock from a crashed run


def _pid_alive(pid) -> bool:
    """True if a pid is still running. Stdlib only, no psutil dependency."""
    if not isinstance(pid, int):
        return False
    try:
        os.kill(pid, 0)
    except (OSError, PermissionError) as exc:
        return isinstance(exc, PermissionError)
    return True


def reset_sandbox(force: bool = False) -> Path:
    """rm -rf fixtures/run && cp -r fixtures/seed fixtures/run."""
    _check_free(force)
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
