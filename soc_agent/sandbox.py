"""Sandbox filesystem layer.

CLAUDE.md 5.2: fixtures/seed is pristine and committed; fixtures/run is the
working copy and is gitignored. Every tool reads and writes the run copy only.
reset_sandbox() restores run/ from seed/ and is called before every scenario.

There is no hidden global state here: each read hits the JSON file on disk and
each write lands on disk immediately. That is what makes the block_ip ->
check_firewall_state verification loop real rather than theatre (guardrail 4).
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from . import config


# The lock lives OUTSIDE fixtures/run, deliberately. An earlier version put it
# inside, where reset_sandbox's rmtree deleted it between scenarios - leaving an
# unlocked window in which a concurrent process saw no lock and wiped the live
# run's directory. The lock cannot live in the directory it protects.
LOCK = ".soc_run.lock"


class SandboxBusy(RuntimeError):
    """Another process is mid-run against fixtures/run."""


def _lock_path() -> Path:
    return config.ROOT / LOCK


def acquire(owner: str) -> None:
    """Mark fixtures/run as in use by a live run.

    fixtures/run is a single shared directory. Without this, running
    selfcheck.py (which resets the sandbox) while run_all.py is mid-scenario
    silently deletes the firewall state the running scenario is about to
    verify - the block succeeds, the verification then reads an empty file,
    and the scenario fails for a reason that has nothing to do with the agent.
    That happened during a live run; hence the guard.
    """
    _lock_path().write_text(
        json.dumps({"owner": owner, "pid": os.getpid(),
                    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}),
        encoding="utf-8")


def release() -> None:
    p = _lock_path()
    if p.exists():
        p.unlink()


def _lock_age_s(started) -> float:
    """Seconds since the lock was taken; 0.0 if the stamp is unreadable."""
    if not isinstance(started, str):
        return 0.0
    try:
        ts = datetime.datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return 0.0
    return (datetime.datetime.utcnow() - ts).total_seconds()


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
    if _lock_age_s(info.get("started")) > LOCK_STALE_AFTER_S:
        p.unlink()  # older than any real run; the owner is not coming back
        return
    if _pid_alive(info.get("pid")):
        raise SandboxBusy(
            f"fixtures/run is in use by {info.get('owner')} (pid {info.get('pid')}, "
            f"started {info.get('started')}). Resetting it now would delete state "
            f"that run is about to verify. Wait for it to finish, or pass "
            f"force=True if you are certain it is dead."
        )
    p.unlink()  # stale lock from a crashed run


# A killed run leaves its lock behind. If liveness can never be resolved the
# sandbox is wedged for every future run, so the lock also expires by age.
# Generous: a full seven-scenario run is well under an hour.
LOCK_STALE_AFTER_S = 2 * 3600


def _pid_alive(pid) -> bool:
    """True if a pid is still running. Stdlib only, no psutil dependency."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True          # exists, owned by someone else
    except OSError:
        return False         # ESRCH - definitely gone
    except SystemError:
        # CPython on Windows raises SystemError, NOT OSError, for some dead
        # pids. This escaped the old except clause entirely, so _check_free
        # propagated it and the stale lock could never be removed - one killed
        # run wedged the sandbox permanently (Toknow P-025). Alive/dead is
        # genuinely unknown here, so answer ALIVE: refusing to reset is
        # recoverable, wiping a live run's fixtures is not. The age expiry
        # below is what guarantees we do not stay wedged.
        return True
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
