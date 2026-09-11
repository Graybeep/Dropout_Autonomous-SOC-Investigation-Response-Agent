"""Demo / control-plane tools - CLAUDE.md section 8.

These are the operator's, NOT the agent's. They are never exposed as tool
schemas. They simulate the outside world changing underneath an open case:
late-arriving log evidence, a second alert, a human analyst disagreeing.

Each returns an event dict suitable for handing to agent.reconsider().
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from . import config, sandbox

reset_sandbox = sandbox.reset_sandbox


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inject_new_evidence(case_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Append log entries to an asset's server logs at runtime.

    evidence = {"asset_id": ..., "entries": [ {ts, source, event_type, raw}, ... ],
                "detail": "what the operator is telling the agent arrived"}
    """
    asset_id = evidence["asset_id"]
    entries = evidence["entries"]
    logs = sandbox.read_json(config.SERVER_LOGS)
    bucket = logs.setdefault(asset_id, [])
    for entry in entries:
        bucket.append({**entry, "injected": True})
    bucket.sort(key=lambda e: e.get("ts", ""))
    sandbox.write_json(config.SERVER_LOGS, logs)

    return {
        "kind": "NEW_EVIDENCE",
        "case_id": case_id,
        "at": _now(),
        "detail": evidence.get(
            "detail",
            f"{len(entries)} new log entries landed for asset {asset_id}."),
        "payload": {"asset_id": asset_id, "entries": entries},
    }


def inject_alert(alert: dict[str, Any],
                 extra_server_logs: dict[str, Any] | None = None) -> dict[str, Any]:
    """Introduce a new alert into the sandbox. Opens its own case (section 2.5).

    extra_server_logs = {"asset_id": ..., "entries": [...]} lets a later alert
    bring the host-side activity that accompanied it, so an earlier case cannot
    see evidence that had not happened yet.
    """
    alerts = sandbox.read_json(config.ALERTS)
    alerts[alert["id"]] = alert
    sandbox.write_json(config.ALERTS, alerts)

    if extra_server_logs:
        logs = sandbox.read_json(config.SERVER_LOGS)
        bucket = logs.setdefault(extra_server_logs["asset_id"], [])
        for entry in extra_server_logs["entries"]:
            bucket.append({**entry, "injected": True})
        bucket.sort(key=lambda e: e.get("ts", ""))
        sandbox.write_json(config.SERVER_LOGS, logs)

    return {
        "kind": "NEW_ALERT",
        "at": _now(),
        "alert_id": alert["id"],
        "detail": f"New alert {alert['id']} raised on asset {alert['asset_id']}.",
        "payload": alert,
    }


def human_override(case_id: str, decision: str,
                   justification: str) -> dict[str, Any]:
    """A human analyst overrides the agent. decision in {benign, malicious}."""
    if decision not in ("benign", "malicious"):
        raise ValueError(
            f"decision must be 'benign' or 'malicious', got {decision!r}")
    return {
        "kind": "HUMAN_OVERRIDE",
        "case_id": case_id,
        "decision": decision,
        "justification": justification,
        "at": _now(),
        "detail": (f"Human analyst marked this case '{decision}'. "
                   f"Justification: {justification}"),
    }


def related_case_event(case_id: str, other_case_id: str,
                       detail: str) -> dict[str, Any]:
    """A conclusion reached on another case bears on this one (Scenario 5)."""
    return {
        "kind": "RELATED_CASE",
        "case_id": case_id,
        "other_case_id": other_case_id,
        "at": _now(),
        "detail": detail,
    }
