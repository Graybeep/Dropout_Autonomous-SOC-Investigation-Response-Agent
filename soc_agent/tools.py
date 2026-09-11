"""Agent-facing tool implementations - CLAUDE.md section 8.

Every function here is pure with respect to its JSON files: explicit read/write
against fixtures/run, no hidden module state. The per-case context (case_id,
scenario) is passed in explicitly by the tool bus rather than stashed globally.

Two rules these implementations exist to enforce:

  * A lookup that misses returns {"status": "no_data"} with an explanation.
    It never returns null, {} or a fabricated plausible answer (guardrail 3).
  * get_vulnerabilities returns affected ranges and does NOT resolve patch
    status. Deciding whether a running version falls in range is the agent's
    job and must be visible in the trace (section 5.1).
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from . import config, sandbox


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _no_data(what: str, hint: str = "") -> dict[str, Any]:
    out = {"status": "no_data", "detail": f"No record found for {what}."}
    if hint:
        out["hint"] = hint
    return out


# --------------------------------------------------------------------------
# Evidence retrieval
# --------------------------------------------------------------------------
def get_alert(ctx: dict, alert_id: str) -> dict[str, Any]:
    alerts = sandbox.read_json(config.ALERTS)
    rec = alerts.get(alert_id)
    if not rec:
        known = [k for k in alerts if not k.startswith("_")]
        return _no_data(f"alert '{alert_id}'", f"Known alert ids: {', '.join(known)}")
    return {"status": "ok", "alert": rec}


def get_packet_metadata(ctx: dict, alert_id: str) -> dict[str, Any]:
    logs = sandbox.read_json(config.PACKET_LOGS)
    rec = logs.get(alert_id)
    if not rec:
        return _no_data(
            f"packet metadata for alert '{alert_id}'",
            "The sensor may not have retained flow data for this alert.",
        )
    return {"status": "ok", "packet_metadata": rec}


def get_asset_info(ctx: dict, asset_id: str) -> dict[str, Any]:
    inv = sandbox.read_json(config.ASSET_INVENTORY)
    rec = inv.get(asset_id)
    if not rec:
        known = [k for k in inv if not k.startswith("_")]
        return _no_data(f"asset '{asset_id}'", f"Known asset ids: {', '.join(known)}")
    return {"status": "ok", "asset": rec}


def get_vulnerabilities(ctx: dict, service_name: str) -> dict[str, Any]:
    """Return CVE entries for a service. Does NOT resolve patch status."""
    kb = sandbox.read_json(config.CVE_KB)
    entries = kb.get(service_name.lower())
    if not entries:
        known = [k for k in kb if not k.startswith("_")]
        return _no_data(
            f"service '{service_name}' in the CVE knowledge base",
            f"Services present in the KB: {', '.join(known)}",
        )
    return {
        "status": "ok",
        "service": service_name.lower(),
        "cves": entries,
        "note": (
            "This knowledge base does not know which version any host is running. "
            "To decide whether a host is affected, compare that host's running "
            "version (from get_asset_info) against affected_versions above."
        ),
    }


def get_server_logs(
    ctx: dict, asset_id: str, time_range: str | None = None
) -> dict[str, Any]:
    logs = sandbox.read_json(config.SERVER_LOGS)
    entries = logs.get(asset_id)
    if entries is None:
        known = [k for k in logs if not k.startswith("_")]
        return _no_data(
            f"server logs for asset '{asset_id}'",
            f"Assets with log data: {', '.join(known)}",
        )
    selected = entries
    if time_range and "/" in time_range:
        start, end = (s.strip() for s in time_range.split("/", 1))
        selected = [e for e in entries if start <= e.get("ts", "") <= end]
    if not selected:
        return {
            "status": "no_data",
            "detail": (
                f"Asset '{asset_id}' has log data, but no entries fall inside "
                f"time_range '{time_range}'."
            ),
            "available_window": f"{entries[0]['ts']}/{entries[-1]['ts']}",
        }
    return {
        "status": "ok",
        "asset_id": asset_id,
        "time_range": time_range or "all",
        "entry_count": len(selected),
        "entries": selected,
    }


def get_related_alerts(ctx: dict, asset_id: str) -> dict[str, Any]:
    """Other alerts on this asset, plus their case ids and stored conclusions.

    Scenario 5 depends on the stored conclusion being returned here.
    """
    alerts = sandbox.read_json(config.ALERTS)
    cases = sandbox.read_json(config.CASES)
    this_case = ctx.get("case_id")

    related = []
    for aid, alert in alerts.items():
        if aid.startswith("_") or alert.get("asset_id") != asset_id:
            continue
        if aid == ctx.get("alert_id"):
            continue
        entry = {"alert": alert, "case_id": None, "stored_conclusion": None}
        for cid, case in cases.items():
            if cid == this_case or case.get("alert_id") != aid:
                continue
            entry["case_id"] = cid
            entry["stored_conclusion"] = {
                "status": case.get("status"),
                "outcome": case.get("outcome"),
                "confidence": case.get("confidence"),
                "summary": case.get("summary"),
                "concluded_at": case.get("concluded_at"),
            }
        related.append(entry)

    if not related:
        return {
            "status": "no_data",
            "detail": f"No other alerts recorded against asset '{asset_id}'.",
            "asset_id": asset_id,
        }
    return {"status": "ok", "asset_id": asset_id, "related_count": len(related),
            "related_alerts": related}


# --------------------------------------------------------------------------
# Firewall - the mutation and its verification both hit the same file
# --------------------------------------------------------------------------
def check_firewall_state(ctx: dict, ip: str) -> dict[str, Any]:
    state = sandbox.read_json(config.FIREWALL_STATE)
    blocked = state.get("blocked_ips", {})
    rec = blocked.get(ip)
    return {
        "status": "ok",
        "ip": ip,
        "blocked": rec is not None,
        "record": rec,
        "total_blocked": len(blocked),
        "read_from": str((config.RUN_DIR / config.FIREWALL_STATE).as_posix()),
    }


def block_ip(
    ctx: dict, ip: str, reason: str, precautionary: bool = False
) -> dict[str, Any]:
    state = sandbox.read_json(config.FIREWALL_STATE)
    blocked = state.setdefault("blocked_ips", {})
    if ip in blocked:
        return {
            "status": "already_blocked",
            "ip": ip,
            "record": blocked[ip],
            "detail": "No change made; this IP was already blocked.",
        }
    record = {
        "ip": ip,
        "reason": reason,
        "precautionary": bool(precautionary),
        "blocked_at": _now(),
        "case_id": ctx.get("case_id"),
        "rule": f"DROP all from {ip}",
    }
    blocked[ip] = record
    state.setdefault("audit_log", []).append(
        {"action": "block_ip", "ip": ip, "at": record["blocked_at"],
         "case_id": ctx.get("case_id"), "precautionary": bool(precautionary),
         "reason": reason}
    )
    sandbox.write_json(config.FIREWALL_STATE, state)
    return {"status": "ok", "action": "block_ip", "ip": ip, "record": record,
            "detail": "Firewall state written to disk. Verify with check_firewall_state."}


def unblock_ip(ctx: dict, ip: str, reason: str) -> dict[str, Any]:
    state = sandbox.read_json(config.FIREWALL_STATE)
    blocked = state.setdefault("blocked_ips", {})
    if ip not in blocked:
        return {
            "status": "not_blocked",
            "ip": ip,
            "detail": "No change made; this IP was not blocked.",
        }
    removed = blocked.pop(ip)
    state.setdefault("audit_log", []).append(
        {"action": "unblock_ip", "ip": ip, "at": _now(),
         "case_id": ctx.get("case_id"), "reason": reason, "removed_record": removed}
    )
    sandbox.write_json(config.FIREWALL_STATE, state)
    return {"status": "ok", "action": "unblock_ip", "ip": ip, "removed": removed,
            "detail": "Firewall state written to disk. Verify with check_firewall_state."}


# --------------------------------------------------------------------------
# Assessment submission - how the agent hands its findings to section 7.2
# --------------------------------------------------------------------------
def submit_assessment(
    ctx: dict,
    hypothesis: str,
    factors: list[dict[str, Any]],
    sufficiency: str,
    disconfirming_evidence_checked: str = "",
) -> dict[str, Any]:
    """Validated here; the actual scoring is done by the orchestrator."""
    from . import confidence

    problems = confidence.validate([f.get("factor", "") for f in factors])
    for item in factors:
        if not item.get("citation"):
            problems.append(
                f"factor '{item.get('factor')}' has no citation. Every factor must "
                "cite the specific tool result that supports it."
            )
    if problems:
        return {"status": "rejected", "problems": problems,
                "detail": "Assessment not accepted. Fix these and resubmit."}
    return {"status": "accepted", "hypothesis": hypothesis, "factors": factors,
            "sufficiency": sufficiency,
            "disconfirming_evidence_checked": disconfirming_evidence_checked}


IMPLEMENTATIONS = {
    "get_alert": get_alert,
    "get_packet_metadata": get_packet_metadata,
    "get_asset_info": get_asset_info,
    "get_vulnerabilities": get_vulnerabilities,
    "get_server_logs": get_server_logs,
    "get_related_alerts": get_related_alerts,
    "check_firewall_state": check_firewall_state,
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "submit_assessment": submit_assessment,
}
