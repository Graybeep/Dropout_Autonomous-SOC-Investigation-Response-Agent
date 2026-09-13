"""Deterministic confidence scoring - CLAUDE.md section 7.2.

Confidence is computed here, in Python, from the evidence classes the agent
declared. The agent decides what evidence exists and what it means; this module
only does the arithmetic, so a demo run is reproducible and "where did 0.85 come
from" has a one-line answer.

DO NOT retune these numbers. CLAUDE.md section 14: they are calibrated so that
all six scenarios land on their expected outcome, and changing one silently
breaks another scenario.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

BASE = 0.50

# factor name -> (delta, human-readable label)
FACTORS: dict[str, tuple[float, str]] = {
    "version_in_range": (+0.25, "Running version falls inside a CVE's affected range"),
    "logs_consistent": (+0.25, "Server logs show activity consistent with the signature"),
    "exfil_indicators": (+0.15, "Packet metadata shows exfil / payload-anomaly indicators"),
    "related_alert_corroborates": (+0.15, "A related alert on the same asset corroborates"),
    "version_patched": (-0.30, "Running version outside all affected ranges (patched)"),
    "logs_clean": (-0.25, "Server logs clean across the relevant window"),
    "packet_benign": (-0.10, "Packet metadata benign"),
}

# A finding and its negation cannot both hold.
CONTRADICTIONS = [
    ("version_in_range", "version_patched"),
    ("logs_consistent", "logs_clean"),
    ("exfil_indicators", "packet_benign"),
]

# A factor may only be declared if the source that could establish it was
# actually read successfully. This is guardrail 3 (never fabricate evidence)
# enforced structurally: it does not judge what the evidence MEANS - that stays
# the agent's call - it only refuses a finding drawn from a source the agent
# never successfully read. Added after a run in which the agent declared
# `related_alert_corroborates` while citing "no other alerts recorded".
FACTOR_PRECONDITIONS: dict[str, list[str]] = {
    "version_in_range": ["get_asset_info", "get_vulnerabilities"],
    "version_patched": ["get_asset_info", "get_vulnerabilities"],
    "logs_consistent": ["get_server_logs"],
    "logs_clean": ["get_server_logs"],
    "exfil_indicators": ["get_packet_metadata"],
    "packet_benign": ["get_packet_metadata"],
    "related_alert_corroborates": ["get_related_alerts"],
}

CLAMP = (0.05, 0.95)
DEGRADED_CLAMP = (0.35, 0.65)

SUCCEEDED = "SUCCEEDED"
FAILED = "FAILED"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class Scoring:
    raw: float
    score: float
    outcome: str
    confidence: float
    applied: list[dict[str, Any]] = field(default_factory=list)
    ignored: list[dict[str, Any]] = field(default_factory=list)
    degraded: bool = False
    degraded_sources: list[str] = field(default_factory=list)
    ceiling_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": BASE,
            "raw_sum": round(self.raw, 4),
            "score": round(self.score, 4),
            "outcome": self.outcome,
            "confidence": round(self.confidence, 4),
            "applied_factors": self.applied,
            "ignored_factors": self.ignored,
            "degraded": self.degraded,
            "degraded_sources": self.degraded_sources,
            "ceiling_note": self.ceiling_note,
        }


def validate(factor_names: list[str]) -> list[str]:
    """Return a list of human-readable problems with a declared factor set."""
    problems: list[str] = []
    for name in factor_names:
        if name not in FACTORS:
            problems.append(
                f"unknown factor '{name}'. Valid factors: {', '.join(FACTORS)}"
            )
    for a, b in CONTRADICTIONS:
        if a in factor_names and b in factor_names:
            problems.append(
                f"contradictory factors '{a}' and '{b}' were both declared; "
                "the evidence cannot support both at once."
            )
    return problems


def check_preconditions(factor_names: list[str],
                        ok_tools: set[str] | list[str]) -> list[str]:
    """Refuse factors drawn from a source that was never read successfully."""
    ok = set(ok_tools)
    problems: list[str] = []
    for name in factor_names:
        needed = FACTOR_PRECONDITIONS.get(name, [])
        missing = [t for t in needed if t not in ok]
        if missing:
            problems.append(
                f"factor '{name}' cannot be declared: it requires a successful "
                f"result from {' and '.join(missing)}, which you have not "
                f"obtained. Either call it and read the result, or drop this "
                f"factor. A source that returned no_data or failed does not "
                f"establish a finding."
            )
    return problems


def check_version_patched_coverage(
    asset_services: dict[str, list[str]],
    services_checked: set[str] | list[str],
    kb_services: set[str] | list[str],
) -> list[str]:
    """`version_patched` is a UNIVERSAL claim; it needs universal coverage.

    "Running version outside ALL affected ranges" cannot be asserted from one
    service when the host runs several that the CVE KB covers. `version_in_range`
    is existential - a single CVE in range establishes it - so it is NOT subject
    to this check.

    Added after a live run where the agent checked only tomcat 9.0.50 (correctly
    outside its CVE), declared the host patched, and never compared the same
    host's mysql 5.7.28 against CVE-2023-21980 - the SQL-injection CVE matching
    the alert that opened the case.
    """
    checked = {s.lower() for s in services_checked}
    kb = {s.lower() for s in kb_services}
    problems: list[str] = []
    for asset_id, services in asset_services.items():
        covered = {s.lower() for s in services} & kb
        missing = sorted(covered - checked)
        if missing:
            problems.append(
                f"factor 'version_patched' claims {asset_id} is outside ALL "
                f"affected ranges, but you have not looked up "
                f"{', '.join(missing)} - service(s) this host runs that the CVE "
                f"knowledge base covers. Call get_vulnerabilities for each of "
                f"them and compare the running version before claiming the host "
                f"is patched."
            )
    return problems


def check_sibling_verdict_conflict(
    declared: list[str],
    related_alerts: list[dict[str, Any]],
    covered,
) -> list[str]:
    """A FOURTH guard family - and the first whose input is an agent conclusion.

    The other three compare a declared factor against BOOKKEEPING: which tools
    returned ok, which services were looked up, which windows were queried.
    This one compares it against a SIBLING CASE'S VERDICT, which the agent
    itself produced earlier. That difference has three consequences worth
    stating rather than discovering:

      order-dependent   It fires only if the sibling concluded first. Run the
                        same two cases in the opposite order and it is silent.
      error-propagating A sibling that wrongly concluded SUCCEEDED constrains
                        this case. The guard inherits the earlier case's
                        mistake instead of catching it.
      SUCCEEDED only    A sibling at INCONCLUSIVE does NOT fire it - including
                        an INCONCLUSIVE that triggered a precautionary block.
                        Containment under uncertainty is explicitly not a
                        finding that the asset was breached (section 7.3), so
                        it cannot contradict "logs clean". Verified: SUCCEEDED
                        fires, INCONCLUSIVE / FAILED / unconcluded do not.
    """
    problems: list[str] = []
    for rel in related_alerts:
        rts, outcome = rel.get("timestamp"), rel.get("outcome")
        if outcome == SUCCEEDED and rts and covered(rts):
            problems.append(
                f"factor 'logs_clean' cannot stand: case {rel.get('case_id')} "
                f"has already concluded {outcome} for alert {rel.get('id')} "
                f"at {rts} on this same asset, and the window you read covers "
                f"that time. 'No successful attacker activity' contradicts a "
                f"stored verdict you retrieved yourself. Either declare "
                f"logs_consistent, or drop the log factor - you cannot call "
                f"the asset clean over a period another case found it breached."
            )
    return problems


def check_negative_scope(
    declared: list[str],
    case_alert_id: str,
    packet_alerts: set[str] | list[str],
    log_windows: list[str | None],
    alert_ts: str | None,
    related_alerts: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Scope guards for the remaining universal / provenance claims.

    Section 7.2's three positive factors are EXISTENTIAL - one witness settles
    them. All three negatives are UNIVERSAL: "I looked and found nothing" is
    meaningless without a stated scope. `version_patched` is handled by
    check_version_patched_coverage; this covers the other two.

      logs_clean     asserts nothing happened across the relevant window, so
                     the window actually queried must contain the alert. A
                     query with no time_range reads everything and qualifies.
      packet_benign  and its positive twin are about THIS case's flow, so the
                     agent must have READ this case's own alert's packet record
                     before characterising the traffic.

    KNOWN GAP, stated precisely because the earlier wording overstated it: this
    checks that the case's own packet record was READ, not that the citation
    TEXT names it. An agent that reads its own flow and then cites a sibling's
    numbers passes - which is exactly what scenario 5 case A does. Closing it
    would mean parsing the citation prose, i.e. judging content, which is the
    one thing these guards refuse to do. See Toknow K-7.
    """
    problems: list[str] = []
    related_alerts = list(related_alerts or [])

    if "packet_benign" in declared or "exfil_indicators" in declared:
        seen = set(packet_alerts)
        if case_alert_id and case_alert_id not in seen:
            which = "packet_benign" if "packet_benign" in declared else "exfil_indicators"
            got = ", ".join(sorted(seen)) or "none"
            problems.append(
                f"factor '{which}' describes the flow for this case's alert "
                f"{case_alert_id}, but you have not read its packet metadata "
                f"(you read: {got}). Call get_packet_metadata('{case_alert_id}') "
                f"before characterising this case's traffic."
            )

    if "logs_clean" in declared and alert_ts:
        def _covered(ts: str) -> bool:
            for w in log_windows:
                if w is None:            # no time_range -> whole log
                    return True
                if "/" not in w:
                    continue
                start, end = (x.strip() for x in w.split("/", 1))
                if start <= ts <= end:
                    return True
            return False

        shown = ", ".join(w or "(whole log)" for w in log_windows) or "none"

        if not _covered(alert_ts):
            problems.append(
                f"factor 'logs_clean' asserts the logs are clean across the "
                f"relevant window, but no log query you made covers the alert "
                f"timestamp {alert_ts} (windows queried: {shown}). Re-query "
                f"get_server_logs over a window that contains the alert, or omit "
                f"time_range to read the whole log, before claiming it is clean."
            )

        # (a) Once related alerts are known, "the relevant window" is no longer
        # this alert's window alone - the asset's story spans its siblings too.
        for rel in related_alerts:
            rts = rel.get("timestamp")
            if rts and not _covered(rts):
                problems.append(
                    f"factor 'logs_clean' asserts this asset's logs are clean, "
                    f"but get_related_alerts told you about {rel.get('id')} at "
                    f"{rts} on the same asset, and no log query you made covers "
                    f"that time (windows queried: {shown}). Widen the window to "
                    f"span the related alert, or omit time_range, before calling "
                    f"the asset clean."
                )

        problems += check_sibling_verdict_conflict(
            declared, related_alerts, _covered)

    return problems


def score(
    factors: list[dict[str, Any]],
    degraded_sources: list[str] | None = None,
) -> Scoring:
    """Apply section 7.2 to the agent's declared evidence findings.

    `factors` is a list of {"factor": name, "citation": str, "rationale": str}.
    Each distinct factor is applied at most once; repeats are recorded in
    `ignored` so the trace shows they were seen and deliberately not counted.
    """
    degraded_sources = list(degraded_sources or [])
    applied: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = BASE

    for item in factors:
        name = item.get("factor", "")
        if name not in FACTORS:
            ignored.append({**item, "reason": f"unknown factor '{name}'"})
            continue
        if name in seen:
            ignored.append({**item, "reason": "factor already applied once"})
            continue
        delta, label = FACTORS[name]
        seen.add(name)
        total += delta
        applied.append(
            {
                "factor": name,
                "label": label,
                "delta": delta,
                "citation": item.get("citation", ""),
                "rationale": item.get("rationale", ""),
            }
        )

    raw = total
    s = max(CLAMP[0], min(CLAMP[1], raw))

    degraded = bool(degraded_sources)
    ceiling_note = ""
    if degraded:
        before = s
        s = max(DEGRADED_CLAMP[0], min(DEGRADED_CLAMP[1], s))
        ceiling_note = (
            f"Degraded-evidence clamp applied: {', '.join(degraded_sources)} returned "
            f"unavailable/failed, so confidence is restricted to "
            f"[{DEGRADED_CLAMP[0]}, {DEGRADED_CLAMP[1]}]. Unclamped score was "
            f"{before:.2f}; reported score is {s:.2f}. The missing source, not the "
            f"evidence that was gathered, is what caps this conclusion."
        )

    if s >= 0.75:
        outcome, conf = SUCCEEDED, s
    elif s <= 0.25:
        outcome, conf = FAILED, 1.0 - s
    else:
        outcome, conf = INCONCLUSIVE, s

    return Scoring(
        raw=raw,
        score=s,
        outcome=outcome,
        confidence=conf,
        applied=applied,
        ignored=ignored,
        degraded=degraded,
        degraded_sources=degraded_sources,
        ceiling_note=ceiling_note,
    )


def decide_action(outcome: str, s: float, criticality: str) -> dict[str, Any]:
    """CLAUDE.md section 7.3 action policy.

    Returns the policy's expectation. The agent is told this and is the one that
    actually calls block_ip/unblock_ip - this is the rule it is held to, not a
    substitute for it acting.
    """
    if outcome == SUCCEEDED and s >= 0.75:
        return {
            "action": "block_ip",
            "precautionary": False,
            "reason": "Outcome SUCCEEDED with score >= 0.75.",
        }
    if outcome == INCONCLUSIVE and criticality == "critical":
        return {
            "action": "block_ip",
            "precautionary": True,
            "reason": (
                "Outcome INCONCLUSIVE on a critical asset. Containment under "
                "uncertainty, not a verdict that the attack succeeded."
            ),
        }
    if outcome == INCONCLUSIVE:
        return {
            "action": "none",
            "precautionary": False,
            "reason": (
                f"Outcome INCONCLUSIVE on a {criticality} (non-critical) asset. "
                "No automated action; flagged for analyst review."
            ),
        }
    return {
        "action": "none",
        "precautionary": False,
        "reason": f"Outcome {outcome} does not justify an action.",
    }
