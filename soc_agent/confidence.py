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
