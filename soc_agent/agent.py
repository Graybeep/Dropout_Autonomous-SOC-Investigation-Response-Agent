"""The agent state machine - CLAUDE.md section 6.

  INGEST_ALERT -> HYPOTHESIZE -> GATHER_EVIDENCE -> DETERMINE_OUTCOME
               -> ACT -> VERIFY -> [event] -> reconsider() -> HYPOTHESIZE -> ...
               -> REPORT

The orchestrator here does exactly three things the model does not: it runs the
deterministic arithmetic of 7.2, it holds the action policy of 7.3 that the
model is told to follow, and it enforces guardrail 6 (a human override is never
re-overridden by an automated action). Every decision about which evidence to
look at, in what order, and what it means is the model's.

reconsider() is ONE function (6.1). The delayed-evidence path, the override path
and the related-case path all call it. There is no separate code path for a
first conclusion versus a revised one.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from typing import Any

from . import config, confidence, llm, prompts, sandbox, schemas, tools as tools_mod
from . import trace as trace_mod
from .toolbus import ToolBus


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


OPEN = "OPEN"
CONCLUDED = "CONCLUDED"
OVERRIDDEN_BENIGN = "OVERRIDDEN_BENIGN"
OVERRIDDEN_MALICIOUS = "OVERRIDDEN_MALICIOUS"


@dataclass
class Conclusion:
    outcome: str
    confidence: float
    score: float
    hypothesis: str
    sufficiency: str
    disconfirming: str
    scoring: dict[str, Any]
    at: str = field(default_factory=_now)
    label: str = "initial"

    def summary(self) -> str:
        return (f"{self.outcome} (score {self.score:.2f}, confidence "
                f"{self.confidence:.2f}) - {self.hypothesis}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label, "outcome": self.outcome,
            "confidence": round(self.confidence, 4), "score": round(self.score, 4),
            "hypothesis": self.hypothesis, "sufficiency": self.sufficiency,
            "disconfirming_evidence_checked": self.disconfirming,
            "scoring": self.scoring, "at": self.at,
        }


@dataclass
class Case:
    case_id: str
    alert_id: str
    asset_id: str
    src_ip: str
    scenario: str
    status: str = OPEN
    conclusions: list[Conclusion] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    verifications: list[dict[str, Any]] = field(default_factory=list)
    reconsiderations: list[dict[str, Any]] = field(default_factory=list)
    overrides: list[dict[str, Any]] = field(default_factory=list)
    degraded_sources: list[str] = field(default_factory=list)
    tools_called: list[str] = field(default_factory=list)

    @property
    def current(self) -> Conclusion | None:
        return self.conclusions[-1] if self.conclusions else None

    @property
    def override_active(self) -> bool:
        return self.status in (OVERRIDDEN_BENIGN, OVERRIDDEN_MALICIOUS)

    def persist(self) -> None:
        """Write the case to the shared store so get_related_alerts can see it."""
        cases = sandbox.read_json(config.CASES)
        cur = self.current
        cases[self.case_id] = {
            "case_id": self.case_id, "alert_id": self.alert_id,
            "asset_id": self.asset_id, "src_ip": self.src_ip,
            "status": self.status,
            "outcome": cur.outcome if cur else None,
            "confidence": round(cur.confidence, 4) if cur else None,
            "summary": cur.summary() if cur else None,
            "concluded_at": cur.at if cur else None,
        }
        sandbox.write_json(config.CASES, cases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id, "alert_id": self.alert_id,
            "asset_id": self.asset_id, "src_ip": self.src_ip,
            "scenario": self.scenario, "status": self.status,
            "conclusions": [c.to_dict() for c in self.conclusions],
            "actions": self.actions, "verifications": self.verifications,
            "reconsiderations": self.reconsiderations, "overrides": self.overrides,
            "degraded_sources": self.degraded_sources,
            "tools_called": self.tools_called,
        }


class Investigation:
    """Owns one case, its trace and its tool bus."""

    def __init__(self, case: Case, tr: trace_mod.Trace,
                 fail_tools: list[str] | None = None) -> None:
        self.case = case
        self.trace = tr
        self.fail_tools = list(fail_tools or [])
        self.bus = self._new_bus()

    def _sync_tools(self) -> None:
        """Record this bus's calls against the case.

        Called from every phase that uses a bus - including the override
        short-circuit, which previously left its unblock_ip call unrecorded.
        """
        for name in self.bus.calls:
            if name not in self.case.tools_called:
                self.case.tools_called.append(name)
        for src in self.bus.degraded_sources:
            if src not in self.case.degraded_sources:
                self.case.degraded_sources.append(src)

    def _new_bus(self) -> ToolBus:
        ctx = {"case_id": self.case.case_id, "alert_id": self.case.alert_id,
               "asset_id": self.case.asset_id, "scenario": self.case.scenario}
        bus = ToolBus(self.trace, ctx, self.fail_tools)
        return bus

    # ------------------------------------------------------------------
    # The tool-use loop. The model picks the calls; we execute and feed back.
    # ------------------------------------------------------------------
    def _loop(self, system: str, messages: list[dict[str, Any]],
              tool_names: list[str], stop_on_assessment: bool,
              max_turns: int | None = None) -> None:
        max_turns = max_turns or config.MAX_TURNS_PER_PHASE
        nudged = False

        for turn in range(max_turns):
            try:
                resp = llm.chat(system, messages, tool_names)
            except llm.LLMError as exc:
                self.trace.add(trace_mod.ERROR, stage="llm", detail=str(exc))
                raise

            if resp.text.strip():
                self.trace.add(trace_mod.SUFFICIENCY if turn else trace_mod.THOUGHT,
                               text=resp.text.strip(), turn=turn + 1)

            if not resp.wants_tools:
                if stop_on_assessment and self.bus.assessment is None and not nudged:
                    nudged = True
                    messages.append(llm.assistant(resp.text))
                    messages.append(llm.user(
                        "You have not submitted an assessment yet. Either call "
                        "another tool if you still need evidence, or call "
                        "submit_assessment now with the factors you have "
                        "established and their citations."))
                    continue
                messages.append(llm.assistant(resp.text))
                return

            messages.append(llm.assistant(resp.text, resp.tool_calls))
            results = []
            for tc in resp.tool_calls:
                result = self.bus.invoke(tc.name, tc.args)
                results.append({"id": tc.id, "name": tc.name,
                                "content": ToolBus.render(result)})
            messages.append(llm.tool_results(results))

            if stop_on_assessment and self.bus.assessment is not None:
                return

    # ------------------------------------------------------------------
    # HYPOTHESIZE + GATHER_EVIDENCE
    # ------------------------------------------------------------------
    def gather(self, opening: str) -> dict[str, Any] | None:
        self.trace.state("HYPOTHESIZE",
                         "Agent forms a hypothesis and decides what to check.")
        self.trace.state("GATHER_EVIDENCE",
                         "Agent chooses tools at runtime; order is not scripted.")
        messages = [llm.user(opening)]
        self._loop(prompts.SYSTEM, messages, schemas.GATHER_TOOLS,
                   stop_on_assessment=True)
        self._sync_tools()
        return self.bus.assessment

    # ------------------------------------------------------------------
    # DETERMINE_OUTCOME - deterministic, section 7.2
    # ------------------------------------------------------------------
    def determine(self, assessment: dict[str, Any] | None,
                  label: str = "initial") -> Conclusion:
        self.trace.state("DETERMINE_OUTCOME",
                         "Confidence computed in Python from declared factors.")
        if assessment is None:
            self.trace.add(
                trace_mod.ERROR, stage="determine",
                detail="Agent produced no assessment; scoring an empty factor set.")
            assessment = {"hypothesis": "(no assessment submitted)", "factors": [],
                          "sufficiency": "(none stated)",
                          "disconfirming_evidence_checked": ""}

        scoring = confidence.score(assessment.get("factors", []),
                                   self.case.degraded_sources)
        self.trace.add(trace_mod.SCORING, **scoring.to_dict())

        c = Conclusion(
            outcome=scoring.outcome, confidence=scoring.confidence,
            score=scoring.score, hypothesis=assessment.get("hypothesis", ""),
            sufficiency=assessment.get("sufficiency", ""),
            disconfirming=assessment.get("disconfirming_evidence_checked", ""),
            scoring=scoring.to_dict(), label=label,
        )
        self.case.conclusions.append(c)
        self.case.status = CONCLUDED
        self.case.persist()
        self.trace.add(trace_mod.CONCLUSION, **c.to_dict())
        return c

    # ------------------------------------------------------------------
    # ACT + VERIFY
    # ------------------------------------------------------------------
    def act_and_verify(self, conclusion: Conclusion) -> None:
        asset = tools_mod.get_asset_info({}, self.case.asset_id)
        criticality = (asset.get("asset", {}) or {}).get("criticality", "unknown")
        policy = confidence.decide_action(conclusion.outcome, conclusion.score,
                                          criticality)

        # Guardrail 6: an override is never re-overridden by an automated action.
        if self.case.override_active and policy["action"] != "none":
            self.trace.add(
                trace_mod.ACTION, skipped=True, policy=policy,
                detail=("Human override is in force on this case. The automated "
                        "action policy would call for "
                        f"{policy['action']}, but guardrail 6 forbids re-triggering "
                        "an opposing automated action without a new explicit "
                        "trigger. No action taken."))
            return

        self.trace.state("ACT", f"Policy: {policy['action']} - {policy['reason']}")
        before = tools_mod.check_firewall_state({}, self.case.src_ip)

        self.bus = self._new_bus()
        opening = (
            f"Case {self.case.case_id}. Alert {self.case.alert_id} from source IP "
            f"{self.case.src_ip} against asset {self.case.asset_id} "
            f"(criticality: {criticality}).\n\n"
            f"Deterministic scoring result:\n"
            f"  outcome    = {conclusion.outcome}\n"
            f"  score      = {conclusion.score:.2f}\n"
            f"  confidence = {conclusion.confidence:.2f}\n"
            f"{conclusion.scoring.get('ceiling_note') or ''}\n\n"
            f"Standing policy for this case: {policy['action']}"
            f"{' with precautionary=true' if policy['precautionary'] else ''}. "
            f"Rationale: {policy['reason']}\n\n"
            f"Carry this out and then verify it from disk."
        )
        self._loop(prompts.ACT_SYSTEM, [llm.user(opening)], schemas.ACT_TOOLS,
                   stop_on_assessment=False, max_turns=6)

        self._sync_tools()

        # VERIFY - independent re-read from disk, regardless of what the agent did.
        self.trace.state("VERIFY", "Re-reading firewall state from disk.")
        after = tools_mod.check_firewall_state({}, self.case.src_ip)
        expected_blocked = policy["action"] == "block_ip"
        verification = {
            "ip": self.case.src_ip,
            "policy_action": policy["action"],
            "precautionary": policy["precautionary"],
            "blocked_before": before["blocked"],
            "blocked_after": after["blocked"],
            "expected_blocked": expected_blocked,
            "matches_policy": after["blocked"] == expected_blocked,
            "record": after["record"],
            "read_from": after["read_from"],
        }
        self.case.verifications.append(verification)
        self.trace.add(trace_mod.VERIFICATION, **verification)

        if after["blocked"] and not before["blocked"]:
            self.case.actions.append(
                {"action": "block_ip", "ip": self.case.src_ip,
                 "precautionary": bool(after["record"].get("precautionary")),
                 "reason": after["record"].get("reason", ""), "at": after["record"].get("blocked_at"),
                 "verified": True})
        elif before["blocked"] and not after["blocked"]:
            self.case.actions.append(
                {"action": "unblock_ip", "ip": self.case.src_ip, "at": _now(),
                 "verified": True})
        elif expected_blocked and after["blocked"] and before["blocked"]:
            # Another case on the same source IP already contained it. The
            # policy outcome holds, so record it rather than reporting "no
            # action taken" while a DROP rule is demonstrably in place.
            self.case.actions.append(
                {"action": "block_ip", "ip": self.case.src_ip,
                 "precautionary": bool((after["record"] or {}).get("precautionary")),
                 "reason": (after["record"] or {}).get("reason", ""),
                 "at": (after["record"] or {}).get("blocked_at"),
                 "verified": True, "status": "already_in_effect",
                 "note": (
                     "This case's policy called for a block and the IP was already "
                     f"blocked under case "
                     f"{(after['record'] or {}).get('case_id')}. No duplicate rule "
                     "was written; containment is in force and was verified.")})

        self.case.persist()


# ==========================================================================
# Entry points
# ==========================================================================
def investigate(case: Case, tr: trace_mod.Trace,
                fail_tools: list[str] | None = None,
                opening: str | None = None) -> Investigation:
    """INGEST_ALERT through VERIFY for a freshly opened case."""
    inv = Investigation(case, tr, fail_tools)
    # Bind the trace to this case, so every step it records is attributed to
    # the case the report and viewer filter on.
    tr.case_id = case.case_id
    tr.state("INGEST_ALERT", f"Case {case.case_id} opened for alert {case.alert_id}.")
    case.persist()
    assessment = inv.gather(opening or prompts.framing(case.alert_id, case.case_id))
    conclusion = inv.determine(assessment, label="initial")
    inv.act_and_verify(conclusion)
    return inv


def reconsider(inv: Investigation, event: dict[str, Any]) -> Conclusion | None:
    """The ONE reconsideration function - CLAUDE.md 6.1.

    Called by the delayed-evidence path, the human-override path and the
    related-case path. Re-enters at HYPOTHESIZE so the agent can form a new
    hypothesis and gather NEW evidence, rather than merely re-scoring what it
    already had. The override branch is the single short-circuit: it skips
    gathering and goes straight to the specified behaviour, then to REPORT.
    """
    case = inv.case
    prior = case.current
    prior_summary = prior.summary() if prior else "(no prior conclusion)"
    kind = event.get("kind", "NEW_EVIDENCE")

    inv.trace.add(trace_mod.EVENT, event_kind=kind, detail=event.get("detail", ""),
                  payload=event.get("payload"))
    inv.trace.add(trace_mod.RECONSIDER, trigger=kind,
                  prior_conclusion=prior.to_dict() if prior else None,
                  detail=event.get("detail", ""))

    # ---- Override short-circuit (Scenario 4, fully specified) -------------
    if kind == "HUMAN_OVERRIDE":
        decision = event["decision"]
        justification = event.get("justification", "")
        inv.trace.state("ACT", f"Human override: {decision}. Guardrail 6 applies.")
        inv.bus = inv._new_bus()

        if decision == "benign":
            result = inv.bus.invoke(
                "unblock_ip",
                {"ip": case.src_ip,
                 "reason": f"Human override (benign): {justification}"})
            case.status = OVERRIDDEN_BENIGN
        elif decision == "malicious":
            result = {"status": "retained",
                      "detail": "Block retained per human override (malicious). "
                                "No firewall change required."}
            inv.trace.add(trace_mod.ACTION, action="retain_block", result=result)
            case.status = OVERRIDDEN_MALICIOUS
        else:
            raise ValueError(f"decision must be 'benign' or 'malicious', got {decision!r}")

        override_record = {
            "decision": decision, "justification": justification, "at": _now(),
            "prior_conclusion": prior.to_dict() if prior else None,
            "resulting_status": case.status,
            "firewall_result": result,
        }
        inv._sync_tools()
        case.overrides.append(override_record)
        case.reconsiderations.append(
            {"trigger": "HUMAN_OVERRIDE", "detail": event.get("detail", ""),
             "prior_conclusion": prior.to_dict() if prior else None,
             "new_conclusion": None,
             "note": ("Prior machine conclusion is preserved and NOT overwritten. "
                      "The case status reflects the human decision."),
             "at": _now()})
        inv.trace.add(trace_mod.ACTION, **override_record)

        inv.trace.state("VERIFY", "Re-reading firewall state from disk after override.")
        after = tools_mod.check_firewall_state({}, case.src_ip)
        verification = {
            "ip": case.src_ip, "policy_action": f"override:{decision}",
            "blocked_after": after["blocked"],
            "expected_blocked": decision == "malicious",
            "matches_policy": after["blocked"] == (decision == "malicious"),
            "record": after["record"], "read_from": after["read_from"],
        }
        case.verifications.append(verification)
        inv.trace.add(trace_mod.VERIFICATION, **verification)
        if decision == "benign":
            case.actions.append({"action": "unblock_ip", "ip": case.src_ip,
                                 "at": _now(), "verified": not after["blocked"],
                                 "reason": f"Human override (benign): {justification}"})
        case.persist()
        return None

    # ---- Everything else re-enters at HYPOTHESIZE (6.1) ------------------
    # The fresh ToolBus is load-bearing, not bookkeeping. Its `ok_tools` starts
    # empty, so the factor preconditions force the agent to RE-CALL every
    # source before it may declare any finding on it - it cannot carry a stale
    # "logs were clean" reading across the reconsideration boundary. This, not
    # the logs_clean window guard, is what makes 6.1's "gather, don't re-score"
    # structural rather than merely requested in the prompt.
    inv.bus = inv._new_bus()
    opening = prompts.reconsider_framing(
        case.case_id, kind, event.get("detail", ""), prior_summary)
    case.status = OPEN
    assessment = inv.gather(opening)
    new_conclusion = inv.determine(assessment, label=f"after {kind}")

    case.reconsiderations.append(
        {"trigger": kind, "detail": event.get("detail", ""),
         "prior_conclusion": prior.to_dict() if prior else None,
         "new_conclusion": new_conclusion.to_dict(),
         "changed": bool(prior and prior.outcome != new_conclusion.outcome),
         "at": _now()})

    inv.act_and_verify(new_conclusion)
    return new_conclusion
