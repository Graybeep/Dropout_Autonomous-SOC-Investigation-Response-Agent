"""The single wrapper every agent-facing tool call goes through - CLAUDE.md 8.

Responsibilities:
  (a) log the call and its result to the trace,
  (b) honour the scenario's fail_tools list (fault injection for Scenario 6),
  (c) make sure a miss surfaces as an explicit no_data, never as null.

It also records which sources came back failed/unavailable, because that set is
what triggers the degraded-evidence clamp in section 7.2.
"""
from __future__ import annotations

import inspect
import json
import re
import traceback
from typing import Any

from . import tools, trace as trace_mod


class ToolBus:
    def __init__(self, tr: trace_mod.Trace, ctx: dict[str, Any],
                 fail_tools: list[str] | None = None) -> None:
        self.trace = tr
        self.ctx = ctx
        self.fail_tools = list(fail_tools or [])
        self.calls: list[str] = []
        self.degraded_sources: list[str] = []
        self.attempts: dict[str, int] = {}
        self.assessment: dict[str, Any] | None = None
        self.impasse: dict[str, Any] | None = None
        # Tools that returned a usable result. Used to enforce factor
        # preconditions when the agent submits its assessment.
        self.ok_tools: set[str] = set()
        # Tracked so a universal claim (version_patched) can be checked for
        # universal coverage. See confidence.check_version_patched_coverage.
        self.asset_services: dict[str, list[str]] = {}
        self.services_checked: set[str] = set()
        # Scope tracking for the universal/provenance guards on the negatives.
        self.packet_alerts: set[str] = set()
        # Surfaces get_configuration returned per asset, so the universal
        # claim config_prevents_exploitation can be checked for universal
        # coverage. See confidence.check_config_surface_coverage.
        self.config_surfaces: dict[str, list[str]] = {}
        self.log_windows: list[str | None] = []
        # Related alerts this case has actually been told about, with their
        # timestamps and any stored verdict. Once these are known, "the
        # relevant window" for logs_clean is no longer this alert's alone.
        self.related_alerts: list[dict[str, Any]] = []
        self.rejections = 0

    # -- introspection used by the harness and the report -------------------
    def called(self, name: str) -> bool:
        return name in self.calls

    def call_counts(self) -> dict[str, int]:
        return dict(self.attempts)

    # -- the one entry point ------------------------------------------------
    def invoke(self, name: str, args: dict[str, Any], reason: str = "") -> dict[str, Any]:
        # 'reason' is a schema-level parameter on every evidence tool so the
        # trace always carries a stated justification. For most tools it is
        # narration only and must be stripped before dispatch - but block_ip
        # and unblock_ip genuinely take a `reason` argument (it is persisted
        # in firewall state), so for those it is passed through.
        args = dict(args)
        impl_for_sig = tools.IMPLEMENTATIONS.get(name)
        takes_reason = bool(impl_for_sig) and "reason" in inspect.signature(
            impl_for_sig).parameters
        reason = (args["reason"] if takes_reason else args.pop("reason", "")) or reason
        self.attempts[name] = self.attempts.get(name, 0) + 1
        attempt = self.attempts[name]
        self.calls.append(name)
        self.trace.add(
            trace_mod.TOOL_CALL,
            tool=name,
            args=args,
            attempt=attempt,
            reason=reason or "(no stated reason)",
        )

        # Guardrail 3, structurally: a factor may not be declared from a
        # source that was never successfully read.
        if name == "submit_assessment":
            from . import config, confidence
            declared = [f.get("factor", "") for f in args.get("factors", [])]
            problems = confidence.check_preconditions(declared, self.ok_tools)
            from . import config, sandbox
            if "version_patched" in declared:
                kb = [k for k in sandbox.read_json(config.CVE_KB)
                      if not k.startswith("_")]
                problems += confidence.check_version_patched_coverage(
                    self.asset_services, self.services_checked, kb)
            if "config_prevents_exploitation" in declared:
                aid = self.ctx.get("asset_id", "")
                accounted: set[str] = set()
                for f in args.get("factors", []):
                    if f.get("factor") == "config_prevents_exploitation":
                        accounted |= {str(x) for x in (f.get("surfaces_accounted") or [])}
                problems += confidence.check_config_surface_coverage(
                    aid, self.config_surfaces.get(aid, []), accounted)
            case_alert = self.ctx.get("alert_id", "")
            alert_rec = sandbox.read_json(config.ALERTS).get(case_alert) or {}
            problems += confidence.check_negative_scope(
                declared, case_alert, self.packet_alerts, self.log_windows,
                alert_rec.get("timestamp"), self.related_alerts)
            if problems:
                self.rejections += 1
                if self.rejections <= config.MAX_ASSESSMENT_REJECTIONS:
                    result = {
                        "status": "rejected", "problems": problems,
                        "attempt": self.rejections,
                        "remaining_attempts":
                            config.MAX_ASSESSMENT_REJECTIONS - self.rejections,
                        "detail": "Assessment not accepted. Fix these and resubmit.",
                    }
                    self.trace.add(trace_mod.TOOL_RESULT, tool=name,
                                   status="rejected", result=result)
                    return result

                # Impasse. Stop arguing: drop every factor the guards named,
                # accept what survives, and put the unresolved objections on the
                # record. Looping further would only grow the conversation.
                named = set()
                for prob in problems:
                    named.update(re.findall(r"factor '([a-z_]+)'", prob))
                kept = [f for f in args.get("factors", [])
                        if f.get("factor") not in named]
                args = {**args, "factors": kept}
                self.impasse = {
                    "after_attempts": self.rejections,
                    "dropped_factors": sorted(named),
                    "unresolved": problems,
                }
                self.trace.add(
                    trace_mod.ERROR, tool=name, status="impasse",
                    detail=(f"Assessment refused {self.rejections} times. Dropping "
                            f"{', '.join(sorted(named)) or 'no'} factor(s) the guards "
                            f"rejected and scoring what remains; the objections are "
                            f"recorded rather than argued further."),
                    result=self.impasse)

                # Terminal by construction. Accepting here - rather than
                # re-dispatching - is deliberate: submit_assessment refuses an
                # empty factor list, so if the guards rejected everything the
                # agent declared, re-dispatching would refuse again and the loop
                # would run to the turn cap. An impasse scores what survives
                # (possibly nothing, i.e. the 0.50 base -> INCONCLUSIVE), which
                # is the honest outcome when nothing the agent claimed can stand.
                result = {
                    "status": "accepted",
                    "hypothesis": args.get("hypothesis", ""),
                    "factors": kept,
                    "sufficiency": args.get("sufficiency", ""),
                    "disconfirming_evidence_checked":
                        args.get("disconfirming_evidence_checked", ""),
                    "impasse": self.impasse,
                }
                self.assessment = result
                self.trace.add(trace_mod.TOOL_RESULT, tool=name,
                               status="accepted", result=result)
                return result

        # The model occasionally emits tool arguments that are not valid JSON;
        # llm.py preserves the raw text under __unparsed__ rather than guessing.
        if "__unparsed__" in args:
            result = {
                "status": "error",
                "detail": (
                    f"The arguments you sent for '{name}' were not valid JSON and "
                    "could not be read."
                ),
                "hint": "Re-send this tool call with well-formed JSON arguments.",
            }
            self.trace.add(trace_mod.ERROR, tool=name, args=args, result=result)
            return result

        impl = tools.IMPLEMENTATIONS.get(name)
        if impl is None:
            result = {
                "status": "error",
                "detail": f"No such tool '{name}'. Available: "
                          f"{', '.join(tools.IMPLEMENTATIONS)}",
            }
            self.trace.add(trace_mod.ERROR, tool=name, result=result)
            return result

        # (b) fault injection - scenario-configured, not a general framework.
        if name in self.fail_tools:
            result = {
                "status": "unavailable",
                "reason": "log collector timeout",
                "detail": (
                    f"'{name}' did not return data (attempt {attempt}). This is a "
                    "TOOL FAILURE, not a finding. It is not evidence that nothing "
                    "happened on this host."
                ),
                "attempt": attempt,
            }
            if name not in self.degraded_sources:
                self.degraded_sources.append(name)
            self.trace.add(
                trace_mod.TOOL_FAILURE, tool=name, args=args,
                attempt=attempt, result=result,
            )
            return result

        try:
            result = impl(self.ctx, **args)
        except TypeError as exc:
            # Tell the model the parameter names it may use. Without this it
            # tends to DELETE a misspelled field rather than correct it.
            accepted = [p for p in inspect.signature(impl).parameters
                        if p != "ctx"]
            result = {
                "status": "error",
                "detail": f"Bad arguments for '{name}': {exc}",
                "accepted_parameters": accepted,
                "you_sent": sorted(args),
                "hint": (
                    f"Re-send the call using exactly these parameter names: "
                    f"{', '.join(accepted)}. Correct any misspelling rather than "
                    f"dropping the field."
                ),
            }
            self.trace.add(trace_mod.ERROR, tool=name, args=args, result=result)
            return result
        except Exception as exc:  # noqa: BLE001 - surface, never swallow
            result = {
                "status": "unavailable",
                "reason": f"{type(exc).__name__}: {exc}",
                "detail": "Unexpected tool failure.",
                "traceback": traceback.format_exc(limit=3),
            }
            if name not in self.degraded_sources:
                self.degraded_sources.append(name)
            self.trace.add(trace_mod.TOOL_FAILURE, tool=name, args=args,
                           attempt=attempt, result=result)
            return result

        if result.get("status") == "unavailable" and name not in self.degraded_sources:
            self.degraded_sources.append(name)

        if result.get("status") == "ok":
            self.ok_tools.add(name)
            if name == "get_asset_info":
                a = result.get("asset", {})
                if a.get("asset_id"):
                    self.asset_services[a["asset_id"]] = list(
                        (a.get("service_versions") or {}).keys())
            elif name == "get_configuration":
                aid = result.get("asset_id")
                if aid:
                    self.config_surfaces[aid] = [
                        str(su.get("surface", "")) for su in result.get("surfaces") or []]
            elif name == "get_vulnerabilities":
                self.services_checked.add(str(result.get("service", "")).lower())
            elif name == "get_packet_metadata":
                aid = (result.get("packet_metadata") or {}).get("alert_id")
                if aid:
                    self.packet_alerts.add(aid)
            elif name == "get_server_logs":
                tr_ = result.get("time_range")
                self.log_windows.append(None if tr_ in (None, "all") else tr_)
            elif name == "get_related_alerts":
                for rel in result.get("related_alerts") or []:
                    al = rel.get("alert") or {}
                    sc = rel.get("stored_conclusion") or {}
                    if not al.get("id"):
                        continue
                    if any(r["id"] == al["id"] for r in self.related_alerts):
                        continue
                    self.related_alerts.append({
                        "id": al["id"], "timestamp": al.get("timestamp"),
                        "case_id": rel.get("case_id"),
                        "outcome": sc.get("outcome"),
                    })

        if name == "submit_assessment" and result.get("status") == "accepted":
            self.assessment = result

        self.trace.add(trace_mod.TOOL_RESULT, tool=name, status=result.get("status"),
                       result=result)
        return result

    @staticmethod
    def render(result: dict[str, Any]) -> str:
        """Serialise a tool result for the model."""
        return json.dumps(result, indent=2, default=str)
