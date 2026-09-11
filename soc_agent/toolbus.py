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
        # Tools that returned a usable result. Used to enforce factor
        # preconditions when the agent submits its assessment.
        self.ok_tools: set[str] = set()

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
            from . import confidence
            problems = confidence.check_preconditions(
                [f.get("factor", "") for f in args.get("factors", [])],
                self.ok_tools)
            if problems:
                result = {"status": "rejected", "problems": problems,
                          "detail": "Assessment not accepted. Fix these and resubmit."}
                self.trace.add(trace_mod.TOOL_RESULT, tool=name,
                               status="rejected", result=result)
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
            result = {
                "status": "error",
                "detail": f"Bad arguments for '{name}': {exc}",
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

        if name == "submit_assessment" and result.get("status") == "accepted":
            self.assessment = result

        self.trace.add(trace_mod.TOOL_RESULT, tool=name, status=result.get("status"),
                       result=result)
        return result

    @staticmethod
    def render(result: dict[str, Any]) -> str:
        """Serialise a tool result for the model."""
        return json.dumps(result, indent=2, default=str)
