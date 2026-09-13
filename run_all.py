#!/usr/bin/env python
"""Evaluation harness - CLAUDE.md section 11. Deliberately minimal.

  * reset_sandbox() before EVERY scenario
  * run all six
  * assert outcome class, action fired, reconsideration fired, expected tools
  * write each trace to traces/scenario_N.json (these feed viewer.html)
  * print a pass/fail table

No statistical reporting, no N=10 sweeps, no metrics dashboard.

    python run_all.py             # all six
    python run_all.py 3 6         # just those
    python run_all.py --no-api    # offline self-check of everything but the loop
"""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

from soc_agent import config, control, llm, report, sandbox, trace as trace_mod
from scenarios.definitions import SCENARIOS


def _scoped(tr, phase: str = "any", case_id: str | None = None):
    """Steps narrowed to a case and, optionally, to before its first conclusion."""
    steps = [s for s in tr.steps
             if case_id is None or s.get("case_id") == case_id]
    if phase == "pre_conclusion":
        for i, s in enumerate(steps):
            if s["kind"] == "conclusion":
                return steps[:i]
    return steps


def _calls(tr, tool: str, phase: str = "any", case_id: str | None = None) -> int:
    return sum(1 for s in _scoped(tr, phase, case_id)
               if s["kind"] == "tool_call" and s.get("tool") == tool)


def _gathered_after_reconsider(tr, case_id: str | None = None) -> int:
    """Tool calls made AFTER a reconsideration trigger.

    Section 6.1: re-entering at HYPOTHESIZE is only meaningful if the agent
    actually gathers something new. Re-scoring the evidence it already had is
    the weak-adaptation failure the design exists to prevent.
    """
    steps = _scoped(tr, "any", case_id)
    for i, s in enumerate(steps):
        if s["kind"] == "reconsider":
            return sum(1 for t in steps[i + 1:] if t["kind"] == "tool_call")
    return 0


def _tool_args_called(tr, tool: str, key: str, value: str,
                      phase: str = "any", case_id: str | None = None) -> bool:
    """Was `tool` called with `key`=`value`? Order within the phase is irrelevant.

    phase="pre_conclusion" restricts the search to steps before the FIRST
    conclusion. That distinction matters: in the P-016 trace the agent did
    eventually look up mysql - but only during reconsideration, long after it
    had already concluded `FAILED` from tomcat alone. A whole-trace search
    passes that trace; a pre-conclusion search fails it, which is the point.
    """
    steps = _scoped(tr, phase, case_id)
    return any(s["kind"] == "tool_call" and s.get("tool") == tool
               and str((s.get("args") or {}).get(key, "")).lower() == value.lower()
               for s in steps)


def _check(scenario, result, tr=None) -> list[tuple[bool, str]]:
    case = result["primary"]
    exp = scenario.expect
    cur = case.current
    checks: list[tuple[bool, str]] = []

    outcome = cur.outcome if cur else None
    checks.append((outcome == exp.outcome,
                   f"outcome {outcome!r} == {exp.outcome!r}"))

    fired = bool(case.actions)
    checks.append((fired == exp.action_fired,
                   f"action_fired {fired} == {exp.action_fired}"))

    recon = bool(case.reconsiderations)
    checks.append((recon == exp.reconsideration_fired,
                   f"reconsideration_fired {recon} == {exp.reconsideration_fired}"))

    missing = [t for t in exp.expected_tools if t not in case.tools_called]
    checks.append((not missing,
                   f"expected tools called (missing: {missing or 'none'})"))

    if exp.final_status:
        checks.append((case.status == exp.final_status,
                       f"status {case.status!r} == {exp.final_status!r}"))

    if exp.precautionary is not None and case.actions:
        got = any(bool(a.get("precautionary")) for a in case.actions)
        checks.append((got == exp.precautionary,
                       f"precautionary {got} == {exp.precautionary}"))

    # Assert ARGUMENTS, not just tool names. "get_vulnerabilities was called"
    # passed a scenario that had looked up the wrong service (Toknow P-016).
    if tr is not None:
        for spec in exp.expected_tool_args:
            tool, key, value = spec[0], spec[1], spec[2]
            phase = spec[3] if len(spec) > 3 else "any"
            cid = spec[4] if len(spec) > 4 else None
            when = " before concluding" if phase == "pre_conclusion" else ""
            where = f" in {cid}" if cid else ""
            checks.append((_tool_args_called(tr, tool, key, value, phase, cid),
                           f"{tool}({key}={value!r}) was called{when}{where}"))

        # Minimum call counts, phase-scoped. Scenario 6's retry is only a retry
        # if both attempts happen before it concludes.
        for tool, count, phase in exp.min_calls:
            got = _calls(tr, tool, phase)
            when = " before concluding" if phase == "pre_conclusion" else ""
            checks.append((got >= count,
                           f"{tool} called >={count}x{when} (got {got})"))

        if exp.gather_after_reconsider:
            got = _gathered_after_reconsider(tr, case.case_id)
            checks.append((got > 0,
                           f"gathered NEW evidence after reconsidering "
                           f"({got} tool calls, not a bare re-score)"))

    # Assert the reasoning path, not only the final number: the first
    # conclusion and the findings that had to be established.
    if exp.initial_outcome and case.conclusions:
        got = case.conclusions[0].outcome
        checks.append((got == exp.initial_outcome,
                       f"initial outcome {got!r} == {exp.initial_outcome!r}"))
    if exp.required_factors and case.conclusions:
        declared = {f["factor"] for c in case.conclusions
                    for f in c.scoring.get("applied_factors", [])}
        missing = [f for f in exp.required_factors if f not in declared]
        checks.append((not missing,
                       f"required factors established (missing: {missing or 'none'})"))

    # Verification must actually reflect the mutation (guardrail 4).
    if case.verifications:
        v = case.verifications[-1]
        checks.append((v["matches_policy"],
                       "firewall verification matches policy"))
    return checks


def run_one(key: str) -> dict:
    scenario = SCENARIOS[key]
    control.reset_sandbox()
    # Claim fixtures/run for the duration of this scenario, so a concurrent
    # selfcheck.py (which also resets the sandbox) cannot delete the state this
    # run is about to verify.
    sandbox.acquire(f"run_all.py scenario {key}")

    tr = trace_mod.Trace(case_id=f"CASE-{key}", scenario=key)
    tr.add("scenario_meta", title=scenario.title, summary=scenario.summary,
           expectation={
               "outcome": scenario.expect.outcome,
               "action_fired": scenario.expect.action_fired,
               "reconsideration_fired": scenario.expect.reconsideration_fired,
               "notes": scenario.expect.notes,
           })

    error = None
    result = None
    try:
        result = scenario.run(tr)
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
        tr.add(trace_mod.ERROR, stage="scenario", detail=error,
               traceback=traceback.format_exc(limit=6))

    payload = tr.to_dict()
    payload["title"] = scenario.title
    payload["summary"] = scenario.summary
    if result:
        payload["cases"] = [c.to_dict() for c in result["cases"]]
    if error:
        payload["error"] = error
    trace_mod.save(payload, config.TRACE_DIR / f"scenario_{key}.json")

    checks: list[tuple[bool, str]] = []
    if result:
        checks = _check(scenario, result, tr)
        config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        for case in result["cases"]:
            md = report.render(case, tr, scenario.title)
            (config.REPORT_DIR / f"{case.case_id}.md").write_text(md, encoding="utf-8")

    return {"key": key, "scenario": scenario, "result": result,
            "checks": checks, "error": error, "payload": payload}


def _summarise(runs: list[dict]) -> None:
    """One line per scenario saying what the agent actually did, then totals.

    The pass/fail table above says whether the run met expectations; it does not
    say what happened. This does - the verdict it reached, what it did about it,
    and how much evidence and argument it took to get there.

    ASCII only, deliberately. The first version used a middot separator and an
    arrow in "overridden -> benign"; the arrow is not in cp1252, so printing
    scenario 4 raised UnicodeEncodeError and took the whole harness down after
    it had already done the work.
    """
    tot = {"calls": 0, "refusals": 0, "recons": 0, "actions": 0, "degraded": 0}
    lines = []
    plural = lambda n, word: f"{n} {word}{'' if n == 1 else 's'}"

    for run in runs:
        steps = (run["payload"] or {}).get("steps", [])
        cases = (run["payload"] or {}).get("cases", []) or []

        calls = sum(1 for x in steps
                    if x.get("kind") == "tool_call" and x.get("tool") != "submit_assessment")
        refusals = sum(1 for x in steps
                       if x.get("kind") == "tool_result"
                       and x.get("tool") == "submit_assessment"
                       and x.get("status") == "rejected")
        recons = sum(1 for x in steps if x.get("kind") == "reconsider")

        verdicts, acts, degraded = [], [], []
        for c in cases:
            concl = (c.get("conclusions") or [])
            if concl:
                last = concl[-1]
                verdicts.append(f"{last.get('outcome')} {float(last.get('confidence', 0)):.2f}")
            status = c.get("status", "")
            if status.startswith("OVERRIDDEN"):
                verdicts.append(status.replace("OVERRIDDEN_", "overridden -> ").lower())
            for a in (c.get("actions") or []):
                acts.append(a.get("action", "?")
                            + (" (precautionary)" if a.get("precautionary") else ""))
            degraded += c.get("degraded_sources") or []

        tot["calls"] += calls
        tot["refusals"] += refusals
        tot["recons"] += recons
        tot["actions"] += len(acts)
        tot["degraded"] += len(set(degraded))

        bits = [", ".join(verdicts) or "no conclusion"]
        bits.append(", ".join(dict.fromkeys(acts)) if acts else "no action")
        bits.append(f"{calls} evidence calls")
        if refusals:
            bits.append(plural(refusals, "refusal") + " resolved")
        if recons:
            bits.append(plural(recons, "reconsideration"))
        if degraded:
            bits.append(f"degraded: {', '.join(sorted(set(degraded)))}")
        if run["error"]:
            bits.append(f"ERROR {run['error']}")

        lines.append(f"{run['key']:<3}{run['scenario'].title[:34]:<36}"
                     f"{' | '.join(bits)}")

    print()
    print("What happened")
    print("-" * 78)
    for ln in lines:
        print(ln)
    print("-" * 78)
    print(" | ".join([
        plural(len(runs), "scenario"),
        plural(tot["calls"], "evidence call"),
        plural(tot["refusals"], "guard refusal"),
        plural(tot["recons"], "reconsideration"),
        plural(tot["actions"], "firewall action"),
        plural(tot["degraded"], "degraded source"),
    ]))


def main(argv: list[str]) -> int:
    if "--no-api" in argv:
        from selfcheck import offline_selfcheck
        return offline_selfcheck()

    keys = [a for a in argv if a in SCENARIOS] or list(SCENARIOS)
    print(f"Model: {config.MODEL}  via {config.BASE_URL} "
          f"(style: {config.API_STYLE})\n")

    runs = []
    for key in keys:
        print(f"--- Scenario {key}: {SCENARIOS[key].title}")
        run = run_one(key)
        runs.append(run)
        if run["error"]:
            print(f"    ERROR: {run['error']}")
        for ok, label in run["checks"]:
            print(f"    [{'PASS' if ok else 'FAIL'}] {label}")
        print()

    print("=" * 78)
    print(f"{'Scenario':<10}{'Title':<34}{'Checks':<12}{'Result'}")
    print("-" * 78)
    all_ok = True
    for run in runs:
        passed = sum(1 for ok, _ in run["checks"] if ok)
        total = len(run["checks"])
        ok = bool(run["checks"]) and passed == total and not run["error"]
        xfail = run["scenario"].expect.expected_to_fail
        # A declared limitation is not a regression. Scenario 7 documents a
        # correlation section 7.2 has no term for; it is kept in the suite
        # because the gap is the finding, so it must not drag the exit code.
        all_ok &= (ok or xfail)
        if ok:
            status = "XPASS" if xfail else "PASS"
        elif run["error"]:
            status = "ERROR"
        else:
            status = "XFAIL (declared)" if xfail else "FAIL"
        print(f"{run['key']:<10}{run['scenario'].title[:32]:<34}"
              f"{f'{passed}/{total}':<12}{status}")
    print("=" * 78)
    _summarise(runs)
    print("=" * 78)
    if any(r["scenario"].expect.expected_to_fail for r in runs):
        print("XFAIL = expected not to hold and kept on purpose; see its notes")
        print("        and Toknow/DECISIONS.md Part 22.")
    print(f"\nTraces  -> {config.TRACE_DIR}")
    print(f"Reports -> {config.REPORT_DIR}")
    # Not "open viewer.html": the browser blocks fetch() on file:// origins,
    # so the trace JSON silently fails to load. It has to be served.
    print("Open    -> python -m http.server 8000, "
          "then http://localhost:8000/  (viewer at /viewer.html)")
    sandbox.release()
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
