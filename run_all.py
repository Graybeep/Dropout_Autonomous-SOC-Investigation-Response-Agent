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

from soc_agent import config, control, llm, report, trace as trace_mod
from scenarios.definitions import SCENARIOS


def _check(scenario, result) -> list[tuple[bool, str]]:
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

    # Verification must actually reflect the mutation (guardrail 4).
    if case.verifications:
        v = case.verifications[-1]
        checks.append((v["matches_policy"],
                       "firewall verification matches policy"))
    return checks


def run_one(key: str) -> dict:
    scenario = SCENARIOS[key]
    control.reset_sandbox()

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
        checks = _check(scenario, result)
        config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        for case in result["cases"]:
            md = report.render(case, tr, scenario.title)
            (config.REPORT_DIR / f"{case.case_id}.md").write_text(md, encoding="utf-8")

    return {"key": key, "scenario": scenario, "result": result,
            "checks": checks, "error": error}


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
        all_ok &= ok
        status = "PASS" if ok else ("ERROR" if run["error"] else "FAIL")
        print(f"{run['key']:<10}{run['scenario'].title[:32]:<34}"
              f"{f'{passed}/{total}':<12}{status}")
    print("=" * 78)
    print(f"\nTraces  -> {config.TRACE_DIR}")
    print(f"Reports -> {config.REPORT_DIR}")
    print(f"Viewer  -> open viewer.html and pick a scenario")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
