#!/usr/bin/env python
"""Does a badly-reasoning trajectory that lands on the right answer pass?

Run:  python scoring/test_luck_vs_reasoning.py

This is not a constructed hypothetical. `_bad_trajectory.json` is a real trace
from commit ee50c21 of this repo. In it the agent:

  * reached the CORRECT final outcome (SUCCEEDED), which is what the scenario
    expects, and
  * got there by declaring `version_patched` after looking up exactly ONE of the
    host's three CVE-covered services - on a SQL-injection alert, having never
    compared the host's MySQL version at all.

It concluded `FAILED` at T0 where the spec calls for `INCONCLUSIVE`, then the
injected lateral-movement evidence pushed it to the right final answer anyway.

That is precisely "lands on the right factor by luck". The script replays it
through the harness's own assertions at two bars:

  OLD BAR - outcome, action fired, reconsideration fired, tool NAMES called
  CURRENT BAR - the above plus argument-level, phase-scoped and initial-outcome
                assertions

and prints which assertions each bar catches it on. No mocking: it calls
run_all._check, the same function `python run_all.py` uses.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import run_all                                   # noqa: E402
from rebuild_reports import case_from_dict       # noqa: E402
from scenarios.definitions import SCENARIOS      # noqa: E402
from soc_agent import trace as trace_mod         # noqa: E402


def load(path: Path):
    d = json.loads(path.read_text(encoding="utf-8"))
    tr = trace_mod.Trace(case_id=d.get("case_id", ""), scenario=d.get("scenario", ""))
    tr.steps = d["steps"]
    case = case_from_dict(d["cases"][0])
    return d, tr, case


def show(title, checks):
    print(f"\n{title}")
    print("-" * 74)
    failed = 0
    for ok, label in checks:
        if not ok:
            failed += 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    verdict = "CAUGHT" if failed else "PASSED - the bad trajectory slips through"
    print(f"  => {failed} failing assertion(s): {verdict}")
    return failed


# Which assertions are actually load-bearing? A "coarse" check tests the
# outcome class or a bare tool NAME - the kind the bad trajectory above sails
# straight through. A "path-pinning" check tests an argument, a phase, an
# intermediate verdict or a post-reconsideration call count. The ratio is the
# honest way to read the headline pass count, so it is computed here from the
# shipped traces rather than asserted.
COARSE_PREFIXES = ("outcome ", "action_fired", "reconsideration_fired",
                   "expected tools called", "status ")


def census() -> None:
    print("\n" + "=" * 74)
    print("ASSERTION CENSUS - how much of the pass count is cheap?")
    print("=" * 74)
    total = coarse = 0
    for f in sorted((ROOT / "traces").glob("scenario_*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        tr = trace_mod.Trace(case_id=d.get("case_id", ""), scenario=d.get("scenario", ""))
        tr.steps = d["steps"]
        cases = [case_from_dict(c) for c in d["cases"]]
        checks = run_all._check(SCENARIOS[str(d["scenario"])],
                                {"primary": cases[0], "cases": cases}, tr)
        c = sum(1 for _, lab in checks if lab.startswith(COARSE_PREFIXES))
        total += len(checks); coarse += c
        print(f"  {f.name:20} {len(checks):>3} checks   coarse={c}   "
              f"path-pinning={len(checks) - c}")
    if total:
        print(f"\n  {total} assertions: {coarse} coarse ({coarse * 100 // total}%), "
              f"{total - coarse} path-pinning ({(total - coarse) * 100 // total}%)")
        print("  Scenario 4 is the weakest: one path-pinning check.")


def main() -> int:
    path = Path(__file__).parent / "_bad_trajectory.json"
    if not path.exists():
        print(f"missing {path}"); return 2
    d, tr, case = load(path)
    scenario = SCENARIOS[str(d["scenario"])]
    result = {"primary": case, "cases": [case]}

    print("=" * 74)
    print("THE TRAJECTORY UNDER TEST  (real trace, commit ee50c21)")
    print("=" * 74)
    print(f"  expected final outcome : {scenario.expect.outcome}")
    print(f"  actual final outcome   : {case.conclusions[-1].outcome}   <- correct")
    print(f"  actual FIRST outcome   : {case.conclusions[0].outcome}   <- spec says INCONCLUSIVE")
    pre = [s["args"].get("service_name") for s in tr.steps
           if s["kind"] == "tool_call" and s.get("tool") == "get_vulnerabilities"]
    idx = next((i for i, s in enumerate(tr.steps) if s["kind"] == "conclusion"), len(tr.steps))
    pre_conc = [s["args"].get("service_name") for s in tr.steps[:idx]
                if s["kind"] == "tool_call" and s.get("tool") == "get_vulnerabilities"]
    print(f"  services looked up before concluding : {pre_conc}")
    print(f"  services looked up in the whole run  : {pre}")
    print("  the host runs mysql 5.7.28, which IS inside CVE-2023-21980.")

    # --- OLD BAR: outcome + coarse tool-name checks -----------------------
    exp = scenario.expect
    old = []
    cur = case.current
    old.append((cur.outcome == exp.outcome, f"outcome {cur.outcome!r} == {exp.outcome!r}"))
    old.append((bool(case.actions) == exp.action_fired,
                f"action_fired {bool(case.actions)} == {exp.action_fired}"))
    old.append((bool(case.reconsiderations) == exp.reconsideration_fired,
                f"reconsideration_fired {bool(case.reconsiderations)} == "
                f"{exp.reconsideration_fired}"))
    missing = [t for t in exp.expected_tools if t not in case.tools_called]
    old.append((not missing, f"expected TOOL NAMES called (missing: {missing or 'none'})"))
    old_fail = show("OLD BAR - outcome class + tool names only", old)

    # --- CURRENT BAR: the harness's real _check --------------------------
    cur_checks = run_all._check(scenario, result, tr)
    new_fail = show("CURRENT BAR - run_all._check, the same function run_all.py uses",
                    cur_checks)

    print("\n" + "=" * 74)
    print("ANSWER")
    print("=" * 74)
    if old_fail == 0 and new_fail > 0:
        print("  The old bar PASSED this trajectory. The current bar FAILS it.")
        print("  A right answer reached by wrong reasoning does NOT pass today.")
    elif new_fail == 0:
        print("  The current bar PASSES it. The assertions do NOT separate luck")
        print("  from reasoning on this trajectory. Treat '99/99' accordingly.")
    else:
        print("  Both bars catch it.")
    census()

    print("\n  Note on scope: these assertions pin the REASONING PATH (which")
    print("  service was checked before concluding, what the first conclusion")
    print("  was, which factors were established). They do NOT verify that a")
    print("  citation's prose actually supports its factor - that would require")
    print("  judging evidence content, which is the one thing the design")
    print("  forbids. See scoring/README.md, 'What these assertions cannot do'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
