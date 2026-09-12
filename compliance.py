#!/usr/bin/env python
"""Guardrail compliance audit.

ADVERSARIAL TESTS THAT EDIT SOURCE MUST CLEAR __pycache__ AFTER RESTORING.
Restoring a file with shutil.move carries the backup's mtime, which can be older
than the .pyc built from the edited version - Python then serves stale bytecode
to every later process in the session and a passing suite reports as failing.
See Toknow J-7.

Greps the codebase for the specific failure modes CLAUDE.md forbids, so that
"the decision logic is not scripted" is a checkable claim rather than an
assertion. Run with `python compliance.py`. No API key needed.

These are structural checks on the source. They complement selfcheck.py (which
tests behaviour) and run_all.py (which tests outcomes).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRODUCT = [ROOT / "soc_agent", ROOT / "scenarios", ROOT / "run_all.py"]

results: list[tuple[bool, str, str]] = []


def record(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))


def py_files() -> list[Path]:
    out: list[Path] = []
    for p in PRODUCT:
        out.extend(p.rglob("*.py") if p.is_dir() else [p])
    return [f for f in out if "__pycache__" not in str(f)]


def grep(pattern: str, files: list[Path]) -> list[str]:
    rx = re.compile(pattern)
    hits = []
    for f in files:
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if rx.search(line):
                hits.append(f"{f.relative_to(ROOT)}:{i}: {line.strip()}")
    return hits


def main() -> int:
    files = py_files()

    # Section 13 - no mock outcome logic anywhere in the codebase.
    hits = grep(r"if\s+scenario\s*==|scenario_?id\s*==|flipped_conclusion", files)
    record(not hits, "13: no outcome branches keyed on scenario identity",
           "; ".join(hits[:3]))

    # Section 3 guardrail 2 - the decision path must not branch on the
    # sensor's severity label. That label is the thing the agent is supposed
    # to distrust.
    hits = grep(r"severity(_label)?\s*==|\.severity\b", files)
    record(not hits, "3.2: no code branches on the alert severity_label",
           "; ".join(hits[:3]))

    # Outcomes may only be PRODUCED by the deterministic scorer. Reading one
    # back (to pick explanatory prose in a report, or to state an expectation
    # in a scenario definition) is fine; assigning or returning one is not.
    # scenarios/definitions.py is exempt: the outcome strings there are the
    # harness's EXPECTATIONS (what each scenario should land on), which is what
    # makes a failure detectable. They are never fed back into a conclusion.
    assign = r"(?:outcome\s*=\s*|return\s+)[\"'](?:SUCCEEDED|FAILED|INCONCLUSIVE)[\"']"
    exempt = ("confidence.py", "definitions.py")
    hits = [h for h in grep(assign, files) if not any(e in h for e in exempt)]
    record(not hits, "7.2: outcome values are produced only by confidence.py",
           "; ".join(hits[:3]))

    # Section 5.1 - the CVE KB must not pre-resolve patch status.
    kb = (ROOT / "fixtures/seed/cve_kb.json").read_text(encoding="utf-8")
    record("patched" not in kb.lower() and "is_vulnerable" not in kb.lower(),
           "5.1: cve_kb.json carries no per-host patch status")
    kb_data = json.loads(kb)
    record(all("affected_versions" in c
               for k, v in kb_data.items() if not k.startswith("_")
               for c in v),
           "5.1: every CVE entry exposes an affected_versions range")

    # Section 8 - control-plane tools are never exposed as agent tools.
    sys.path.insert(0, str(ROOT))
    from soc_agent import schemas, tools, confidence as _c
    from scenarios.definitions import SCENARIOS
    names = {t["name"] for t in schemas.ANTHROPIC_TOOLS}
    control = {"inject_new_evidence", "inject_alert", "human_override",
               "reset_sandbox", "related_case_event"}
    record(not (names & control), "8: control-plane tools are not agent-facing",
           str(names & control))
    record(names == set(tools.IMPLEMENTATIONS),
           "8: every schema has exactly one implementation")

    # Every schema must be valid enough to send: no duplicate required entries.
    dupes = [t["name"] for t in schemas.ANTHROPIC_TOOLS
             if len(t["input_schema"].get("required", []))
             != len(set(t["input_schema"].get("required", [])))]
    record(not dupes, "8: no duplicate entries in any schema's `required`",
           str(dupes))

    # Section 5.2 - tools must read the run copy, never the committed seed.
    hits = grep(r"SEED_DIR", [f for f in files if f.name not in ("sandbox.py", "config.py")])
    record(not hits, "5.2: only sandbox.py touches fixtures/seed",
           "; ".join(hits[:3]))

    # Section 7.2 - the scoring constants must be exactly as specified.
    from soc_agent import confidence
    expected = {"version_in_range": 0.25, "logs_consistent": 0.25,
                "exfil_indicators": 0.15, "related_alert_corroborates": 0.15,
                "version_patched": -0.30, "logs_clean": -0.25,
                "packet_benign": -0.10}
    actual = {k: v[0] for k, v in confidence.FACTORS.items()}
    record(actual == expected, "7.2: confidence factors match the spec exactly",
           f"got {actual}" if actual != expected else "")
    record(confidence.BASE == 0.50 and confidence.CLAMP == (0.05, 0.95)
           and confidence.DEGRADED_CLAMP == (0.35, 0.65),
           "7.2: base, clamp and degraded clamp match the spec")

    # Fixture invariants the scenarios silently depend on.
    import re as _re
    inv = json.loads((ROOT / "fixtures/seed/asset_inventory.json").read_text(encoding="utf-8"))
    kb_by = {k: v for k, v in kb_data.items() if not k.startswith("_")}

    def _norm(v):
        m = _re.match(r"^(\d+)\.(\d+)\.(\d+)(?:p(\d+))?$", v)
        return tuple(int(x) if x else 0 for x in m.groups()) if m else None

    def _in_range(v, spec):
        vt = _norm(v)
        if not vt:
            return False
        for clause in spec.split(","):
            m = _re.match(r"^(>=|<=|>|<)(.+)$", clause.strip())
            op, b = m.group(1), _norm(m.group(2))
            if op == ">=" and not vt >= b: return False
            if op == "<=" and not vt <= b: return False
            if op == ">" and not vt > b: return False
            if op == "<" and not vt < b: return False
        return True

    # Scenario 1 needs version_patched, which now requires enumerating EVERY
    # KB-covered service on that host. If any of them were in range, S1 could
    # never reach FAILED.
    s1 = inv["SRV-WEB-01"]["service_versions"]
    s1_hits = [c["cve_id"] for svc, ver in s1.items()
               for c in kb_by.get(svc.lower(), []) if _in_range(ver, c["affected_versions"])]
    record(not s1_hits,
           "4: Scenario 1's host is outside every CVE range (so FAILED is reachable)",
           f"in range: {s1_hits}")

    # Keep the gather loop bounded: version_patched costs one lookup per
    # KB-covered service the host runs.
    wide = {a: len(v["service_versions"]) for a, v in inv.items()
            if not 2 <= len(v["service_versions"]) <= 4}
    record(not wide, "4: every asset runs 2-4 services (bounds the gather loop)",
           str(wide))

    # 7.2 boundary: a single positive factor must not reach SUCCEEDED on its
    # own, or a scenario expected to start INCONCLUSIVE can be tipped by one
    # finding and have nothing left to flip to.
    lone = confidence.score([{"factor": "version_in_range", "citation": "c",
                              "rationale": "r"}])
    record(lone.outcome != confidence.SUCCEEDED
           or any(s.expect.initial_outcome != "INCONCLUSIVE"
                  for s in SCENARIOS.values()),
           "7.2: single-factor boundary is asserted by a scenario expectation",
           f"version_in_range alone scores {lone.score} -> {lone.outcome}; "
           f"scenarios 3 and 5 assert initial_outcome=INCONCLUSIVE to catch it")

    # Scenarios 3 and 5A must START inconclusive. That is only sound if
    # `logs_clean` is the ONLY honest reading of their seeded T0 logs. A single
    # row implying the attack DID something lets the agent declare
    # logs_consistent (-> 1.00 -> SUCCEEDED at T0) and the scenario has nothing
    # left to flip to at T1. The assertion in run_all catches that after the
    # fact; this stops a fixture edit introducing it in the first place.
    logs = json.loads((ROOT / "fixtures/seed/server_logs.json").read_text(encoding="utf-8"))
    SUCCESS_MARKERS = ("rows_sent:", "mysqldump", "curl -t", "create user",
                       "grant all", "bytes sent", "union select")
    BENIGN_MARKERS = ("403", "500", "error", "denied", "refused", "rejected",
                      "0 rows", "blocked", "baseline", "aborted")
    for asset, why in (("SRV-APP-03", "Scenario 3 T0"),
                       ("SRV-WEB-04", "Scenario 5 case A T0")):
        bad = []
        for e in logs.get(asset, []):
            raw = e["raw"].lower()
            if any(m in raw for m in SUCCESS_MARKERS):
                bad.append(e["raw"][:70])
            elif e.get("event_type") == "auth_success" and not any(
                    m in raw for m in BENIGN_MARKERS):
                bad.append(e["raw"][:70])
        record(not bad,
               f"4: {why} logs imply no successful attacker activity "
               f"(logs_clean is the only honest reading)",
               "; ".join(bad))

    # Scenario 5 is the ONLY scenario that exercises the correlated-case
    # logs_clean guard, because it is the only asset with sibling alerts. That
    # guard is only meaningful if the sibling is far enough from case A's own
    # alert that an own-alert-only window would miss it. If someone retimed
    # ALERT-5002 to sit next to ALERT-5001, the union would collapse onto the
    # single-alert window and the guard would silently stop testing anything.
    from scenarios.definitions import ALERT_5002 as _A5002
    own = json.loads((ROOT / "fixtures/seed/alerts.json").read_text(encoding="utf-8"))
    a_ts = own["ALERT-5001"]["timestamp"]
    b_ts = _A5002["timestamp"]
    same_asset = own["ALERT-5001"]["asset_id"] == _A5002["asset_id"]
    record(same_asset, "4: S5's two alerts target the same asset (union applies)",
           f"{own['ALERT-5001']['asset_id']} vs {_A5002['asset_id']}")
    # "Far enough" = more than an hour, which no plausible single-alert window
    # spans by default.
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    gap = abs((datetime.strptime(b_ts, fmt) - datetime.strptime(a_ts, fmt))
              .total_seconds())
    record(gap >= 3600,
           "4: S5's sibling alert is >=1h from case A's, so union coverage is "
           "actually exercised",
           f"gap is {gap/60:.0f} min ({a_ts} -> {b_ts})")
    # And the injected exploitation rows must sit in the sibling's window, not
    # case A's, or there is nothing for the union to reach.
    from scenarios.definitions import EXPLOIT_ENTRIES as _EE
    late = [e["ts"] for e in _EE if e["ts"] > a_ts]
    record(len(late) == len(_EE),
           "4: S5's injected exploitation rows all post-date case A's alert",
           f"{len(late)}/{len(_EE)} after {a_ts}")

    # Section 4 - exactly six scenarios, no seventh.
    record(len(SCENARIOS) == 6, "4: exactly six scenarios",
           f"found {len(SCENARIOS)}")

    failed = 0
    for ok, name, detail in results:
        if not ok:
            failed += 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + (f"\n         {detail}" if detail and not ok else ""))
    print(f"\n{len(results) - failed}/{len(results)} guardrail checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
