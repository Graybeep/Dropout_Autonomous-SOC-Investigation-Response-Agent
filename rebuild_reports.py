#!/usr/bin/env python
"""Regenerate the per-case reports from saved traces, without re-running the agent.

The trace is the single source of truth for both the viewer and the report
(CLAUDE.md section 13), so a report can always be rebuilt from one. Useful when
the report template changes and you do not want to spend another full run
against the model.

    python rebuild_reports.py
"""
from __future__ import annotations

import json

from soc_agent import config, report, trace as trace_mod
from soc_agent.agent import Case, Conclusion


def case_from_dict(d: dict) -> Case:
    c = Case(case_id=d["case_id"], alert_id=d["alert_id"], asset_id=d["asset_id"],
             src_ip=d["src_ip"], scenario=d.get("scenario", ""),
             status=d.get("status", ""))
    c.conclusions = [
        Conclusion(outcome=x["outcome"], confidence=x["confidence"],
                   score=x["score"], hypothesis=x.get("hypothesis", ""),
                   sufficiency=x.get("sufficiency", ""),
                   disconfirming=x.get("disconfirming_evidence_checked", ""),
                   scoring=x.get("scoring", {}), at=x.get("at", ""),
                   label=x.get("label", "initial"))
        for x in d.get("conclusions", [])
    ]
    c.actions = d.get("actions", [])
    c.verifications = d.get("verifications", [])
    c.reconsiderations = d.get("reconsiderations", [])
    c.overrides = d.get("overrides", [])
    c.degraded_sources = d.get("degraded_sources", [])
    c.tools_called = d.get("tools_called", [])
    return c


def main() -> int:
    written = 0
    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    for path in sorted(config.TRACE_DIR.glob("scenario_*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not data.get("cases"):
            print(f"  skip {path.name} (no cases - run errored?)")
            continue
        tr = trace_mod.Trace(case_id=data.get("case_id", ""),
                             scenario=data.get("scenario", ""))
        tr.steps = data.get("steps", [])
        for cd in data["cases"]:
            case = case_from_dict(cd)
            md = report.render(case, tr, data.get("title", ""))
            out = config.REPORT_DIR / f"{case.case_id}.md"
            out.write_text(md, encoding="utf-8")
            print(f"  {out.relative_to(config.ROOT)}  ({len(md):,} chars)")
            written += 1
    print(f"\n{written} reports rebuilt from saved traces.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
