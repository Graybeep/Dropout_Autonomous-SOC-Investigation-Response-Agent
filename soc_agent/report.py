"""Report generation - CLAUDE.md section 9. All seven sections are mandatory.

Built from the trace and the case record, which are the single source of truth
shared with the viewer. Nothing here recomputes a conclusion; it only renders
what the run actually produced.
"""
from __future__ import annotations

from typing import Any

from . import trace as trace_mod
from .agent import Case


def _fmt_args(args: dict[str, Any], limit: int = 90) -> str:
    """Compact one-line argument summary.

    submit_assessment carries the full hypothesis, every citation and the
    disconfirmation text; dumping it inline drowns the evidence chain, and all
    of it is already rendered properly in section 3. So it is summarised to the
    factor names it declared.
    """
    shown = {k: v for k, v in args.items() if k != "reason"}
    if not shown:
        return ""
    parts = []
    for k, v in shown.items():
        if k == "factors" and isinstance(v, list):
            names = [f.get("factor", "?") for f in v if isinstance(f, dict)]
            parts.append(f"factors=[{', '.join(names)}]")
            continue
        text = repr(v)
        if len(text) > limit:
            text = text[: limit - 1] + "…'"
        parts.append(f"{k}={text}")
    return ", ".join(parts)


def render(case: Case, tr: trace_mod.Trace, scenario_title: str = "") -> str:
    steps = [s for s in tr.steps if s.get("case_id") == case.case_id]
    out: list[str] = []
    A = out.append

    A(f"# Case {case.case_id} - {scenario_title or 'SOC investigation report'}")
    A("")
    A(f"**Status:** `{case.status}`  ")
    cur = case.current
    if cur:
        A(f"**Final outcome:** `{cur.outcome}`  |  "
          f"**Score:** {cur.score:.2f}  |  **Confidence:** {cur.confidence:.2f}")
    A("")

    # 1 -------------------------------------------------------------------
    A("## 1. Alert(s) involved")
    A("")
    alert_seen: set[str] = set()
    for s in steps:
        if s["kind"] == trace_mod.TOOL_RESULT and s.get("tool") == "get_alert":
            rec = (s.get("result") or {}).get("alert")
            if rec and rec["id"] not in alert_seen:
                alert_seen.add(rec["id"])
                A(f"- **{rec['id']}** `{rec['signature']}`  ")
                A(f"  {rec['src_ip']} -> {rec['dst_ip']}:{rec.get('dst_port','')} "
                  f"on asset **{rec['asset_id']}** at {rec['timestamp']}  ")
                A(f"  Sensor severity label: `{rec['severity_label']}` "
                  f"*(the sensor's opinion, not a finding)*")
    if not alert_seen:
        A(f"- **{case.alert_id}** on asset **{case.asset_id}** "
          f"(source {case.src_ip})")
    A("")

    # 2 -------------------------------------------------------------------
    A("## 2. Evidence chain")
    A("")
    A("Retrieved in the order the agent chose, with the reason it stated for each step.")
    A("")
    n = 0
    for s in steps:
        if s["kind"] == trace_mod.TOOL_CALL:
            n += 1
            args = _fmt_args(s.get("args", {}))
            attempt = s.get("attempt", 1)
            retry = f" *(attempt {attempt})*" if attempt > 1 else ""
            A(f"{n}. **`{s['tool']}({args})`**{retry}")
            A(f"   - *Reason:* {s.get('reason') or '(none stated)'}")
        elif s["kind"] == trace_mod.TOOL_RESULT and n:
            A(f"   - *Result:* `{s.get('status')}`")
        elif s["kind"] == trace_mod.TOOL_FAILURE and n:
            r = s.get("result", {})
            A(f"   - *Result:* **`{r.get('status')}` - {r.get('reason','')}** "
              f"(this is a tool failure, not a finding)")
    if not n:
        A("*(no tool calls recorded)*")
    A("")

    sufficiency = [s for s in steps if s["kind"] == trace_mod.SUFFICIENCY]
    if sufficiency:
        A("### Sufficiency assessments")
        A("")
        for s in sufficiency:
            A(f"> {s['text'].strip()}")
            A("")

    # 3 -------------------------------------------------------------------
    A("## 3. Outcome and confidence")
    A("")
    for c in case.conclusions:
        sc = c.scoring
        A(f"### Conclusion ({c.label}) - `{c.outcome}`")
        A("")
        A(f"**Hypothesis:** {c.hypothesis}")
        A("")
        A(f"Scoring started at base {sc['base']:.2f}. Factors applied:")
        A("")
        A("| Evidence finding | Delta | Citation |")
        A("|---|---|---|")
        for f in sc["applied_factors"]:
            cite = (f.get("citation") or "").replace("|", "\\|")
            A(f"| {f['label']} | {f['delta']:+.2f} | {cite} |")
        if not sc["applied_factors"]:
            A("| *(no factors declared)* | - | - |")
        A("")
        A(f"Raw sum **{sc['raw_sum']:+.2f}** -> clamped score **{sc['score']:.2f}** "
          f"-> **{c.outcome}**, confidence **{c.confidence:.2f}**.")
        A("")
        if sc.get("ignored_factors"):
            A("Declared but not counted:")
            for f in sc["ignored_factors"]:
                A(f"- `{f.get('factor')}` - {f.get('reason')}")
            A("")
        if c.sufficiency:
            A(f"**Why this was sufficient:** {c.sufficiency}")
            A("")
        if c.disconfirming:
            A(f"**Disconfirming evidence checked:** {c.disconfirming}")
            A("")

    # 4 -------------------------------------------------------------------
    A("## 4. Action taken")
    A("")
    if case.actions:
        for a in case.actions:
            flag = " **[PRECAUTIONARY]**" if a.get("precautionary") else ""
            if a.get("status") == "already_in_effect":
                flag += " **[ALREADY IN EFFECT]**"
            A(f"- **`{a['action']}`** on `{a['ip']}` at {a.get('at')}{flag}")
            if a.get("reason"):
                A(f"  - Justification: {a['reason']}")
            if a.get("note"):
                A(f"  - {a['note']}")
            if a.get("precautionary"):
                A("  - This is containment under uncertainty, **not** a verdict "
                  "that the attack succeeded.")
    else:
        A("No action taken.")
        skipped = [s for s in steps
                   if s["kind"] == trace_mod.ACTION and s.get("skipped")]
        for s in skipped:
            A(f"- {s.get('detail')}")
        if cur and cur.outcome == "FAILED":
            A("- Outcome `FAILED`: the alert did not reflect a successful attack, "
              "so no containment was warranted.")
        elif cur and cur.outcome == "INCONCLUSIVE":
            A("- Outcome `INCONCLUSIVE` on a non-critical asset: flagged for "
              "analyst review rather than blocked.")
    A("")

    # 5 -------------------------------------------------------------------
    A("## 5. Verification")
    A("")
    if case.verifications:
        for v in case.verifications:
            mark = "OK" if v["matches_policy"] else "MISMATCH"
            A(f"- Re-read firewall state from `{v['read_from']}` for `{v['ip']}`.")
            A(f"  - Expected blocked: `{v['expected_blocked']}` | "
              f"observed blocked: `{v['blocked_after']}` -> **{mark}**")
            if v.get("record"):
                A(f"  - Rule on disk: `{v['record'].get('rule')}` "
                  f"(precautionary: {v['record'].get('precautionary')})")
    else:
        A("*(no verification recorded)*")
    A("")

    # 6 -------------------------------------------------------------------
    A("## 6. Reconsideration events")
    A("")
    if case.reconsiderations:
        for r in case.reconsiderations:
            prior, new = r.get("prior_conclusion"), r.get("new_conclusion")
            A(f"### Trigger: `{r['trigger']}`")
            A("")
            A(f"{r.get('detail','')}")
            A("")
            A("| | Prior conclusion | New conclusion |")
            A("|---|---|---|")
            po = prior["outcome"] if prior else "-"
            no = new["outcome"] if new else "(unchanged - human decision applied)"
            pc = f"{prior['confidence']:.2f}" if prior else "-"
            nc = f"{new['confidence']:.2f}" if new else "-"
            A(f"| Outcome | `{po}` | `{no}` |")
            A(f"| Confidence | {pc} | {nc} |")
            A("")
            A(f"*{r['note']}*" if r.get("note")
              else "*The prior conclusion is preserved above and is never "
                   "overwritten.*")
            A("")
    else:
        A("None. The case reached its conclusion in a single pass.")
    A("")

    if case.overrides:
        A("### Human override record")
        A("")
        for o in case.overrides:
            A(f"- Decision: **`{o['decision']}`** at {o['at']}")
            A(f"  - Justification: {o['justification']}")
            A(f"  - Resulting case status: `{o['resulting_status']}`")
            A("  - The agent must not re-trigger an opposing automated action on "
              "this case without a new explicit trigger (guardrail 6).")
        A("")

    # 7 -------------------------------------------------------------------
    A("## 7. Degraded-evidence note")
    A("")
    if case.degraded_sources:
        A(f"The following sources failed or were unavailable: "
          f"**{', '.join('`'+s+'`' for s in case.degraded_sources)}**.")
        A("")
        for s in steps:
            if s["kind"] == trace_mod.TOOL_FAILURE:
                r = s.get("result", {})
                A(f"- `{s['tool']}` attempt {s.get('attempt')}: "
                  f"`{r.get('status')}` - {r.get('reason')}")
        A("")
        note = cur.scoring.get("ceiling_note") if cur else ""
        if note:
            A(f"**Confidence ceiling imposed:** {note}")
        A("")
        A("This gap is a limit on what could be established, not a finding that "
          "nothing happened.")
    else:
        no_data = [s for s in steps
                   if s["kind"] == trace_mod.TOOL_RESULT
                   and s.get("status") == "no_data"]
        if no_data:
            A("No tool failed. The following lookups returned an explicit "
              "`no_data` (the source genuinely holds nothing for that key):")
            A("")
            for s in no_data:
                A(f"- `{s['tool']}`: {(s.get('result') or {}).get('detail','')}")
        else:
            A("No tool failed and no source returned `no_data`. "
              "The evidence base was complete; no confidence ceiling applied.")
    A("")
    return "\n".join(out)
