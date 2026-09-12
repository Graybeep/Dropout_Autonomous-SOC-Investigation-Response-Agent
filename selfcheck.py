#!/usr/bin/env python
"""Offline self-check: everything except the model loop.

Run with `python run_all.py --no-api` or `python selfcheck.py`.

WHAT THIS IS: a test of the plumbing - sandbox reset, every tool, the
block -> verify round trip against the real file on disk, the scoring
function, the action policy, guardrail enforcement, and report rendering.

WHAT THIS IS NOT: a substitute for a real run. It never produces a scenario
conclusion and never writes to traces/. The six demo traces come only from the
real agent loop over real fixture evidence (CLAUDE.md section 13 - there is no
mock outcome logic anywhere in this codebase). The stub model in the loop-
mechanics check below drives a deliberately trivial synthetic case whose only
purpose is to prove message conversion and tool dispatch work; its "conclusion"
is discarded.
"""
from __future__ import annotations

import json

from soc_agent import (agent, confidence, config, control, report, sandbox,
                       schemas, tools, trace as trace_mod)
from soc_agent.toolbus import ToolBus

PASS, FAIL = "PASS", "FAIL"
_results: list[tuple[str, str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    _results.append((PASS if cond else FAIL, name, detail))
    return cond


def section(title: str) -> None:
    _results.append(("", f"--- {title} ---", ""))


def offline_selfcheck() -> int:
    # This suite resets fixtures/run repeatedly. If a live run holds it, bail
    # out instead of trampling it - running selfcheck during run_all.py has
    # twice corrupted a live scenario (Toknow P-014, P-017). Never pass
    # force=True here: that defeats the guard this exists to respect.
    try:
        control.reset_sandbox()
    except sandbox.SandboxBusy as exc:
        print(f"REFUSING TO RUN: {exc}")
        return 2

    ctx = {"case_id": "CASE-SELFCHECK", "alert_id": "ALERT-2001",
           "asset_id": "SRV-DB-02"}

    # -- sandbox ---------------------------------------------------------
    section("sandbox")
    control.reset_sandbox()
    check("reset_sandbox creates fixtures/run", config.RUN_DIR.exists())
    check("run copy has all 6 fixtures",
          len([p for p in config.RUN_DIR.glob("*.json")
               if p.name != config.CASES]) == 6)
    check("cases.json starts empty", sandbox.read_json(config.CASES) == {})

    # -- evidence tools --------------------------------------------------
    section("evidence tools")
    a = tools.get_alert(ctx, "ALERT-2001")
    check("get_alert returns the alert", a["status"] == "ok"
          and a["alert"]["asset_id"] == "SRV-DB-02")
    check("get_alert miss -> explicit no_data",
          tools.get_alert(ctx, "ALERT-9999")["status"] == "no_data")

    asset = tools.get_asset_info(ctx, "SRV-DB-02")
    check("get_asset_info returns running versions",
          asset["asset"]["service_versions"]["mysql"] == "5.7.21")

    cves = tools.get_vulnerabilities(ctx, "mysql")
    kb_text = json.dumps(cves)
    check("get_vulnerabilities returns affected ranges",
          "affected_versions" in kb_text)
    check("CVE KB does NOT resolve patch status (section 5.1)",
          "patched" not in kb_text.lower())
    check("get_vulnerabilities miss -> no_data",
          tools.get_vulnerabilities(ctx, "nginx")["status"] == "no_data")

    logs = tools.get_server_logs(ctx, "SRV-DB-02")
    check("get_server_logs returns entries", logs["status"] == "ok"
          and logs["entry_count"] > 0)
    check("get_server_logs time_range filters",
          tools.get_server_logs(
              ctx, "SRV-DB-02",
              "2026-09-11T03:42:00Z/2026-09-11T03:43:00Z")["entry_count"] < logs["entry_count"])
    check("get_server_logs empty window -> no_data",
          tools.get_server_logs(
              ctx, "SRV-DB-02",
              "2020-01-01T00:00:00Z/2020-01-02T00:00:00Z")["status"] == "no_data")

    pkt = tools.get_packet_metadata(ctx, "ALERT-2001")
    check("get_packet_metadata shows exfil indicator",
          pkt["packet_metadata"]["exfil_indicators"] is True)

    # -- firewall: the mutation and its verification share one file ------
    section("firewall mutate -> verify (guardrail 4)")
    before = tools.check_firewall_state(ctx, "198.51.100.23")
    check("IP not blocked initially", before["blocked"] is False)

    tools.block_ip(ctx, "198.51.100.23", "self-check", precautionary=False)
    on_disk = json.loads((config.RUN_DIR / config.FIREWALL_STATE).read_text())
    check("block_ip wrote to firewall_state.json on disk",
          "198.51.100.23" in on_disk["blocked_ips"])
    after = tools.check_firewall_state(ctx, "198.51.100.23")
    check("check_firewall_state reads the mutation back", after["blocked"] is True)
    check("verification depends on the mutation, not on the request",
          after["record"]["case_id"] == "CASE-SELFCHECK")

    tools.unblock_ip(ctx, "198.51.100.23", "self-check cleanup")
    check("unblock_ip removes the rule",
          tools.check_firewall_state(ctx, "198.51.100.23")["blocked"] is False)
    check("audit log records both actions",
          len(sandbox.read_json(config.FIREWALL_STATE)["audit_log"]) == 2)

    # -- seed immutability (section 5.2) ---------------------------------
    section("fixture immutability")
    import hashlib
    seed_before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(config.SEED_DIR.glob("*.json"))}
    tools.block_ip(ctx, "203.0.113.99", "immutability probe")
    tools.get_server_logs(ctx, "SRV-DB-02")
    control.inject_new_evidence(
        "CASE-X", {"asset_id": "SRV-DB-02",
                   "entries": [{"ts": "2026-09-11T09:00:00Z", "source": "t",
                                "event_type": "t", "raw": "probe"}]})
    seed_after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(config.SEED_DIR.glob("*.json"))}
    check("writes never touch fixtures/seed", seed_before == seed_after)
    check("the same writes DID change fixtures/run",
          hashlib.sha256((config.RUN_DIR / config.FIREWALL_STATE).read_bytes())
          .hexdigest()
          != hashlib.sha256((config.SEED_DIR / config.FIREWALL_STATE).read_bytes())
          .hexdigest())
    control.reset_sandbox()
    check("reset_sandbox restores run to match seed",
          hashlib.sha256((config.RUN_DIR / config.FIREWALL_STATE).read_bytes())
          .hexdigest()
          == hashlib.sha256((config.SEED_DIR / config.FIREWALL_STATE).read_bytes())
          .hexdigest())

    # -- fault injection -------------------------------------------------
    section("fault injection (Scenario 6)")
    tr = trace_mod.Trace(case_id="CASE-SELFCHECK", scenario="selfcheck")
    bus = ToolBus(tr, ctx, fail_tools=["get_server_logs"])
    r1 = bus.invoke("get_server_logs", {"asset_id": "SRV-DB-05", "reason": "x"})
    r2 = bus.invoke("get_server_logs", {"asset_id": "SRV-DB-05", "reason": "retry"})
    check("failing tool returns unavailable, not empty",
          r1["status"] == "unavailable" and r2["status"] == "unavailable")
    check("failure persists across retry (agent must route elsewhere)",
          r2["attempt"] == 2)
    check("failure recorded as a degraded source",
          bus.degraded_sources == ["get_server_logs"])
    check("non-failing tool still works under fault injection",
          bus.invoke("get_alert", {"alert_id": "ALERT-6001",
                                   "reason": "x"})["status"] == "ok")

    # -- scoring ---------------------------------------------------------
    section("deterministic scoring (section 7.2)")

    def f(*names):
        return [{"factor": n, "citation": "c", "rationale": "r"} for n in names]

    s1 = confidence.score(f("version_patched", "logs_clean", "packet_benign"), [])
    check("S1 patched+clean -> FAILED", s1.outcome == "FAILED")
    s2 = confidence.score(f("version_in_range", "logs_consistent",
                            "exfil_indicators"), [])
    check("S2 unpatched+logs+exfil -> SUCCEEDED", s2.outcome == "SUCCEEDED")
    s3 = confidence.score(f("version_in_range", "packet_benign"), [])
    check("S3 T0 ambiguous -> INCONCLUSIVE", s3.outcome == "INCONCLUSIVE")
    s6 = confidence.score(f("version_in_range", "exfil_indicators"),
                          ["get_server_logs"])
    check("S6 degraded clamp forces INCONCLUSIVE",
          s6.outcome == "INCONCLUSIVE" and s6.score == 0.65)
    check("S6 would have been SUCCEEDED without the clamp", s6.raw == 0.90)
    check("S6 ceiling note explains the cap", "Degraded-evidence clamp" in s6.ceiling_note)

    dup = confidence.score(f("version_in_range", "version_in_range"), [])
    check("each factor applies at most once",
          len(dup.applied) == 1 and len(dup.ignored) == 1)
    check("contradictory factors rejected",
          bool(confidence.validate(["logs_clean", "logs_consistent"])))
    check("unknown factor rejected", bool(confidence.validate(["nonsense"])))
    check("clamp floor holds", confidence.score(f("version_patched", "logs_clean",
                                                  "packet_benign"), []).score >= 0.05)

    # -- factor preconditions (guardrail 3, structural) -------------------
    section("factor preconditions")
    check("factor from an unread source is refused",
          bool(confidence.check_preconditions(["related_alert_corroborates"], set())))
    check("factor is allowed once its source read ok",
          not confidence.check_preconditions(["related_alert_corroborates"],
                                             {"get_related_alerts"}))
    check("version factors need BOTH asset info and CVE data",
          bool(confidence.check_preconditions(["version_in_range"],
                                              {"get_asset_info"})))
    control.reset_sandbox()
    tr_p = trace_mod.Trace(case_id="CASE-PRE", scenario="pre")
    bus_p = ToolBus(tr_p, ctx)
    rej = bus_p.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "related_alert_corroborates",
                     "citation": "no other alerts recorded", "rationale": "r"}]})
    check("bus rejects an assessment citing an unread source",
          rej["status"] == "rejected")
    # SRV-WEB-01 carries only ALERT-1001, so from that alert's own case there
    # are no *other* alerts and the lookup genuinely returns no_data.
    bus_solo = ToolBus(tr_p, {"case_id": "CASE-1001", "alert_id": "ALERT-1001",
                              "asset_id": "SRV-WEB-01"})
    solo = bus_solo.invoke("get_related_alerts",
                           {"asset_id": "SRV-WEB-01", "reason": "x"})
    check("lone alert on an asset -> no_data", solo["status"] == "no_data")
    check("no_data result does NOT count as a successful read",
          "get_related_alerts" not in bus_solo.ok_tools)
    rej2 = bus_solo.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "related_alert_corroborates",
                     "citation": "No other alerts recorded", "rationale": "r"}]})
    check("corroboration cannot be claimed from an empty lookup",
          rej2["status"] == "rejected")


    # -- malformed tool calls must be recoverable, not dead ends ----------
    section("tool-call error recovery")
    bus_e = ToolBus(tr_p, ctx)
    empty = bus_e.invoke("submit_assessment",
                         {"hypothesis": "h", "factors": [], "sufficiency": "s"})
    check("assessment declaring zero factors is rejected",
          empty["status"] == "rejected")
    check("rejection names the valid factors",
          "version_in_range" in " ".join(empty.get("problems", [])))
    unparsed = bus_e.invoke("submit_assessment", {"__unparsed__": "{bad json"})
    check("unparseable tool arguments produce a readable error",
          unparsed["status"] == "error" and "hint" in unparsed)
    typo = bus_e.invoke("submit_assessment",
                        {"hypothesis": "h", "factors": [], "sufficiency": "s",
                         "disconfirming_evidence_check": "typo"})
    check("misspelled parameter error lists the accepted names",
          "disconfirming_evidence_checked" in typo.get("accepted_parameters", []))
    check("misspelled parameter error says to correct, not drop",
          "rather than" in typo.get("hint", ""))


    # -- version_patched is universal, and needs universal coverage --------
    section("version_patched coverage")
    control.reset_sandbox()
    tr_v = trace_mod.Trace(case_id="CASE-COV", scenario="cov")
    bus_v = ToolBus(tr_v, {"case_id": "CASE-COV", "alert_id": "ALERT-3001",
                           "asset_id": "SRV-APP-03"})
    bus_v.invoke("get_asset_info", {"asset_id": "SRV-APP-03", "reason": "x"})
    bus_v.invoke("get_vulnerabilities", {"service_name": "tomcat", "reason": "x"})
    partial = bus_v.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "version_patched", "citation": "tomcat only",
                     "rationale": "r"}]})
    check("version_patched refused when a KB-covered service is unchecked",
          partial["status"] == "rejected")
    check("the refusal names the unchecked services",
          "mysql" in " ".join(partial.get("problems", [])))
    bus_v.invoke("get_vulnerabilities", {"service_name": "mysql", "reason": "x"})
    bus_v.invoke("get_vulnerabilities", {"service_name": "openssh", "reason": "x"})
    full = bus_v.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "version_patched", "citation": "all three",
                     "rationale": "r"}]})
    check("version_patched accepted once every covered service is checked",
          full["status"] == "accepted")
    bus_x = ToolBus(tr_v, {"case_id": "CASE-COV2", "alert_id": "ALERT-3001",
                           "asset_id": "SRV-APP-03"})
    bus_x.invoke("get_asset_info", {"asset_id": "SRV-APP-03", "reason": "x"})
    bus_x.invoke("get_vulnerabilities", {"service_name": "mysql", "reason": "x"})
    exi = bus_x.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "version_in_range", "citation": "mysql in range",
                     "rationale": "r"}]})
    check("version_in_range is existential and NOT subject to the check",
          exi["status"] == "accepted")


    # -- transport: which failures are worth retrying ---------------------
    section("retry policy")
    from soc_agent import llm as _llm
    check("429 is retried (the one 4xx that means try again)",
          429 in _llm.RETRY_STATUS)
    check("5xx are retried",
          all(c in _llm.RETRY_STATUS for c in (500, 502, 503, 504, 529)))
    check("400 is NEVER retried - replaying it cannot succeed",
          400 not in _llm.RETRY_STATUS)
    check("408 is NEVER retried despite being a timeout",
          408 not in _llm.RETRY_STATUS)
    check("429 is the ONLY retryable 4xx",
          {c for c in _llm.RETRY_STATUS if 400 <= c < 500} == {429})
    check("the transient-400 special case is gone",
          not hasattr(_llm, "_is_transient_400")),

    # -- the other two negatives are universal too -------------------------
    section("negative-factor scope guards")
    control.reset_sandbox()
    tr_n = trace_mod.Trace(case_id="CASE-NEG", scenario="neg")
    nctx = {"case_id": "CASE-3001", "alert_id": "ALERT-3001",
            "asset_id": "SRV-APP-03"}

    bus_p1 = ToolBus(tr_n, nctx)
    bus_p1.invoke("get_packet_metadata", {"alert_id": "ALERT-5001", "reason": "x"})
    wrong = bus_p1.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "packet_benign", "citation": "c", "rationale": "r"}]})
    check("packet_benign refused when citing another alert's flow",
          wrong["status"] == "rejected")

    bus_p2 = ToolBus(tr_n, nctx)
    bus_p2.invoke("get_packet_metadata", {"alert_id": "ALERT-3001", "reason": "x"})
    right = bus_p2.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "packet_benign", "citation": "c", "rationale": "r"}]})
    check("packet_benign accepted for the case's own alert",
          right["status"] == "accepted")

    # ALERT-3001 is at 01:07:33Z; this window returns rows but excludes it.
    bus_l1 = ToolBus(tr_n, nctx)
    bus_l1.invoke("get_server_logs", {
        "asset_id": "SRV-APP-03",
        "time_range": "2026-09-11T01:08:00Z/2026-09-11T01:13:00Z", "reason": "x"})
    narrow = bus_l1.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "logs_clean", "citation": "c", "rationale": "r"}]})
    check("logs_clean refused when the window excludes the alert",
          narrow["status"] == "rejected")
    check("the refusal names the alert timestamp",
          "01:07:33" in " ".join(narrow.get("problems", [])))

    bus_l2 = ToolBus(tr_n, nctx)
    bus_l2.invoke("get_server_logs", {"asset_id": "SRV-APP-03", "reason": "x"})
    full_log = bus_l2.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "logs_clean", "citation": "c", "rationale": "r"}]})
    check("logs_clean accepted after reading the whole log",
          full_log["status"] == "accepted")

    # Positives stay existential - one witness is enough, no scope demanded.
    bus_e = ToolBus(tr_n, nctx)
    bus_e.invoke("get_server_logs", {
        "asset_id": "SRV-APP-03",
        "time_range": "2026-09-11T01:08:00Z/2026-09-11T01:13:00Z", "reason": "x"})
    pos = bus_e.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "logs_consistent", "citation": "c", "rationale": "r"}]})
    check("logs_consistent is existential and needs no window proof",
          pos["status"] == "accepted")


    # -- logs_clean scope widens once siblings are known -------------------
    section("logs_clean in correlated cases")
    from scenarios.definitions import ALERT_5002 as _A5002, EXPLOIT_ENTRIES as _EE

    def _s5_bus(window, sibling_outcome, call_related=True):
        control.reset_sandbox()
        control.inject_alert(_A5002, {"asset_id": "SRV-WEB-04", "entries": _EE})
        cases = sandbox.read_json(config.CASES)
        cases["CASE-5002"] = {"case_id": "CASE-5002", "alert_id": "ALERT-5002",
                              "asset_id": "SRV-WEB-04", "src_ip": "192.0.2.66",
                              "status": "CONCLUDED", "outcome": sibling_outcome,
                              "confidence": 0.95, "summary": "s",
                              "concluded_at": "x"}
        sandbox.write_json(config.CASES, cases)
        tr_s = trace_mod.Trace(case_id="CASE-5001", scenario="s5")
        b = ToolBus(tr_s, {"case_id": "CASE-5001", "alert_id": "ALERT-5001",
                           "asset_id": "SRV-WEB-04"})
        a = {"asset_id": "SRV-WEB-04", "reason": "x"}
        if window:
            a["time_range"] = window
        b.invoke("get_server_logs", a)
        if call_related:
            b.invoke("get_related_alerts", {"asset_id": "SRV-WEB-04", "reason": "x"})
        return b.invoke("submit_assessment", {
            "hypothesis": "h", "sufficiency": "s",
            "factors": [{"factor": "logs_clean", "citation": "c",
                         "rationale": "r"}]})

    narrow = _s5_bus("2026-09-11T04:30:00Z/2026-09-11T05:30:00Z", "INCONCLUSIVE")
    check("logs_clean refused when the window misses a known sibling alert",
          narrow["status"] == "rejected")
    check("that refusal names the sibling alert",
          "ALERT-5002" in " ".join(narrow.get("problems", [])))

    wide = _s5_bus(None, "INCONCLUSIVE")
    check("logs_clean accepted when the window spans the sibling too",
          wide["status"] == "accepted")

    breached = _s5_bus(None, "SUCCEEDED")
    check("logs_clean refused when a sibling case already concluded SUCCEEDED",
          breached["status"] == "rejected")
    check("that refusal cites the sibling's stored verdict",
          "CASE-5002" in " ".join(breached.get("problems", [])))

    unrelated = _s5_bus(None, "SUCCEEDED", call_related=False)
    check("behaviour unchanged before get_related_alerts has returned",
          unrelated["status"] == "accepted")

    # The positive twin stays existential.
    control.reset_sandbox()
    control.inject_alert(_A5002, {"asset_id": "SRV-WEB-04", "entries": _EE})
    tr_x = trace_mod.Trace(case_id="CASE-5001", scenario="s5")
    bx = ToolBus(tr_x, {"case_id": "CASE-5001", "alert_id": "ALERT-5001",
                        "asset_id": "SRV-WEB-04"})
    bx.invoke("get_server_logs", {
        "asset_id": "SRV-WEB-04",
        "time_range": "2026-09-11T04:30:00Z/2026-09-11T05:30:00Z", "reason": "x"})
    bx.invoke("get_related_alerts", {"asset_id": "SRV-WEB-04", "reason": "x"})
    pos = bx.invoke("submit_assessment", {
        "hypothesis": "h", "sufficiency": "s",
        "factors": [{"factor": "logs_consistent", "citation": "c",
                     "rationale": "r"}]})
    check("logs_consistent stays exempt in correlated cases",
          pos["status"] == "accepted")

    # -- the refuse/resubmit cycle is bounded ------------------------------
    section("bounded refusal loop")
    control.reset_sandbox()
    tr_i = trace_mod.Trace(case_id="CASE-IMP", scenario="imp")
    bus_i = ToolBus(tr_i, {"case_id": "CASE-1001", "alert_id": "ALERT-1001",
                           "asset_id": "SRV-WEB-01"})
    doomed = {"hypothesis": "h", "sufficiency": "s", "factors": [
        {"factor": "related_alert_corroborates", "citation": "none recorded",
         "rationale": "r"}]}
    outcomes = [bus_i.invoke("submit_assessment", dict(doomed))["status"]
                for _ in range(config.MAX_ASSESSMENT_REJECTIONS + 1)]
    check("the first N resubmissions are refused",
          outcomes[:config.MAX_ASSESSMENT_REJECTIONS]
          == ["rejected"] * config.MAX_ASSESSMENT_REJECTIONS)
    check("the loop terminates at the bound instead of arguing forever",
          outcomes[-1] == "accepted")
    # Defensive: under guard ablation no problems are raised, so no impasse is
    # reached. These assert the impasse SHAPE when one occurred, without
    # assuming it did - otherwise ablating an unrelated guard crashes the suite
    # instead of failing a check.
    imp = bus_i.impasse or {}
    check("the impasse is recorded, not silently swallowed",
          "related_alert_corroborates" in imp.get("dropped_factors", []))
    check("the unresolved objection is kept on the record",
          bool(imp.get("unresolved")))
    check("an impasse that drops everything scores the bare base",
          confidence.score((bus_i.assessment or {}).get("factors", [])).score
          == confidence.BASE)
    check("the impasse surfaces in the trace as its own step",
          any(s["kind"] == trace_mod.ERROR and s.get("status") == "impasse"
              for s in tr_i.steps))

    # -- action policy ---------------------------------------------------
    section("action policy (section 7.3)")
    check("SUCCEEDED -> block",
          confidence.decide_action("SUCCEEDED", 0.95, "high")["action"] == "block_ip")
    p = confidence.decide_action("INCONCLUSIVE", 0.65, "critical")
    check("INCONCLUSIVE + critical -> precautionary block",
          p["action"] == "block_ip" and p["precautionary"] is True)
    check("INCONCLUSIVE + non-critical -> no action",
          confidence.decide_action("INCONCLUSIVE", 0.65, "high")["action"] == "none")
    check("FAILED -> no action",
          confidence.decide_action("FAILED", 0.05, "critical")["action"] == "none")

    # -- schemas ---------------------------------------------------------
    section("tool schemas")
    names = {t["name"] for t in schemas.ANTHROPIC_TOOLS}
    check("all 10 agent-facing tools exposed", len(names) == 10)
    check("every schema has an implementation",
          names == set(tools.IMPLEMENTATIONS))
    check("every evidence tool requires a stated reason",
          all("reason" in t["input_schema"]["required"]
              for t in schemas.ANTHROPIC_TOOLS if t["name"] != "submit_assessment"))
    check("OpenAI conversion produces function shape",
          schemas.openai_tools(["get_alert"])[0]["function"]["name"] == "get_alert")
    check("control-plane tools are NOT exposed to the agent",
          not names & {"inject_new_evidence", "inject_alert", "human_override",
                       "reset_sandbox"})

    # -- control plane ---------------------------------------------------
    section("control plane")
    control.reset_sandbox()
    ev = control.inject_new_evidence(
        "CASE-3001", {"asset_id": "SRV-APP-03",
                      "entries": [{"ts": "2026-09-11T03:14:50Z", "source": "ueba",
                                   "event_type": "lateral_movement", "raw": "test"}]})
    after_logs = tools.get_server_logs(ctx, "SRV-APP-03")
    check("inject_new_evidence appends to server logs",
          any(e.get("injected") for e in after_logs["entries"]))
    check("injected event is a NEW_EVIDENCE event", ev["kind"] == "NEW_EVIDENCE")
    check("human_override rejects a bad decision",
          _raises(lambda: control.human_override("C", "maybe", "j")))

    # -- guardrail 6 -----------------------------------------------------
    section("guardrail 6 (override wins)")
    case = agent.Case(case_id="CASE-G6", alert_id="ALERT-4001",
                      asset_id="SRV-FIN-07", src_ip="198.51.100.88", scenario="g6")
    case.status = agent.OVERRIDDEN_BENIGN
    check("overridden case reports override_active", case.override_active is True)
    tr2 = trace_mod.Trace(case_id="CASE-G6", scenario="g6")
    inv = agent.Investigation(case, tr2)
    c = agent.Conclusion(outcome="SUCCEEDED", confidence=0.95, score=0.95,
                         hypothesis="h", sufficiency="s", disconfirming="d",
                         scoring=confidence.score(f("version_in_range",
                                                    "logs_consistent",
                                                    "exfil_indicators"), []).to_dict())
    case.conclusions.append(c)
    inv.act_and_verify(c)
    check("no automated re-block on an overridden case",
          tools.check_firewall_state(ctx, "198.51.100.88")["blocked"] is False)
    check("skip is recorded in the trace",
          any(s["kind"] == trace_mod.ACTION and s.get("skipped") for s in tr2.steps))

    # -- report ----------------------------------------------------------
    section("report rendering (section 9)")
    md = report.render(case, tr2, "guardrail check")
    for n, heading in [(1, "Alert(s) involved"), (2, "Evidence chain"),
                       (3, "Outcome and confidence"), (4, "Action taken"),
                       (5, "Verification"), (6, "Reconsideration events"),
                       (7, "Degraded-evidence note")]:
        check(f"report has section {n}: {heading}", f"## {n}. {heading}" in md)

    # -- summary ---------------------------------------------------------
    print()
    failed = 0
    for status, name, detail in _results:
        if not status:
            print(f"\n{name}")
            continue
        if status == FAIL:
            failed += 1
        print(f"  [{status}] {name}" + (f"  {detail}" if detail else ""))
    total = sum(1 for s, _, _ in _results if s)
    print(f"\n{total - failed}/{total} offline checks passed.")
    if failed:
        print("\nNOTE: the agent loop itself is NOT covered here - it needs a model.")
        return 1
    print("\nEverything except the model loop is verified. "
          "Run `python run_all.py` with SOC_API_KEY set to exercise the agent.")
    return 0


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


if __name__ == "__main__":
    raise SystemExit(offline_selfcheck())
