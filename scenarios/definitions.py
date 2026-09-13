"""The evidence scenarios - CLAUDE.md section 4.

Section 4 says six and says do not add a seventh; section 14 lists a seventh
under "stop and ask". Scenario 7 was added after that question was put to the
owner and answered, behind a revert gate: if it perturbs scenarios 1-6 at all,
it comes out. It exists because the problem statement requires correlating
asset, vulnerability, CONFIGURATION and response, and configuration had no
source in the original schema.

Each scenario is a fixture set plus an expected trajectory. The scenario code
below drives the OUTSIDE WORLD only (what evidence arrives when, which human
intervenes). It never tells the agent what to conclude and never dictates a
tool order - that remains the model's decision at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from soc_agent import agent, control, trace as trace_mod
from soc_agent.agent import Case, Investigation


@dataclass
class Expectation:
    """What run_all.py asserts. Deliberately coarse: outcome class, whether an
    action fired, whether reconsideration fired, and which tools were among
    those called. Not an exact tool sequence - that would re-introduce the
    scripted behaviour guardrail 2 forbids."""
    outcome: str
    action_fired: bool
    reconsideration_fired: bool
    expected_tools: list[str] = field(default_factory=list)
    final_status: str | None = None
    precautionary: bool | None = None
    notes: str = ""
    # Asserting tool NAMES alone let a scenario pass while reasoning wrongly:
    # get_vulnerabilities was called, just on the wrong service (Toknow P-016).
    # These pin the reasoning path without pinning tool ORDER, which would
    # re-introduce the scripted behaviour guardrail 2 forbids.
    expected_tool_args: list[tuple[str, str, str]] = field(default_factory=list)
    initial_outcome: str | None = None
    required_factors: list[str] = field(default_factory=list)
    # (tool, minimum count, phase) - a retry split across the reconsideration
    # boundary is not the retry behaviour section 4.6 specifies.
    min_calls: list[tuple[str, int, str]] = field(default_factory=list)
    gather_after_reconsider: bool = False


@dataclass
class Scenario:
    key: str
    title: str
    summary: str
    run: Callable[[trace_mod.Trace], dict[str, Any]]
    expect: Expectation
    fail_tools: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
def _case(alert_id: str, asset_id: str, src_ip: str, case_id: str,
          scenario: str) -> Case:
    return Case(case_id=case_id, alert_id=alert_id, asset_id=asset_id,
                src_ip=src_ip, scenario=scenario)


# --- Scenario 1: false alarm, patched --------------------------------------
def run_s1(tr: trace_mod.Trace) -> dict[str, Any]:
    case = _case("ALERT-1001", "SRV-WEB-01", "203.0.113.45", "CASE-1001", "1")
    inv = agent.investigate(case, tr)
    return {"cases": [case], "primary": case, "investigation": inv}


# --- Scenario 2: true positive, unpatched ----------------------------------
def run_s2(tr: trace_mod.Trace) -> dict[str, Any]:
    case = _case("ALERT-2001", "SRV-DB-02", "198.51.100.23", "CASE-2001", "2")
    inv = agent.investigate(case, tr)
    return {"cases": [case], "primary": case, "investigation": inv}


# --- Scenario 3: delayed evidence, re-hypothesise --------------------------
LATERAL_ENTRIES = [
    {"ts": "2026-09-11T03:14:48Z", "source": "process", "event_type": "process_spawn",
     "raw": "bash[69881]: svc_app executed: ssh svc_app@10.20.2.99 -o StrictHostKeyChecking=no"},
    {"ts": "2026-09-11T03:14:50Z", "source": "ueba", "event_type": "lateral_movement",
     "raw": ("Lateral movement detected: SRV-APP-03 -> 10.20.2.99 (SRV-DB-09) using "
             "service account svc_app, outside its normal access pattern. "
             "Credential material appears reused from the earlier session.")},
]


def run_s3(tr: trace_mod.Trace) -> dict[str, Any]:
    case = _case("ALERT-3001", "SRV-APP-03", "203.0.113.77", "CASE-3001", "3")
    inv = agent.investigate(case, tr)

    event = control.inject_new_evidence(
        case.case_id,
        {"asset_id": "SRV-APP-03", "entries": LATERAL_ENTRIES,
         "detail": ("Delayed log shipping delivered two entries for SRV-APP-03 that "
                    "post-date your investigation. They indicate lateral movement "
                    "from SRV-APP-03 to a second host, 10.20.2.99 (SRV-DB-09), using "
                    "the svc_app service account.")})
    agent.reconsider(inv, event)
    return {"cases": [case], "primary": case, "investigation": inv}


# --- Scenario 4: human override --------------------------------------------
def run_s4(tr: trace_mod.Trace) -> dict[str, Any]:
    case = _case("ALERT-4001", "SRV-FIN-07", "198.51.100.88", "CASE-4001", "4")
    inv = agent.investigate(case, tr)

    event = control.human_override(
        case.case_id, "benign",
        ("Confirmed as an authorised red-team exercise. 198.51.100.88 is the "
         "contracted tester's egress address; engagement ref PT-2026-0914. The "
         "data access was in-scope and the extract was destroyed under the "
         "engagement terms."))
    agent.reconsider(inv, event)
    return {"cases": [case], "primary": case, "investigation": inv}


# --- Scenario 5: multi-alert correlation -----------------------------------
ALERT_5002 = {
    "id": "ALERT-5002",
    "timestamp": "2026-09-11T07:14:02Z",
    "signature": "ET WEB_SERVER SQL Injection Attempt UNION SELECT",
    "sid": 2006446,
    "src_ip": "192.0.2.66",
    "dst_ip": "10.20.1.44",
    "dst_port": 3306,
    "protocol": "TCP",
    "asset_id": "SRV-WEB-04",
    "severity_label": "high",
    "sensor": "suricata-dmz-01",
}

EXPLOIT_ENTRIES = [
    {"ts": "2026-09-11T07:14:02Z", "source": "mysql/general", "event_type": "db_query",
     "raw": ("Query  SELECT id,title FROM articles WHERE id=3 UNION SELECT "
             "user,authentication_string FROM mysql.user--")},
    {"ts": "2026-09-11T07:14:31Z", "source": "mysql/slow", "event_type": "db_query",
     "raw": ("Query_time: 26.700  Rows_sent: 38402  Rows_examined: 38402  "
             "SELECT email,password_hash,address FROM portal_users")},
    {"ts": "2026-09-11T07:15:09Z", "source": "mysql/error", "event_type": "db_status",
     "raw": "Note  Connection from 192.0.2.66 closed after 28.9s, 1743908 bytes sent"},
]


def run_s5(tr: trace_mod.Trace) -> dict[str, Any]:
    # Case A - the quiet one.
    case_a = _case("ALERT-5001", "SRV-WEB-04", "192.0.2.66", "CASE-5001", "5")
    tr.case_id = case_a.case_id
    inv_a = agent.investigate(case_a, tr)

    # Alert B arrives later and opens its OWN case (settled decision 2.5).
    control.inject_alert(ALERT_5002,
                         {"asset_id": "SRV-WEB-04", "entries": EXPLOIT_ENTRIES})
    case_b = _case("ALERT-5002", "SRV-WEB-04", "192.0.2.66", "CASE-5002", "5")
    tr.case_id = case_b.case_id
    tr.add(trace_mod.EVENT, event_kind="NEW_ALERT",
           detail=("Second alert ALERT-5002 raised on SRV-WEB-04, same source IP as "
                   "the earlier alert. Opening case CASE-5002."))
    inv_b = agent.investigate(case_b, tr)

    # Case B's conclusion bears on case A -> case A reconsiders.
    tr.case_id = case_a.case_id
    conclusion_b = case_b.current
    event = control.related_case_event(
        case_a.case_id, case_b.case_id,
        (f"A later alert on the same asset, ALERT-5002 (case {case_b.case_id}), has "
         f"concluded: {conclusion_b.summary() if conclusion_b else 'n/a'}. It came "
         f"from the same source IP {case_a.src_ip} that produced the activity in "
         f"this case. Re-examine your conclusion for case {case_a.case_id} in that "
         f"light."))
    agent.reconsider(inv_a, event)
    return {"cases": [case_a, case_b], "primary": case_a,
            "investigation": inv_a, "secondary": case_b}


# --- Scenario 6: tool failure / degraded recovery --------------------------
def run_s6(tr: trace_mod.Trace) -> dict[str, Any]:
    case = _case("ALERT-6001", "SRV-DB-05", "203.0.113.150", "CASE-6001", "6")
    inv = agent.investigate(case, tr, fail_tools=["get_server_logs"])
    return {"cases": [case], "primary": case, "investigation": inv}



# --- Scenario 7: configuration prevents exploitation -----------------------
# The host IS vulnerable on paper and the logs DO look consistent with a
# successful injection - the WAF ran in DetectionOnly and the statements reached
# the database. Nothing in the alert, the version join or the logs distinguishes
# this from scenario 2. Only the configuration does: the portal's database
# account holds no privilege on the table the injection targets, so the read
# returns nothing however well-formed it is.
def run_s7(tr: trace_mod.Trace) -> dict[str, Any]:
    case = _case("ALERT-7001", "SRV-HR-11", "198.51.100.203", "CASE-7001", "7")
    inv = agent.investigate(case, tr)
    return {"cases": [case], "primary": case, "investigation": inv}


SCENARIOS: dict[str, Scenario] = {
    "1": Scenario(
        key="1", title="False alarm, patched host",
        summary=("A critical-labelled SQLi signature fires against SRV-WEB-01. The "
                 "host runs MySQL 8.0.36, outside every affected range in the KB, "
                 "and its logs show the WAF returned 403. The alert is loud and "
                 "wrong."),
        run=run_s1,
        expect=Expectation(
            outcome="FAILED", action_fired=False, reconsideration_fired=False,
            expected_tools=["get_alert", "get_asset_info", "get_vulnerabilities",
                            "get_server_logs", "submit_assessment"],
            expected_tool_args=[("get_vulnerabilities", "service_name", "mysql",
                                 "pre_conclusion")],
            required_factors=["version_patched"],
            final_status="CONCLUDED",
            notes="Severity label must not drive the verdict."),
    ),
    "2": Scenario(
        key="2", title="True positive, unpatched host",
        summary=("The same signature against SRV-DB-02, which runs MySQL 5.7.21 - "
                 "inside CVE-2023-21980's range. Logs show information_schema "
                 "enumeration and a 48k-row customer export; 2.4 MB left the host."),
        run=run_s2,
        expect=Expectation(
            outcome="SUCCEEDED", action_fired=True, reconsideration_fired=False,
            expected_tools=["get_alert", "get_asset_info", "get_vulnerabilities",
                            "get_server_logs", "submit_assessment", "block_ip",
                            "check_firewall_state"],
            final_status="CONCLUDED", precautionary=False,
            notes="Block must be verified by re-reading firewall state from disk."),
    ),
    "3": Scenario(
        key="3", title="Delayed evidence, re-hypothesise",
        summary=("Evidence on SRV-APP-03 is genuinely ambiguous at T0 - the injected "
                 "SQL errored out. The agent concludes INCONCLUSIVE. Late log "
                 "shipping then reveals lateral movement to a SECOND host, and the "
                 "agent must go and investigate that host, not merely re-score."),
        run=run_s3,
        expect=Expectation(
            outcome="SUCCEEDED", action_fired=True, reconsideration_fired=True,
            expected_tools=["get_server_logs", "submit_assessment"],
            expected_tool_args=[("get_vulnerabilities", "service_name", "mysql",
                                 "pre_conclusion"),
                                ("get_asset_info", "asset_id", "SRV-DB-09")],
            initial_outcome="INCONCLUSIVE",
            required_factors=["version_in_range"],
            gather_after_reconsider=True,
            final_status="CONCLUDED",
            notes="Highest-value adaptation demo: must GATHER after the injection."),
    ),
    "4": Scenario(
        key="4", title="Human override",
        summary=("The agent correctly concludes SUCCEEDED on SRV-FIN-07 and blocks "
                 "the source. A human analyst then rules it benign - an authorised "
                 "red-team exercise. The agent unblocks, records both views side by "
                 "side, and must not re-block."),
        run=run_s4,
        expect=Expectation(
            outcome="SUCCEEDED", action_fired=True, reconsideration_fired=True,
            expected_tools=["submit_assessment", "block_ip", "unblock_ip"],
            final_status="OVERRIDDEN_BENIGN",
            notes="Prior conclusion preserved, never overwritten. Guardrail 6."),
    ),
    "5": Scenario(
        key="5", title="Multi-alert correlation",
        summary=("Alert A on SRV-WEB-04 is failed-login noise - INCONCLUSIVE. Alert "
                 "B later, same source IP, opens its own case. While working case B "
                 "the agent finds case A via get_related_alerts and correlates. Case "
                 "A then reconsiders on the strength of case B."),
        run=run_s5,
        expect=Expectation(
            outcome="SUCCEEDED", action_fired=True, reconsideration_fired=True,
            expected_tools=["get_related_alerts", "submit_assessment"],
            expected_tool_args=[("get_related_alerts", "asset_id", "SRV-WEB-04",
                                 "pre_conclusion", "CASE-5002")],
            initial_outcome="INCONCLUSIVE",
            gather_after_reconsider=True,
            final_status="CONCLUDED",
            notes="Two cases, one trace. Case A shows a reconsideration entry."),
    ),
    "6": Scenario(
        key="6", title="Tool failure, degraded recovery",
        summary=("get_server_logs is configured to fail on SRV-DB-05, a critical "
                 "asset. The agent must notice the failure rather than read it as "
                 "'no evidence of attack', retry, route to alternates, and let the "
                 "gap cap its confidence - landing INCONCLUSIVE with a precautionary "
                 "block instead of the SUCCEEDED the raw evidence would imply."),
        run=run_s6,
        expect=Expectation(
            outcome="INCONCLUSIVE", action_fired=True, reconsideration_fired=False,
            expected_tools=["get_server_logs", "get_packet_metadata",
                            "submit_assessment", "block_ip"],
            expected_tool_args=[("get_packet_metadata", "alert_id", "ALERT-6001")],
            min_calls=[("get_server_logs", 2, "pre_conclusion")],
            required_factors=["version_in_range"],
            final_status="CONCLUDED", precautionary=True,
            notes="Degraded clamp must be cited as the reason for the ceiling."),
        fail_tools=["get_server_logs"],
    ),
    "7": Scenario(
        key="7", title="Configuration prevents exploitation",
        summary=("A critical SQLi signature fires against SRV-HR-11. The host runs "
                 "MySQL 5.7.24, INSIDE CVE-2023-21980's range, and the logs show the "
                 "injected UNION SELECT reaching the database - the WAF was in "
                 "DetectionOnly and did not block. On version and logs alone this "
                 "looks like scenario 2. The portal's database account holds SELECT "
                 "on hr_public only and no privilege on the targeted table."),
        run=run_s7,
        expect=Expectation(
            outcome="FAILED", action_fired=False, reconsideration_fired=False,
            expected_tools=["get_alert", "get_asset_info", "get_vulnerabilities",
                            "get_configuration", "get_server_logs",
                            "submit_assessment"],
            expected_tool_args=[
                ("get_vulnerabilities", "service_name", "mysql", "pre_conclusion"),
                ("get_configuration", "asset_id", "SRV-HR-11", "pre_conclusion"),
            ],
            final_status="CONCLUDED",
            notes=("Stage 1 (tool only, no factor) is EXPECTED TO FAIL this "
                   "expectation: with version_in_range and logs_consistent and no "
                   "term for configuration, the scoring model can only reach "
                   "SUCCEEDED. That failure is the diagnosis - it shows the "
                   "missing term - and stage 2 adds the factor that closes it."),
        ),
    ),
}
