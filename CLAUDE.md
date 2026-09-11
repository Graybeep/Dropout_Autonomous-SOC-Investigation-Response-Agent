# CLAUDE.md — Autonomous SOC Investigation & Response Agent (PS9)

This file governs how Claude Code should build this project. Read it fully before writing any code. If a decision isn't covered here, stop and ask rather than assuming — see Section 13.

**Hard constraint: this ships in 24–34 hours.** Section 12 is the schedule with cut-gates. Every section below has been scoped to fit that. Do not expand scope.

---

## 1. What we're building

An autonomous SOC agent that takes a simulated NIDS/Snort/Suricata alert and determines whether the attack **actually succeeded**, by correlating alert data with asset, vulnerability, configuration, and log evidence — not by trusting the alert's severity label. It then takes a sandboxed firewall action when justified, verifies the action took effect, and reconsiders its conclusion when new evidence, a tool failure, or a human override arrives.

Judged on this rubric:

| Criterion | Weight |
|---|---|
| Agentic workflow & autonomy | 25% |
| Tool/environment interaction | 15% |
| Adaptation & failure recovery | 15% |
| Technical implementation | 15% |
| Problem relevance & innovation | 10% |
| Prototype functionality & UX | 10% |
| Evaluation, verification & robustness | 10% |

**Implication:** autonomy + tool interaction + adaptation + verification = 65%. The agent's *reasoning trace* (what it decided to check, why, and how it changed its mind) is worth more than the polish of any single component. Do not sacrifice trace legibility for code cleverness, and do not sacrifice it for UI.

Note that "Adaptation & failure recovery" is two things. Scenarios 3, 4 and 5 cover adaptation. **Scenario 6 covers recovery.** Do not skip it — it is the cheapest scoring evidence in this entire build.

---

## 2. Settled decisions (previously open — do not re-litigate)

These were flagged as "stop and ask" in an earlier draft. They are answered. Build against them.

1. **Reasoning engine: Claude's native tool-use API.** The model receives the tool schemas and chooses calls. Hand-rolled Python decision logic with the LLM only generating prose is forbidden — it is exactly the failure mode guardrail 2 exists to prevent, and it forfeits the 25% autonomy score.
2. **Model:** use the smallest model that holds the loop reliably. Start with Sonnet. If tool-call ordering is erratic after prompt tuning, escalate — but escalate late, not at hour 2.
3. **UI:** single-file HTML + vanilla JS. No framework, no build step, no server. It loads a saved trace JSON and replays it. See Section 10.
4. **Confidence:** deterministic scoring function, not an LLM-emitted float. See Section 7.
5. **Case identity:** each alert opens its own case. Correlation across alerts happens through `get_related_alerts`, not through pre-merging cases in the fixtures.

---

## 3. Non-negotiable guardrails

1. **All actions stay inside the sandbox.** No real network calls, no real firewall, no real credentials. Every "action" is a mutation to a local JSON state file.
2. **The agent decides tool-call order at runtime.** Do not hardcode a fixed sequence. If you catch yourself writing `if alert.severity == 'high': check_cve(); check_logs()` as the *decision* logic (as opposed to a tool implementation), stop — that's scripted, not agentic.
3. **Never fabricate evidence.** If a tool has no data, it returns an explicit "no data" result. The agent reasons under that uncertainty; it does not invent a plausible-sounding answer.
4. **The firewall block must be real within the sandbox.** `block_ip()` mutates `firewall_state.json`. `check_firewall_state()` reads that same file. If verification doesn't actually depend on the mutation, the loop is theater — flag it, don't ship it.
5. **Every conclusion cites the evidence it used.** The report format (Section 9) is mandatory.
6. **Human override always wins.** The agent must not re-trigger an opposing automated action in the same case without a new explicit trigger.
7. **Fixtures are immutable; a working copy is not.** See Section 5.

---

## 4. Evidence scenarios — six, fixed

Each is a fixture set + an expected trajectory. **Do not add a seventh.** Each must be testable in isolation.

**Scenario 1 — False alarm, patched.**
SQLi-signature alert on an asset running a version outside any CVE's affected range. Server logs clean. Expected: `FAILED`, high confidence, no action.

**Scenario 2 — True positive, unpatched.**
Same signature; running version falls inside a CVE's affected range. Server logs show anomalous DB queries; packet metadata shows exfil-shaped payload. Expected: `SUCCEEDED`, high confidence, `block_ip` executed and verified in firewall state.

**Scenario 3 — Delayed evidence / reconsideration.**
At T0 evidence is ambiguous. Agent concludes `INCONCLUSIVE`. At T1 a lateral-movement log entry is injected via `inject_new_evidence`. The agent must re-open the case, **re-hypothesize** (the new evidence points at a second host — it should want to check that host's asset info and logs), gather, and flip to `SUCCEEDED`.
This is the highest-value adaptation demo. Its value comes from the agent *gathering new evidence* after the injection, not just re-scoring what it already had.

**Scenario 4 — Human override.**
Agent reaches `SUCCEEDED` and blocks. A `human_override(case_id, decision, justification)` event arrives. Behaviour is fully specified — no "as appropriate":
- `decision="benign"` → call `unblock_ip`, record override + prior conclusion, set case to `OVERRIDDEN_BENIGN`, do not re-block.
- `decision="malicious"` → retain block, record override, set case to `OVERRIDDEN_MALICIOUS`.
In both cases the prior conclusion is preserved in the report side-by-side, never overwritten.

**Scenario 5 — Multi-alert correlation.**
Alert A on asset X yields `INCONCLUSIVE`. Alert B arrives later on asset X and opens **its own case**. While investigating case B, the agent calls `get_related_alerts(asset_id)`, discovers case A, reads case A's stored conclusion, and correlates. Both cases end `SUCCEEDED`; case A shows a reconsideration entry triggered by case B.

**Scenario 6 — Tool failure / degraded recovery.** *(new — this is the "failure recovery" half of a 15% criterion)*
`get_server_logs` is configured to fail for this scenario (raises, or returns `{"status":"unavailable","reason":"log collector timeout"}`). The agent must:
1. notice the failure rather than treating it as "no evidence of attack",
2. retry once,
3. on second failure, route to an alternate source (`get_packet_metadata`, `get_related_alerts`),
4. conclude `INCONCLUSIVE` **citing the tool failure as the reason for the ceiling**, and
5. apply the precautionary-containment branch if the asset is critical.

Implementation: a `fail_tools: ["get_server_logs"]` key in the scenario config that the tool wrapper reads. Ten lines. Do not build a general fault-injection framework.

---

## 5. Data schema (sandbox fixtures)

Flat JSON, one file per evidence source, human-readable — judges may open them.

- `alerts.json` — `id, timestamp, signature, src_ip, dst_ip, asset_id, severity_label`
- `packet_logs.json` — keyed by `alert_id`: payload size, protocol anomalies, exfil indicators
- `asset_inventory.json` — `asset_id, hostname, ip, criticality, os_version, service_versions`
- `cve_kb.json` — **keyed by service name only**: `service → [{cve_id, affected_versions, fixed_in, cvss, description}]`
- `server_logs.json` — keyed by `asset_id`: timestamped entries (queries, auth events, process spawns)
- `firewall_state.json` — **mutable at runtime**

### 5.1 `cve_kb.json` must NOT contain a `patched` boolean

A CVE knowledge base does not know whether *your* host is patched. If the KB pre-computes that answer, `get_vulnerabilities()` hands the agent a verdict and the version-range join — the exact correlation the problem statement asks for — never happens in the trace.

The agent must: call `get_asset_info` to learn the running version, call `get_vulnerabilities` to get affected ranges, and reason about whether the version falls in range. That reasoning step is visible in the trace and is graded.

### 5.2 Fixture immutability and reset

`inject_new_evidence` writes to server logs and `block_ip` writes firewall state. After one run the working set is dirty and the next run doesn't reproduce.

- `fixtures/seed/` — pristine, read-only, committed.
- `fixtures/run/` — working copy, gitignored, all tools read/write here.
- `reset_sandbox()` — `rm -rf fixtures/run && cp -r fixtures/seed fixtures/run`. Called at the start of every scenario run, including every demo run.

Build this in step 1. You will need it during rehearsal and you do not want to be writing it at hour 30.

---

## 6. Architecture — agent state machine

```
INGEST_ALERT
   |
   v
HYPOTHESIZE  (what evidence would confirm or deny "attack succeeded"?
              what would FALSIFY the leading hypothesis?)
   |
   v
GATHER_EVIDENCE (loop: agent picks a tool call -> assess sufficiency -> pick next, or stop)
   |
   v
DETERMINE_OUTCOME (SUCCEEDED | FAILED | INCONCLUSIVE, + score, + evidence citations)
   |
   v
ACT (block_ip / precautionary block, per Section 7 action policy)
   |
   v
VERIFY (re-query firewall_state and related evidence to confirm effect)
   |
   v
[event: NEW_EVIDENCE | HUMAN_OVERRIDE | RELATED_CASE] --> reconsider() --> back to HYPOTHESIZE
   |
   v
REPORT
```

### 6.1 `reconsider()` re-enters at HYPOTHESIZE, not DETERMINE_OUTCOME

An earlier draft routed new evidence straight to DETERMINE_OUTCOME. That is wrong, and it caps Scenario 3 at "the confidence number moved."

When a lateral-movement log lands, the correct analyst response is *"now go check that other host."* That requires new evidence gathering. Re-entering at HYPOTHESIZE lets the agent form a new hypothesis, pick new tools, and gather — which is the version of adaptation that scores.

Keep the single-function discipline: `reconsider(case_state, new_event)` is one function, called by the delayed-evidence path, the override path, and the related-case path. Do not write separate code paths for "first conclusion" and "revised conclusion."

Override is the one branch that short-circuits: `reconsider()` with a `human_override` event skips gathering, applies Scenario 4's specified behaviour, and goes to REPORT.

---

## 7. Decision logic

### 7.1 Sufficiency check
After each tool call the agent must explicitly state, in its output, whether it has enough evidence to classify or needs another source, and why. This string goes into the trace and is rendered in the UI.

### 7.2 Deterministic confidence scoring

Confidence is **computed in Python from the evidence classes the agent found**, not emitted by the LLM. The agent still decides what evidence exists and what it means; the arithmetic is reproducible. This makes demo runs stable and gives you a one-line answer when a judge asks where 0.85 came from.

Start at `S = 0.50` (no prior). Apply each factor at most once:

| Evidence finding | Δ |
|---|---|
| Running version falls inside a CVE's affected range | +0.25 |
| Server logs show activity consistent with the signature | +0.25 |
| Packet metadata shows exfil / payload-anomaly indicators | +0.15 |
| A related alert on the same asset corroborates | +0.15 |
| Running version outside all affected ranges (patched) | −0.30 |
| Server logs clean across the relevant window | −0.25 |
| Packet metadata benign | −0.10 |

Clamp to `[0.05, 0.95]`.
**Degraded-evidence clamp:** if ≥1 evidence source returned unavailable/failed, additionally clamp to `[0.35, 0.65]`. This is what forces Scenario 6 to `INCONCLUSIVE` for the right reason, and it must appear in the report as an explicit ceiling.

**Outcome mapping:**
- `S ≥ 0.75` → `SUCCEEDED`, confidence = `S`
- `S ≤ 0.25` → `FAILED`, confidence = `1 − S`
- otherwise → `INCONCLUSIVE`, confidence reported as `S` with the ambiguity flagged

### 7.3 Action policy
- `SUCCEEDED` and `S ≥ 0.75` → `block_ip`
- `INCONCLUSIVE` and asset `criticality == "critical"` → `block_ip`, **tagged `precautionary: true`** in state and report, with an explicit note that it is containment under uncertainty, not a verdict
- `INCONCLUSIVE` and non-critical asset → no action, flagged for analyst review
- `FAILED` → no action
- A `human_override` supersedes all of the above for that case until a new triggering event.

### 7.4 Disconfirmation step — *build if on schedule, cut if behind at H18*

Before concluding, the agent must state what evidence would **falsify** its leading hypothesis, and check for it if it hasn't already.

This is the only genuine differentiator in the build — every other team will submit a faithful implementation of the problem statement. It's one extra instruction in the system prompt plus one extra loop turn, it mirrors how real analysts avoid confirmation bias, and it makes Scenario 1 much stronger (the agent isn't merely failing to find evidence — it actively went looking for the thing that would prove the alert wrong).

It is nonetheless the first thing to cut. Everything else in this doc is load-bearing for a scored criterion.

---

## 8. Tools

Agent-facing (exposed as Claude tool-use schemas — **not** helper functions the orchestrator calls on the agent's behalf):

- `get_alert(alert_id)`
- `get_packet_metadata(alert_id)`
- `get_asset_info(asset_id)`
- `get_vulnerabilities(service_name)` — returns CVE entries with affected ranges; does **not** resolve patch status
- `get_server_logs(asset_id, time_range)`
- `get_related_alerts(asset_id)` — returns other alerts on the asset **and their case IDs / stored conclusions** (Scenario 5 depends on this)
- `check_firewall_state(ip)`
- `block_ip(ip, reason, precautionary=False)`
- `unblock_ip(ip, reason)`

Demo/control-plane (yours, not the agent's):
- `inject_new_evidence(case_id, evidence)`
- `inject_alert(alert)` — opens a new case; needed for Scenario 5
- `human_override(case_id, decision, justification)` — `decision ∈ {"benign","malicious"}`
- `reset_sandbox()`

Every agent-facing tool goes through one wrapper that (a) logs the call and result to the trace, (b) checks the scenario's `fail_tools` list, (c) returns `{"status":"no_data"}` rather than empty/null when a lookup misses.

---

## 9. Report format (mandatory per case)

1. Alert(s) involved
2. Evidence chain: what was retrieved, in what order, **and the agent's stated reason for each step**
3. Outcome + confidence score, with the scoring factors that produced it itemised, and evidence citations
4. Action taken (if any), justification, and `precautionary` flag if set
5. Verification result: what was re-checked, what it showed
6. Reconsideration events: prior conclusion → trigger → new conclusion, **side by side, never overwritten**
7. Degraded-evidence note: any tool that failed or returned no data, and the confidence ceiling it imposed

Scenarios 3, 5 and 6 must each show a visible before/after or explicit-limitation block. That's the artifact that proves adaptation, correlation and recovery to a judge who isn't reading your code.

---

## 10. UI — trace replay, not live streaming

**Build a single-file `viewer.html`:** a dropdown of the six scenarios, loading each one's saved trace JSON, rendering it as a vertical timeline of `thought → tool call → result → sufficiency assessment → conclusion`, with reconsideration events visually marked as a fork.

Add a "play" control that reveals steps at ~400ms intervals so it *looks* live for the demo.

**Do not build live streaming.** It costs 3–4× as much, and a live agent loop on stage can hang, rate-limit, or produce an off-script trajectory in front of judges. Replaying saved traces is deterministic and rehearsable. Run the agent live once in the terminal to prove it's real, then demo from the viewer.

If you are behind at H20: drop the play animation, keep the static timeline.

---

## 11. Evaluation harness — minimal

`run_all.py`:
- calls `reset_sandbox()` before each scenario
- runs all six
- asserts per scenario: final outcome class, whether an action fired, whether reconsideration fired, and that the expected tools were among those called
- writes each trace to `traces/scenario_N.json` (these feed the viewer)
- prints a pass/fail table

That's the whole harness. **Run it three times before the demo** and look at variance in tool-call ordering and outcome. If a scenario is flaky, the fix is prompt-side (tighten the sufficiency instruction) — the deterministic confidence function in 7.2 already removes the largest source of drift.

Do not build statistical reporting, N=10 sweeps, or a metrics dashboard. Not in this budget.

---

## 12. Build order and schedule

Hours are aggressive. The buffer at the end is real, not padding — an agent loop that misbehaves at H6 will consume it.

| Window | Step | Cut-gate |
|---|---|---|
| H0–H2 | Seed fixtures for all 6 scenarios + all tool functions + trace wrapper + `reset_sandbox()` | Safe to delegate fully to Claude Code. If past H3, you are over-designing fixtures — simplify. |
| H2–H5 | Agent loop on native tool use. Scenarios 1 & 2 passing end to end. | **Hard gate.** If the loop isn't choosing tools sensibly by H6, stop adding scenarios and fix the system prompt. Everything downstream depends on this. |
| H5–H6 | `block_ip` → `check_firewall_state` verification; confirm the mutation is real and re-read from disk | |
| H6–H9 | `reconsider()` + Scenario 3 in isolation | If this isn't working by H10, fall back to re-entering at DETERMINE_OUTCOME instead of HYPOTHESIZE. Weaker demo, still scores. |
| H9–H10 | Scenario 4 override | Cheap once `reconsider()` exists |
| H10–H12 | Scenario 5 multi-alert correlation | |
| H12–H13 | Scenario 6 tool failure | Cheapest points on the board. Do not skip even if behind. |
| H13–H16 | Report generation across all six | |
| H16–H19 | `viewer.html` | At H20 with no viewer: ship the JSON traces pretty-printed in a terminal and spend the time on rehearsal instead. |
| H19–H20 | `run_all.py` + three stability runs | |
| H20–H22 | Disconfirmation step (7.4) | **Cut here first** if behind |
| H22–H24 | Integration, README, demo rehearsal, buffer | |

**Checkpoint rule:** at H12, if Scenarios 1–4 aren't passing, cut Scenario 5 and go straight to report + viewer. A working four-scenario demo with a legible trace beats a six-scenario build with no UI and no rehearsal.

---

## 13. Coding standards

- Python for agent/orchestration.
- Tool functions pure with respect to their JSON files: explicit read/write against `fixtures/run/`, no hidden global state.
- Every tool call and every reasoning string logged to a structured trace (list of dicts → JSON), not printed. The UI and the report both consume this trace; it is the single source of truth for both.
- **No mock outcome logic.** `if scenario == 3: return flipped_conclusion` anywhere in the codebase is a disqualifying bug. Outcomes come from the agent re-running the real loop over real fixture evidence.
- Commit after each completed step in Section 12 so you can roll back a bad hour.

---

## 14. When to stop and ask

Section 2 settled the previously-open questions. What remains:

- Any seventh evidence scenario.
- Any change to the confidence factors or thresholds in Section 7.2/7.3 — these are tuned so that all six scenarios land on their expected outcome. Changing one number silently breaks another scenario.
- Anything that would put a fixed tool-call sequence into the decision path.

If uncertain about anything else, prefer asking over assuming — an assumed shortcut here tends to quietly convert "agentic" into "scripted," which is the one failure mode this project exists to avoid.
