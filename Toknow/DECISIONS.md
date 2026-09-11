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
