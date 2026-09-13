# Autonomous SOC Investigation & Response Agent

**An agent that takes a security alert and determines whether the attack actually
succeeded, then acts on that answer and verifies its own action took effect.**

The rule every conclusion is held to:

> **You cannot say ALL after checking SOME.**

**Live viewer: <https://soc-agent-trace-viewer.vercel.app>**

> The hosted viewer replays traces from real agent runs. Every step shown was
> produced by the live system, not simulated. The agent itself runs locally:
> clone, set your key, run `python run_all.py`.

The single most informative artefact is
**[`reports/CASE-1001.md`](reports/CASE-1001.md), section 2, steps 9-11** — the
agent submits a conclusion, the tool refuses it on two counts, and the agent
resolves each differently:

```
RESULT  REJECTED                                                    CASE-1001
  factor 'related_alert_corroborates' cannot be declared: it requires a
  successful result from get_related_alerts, which you have not obtained.

  factor 'version_patched' claims SRV-WEB-01 is outside ALL affected ranges,
  but you have not looked up openssh - service(s) this host runs that the CVE
  knowledge base covers.

REASONING                                                           CASE-1001
  I need to fix two issues. Let me check openssh CVEs and remove the
  related_alert_corroborates factor since no_data is not a finding.
```

It then **fetches** the missing CVE data and **drops** the claim it could not
support. Two refusal types, two correct responses, one exchange.

---

## The problem, and why an agent

A detection signature fires when traffic *looks* like an attack. Whether the
attack actually worked is a separate question, and the alert cannot answer it.
A "critical" SQL-injection signature against a host patched two years ago whose
logs show a 403 is a false alarm. A quieter alert against an unpatched host that
then shipped 2 MB outbound is a breach.

The agent answers that question by correlating **asset, vulnerability,
configuration, log and packet** evidence instead of trusting the severity label.

This needs an agent rather than a script because **the evidence that settles one
alert is not the evidence that settles the next**, and what the agent finds
changes what it should look at. A script fixes the order in advance. Here the
agent chooses each call, states why before making it, and re-plans when new
evidence arrives mid-investigation.

---

## Architecture

| Component | Where it lives | What it does |
|---|---|---|
| **Agent / Controller** | `soc_agent/agent.py` | Owns the case lifecycle and drives the tool-use loop |
| **Tools** | `soc_agent/tools.py`, `soc_agent/schemas.py` | Eleven schemas: `block_ip`, `unblock_ip`, `submit_assessment`, plus the read tools below |
| **External Systems** | `fixtures/seed/*.json` | Alert feed, asset inventory, CVE knowledge base, configuration, host logs, packet metadata, firewall state |
| **Memory / State** | `soc_agent/trace.py`, `fixtures/run/cases.json` | Structured trace plus append-only per-case conclusions |
| **Retrieval** | the eight read tools in `soc_agent/tools.py` | Keyed lookups over the fixtures, plus stored verdicts from other cases |
| **Planning** | `soc_agent/prompts.py` + the model | Hypothesis, falsifier, and a sufficiency judgement after every result |
| **Evaluation / Verification** | `soc_agent/confidence.py`, `check_firewall_state` | Four guard families, deterministic scoring, re-reading state from disk |
| **Human Interaction** | `soc_agent/control.py` | `human_override()`, which always wins, and evidence injection |
| **Failure Handling** | `soc_agent/toolbus.py`, `soc_agent/llm.py` | Retry, degraded-evidence clamp, guard refusals, impasse after three rejections |

The diagram, the data paths between these components, and the normal,
reconsideration and failure flows are in
**[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

### The state machine

```
INGEST_ALERT
   |
   v
HYPOTHESIZE ......... what evidence would confirm "the attack succeeded"?
   |                  what evidence would FALSIFY it?
   v
GATHER_EVIDENCE ..... loop: pick a tool -> state why -> read -> assess
   |                  sufficiency -> pick next, or stop
   v
DETERMINE_OUTCOME ... SUCCEEDED | FAILED | INCONCLUSIVE
   |                  + deterministic score + evidence citations
   v
ACT ................. block_ip / precautionary block / nothing
   |
   v
VERIFY .............. re-read firewall state FROM DISK, compare to policy
   |
   v
[ NEW_EVIDENCE | TOOL_FAILURE | HUMAN_OVERRIDE ]
   |
   +--> reconsider() ---> back to HYPOTHESIZE
   |
   v
REPORT
```

`reconsider()` re-enters at **HYPOTHESIZE**, not at the verdict. New evidence, a
tool failure and a human override all route through that one function, so the
agent forms a *new* hypothesis and gathers *new* evidence rather than silently
re-scoring what it already had. Rationale in
[`Toknow/DECISIONS.md`](Toknow/DECISIONS.md).

---

## Tech stack

**Python standard library only.** No framework, no dependencies, no
`requirements.txt`, no lockfile. A decision, not an omission: the system is
auditable by reading it, and there is no supply chain to trust.

**No LangChain, no AutoGen.** A hand-written tool-use loop on the model's native
tool calling, so the trace belongs to this project and every decision point is
inspectable rather than hidden in a framework.

**Viewer:** vendored, pinned animation library and **zero external references**,
so it works with no internet. Served under a strict CSP with no `unsafe-inline`.

**Model: provider-agnostic.** `SOC_BASE_URL`, `SOC_MODEL` and `SOC_API_STYLE` are
environment-driven, and the client speaks both wire formats. The default in
`.env.example` is `ling-3.0-flash-fin-free`. The traces committed here were
produced on that provider after a mid-project credit limit forced a swap away
from the originally intended one. **The guards are structural rather than
model-specific**, so the evidence they enforce holds regardless of which model
produced the trace.

---

## Setup

**Requires Python 3.11 or newer** (developed and verified on 3.11.9).

**1. Clone**

```bash
git clone https://github.com/Graybeep/Dropout_Autonomous-SOC-Investigation-Response-Agent.git
cd Dropout_Autonomous-SOC-Investigation-Response-Agent
```

**2. There is no install step.** No `pip install`, no virtualenv required, no
package manifest. If you are looking for one, that is why you cannot find it.

**3. Check it works without a key** — these need no API access at all:

```bash
python selfcheck.py      # 99 behavioural checks
python compliance.py     # 22 guardrail checks
```

**4. Configure a provider** (only needed to re-run the agent; skip to step 6 to
just browse the recorded traces).

```bash
cp .env.example .env
```

Then set four variables. `SOC_API_STYLE` selects the wire format:

*OpenAI-compatible endpoint (`Authorization: Bearer`):*

```
SOC_API_KEY=sk-your-key-here
SOC_BASE_URL=https://api.openai.com/v1
SOC_MODEL=gpt-4o-mini
SOC_API_STYLE=openai
```

*Anthropic-compatible endpoint (`x-api-key`):*

```
SOC_API_KEY=sk-ant-your-key-here
SOC_BASE_URL=https://api.anthropic.com/v1
SOC_MODEL=claude-sonnet-5
SOC_API_STYLE=anthropic
```

**5. Run the agent**

```bash
python run_all.py        # all seven scenarios
python run_all.py 3      # one scenario
python run_all.py 3 6    # a subset
```

Expect roughly **one minute per scenario**; the full suite takes about 25
minutes, since scenarios 3 and 5 open more than one case. Output ends with a
results table, then a "What happened" summary: verdict and confidence per
scenario, action taken, evidence calls, guard refusals and reconsiderations.
Scenarios 1-6 should read `PASS`; scenario 7 should read `XFAIL (declared)` and
the exit code should still be `0`.

**6. View the results**

```bash
python -m http.server 8000
```

Then open **<http://localhost:8000/>**. Leave the server running.

**Opening `viewer.html` by double-clicking it does not work.** That gives the
browser a `file://` page, and browsers block those from reading local files, so
the traces can never load. Nothing is broken when this happens; the files just
have to arrive over `http://`.

---

## The seven scenarios

| # | Tests | Expected |
|---|---|---|
| 1 | A loud alert on a patched host whose logs show the request was blocked | `FAILED`, no action |
| 2 | Vulnerable version, the query executed, data left the host | `SUCCEEDED`, block, then verify |
| 3 | Ambiguous, then late evidence names a second host | `INCONCLUSIVE` → `SUCCEEDED` after investigating that host |
| 4 | An analyst overrules the verdict | `SUCCEEDED` → `OVERRIDDEN_BENIGN`, unblocks, does not re-block |
| 5 | A second alert on the same asset, correlated across two cases | both `SUCCEEDED` |
| 6 | The log source fails mid-investigation | `INCONCLUSIVE`, capped by the degraded clamp, precautionary block |
| 7 | Version in range and attack visible, but configuration made it impossible | **XFAIL (declared)** |

**Scenario 7 is a declared known-fail**, marked `expected_to_fail` and excluded
from the exit code. The agent correctly establishes that the database account
held no privilege on the targeted table and says so in its report, but §7.2 has
no factor for a configuration control, so the case stops at `INCONCLUSIVE` 0.40
instead of `FAILED`. A `config_prevents_exploitation` factor was built and
**reverted**: it passed one full run and failed the next, because the guard
protecting it asked the agent to populate a schema field rather than call a tool,
and the agent dropped a true claim rather than satisfy it. It failed its own gate
and was reverted rather than ship a number that could not be defended.

---

## Deployment

The hosted viewer is **not** the running system, and that is deliberate.

> The hosted viewer replays traces from real agent runs. Every step shown was
> produced by the live system, not simulated. The agent itself runs locally:
> clone, set your key, run `python run_all.py`.

Replay rather than live streaming was decided **before the viewer existed**
(CLAUDE.md §10): a live loop on stage can hang or rate-limit. A design decision,
not a hosting limitation. The deployment is static files only: no agent loop, no
API key, nothing server-side.

---

## Verification and known limitations

| Check | Result |
|---|---|
| `python selfcheck.py` | **99/99** behavioural, no API key |
| `python compliance.py` | **22/22** guardrail, no API key |
| `python run_all.py` | **51/51** live assertions across scenarios 1-6 |
| Stability | green on two consecutive full runs |

Tool *ordering* is never asserted — pinning a sequence would re-introduce the
scripted behaviour the design forbids. Assertions are phase-scoped where timing
matters: scenario 3 asserts the right CVE lookup happened *before the first
conclusion*, not merely somewhere in the trace. Scenarios 3 and 5 assert they
**gathered new evidence** after reconsidering (16 and 10 calls in the shipped
traces; no reconsideration scores 0, the negative control).

### The four guard families

Every guard refuses the **form** of a claim, never its content.

| family | refuses |
|---|---|
| `check_preconditions` | any factor drawn from a source that never returned `ok` |
| `check_version_patched_coverage` | `version_patched` claimed from a subset of the host's covered services |
| `check_negative_scope` | `logs_clean` from a window not containing the alert; packet factors not grounded in this case's own alert |
| `check_sibling_verdict_conflict` | `logs_clean` when a sibling case already concluded `SUCCEEDED` on that asset in that window |

Three were proven load-bearing by runtime ablation, with a negative control on
the reconsideration check.

### Known limitations

- **Scenario 7 fails on purpose.** See above. The gap is documented rather than
  hidden.
- **The packet-provenance guard is existential, not universal.** It checks the
  case's own packet record was *read*, not that the citation names it. Closing it
  would mean parsing citation prose, the one thing these guards refuse to do.
  Documented as `K-7`, not patched.
- **Three guard scopes are structurally verified but not exercised in any
  trace**: related-alert window, sibling verdict, and packet provenance. They are
  covered by `selfcheck.py` and did not need to fire, because the agent declared
  an acceptable factor set first time. Stated as *structurally verified, not
  exercised* rather than implied to appear in an artefact.
- **Refusal counts vary between runs** (10, 11 and 16 measured across three full
  runs over the same eight cases). The model picks its own tool sequence and
  declaration timing, so refusal count is a property of the trajectory, not of
  the fixtures.

### Generalisation probe

[`fixtures/probe/`](fixtures/probe/) runs scenario 2's *shape* over a fixture set
where every surface detail differs — service, CVE, version range, asset, source
IP, and log phrasing sharing no attack vocabulary with the original. It converged
on the same evidence classes, score and action, with no scenario 2 vocabulary in
its citations.

Its README states the caveat that matters: **identical tool ordering is evidence
of consistency, not adaptivity.** The adaptive evidence is scenarios 3 and 6,
where ordering genuinely diverges. The probe is not in the suite and was not
tuned.

---

## Further reading

- [`demo-script.md`](demo-script.md) — the timed four-minute demo script
- [`DEMO.md`](DEMO.md) — presenter's walkthrough and Q&A
- [`Toknow/DECISIONS.md`](Toknow/DECISIONS.md) — the full decision record,
  including every defect found and why each was fixed or deliberately left
- [`reports/`](reports/) — the written case report for every scenario
- [`traces/`](traces/) — the structured trace the viewer and reports both render from
