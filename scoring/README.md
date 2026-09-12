# scoring/ — audit pack

Four things, so the claims in the write-up can be checked rather than believed.
Everything in `src/` is a byte copy of something the agent actually runs, and
`selfcheck.py` fails if a copy drifts from its original — that check was proved
by ablation, not assumed.

| You asked for | File |
|---|---|
| 1. A full trace, not the cleanest one | `trace_scenario_3.json` |
| 2. The agent loop (gather / sufficiency / conclude) | `src/agent.py` |
| 3. Guard + ToolBus source | `src/toolbus.py`, `src/confidence.py` |
| 4. Harness + assertion file | `src/run_all.py`, `src/definitions.py` |
| (answer to the luck question) | `test_luck_vs_reasoning.py`, `_bad_trajectory.json` |

Run the one executable thing here:

```
python scoring/test_luck_vs_reasoning.py
```

---

## 1. The trace — `trace_scenario_3.json`

Scenario 3, the reconsideration case. It is the least flattering of the six on
the metric you care about: 103 steps, **34 tool calls, 3 guard refusals**, one
reconsideration. Scenario 1 is 11 calls / 1 refusal — that is the clean one.
This is not it.

### Q1 — autonomy

The agent chose this opening order:

```
get_alert → get_asset_info → get_server_logs → get_packet_metadata
          → get_related_alerts → get_vulnerabilities(mysql)
          → get_vulnerabilities(tomcat) → submit_assessment
```

Nothing in the code emits that sequence. Compare against `_loop` in
`src/agent.py:149` — it appends the model's tool calls, dispatches them, appends
results, re-enters. The only control flow is a turn cap and "did the model stop
calling tools." Ordering, the choice to check two services, and the decision to
stop are all model output.

The step worth reading closely: after the injection the agent went to
`get_asset_info(SRV-DB-09)` — the *second* host, named only inside the injected
log line. No fixture and no prompt mentions SRV-DB-09 before that point.

### Q2 — counting refusals, not guessing

Three refusals, carrying four guard problems across two families:

| # | Family | What it refused |
|---|---|---|
| 1 | `check_preconditions` | `related_alert_corroborates` declared when `get_related_alerts` returned `no_data` |
| 2 | `check_preconditions` | same factor, resubmitted unchanged |
| 3 | `check_version_patched_coverage` | `version_patched` on SRV-APP-03 with `openssh`, `tomcat` never looked up |
| 3 | `check_version_patched_coverage` | `version_patched` on SRV-DB-09 with `openssh` never looked up |

Refusal #3 is one rejected result carrying two problems. Grep `"status": "rejected"`
for the three, and `factor '` for the four.

The refuse/resubmit cycle is bounded at 3 (`src/toolbus.py:97`). On impasse it
drops the named factors, scores what survives and records the impasse, rather
than looping to the turn cap.

---

## 2. The loop — `src/agent.py`

The claim was that there is no `if signature == X` decision path. Where to check:

- `_loop` — `src/agent.py:149`. The whole cycle.
- `gather` — `:198`; `determine` — `:212`; `act_and_verify` — `:244`.
- `reconsider` — `:350`. One function, three triggers (new evidence, override,
  related case).

Note `inv.bus = inv._new_bus()` (`_new_bus` at `:140`): the fresh ToolBus starts
with an empty `ok_tools`, so after reconsidering the agent must **re-call** every
source before it may re-declare any finding on it. That is what stops a
"reconsideration" from being a silent re-score of stale reads, and it is why the
harness asserts fresh tool calls after the trigger rather than just a changed
number.

Scenario identity reaches the agent only as a `fail_tools` list read by the
wrapper. It never reaches the decision path.

---

## 3. "Guards enforce form, never content" — `src/confidence.py`

The claim, with the code to check it against:

| Guard | Line | What it tests |
|---|---|---|
| `check_preconditions` | `confidence.py:105` | was the *tool* this factor depends on actually called, with a non-empty result |
| `check_version_patched_coverage` | `:124` | were *all* of the host's CVE-covered services looked up |
| `check_negative_scope` | `:200` | does a universal negative state its scope (time window, service set) |
| `check_sibling_verdict_conflict` | `:159` | does this contradict a sibling case's stored verdict |

Each takes factor **names**, tool-call bookkeeping, and declared scope — look at
`check_negative_scope`'s signature at `:200`: alert id, alert-id sets, log
windows, a timestamp. No free text reaches it.

Grepping `citation` in `confidence.py` returns exactly two hits, and neither is
in a guard: line 286 is a docstring, and line 312 is inside `score()`, copying
the citation through into the report so a human can read it. `toolbus.py`
contains no occurrence of `citation` or `rationale` at all. Those three greps are
the whole check.

Why the distinction matters, stated as a limitation rather than a feature: the
three positive factors in §7.2 are **existential** (one witness suffices, so a
guard can only check that a witness was fetched); the three negatives are
**universal** (no witness anywhere — which is why those guards demand a stated
scope). A guard that judged whether a citation *supports* its factor would be an
LLM grading an LLM, which is the one thing this design refuses to do.

**Where that visibly bites, in this very trace.** The agent declared
`version_in_range` and `logs_clean` *together* — "the host is genuinely
vulnerable, but the payload threw a syntax error and returned 0 rows." The
guards let it through, because it is well-formed: both factors have their
witnesses. Whether it is *correct* is not a question they can answer. It happens
to be right here. The guards do not know that.

---

## 4. The pass count, and the actual question

> does a badly-reasoning trajectory that lands on the right factor by luck
> actually fail these assertions, or not?

`_bad_trajectory.json` is a **real trace from commit `ee50c21` of this repo**,
not a constructed strawman. In it the agent reached the correct final outcome
(`SUCCEEDED`) having:

- concluded `FAILED` at T0, where the spec calls for `INCONCLUSIVE`;
- looked up **only `tomcat`** before concluding — on a SQL-injection alert,
  against a host running `mysql 5.7.28`, which *is* inside CVE-2023-21980.

It reached the right final answer because the injected lateral-movement evidence
dragged it there, not because the reasoning held. `test_luck_vs_reasoning.py`
replays it through `run_all._check`, the same function `run_all.py` calls, at
two bars:

```
OLD BAR     outcome + action + reconsideration + tool NAMES     0 failures — slips through
CURRENT BAR run_all._check as it stands today                   2 failures — caught
```

The two that catch it:

- **`get_vulnerabilities(service_name='mysql')` before concluding** — the
  phase-scoped argument assertion (`run_all.py:57`, `_tool_args_called` with
  `phase="pre_conclusion"`). A whole-trace search would **not** catch it: the
  agent did eventually call `mysql`, just after it had already concluded.
- **`initial outcome == 'INCONCLUSIVE'`** — pins the T0 verdict, not only the
  final one, so "wrong first, right later" is not scored as a pass.

**And the one that does not:** `required factors established` **passes** this bad
trajectory. Factor presence alone does not separate luck from reasoning. What
does the work is *phase scoping* (which argument, before which step) and
*pinning intermediate states* (the T0 outcome, the post-reconsideration call
count). If you are going to discount the headline pass count, discount it on
that axis — and here is the number to discount it by, printed by the same
script from the six shipped traces:

```
scenario_1    8 checks   coarse=5   path-pinning=3
scenario_2    7 checks   coarse=5   path-pinning=2
scenario_3   11 checks   coarse=5   path-pinning=6
scenario_4    6 checks   coarse=5   path-pinning=1
scenario_5    9 checks   coarse=5   path-pinning=4
scenario_6   10 checks   coarse=5   path-pinning=5

51 assertions: 30 coarse (58%), 21 path-pinning (41%)
```

"Coarse" = outcome class, action fired, reconsideration fired, bare tool names,
final status — the five the bad trajectory sails through. Every scenario pays
those five. **58% of the live suite is the cheap kind.** Scenario 4 is the
weakest in the set: one path-pinning assertion. The real strength of the suite
is the 21, not the 51.

A note on which number is which, since two are in circulation: **51** is the
live harness (`run_all.py`, six scenarios against the model). **105** is
`selfcheck.py`, the offline plumbing suite — sandbox, tools, scoring, guards,
report rendering — which never runs the agent loop. The census above is of the
51. They should not be added together.

### What these assertions cannot do

They pin the reasoning **path** — which source was consulted before which
conclusion, what the first verdict was, which factors were established, how many
fresh calls a reconsideration produced. They do not verify that a citation's
prose supports the factor attached to it. A trajectory that fetched all the right
evidence in the right order and then reasoned badly about its *content* would
pass every assertion in `definitions.py`. There is no check for that here, and I
am not claiming one.

### Known gap, recorded rather than left to be found

Scenario 5 case A cites a *sibling's* packet record for `exfil_indicators`. The
provenance guard requires the agent to have *read* its own alert's flow, not to
have *cited* it, so the guard passes. No outcome impact — the case clears its
threshold on an independent factor — but it is a real hole in coverage. Left
unpatched deliberately: a fifth guard family this late is unbudgeted risk.
See `Toknow/DECISIONS.md`, K-7.
