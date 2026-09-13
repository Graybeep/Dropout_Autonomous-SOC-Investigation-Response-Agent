# Demo script

Roughly 6–8 minutes. The viewer replays saved traces, so nothing can hang,
rate-limit, or go off-script in front of judges. Run the agent live once
(step 0) to prove it is real, then demo from the viewer.

## Setup (before you present)

```bash
python -m http.server 8000
# open http://localhost:8000/  (viewer at /viewer.html)
```

Have a second terminal ready in the project root.

---

## 0. Prove it is real (60s)

> "Everything you're about to see in the UI was produced by the agent actually
> running. Here it is running."

```bash
python run_all.py 1
```

**The live slot is Scenario 1, 2 or 6 — never 3, 4 or 5.** This is a deliberate
choice, not a preference. Section 10 of the spec says demo from saved replay with
one live run to prove the loop is real; the live run should therefore be a
scenario whose outcome is structurally pinned rather than one that turns on a
judgement call:

| | why it is safe live |
|---|---|
| **S1** | `FAILED` at 0.05 — clamped hard against the floor |
| **S2** | `SUCCEEDED` at 0.95 — clamped hard against the ceiling |
| **S6** | forced `INCONCLUSIVE` by the degraded-evidence clamp regardless of what the agent finds |

Scenario 5 case A is the one case in the suite whose verdict moves on a single
factor's sign. It runs from its saved trace, which passed. Do not put it in the
live slot.

While it runs, say what it is doing: the agent is being handed eleven tool schemas
and is choosing its own calls. Nothing about the order is scripted.

Then show the guardrails are checkable, not just claimed:

```bash
python compliance.py     # 12 structural checks
python selfcheck.py      # 84 behavioural checks
```

> "No outcome branches on scenario identity. No code branches on the alert's
> severity label. Outcome values are produced in exactly one file."

---

## Ordering: open on autonomy, arrive at verification

The strongest single frame in the project is Scenario 6's degraded-evidence
ceiling. **Do not open on it.** It proves verification and robustness — a 10%
criterion you have already maxed. Autonomy is 25%, and it is proved by a
different frame entirely:

> a tool the agent chose → **the reason it gave** → the result → the decision
> about what to look at next.

That is the shape of `docs/viewer.png`, and it is the first thing to put on
screen. Open Scenario 1, press Play, and narrate *that loop* for thirty seconds
before saying anything about scoring or guards. Let a judge watch the agent
decide.

The ceiling frame is the **payoff**, not the opening. By the time you reach
Scenario 6, they have already seen the agent reason; the clamp then lands as
"and it refuses to overclaim when a source is missing" rather than as a lone
party trick.

Order: **1 → 2 → 3 → 6**, with 4 and 5 if time allows.

---

## 1. The core thesis — Scenario 1 vs Scenario 2 (2 min)

Open **Scenario 1** in the viewer. Press **Play**.

> "A *critical*-severity SQL injection alert. Watch what the agent does with
> that label: nothing. It goes and checks."

Point at the `get_asset_info` → `get_vulnerabilities` pair, then the scoring
table:

> "This is the join the whole problem is about. The CVE database doesn't know
> what this host runs — it only knows that CVE-2023-21980 affects versions below
> 5.7.30. The inventory says this host runs 8.0.36. The agent has to put those
> two facts together itself, and you can see it doing it in the citation."

Verdict: **FAILED**, confidence 0.95, no action taken.

Switch to **Scenario 2**. Same signature, different host.

> "Same attack signature. This host runs 5.7.21 — inside the range. Logs show
> the query executed and returned 48,000 customer rows. 2.4 MB left the host."

Verdict: **SUCCEEDED** → blocks the IP → **verifies** it.

> "And the verification isn't the agent saying 'done'. `block_ip` writes a JSON
> file; `check_firewall_state` reads that same file back off disk. Then the
> orchestrator independently re-reads it and compares against what the policy
> expected."

Optionally show it:
```bash
cat fixtures/run/firewall_state.json
```

---

## 2. Adaptation — Scenario 3 (2 min)

> "This is the one I'd actually watch."

Play until the first conclusion: **INCONCLUSIVE, 0.40**.

> "The injection attempt is right there in the logs — but it threw a SQL syntax
> error and returned zero rows. Attempted, not succeeded. The agent declines to
> call it either way, and on a non-critical asset that means no action. An
> inconclusive answer is a legitimate answer."

Continue past the purple **reconsider** fork.

> "Now delayed log shipping delivers two entries that name a *second host*.
> Here's the part that matters: the agent doesn't just re-score what it already
> had. It re-enters at hypothesis formation, and goes and investigates
> SRV-DB-09 — asset info, logs, related alerts — a host it had never looked at."

Land on **SUCCEEDED, 0.95**, and the side-by-side prior/new block.

> "Prior conclusion preserved, never overwritten."

---

## 3. Failure recovery — Scenario 6 (1.5 min)

> "The log collector is down for this one."

Point at the two red `tool_failure` cards.

> "It notices, retries once, fails again, and routes to packet metadata and
> related alerts instead. Critically, it does *not* record 'logs were clean' —
> a broken tool is not evidence that nothing happened."

Then the scoring block:

> "Here's my favourite number in the whole project. The evidence it *did* gather
> scores 0.90 — that's SUCCEEDED. But one source failed, so the degraded-evidence
> clamp pulls it to 0.65 and the verdict to INCONCLUSIVE. The agent doesn't get
> to claim a confident verdict on a half-read evidence base. And because the
> asset is critical, it still contains the threat — tagged **precautionary**,
> explicitly containment under uncertainty rather than a verdict."

---

## 4. Human authority — Scenario 4 (1 min)

> "Agent concludes SUCCEEDED and blocks. Then a human analyst says: that was our
> own red team."

Show the unblock, the `OVERRIDDEN_BENIGN` status, and section 6 of the report.

> "Both views are kept side by side — the machine's conclusion is not erased by
> being overruled. And the agent will not re-block without a new trigger."

---

## 5. Correlation — Scenario 5 (1 min, optional if time is short)

> "Two alerts on one asset, two separate cases. While working the second case
> the agent calls `get_related_alerts`, finds the first case and reads its
> stored conclusion — and the first case then reconsiders on the strength of the
> second. 0.40 to 0.80."

---

## Closing

```bash
ls reports/
```

> "Every case writes a report with the evidence chain, the agent's stated reason
> for each step, the itemised scoring, the action, the verification, any
> reconsideration side by side, and any degraded-evidence ceiling."

Open `Toknow/DECISIONS.md` if asked about process — every decision and every
problem hit during the build is logged there, including two cases where a
scenario passed its assertions but was demonstrating nothing, and how that was
caught.

---

## Questions you should expect

**"Where does 0.85 come from?"**
`soc_agent/confidence.py`. Fixed table, base 0.50, each factor applied at most
once, clamped. The model never emits a confidence number — it declares which
evidence classes it established, with citations, and Python does the arithmetic.

**"How do you know it isn't scripted?"**
`python compliance.py`. Also: tool *ordering* is deliberately not asserted by the
harness, because pinning a sequence is exactly the scripted behaviour the design
forbids. Run the same scenario twice and the order differs; the outcome doesn't.

**"What stops it inventing evidence?"**
Factor preconditions — a factor can't be declared unless the source that would
establish it returned `ok`. `no_data` and `unavailable` don't count. It fired for
real on Scenario 1: the agent claimed corroboration from an empty lookup, the
tool rejected the submission, and it resubmitted correctly. That exchange is in
the trace.

**"Why this model / why not Claude?"**
See `Toknow/DECISIONS.md` D-002. The architecture is Claude-native tool use. The
account is on a free plan with zero credits, so every Claude model returns
"Insufficient credits" — verified by probing each one, not assumed.
`ling-3.0-flash-fin-free` is the strongest model this key can actually reach,
and it is the name the harness banner prints at the top of every run — say that
name, not a friendlier one, because the judge can see it on screen.

**"How stable is it, really?"** — answer this with the number, not a hedge.

> Six of six clean, 51/51, plus 105/105 offline checks. The seventh is a
> declared XFAIL and I will show you why it fails, because that is the more
> useful half. The number I trust more than the total is this: across runs the
> declared factor sets, the scores and the outcomes are identical. What varies
> is tool-call ordering and how many times the guard bus refuses a submission
> before accepting it — variance in how the agent gets there, not in what it
> concludes.

Say it in that order: the outcome is stable *because* the scoring is
deterministic, and the trajectory varies *because* the agent genuinely chooses
its own tools. If both were stable, the second one would be a script.

### The XFAIL — lead with it, do not wait to be asked

`reports/CASE-7001.md`. The agent investigates SRV-HR-11, and on version and
logs alone the case is indistinguishable from scenario 2: MySQL 5.7.24 sits
inside CVE-2023-21980's range and the injected `UNION SELECT` reaches the
database. It calls `get_configuration` unprompted, and its own report says:

> *"the database account `hr_portal_ro` lacked SELECT privileges on the targeted
> tables, causing all UNION SELECT attempts to return ERROR 1142 with 0 rows"*

It even rules out the WAF as the thing that saved the host — DetectionOnly, so
the payload did reach the application. That is the asset + vulnerability +
configuration correlation, done correctly.

And the score still says `INCONCLUSIVE` 0.40, because §7.2 has no factor for a
configuration control. **The agent established a fact the scoring model has no
way to represent.** The one sentence to have ready:

> I built that factor, and I reverted it. It passed one full run and failed the
> next — not because the factor was wrong, but because the guard protecting it
> asked the agent to fill in a schema field instead of to call a tool, and on
> one run in two the agent dropped the claim rather than satisfy the guard. A
> guard that makes a claim harder to state than to abandon will get it
> abandoned. The gate for that work was declared hard in advance, so it went.

If asked "why not just ship it anyway, it worked once": because a gate that
moves when you dislike its answer is not a gate, and the two runs needed to
verify a fix are the two runs this demo was rehearsed in.

Do not offer "a stronger model would fix it." It is a resource excuse dressed as
a robustness story, and it invites "so why didn't you?" — to which the honest
answer is that changing the model invalidates a passing 51/51 suite with no time
to re-verify it. Better not to raise it.

---

## Rehearsed set piece — the guard refusal (know this cold)

**Where:** `reports/CASE-1001.md`, section 2, steps **9–11**. Scenario 1.
Do not go looking for this live; it is here because it is the strongest single
artefact for the autonomy and verification criteria.

The agent submitted its assessment. The bus refused it for **two** reasons in
the same response — use both, they are different guards:

> **Refused:** factor `related_alert_corroborates` cannot be declared: it
> requires a successful result from `get_related_alerts`, which you have not
> obtained.
>
> **Refused:** factor `version_patched` claims SRV-WEB-01 is outside ALL
> affected ranges, but you have not looked up **openssh** — service(s) this host
> runs that the CVE knowledge base covers.

The agent's own next line, which is the one to read aloud:

> *"I need to fix two issues: remove the `related_alert_corroborates` factor
> (since `get_related_alerts` returned `no_data`), and check the openssh CVE."*

It then calls `get_vulnerabilities(service_name='openssh')` and resubmits
without the unsupported factor, and that submission is accepted. **Two refusals,
two different correct responses:** it *gathered* what was missing, and *dropped*
what it could not support. Both the refusal and the correction are steps in the
evidence chain.

### The one sentence, if asked "isn't the bus deciding the verdict?"

> No — the bus refused the **form** of the claim, not its content. The agent said
> the host was outside *all* CVE ranges having looked up only two of its three
> services; you cannot say "all" after checking "some". The bus never decides
> whether MySQL 8.0.36 falls inside a range — that comparison is the agent's, and
> it is the whole point of §5.1.

### If a judge notices refusals everywhere — get ahead of this, do not defend it

Measured across the seven shipped traces: **11 refusals over 8 cases; 6 of the 8
are refused at least once; the busiest case takes 4.** Refusal is the normal
operating mode here, not an exception, so do not present it as a rare catch.

Quote that as **"roughly one or two per case"**, never as a fixed figure. Three
separate full runs measured 10, 11 and 16 over the same 8 cases, with the
per-case maximum moving between 2 and 4 and the number of untouched cases
between 0 and 2. The shape is stable; the count is not. To recount against
whatever traces are on disk:

```bash
python -c "import json,glob;print(sum(1 for p in glob.glob('traces/*.json') for s in json.load(open(p))['steps'] if s.get('tool')=='submit_assessment' and s.get('status')=='rejected'))"
```

Present it as the design:

> Nearly every case gets refused at least once. That is the bus doing its job on
> the normal path, not a stumble on one case.

**Do not claim "it always responds by gathering more evidence."** It does not,
and it should not — the correct response depends on which guard fired, and being
precise about this is stronger than the tidy version:

Family mix also moves run to run; the last full run was provenance 8,
exhaustiveness 4, contradiction 2. What does not move is which response each
family deserves:

- **Exhaustiveness** (`version_patched` claimed having checked only some of the
  host's services) → the agent **gathers**: the next call is
  `get_vulnerabilities` on the service it skipped. This is the scenario 1 set
  piece above.
- **Provenance** (`related_alert_corroborates` declared from a lookup that came
  back empty) → the agent **drops the factor**, and that is the right answer.
  The claim was unfounded; the honest fix is to stop making it, not to go
  manufacture corroboration. Dropping here is the guard working.
- **Contradiction** (`logs_clean` and `logs_consistent` together) → the agent
  picks the side the evidence supports.

The one case where dropping was the *wrong* response is the reverted
configuration guard, and it is worth volunteering rather than hiding: there the
claim was true and supportable, and the agent dropped it anyway because
satisfying the guard meant filling in a schema field rather than calling a tool.
That is what got the guard reverted — see the XFAIL section above.

The three shapes it refuses, worth naming because they are different failures:
**exhaustiveness** (claiming "outside ALL ranges" having checked some),
**provenance** (declaring a factor from a lookup that returned no data or
failed), and **contradiction** (declaring a finding and its negation together).

The sharpest single instance is in Scenario 5: `logs_clean` was refused because
**case 5002 had already concluded SUCCEEDED on that same asset over the window
being called clean.** That one compares a declared factor against a verdict the
agent itself produced in another case — and it is the one to reach for if
someone suspects the guards are cosmetic.

### Two follow-ups to have ready

**"Doesn't naming the missing service hand it the answer?"**
It names which *source* is unread, never what that source will say. The agent
still had to fetch OpenSSH's CVE ranges and decide 8.9p1 was outside them. And
the hint is disclosed in the report rather than hidden, which is why the chain
reads honestly.

**"Why not just check the signature's service?"**
That would be a hardcoded signature→service mapping — Python encoding detection
knowledge, which is the D-001 violation. Exhaustive coverage encodes none: it is
a statement about universal versus existential claims. `version_in_range` is
existential and deliberately exempt.

### Backup artefact
`reports/CASE-3001.md` has a precondition refusal (`related_alert_corroborates`
claimed from a lookup that returned no data) with the same shape, if Scenario 1
is not the one on screen.

### Follow-up — "how do you know the evals themselves are sound?"

Lead with this. It is a stronger answer than any pass count, because it is about
the failure mode that actually threatens a verification suite.

> Six separate times my own tooling produced a **plausible wrong answer**, and
> each time the number looked fine. A regex-based guard ablation mis-attributed
> failures across two guards. An invariant I had "verified" by reading turned
> out never to have been asserted. A sandbox lock deleted itself, because it
> lived in the directory it was protecting. A coherence check printed "single
> coherent run" from a hard-coded string while the underlying span was wrong. A
> viewer "defect" I was about to fix turned out never to have existed. And the
> configuration fixture shipped a `prevents_exploitation` boolean that would
> have handed the agent the verdict it was supposed to derive — while three
> separate comments in the code asserted that it did no such thing.
>
> None of those were caught by a suite going red. All six were caught by
> re-reading the output instead of the summary. That is why the guards are now
> ablated at runtime rather than by patching source, why fixture invariants are
> adversarially tested, and why every count in this project was re-derived
> rather than quoted.

### Second follow-up — the ablation numbers

Do not volunteer this; it belongs after the set piece, if asked.

> Each guard is ablated — monkeypatched to a no-op — and the suite has to fail.
> Preconditions breaks 4 checks, the coverage guard 2, the negative-scope guard
> 3; restore and it's back to 0. Worth saying: my first ablation method patched
> the source with a regex and mis-attributed failures across two guards. It
> looked entirely plausible. Runtime patching was precise, and the
> worse-looking-but-correct numbers are the ones on record.

Same shape for the fixtures: injecting a row that implies successful attacker
activity into a scenario required to start `INCONCLUSIVE` makes `compliance.py`
fail. Verified for both Scenario 3 and Scenario 5 case A.

### The set piece, as spoken (181 words, ~83s deliberate / ~72s normal)

Timed. Budget is 90s, leaving room for the two follow-ups. If it runs long, cut
the first two lines — the refusal is the payload, the setup is not.

> This is Scenario 1. A critical-severity SQL injection alert against SRV-WEB-01.
>
> Watch what the agent does with that severity label: nothing. It goes and checks.
>
> Steps four and five, it pulls the CVE ranges for MySQL and Apache. Step seven,
> related alerts, no data. Then at step eight it submits its assessment, claiming
> the host is patched.
>
> **And the tool refuses it.**
>
> Read the refusal: it claims SRV-WEB-01 is outside ALL affected ranges, but it
> hasn't looked up OpenSSH — a third service this host runs that the knowledge
> base covers.
>
> Step nine is `get_vulnerabilities` on openssh. Step ten, it resubmits, and that
> one is accepted. FAILED, confidence 0.95, no action taken.
>
> Now — the obvious question is whether the tool just decided the verdict. It
> didn't. It refused the **form** of the claim, not its content. The agent said
> "outside all ranges" having checked two of three services. You can't say *all*
> after checking *some*. The tool never decides whether MySQL 8.0.36 falls inside
> a range — that comparison is the agent's, and it's the entire point of the
> design.

---

## The guard families — what the artefacts actually show

Four guard families now exist. **Three are demonstrated live in the committed
traces; three are verified offline only.** Say it that way — claiming a scope the
artefact does not contain is the one thing that turns this set piece against you.

**Demonstrated in `traces/` and visible in the reports:**

| scope | refuses | seen in |
|---|---|---|
| service coverage | `version_patched` claimed from a subset of the host's KB-covered services | scenarios 1, 3, 4, 5 |
| log window | `logs_clean` claimed from a window not containing the alert | scenario 6 |
| precondition | any factor drawn from a source that never returned `ok` | scenarios 2–6 |

**Verified by `selfcheck.py` but NOT present in any trace:** the related-alert
window, the sibling-verdict conflict, and packet provenance. They did not need to
fire — the agent declared an acceptable factor set first time. If asked, say
exactly that: *structurally verified, not exercised in this run.* Do not imply a
trace shows them.

The one-sentence framing covers all of them regardless:

> Every one of these refuses the **form** of a claim, never its content. The
> positives are existential and need one witness; the negatives are universal
> and need a stated scope. The bus never decides what the evidence means.

### If asked about Scenario 5 specifically

> Case A reconsiders and reaches `SUCCEEDED` at 0.95 by declaring
> `logs_consistent`. It is worth knowing it clears the threshold on the other
> honest path too — dropping the log factor lands 0.80 — so the case no longer
> turns on one factor's sign, which is what made it the flakiest scenario
> earlier. `compliance.py` asserts both paths clear.

**Known limitation, if pressed on the packet factor:** in the current S5 trace
case A declares `exfil_indicators` citing ALERT-5002's packet record — a sibling
alert's flow. The provenance guard requires the case to have *read* its own
alert's flow, which it did; it does not require the *citation* to be that flow.
No outcome impact (1.30 and 1.15 both clamp to 0.95). Recorded rather than
patched, because a fifth guard at this stage is unbudgeted risk against a
passing suite.

---

## Completeness pass — the things that get asked

### The model
> It runs on `ling-3.0-flash-fin-free` through a multi-model gateway. The
> architecture is Claude-native tool use and the provider is one config line;
> the account is on a free plan with zero credits, so every Claude model returns
> "insufficient credits" — verified by probing each one. The guards are
> structural, so they hold regardless of which model is behind them.

Say it once, in that form. It is a fact about the account, not an apology.

### The three scopes no trace demonstrates

| scope | if asked |
|---|---|
| related-alert window | "Structurally verified, not exercised in this run. `selfcheck.py` asserts it refuses a `logs_clean` declared from a window that misses a known sibling alert — ablating that guard fails 7 checks." |
| sibling verdict | "Same: verified offline. It refuses `logs_clean` when a sibling case already concluded SUCCEEDED on the same asset. Ablating it fails 2 checks, distinct from the others." |
| packet provenance | "Verified offline. And a known limitation: it requires the case to have *read* its own alert's flow, not that the citation *be* that flow. No outcome impact — both paths clamp to 0.95." |

Never imply a trace shows one of these. The three that **are** in the traces are
service coverage, log window, and precondition.

### Starting the viewer

```bash
python -m http.server 8000
# open http://localhost:8000/  (viewer at /viewer.html)
```

- Press **Play** for the timed reveal; **Show all** to jump to the end.
- `viewer.html#3` deep-links straight to a scenario.
- **If it shows "trace not found":** you opened it as a `file://` URL. Browsers
  block `fetch` on local files. Serve it over HTTP — that is the only cause.
- **If nothing animates:** `vendor/motion.js` did not load, or the machine has
  reduced-motion enabled. The viewer still reveals every card; motion is
  enhancement only and its absence breaks nothing.

### Fallback order if the live leg fails

1. **Saved trace in the viewer** — every scenario already has a passing trace
   committed. Nothing about the demo depends on the live run succeeding.
2. **`reports/CASE-1001.md`** — the set piece reads just as well on the page as
   on screen; section 2, steps 9-11.
3. **`python selfcheck.py` and `python compliance.py`** — 99 and 22 checks, no
   API key, no network. These cannot fail for environmental reasons.

Decide which of these you are on *before* standing up, not during.
