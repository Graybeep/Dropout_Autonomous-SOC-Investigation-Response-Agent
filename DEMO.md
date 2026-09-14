# Demo script

Roughly 6–8 minutes. The viewer replays saved traces, so nothing can hang,
rate-limit, or go off-script in front of judges. The live run that used to open
the demo is no longer possible (step 0 explains why), so the proof that it is real
comes from the traces, the reports and the offline checks instead.

## Setup (before you present)

```bash
python -m http.server 8000
# open http://localhost:8000/  (viewer at /viewer.html)
```

Have a second terminal ready in the project root.

---

## 0. Prove it is real (60s)

**There is no live run in this demo.** The model that produced every committed
trace, `ling-3.0-flash-fin-free` on a multi-model gateway, has been retired by
the provider. On 14 September 2026 a verification run failed on all seven
scenarios with `HTTP 400 "The requested model is not available."`, and the two
other free models tried on the same gateway were refused as well. The failed run
overwrote the traces with error traces; they were restored from git and
confirmed byte-identical before anything else was touched. Do not attempt
`python run_all.py` on stage with this key.

> "Everything you're about to see in the UI was produced by the agent actually
> running, in full runs that passed. The gateway model it ran on has since been
> retired, so rather than a live run I'll show you the checks that run without
> any model at all."

Show the guardrails are checkable, not just claimed:

```bash
python compliance.py     # 22 structural checks
python selfcheck.py      # 99 behavioral checks
```

Both need no API key and no network, so they cannot fail for environmental
reasons.

If a judge wants to see the loop run, the provider is one config line: with an
OpenAI or Anthropic key, set the four variables from README Setup step 4 and run
`python run_all.py 1`. Say plainly that a different model takes its own path and
that outcomes have only been verified on the model that produced the traces. If
you do run one, pick **Scenario 1, 2 or 6, never 3, 4 or 5**: those three have
outcomes pinned structurally rather than by a judgment call.

| | why it is the safer choice |
|---|---|
| **S1** | `FAILED` at 0.05, clamped hard against the floor |
| **S2** | `SUCCEEDED` at 0.95, clamped hard against the ceiling |
| **S6** | forced `INCONCLUSIVE` by the degraded-evidence clamp regardless of what the agent finds |

A run overwrites `traces/`, so restore them afterwards with
`git checkout -- traces reports`; the demo script quotes the committed
trajectories by step number.

> "No outcome branches on scenario identity. No code branches on the alert's
> severity label. Outcome values are produced in exactly one file."

---

## Ordering: open on autonomy, arrive at verification

The strongest single frame in the project is Scenario 6's degraded-evidence
ceiling. **Do not open on it.** It proves verification and robustness, a 10%
criterion you have already maxed. Autonomy is 25%, and it is proved by a
different frame entirely:

> a tool the agent chose → **the reason it gave** → the result → the decision
> about what to look at next.

That is the shape of `docs/viewer-overview.png`, and it is the first thing to put on
screen. Open Scenario 1, press Play, and narrate *that loop* for thirty seconds
before saying anything about scoring or guards. Let a judge watch the agent
decide.

The ceiling frame is the **payoff**, not the opening. By the time you reach
Scenario 6, they have already seen the agent reason; the clamp then lands as
"and it refuses to overclaim when a source is missing" rather than as a lone
party trick.

Order: **1 → 2 → 3 → 6**, with 4 and 5 if time allows.

---

## 1. The core thesis: Scenario 1 vs Scenario 2 (2 min)

Open **Scenario 1** in the viewer. Press **Play**.

> "A *critical*-severity SQL injection alert. Watch what the agent does with
> that label: nothing. It goes and checks."

Point at the `get_asset_info` → `get_vulnerabilities` pair, then the scoring
table:

> "This is the join the whole problem is about. The CVE database doesn't know
> what this host runs; it only knows that CVE-2023-21980 affects versions below
> 5.7.30. The inventory says this host runs 8.0.36. The agent has to put those
> two facts together itself, and you can see it doing it in the citation."

Verdict: **FAILED**, confidence 0.95, no action taken.

Switch to **Scenario 2**. Same signature, different host.

> "Same attack signature. This host runs 5.7.21, inside the range. Logs show
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

## 2. Adaptation: Scenario 3 (2 min)

> "This is the one I'd actually watch."

Play until the first conclusion: **INCONCLUSIVE, 0.40**.

> "The injection attempt is right there in the logs, but it threw a SQL syntax
> error and returned zero rows. Attempted, not succeeded. The agent declines to
> call it either way, and on a non-critical asset that means no action. An
> inconclusive answer is a legitimate answer."

Continue past the purple **reconsider** fork.

> "Now delayed log shipping delivers two entries that name a *second host*.
> Here's the part that matters: the agent doesn't just re-score what it already
> had. It re-enters at hypothesis formation, and goes and investigates
> SRV-DB-09 (asset info, logs, related alerts), a host it had never looked at."

Land on **SUCCEEDED, 0.95**, and the side-by-side prior/new block.

> "Prior conclusion preserved, never overwritten."

---

## 3. Failure recovery: Scenario 6 (1.5 min)

> "The log collector is down for this one."

Point at the two red `tool_failure` cards.

> "It notices, retries once, fails again, and routes to packet metadata and
> related alerts instead. Critically, it does *not* record 'logs were clean',
> because a broken tool is not evidence that nothing happened."

Then the scoring block:

> "Here's my favorite number in the whole project. The evidence it *did* gather
> scores 0.90. That's SUCCEEDED. But one source failed, so the degraded-evidence
> clamp pulls it to 0.65 and the verdict to INCONCLUSIVE. The agent doesn't get
> to claim a confident verdict on a half-read evidence base. And because the
> asset is critical, it still contains the threat, tagged **precautionary**,
> explicitly containment under uncertainty rather than a verdict."

---

## 4. Human authority: Scenario 4 (1 min)

> "Agent concludes SUCCEEDED and blocks. Then a human analyst says: that was our
> own red team."

Show the unblock, the `OVERRIDDEN_BENIGN` status, and section 6 of the report.

> "Both views are kept side by side. The machine's conclusion is not erased by
> being overruled. And the agent will not re-block without a new trigger."

---

## 5. Correlation: Scenario 5 (1 min, optional if time is short)

> "Two alerts on one asset, two separate cases. While working the second case
> the agent calls `get_related_alerts`, finds the first case and reads its
> stored conclusion, and the first case then reconsiders on the strength of the
> second. 0.40 to 0.95."

---

## Closing

```bash
ls reports/
```

> "Every case writes a report with the evidence chain, the agent's stated reason
> for each step, the itemised scoring, the action, the verification, any
> reconsideration side by side, and any degraded-evidence ceiling."

Open `Toknow/DECISIONS.md` if asked about process: every decision and every
problem hit during the build is logged there, including two cases where a
scenario passed its assertions but was demonstrating nothing, and how that was
caught.

---

## Questions you should expect

**"Where does 0.85 come from?"**
`soc_agent/confidence.py`. Fixed table, base 0.50, each factor applied at most
once, clamped. The model never emits a confidence number. It declares which
evidence classes it established, with citations, and Python does the arithmetic.

**"How do you know it isn't scripted?"**
`python compliance.py`. Also: tool *ordering* is deliberately not asserted by the
harness, because pinning a sequence is exactly the scripted behavior the design
forbids. Run the same scenario twice and the order differs; the outcome doesn't.

**"What stops it inventing evidence?"**
Factor preconditions: a factor can't be declared unless the source that would
establish it returned `ok`. `no_data` and `unavailable` don't count. It fired for
real on Scenario 1: the agent claimed corroboration from an empty lookup, the
tool rejected the submission, and it resubmitted correctly. That exchange is in
the trace.

**"Why this model / why not Claude?"**
See `Toknow/DECISIONS.md` D-002. The architecture is Claude-native tool use. The
account is on a free plan with zero credits, so every Claude model returns
"Insufficient credits", verified by probing each one, not assumed.
`ling-3.0-flash-fin-free` was the strongest model this key could reach, and it is
the name in every committed trace. Say that name, not a friendlier one. Then say
the second half without being asked: that model has since been retired by the
provider, which is why there is no live run today.

**"How stable is it, really?"** Answer this with the number, not a hedge.

> Six of six clean, 51/51, plus 99/99 offline checks. The seventh is a
> declared XFAIL and I will show you why it fails, because that is the more
> useful half. The number I trust more than the total is this: across runs the
> declared factor sets, the scores and the outcomes are identical. What varies
> is tool-call ordering and how many times the guard bus refuses a submission
> before accepting it: variance in how the agent gets there, not in what it
> concludes.

Say it in that order: the outcome is stable *because* the scoring is
deterministic, and the trajectory varies *because* the agent genuinely chooses
its own tools. If both were stable, the second one would be a script.

### The XFAIL: lead with it, do not wait to be asked

`reports/CASE-7001.md`. The agent investigates SRV-HR-11, and on version and
logs alone the case is indistinguishable from scenario 2: MySQL 5.7.24 sits
inside CVE-2023-21980's range and the injected `UNION SELECT` reaches the
database. It calls `get_configuration` unprompted, and its own report says:

> *"the database account `hr_portal_ro` lacked SELECT privileges on the targeted
> tables, causing all UNION SELECT attempts to return ERROR 1142 with 0 rows"*

It even rules out the WAF as the thing that saved the host: DetectionOnly, so
the payload did reach the application. That is the asset + vulnerability +
configuration correlation, done correctly.

And the score still says `INCONCLUSIVE` 0.40, because §7.2 has no factor for a
configuration control. **The agent established a fact the scoring model has no
way to represent.** The one sentence to have ready:

> I built that factor, and I reverted it. It passed one full run and failed the
> next, not because the factor was wrong, but because the guard protecting it
> asked the agent to fill in a schema field instead of to call a tool, and on
> one run in two the agent dropped the claim rather than satisfy the guard. A
> guard that makes a claim harder to state than to abandon will get it
> abandoned. The gate for that work was declared hard in advance, so it went.

If asked "why not just ship it anyway, it worked once": because a gate that
moves when you dislike its answer is not a gate, and the two runs needed to
verify a fix are the two runs this demo was rehearsed in.

Do not offer "a stronger model would fix it." It is a resource excuse dressed as
a robustness story, and it invites "so why didn't you?", to which the honest
answer is that changing the model invalidates a passing 51/51 suite with no time
to re-verify it. Better not to raise it.

---

## Rehearsed set piece: the guard refusal (know this cold)

**Where:** `reports/CASE-1001.md`, section 2, steps **9–11**. Scenario 1.
Do not go looking for this live; it is here because it is the strongest single
artifact for the autonomy and verification criteria.

The agent submitted its assessment. The bus refused it for **two** reasons in
the same response. Use both; they are different guards:

> **Refused:** factor `related_alert_corroborates` cannot be declared: it
> requires a successful result from `get_related_alerts`, which you have not
> obtained.
>
> **Refused:** factor `version_patched` claims SRV-WEB-01 is outside ALL
> affected ranges, but you have not looked up **openssh** - service(s) this host
> runs that the CVE knowledge base covers.

The agent's own next line, which is the one to read aloud:

> *"Good catch - I need to fix two issues. Let me check openssh CVEs and remove
> the `related_alert_corroborates` factor since `no_data` is not a finding."*

It then calls `get_vulnerabilities(service_name='openssh')` and resubmits
without the unsupported factor, and that submission is accepted. **Two refusals,
two different correct responses:** it *gathered* what was missing, and *dropped*
what it could not support. Both the refusal and the correction are steps in the
evidence chain.

### The settled wording on guard timing: say it exactly like this

Verified in code before being said out loud. **Say:**

> **Guards validate declared findings; they do not choose tools.**

That is literally true, and here is what backs it if pressed. All four guard
call sites sit inside the `submit_assessment` branch. During gathering the bus
only *observes*. It records which tools returned `ok`, which services were
looked up and which log windows were queried, and that bookkeeping is **write-only
on the gather path**: nothing reads it, nothing alters a result, and a non-submit
call can never come back `rejected`. `GATHER_TOOLS` is a module constant, never
narrowed at runtime. Empirically, across every run, the only tool ever rejected
is `submit_assessment`.

Two precisions to volunteer rather than be caught on:

- A refusal *does* re-enter the loop, and the agent has answered one by going
  and calling `get_vulnerabilities` on the service it skipped. The guard did not
  select that tool; the agent did, in response to being told which source was
  unread. The refusal names **which source is unread, never what it will say**:
  across every refusal message there are zero version numbers, zero CVE ids and
  zero verdict words.
- The one thing that *does* alter a gather-path result is Scenario 6's
  `fail_tools`, and that is declared scenario config (fault injection we chose
  to test recovery), not a guard.

### The one sentence, if asked "isn't the bus deciding the verdict?"

> No. The bus refused the **form** of the claim, not its content. The agent said
> the host was outside *all* CVE ranges having looked up only two of its three
> services; you cannot say "all" after checking "some". The bus never decides
> whether MySQL 8.0.36 falls inside a range; that comparison is the agent's, and
> it is the whole point of §5.1.

### If a judge notices refusals everywhere: get ahead of this, do not defend it

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

**Do not say "the bus refuses the form of a claim and the agent supplies the
evidence."** The first half is right; the second is true of only 2 refusals in
11. Use the measured three-way account instead. It is more precise and it is
stronger:

- **It gathers** when the remedy is a tool call it already knows how to make.
  Refused for claiming a host is outside *all* affected ranges having checked
  only some of its services, the next call is `get_vulnerabilities` on the one
  it skipped. This is the scenario 1 set piece above.
- **It drops the factor** when the remedy is anything else. Refused for citing
  `related_alert_corroborates` from a lookup that came back empty, it stops
  making the claim. That is the correct answer, not a retreat: the claim was
  unfounded, and the honest fix is to withdraw it rather than go manufacture
  corroboration.
- **It has never once resolved a refusal by rewording the same claim.** Zero
  occurrences, every run measured.

Lead with the third. It is the direct answer to "isn't this just a model being
corrected?" A model being corrected argues, rephrases, tries the same claim in
softer words. This one treats a refusal as a genuine constraint: it either goes
and gets what it was missing, or it withdraws the claim. It never negotiates.

That composes with the Gate 2 finding, and the pair is the real lesson: **a
guard whose remedy costs more than abandonment gets the claim abandoned.** The
reverted configuration guard asked the agent to populate a schema field rather
than call a tool, and on one run in two it dropped a claim that was true and
supportable. Which response a refusal gets is a property of how the remedy is
shaped, not of the agent's willingness.

**If asked why identical fixtures give different counts: one line, pinned.**

> The model picks its own tool sequence and declaration timing each run, so the
> refusal count is a property of the trajectory, not of the fixtures.

Volunteer that rather than concede it: it turns the most variable number in the
project into evidence for dynamic action selection, the characteristic with the
weakest independent support. Family mix moves the same way and for the same
reason: provenance 6 / contradiction 3 / exhaustiveness 2 one run, 8 / 2 / 4
the next. What does not move is which response each family deserves.

The three shapes it refuses, worth naming because they are different failures:
**exhaustiveness** (claiming "outside ALL ranges" having checked some),
**provenance** (declaring a factor from a lookup that returned no data or
failed), and **contradiction** (declaring a finding and its negation together).

The sharpest single instance is in Scenario 5: `logs_clean` was refused because
**case 5002 had already concluded SUCCEEDED on that same asset over the window
being called clean.** That one compares a declared factor against a verdict the
agent itself produced in another case, and it is the one to reach for if
someone suspects the guards are cosmetic.

### Two follow-ups to have ready

**"Doesn't naming the missing service hand it the answer?"**
It names which *source* is unread, never what that source will say. The agent
still had to fetch OpenSSH's CVE ranges and decide 8.9p1 was outside them. And
the hint is disclosed in the report rather than hidden, which is why the chain
reads honestly.

**"Why not just check the signature's service?"**
That would be a hardcoded signature→service mapping: Python encoding detection
knowledge, which is the D-001 violation. Exhaustive coverage encodes none: it is
a statement about universal versus existential claims. `version_in_range` is
existential and deliberately exempt.

### Backup artifact
`reports/CASE-3001.md` has a precondition refusal (`related_alert_corroborates`
claimed from a lookup that returned no data) with the same shape, if Scenario 1
is not the one on screen.

### Follow-up: "how do you know the evals themselves are sound?"

Lead with this. It is a stronger answer than any pass count, because it is about
the failure mode that actually threatens a verification suite.

> Ten separate times my own tooling produced a **plausible wrong answer**, and
> every time the report looked fine. A regex-based guard ablation mis-attributed
> failures across two guards. An invariant I had "verified" by reading turned out
> never to have been asserted. A sandbox lock deleted itself, because it lived in
> the directory it was protecting. A coherence check printed "single coherent
> run" from a hard-coded string while the underlying span was wrong. A viewer
> "defect" I was about to fix turned out never to have existed. The configuration
> fixture shipped a `prevents_exploitation` boolean that would have handed the
> agent the verdict it was supposed to derive, while three comments in the code
> asserted it did no such thing. The deploy reported "ready" on a build where
> every single path redirected visitors to a login wall. A check of the Start
> button confirmed its label changed, while playback was frozen after one step. A
> bounds check passed deck slides whose titles were clipped behind content. And a
> phone-width test was really laid out at 500 pixels, so it reported a layout no
> phone would ever show.
>
> None of those were caught by a suite going red. All ten were caught by
> re-reading the output instead of the summary. That is why the guards are now
> ablated at runtime rather than by patching source, why fixture invariants are
> adversarially tested, and why every count in this project was re-derived
> rather than quoted.

### Second follow-up: the ablation numbers

Do not volunteer this; it belongs after the set piece, if asked.

> Each guard is ablated (monkeypatched to a no-op), and the suite has to fail.
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
the first two lines. The refusal is the payload; the setup is not.

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
> hasn't looked up OpenSSH, a third service this host runs that the knowledge
> base covers.
>
> Step nine is `get_vulnerabilities` on openssh. Step ten, it resubmits, and that
> one is accepted. FAILED, confidence 0.95, no action taken.
>
> Now, the obvious question is whether the tool just decided the verdict. It
> didn't. It refused the **form** of the claim, not its content. The agent said
> "outside all ranges" having checked two of three services. You can't say *all*
> after checking *some*. The tool never decides whether MySQL 8.0.36 falls inside
> a range; that comparison is the agent's, and it's the entire point of the
> design.

---

## The guard families: what the artifacts actually show

**Three checks appear in the shipped traces, three more fired as live refusals in
earlier recorded runs, and one has never fired live.** Say it that way: claiming a scope the
artifact does not contain is the one thing that turns this set piece against you.

**Demonstrated in `traces/` and visible in the reports:**

| scope | refuses | seen in |
|---|---|---|
| service coverage | `version_patched` claimed from a subset of the host's KB-covered services | scenarios 1, 3, 4, 7 |
| precondition | any factor drawn from a source that never returned `ok` | scenarios 1, 2, 3, 4, 6 |
| contradiction | a finding declared together with its negation | scenarios 3, 7 |

That table is the **shipped traces**, the ones a judge can open. Three more checks
fired as real refusals in **earlier recorded runs** but are not in the current
traces, because each full run replaces them: sibling verdict (scenario 5), log
window (scenario 6) and packet provenance (scenario 3). If asked, say that plainly
and do not point at a trace for them.

**Never fired in any live run:** only the related-alert time window. `selfcheck.py`
exercises it directly.

The one-sentence framing covers all of them regardless:

> Every one of these refuses the **form** of a claim, never its content. The
> positives are existential and need one witness; the negatives are universal
> and need a stated scope. The bus never decides what the evidence means.

### If asked about Scenario 5 specifically

> Case A reconsiders and reaches `SUCCEEDED` at 0.95 by declaring
> `logs_consistent`. It is worth knowing it clears the threshold on the other
> honest path too (dropping the log factor lands 0.80), so the case no longer
> turns on one factor's sign, which is what made it the flakiest scenario
> earlier. `compliance.py` asserts both paths clear.

**Known limitation, if pressed on the packet factor:** in the current S5 trace
case A declares `exfil_indicators` citing ALERT-5002's packet record, a sibling
alert's flow. The provenance guard requires the case to have *read* its own
alert's flow, which it did; it does not require the *citation* to be that flow.
No outcome impact (1.30 and 1.15 both clamp to 0.95). Recorded rather than
patched, because a fifth guard at this stage is unbudgeted risk against a
passing suite.

---

## Completeness pass: the things that get asked

### The model
> The committed traces were produced by `ling-3.0-flash-fin-free` through a
> multi-model gateway. The architecture is Claude-native tool use and the
> provider is one config line; the account is on a free plan with zero credits,
> so every Claude model returns "insufficient credits", verified by probing each
> one. That gateway model has since been retired, so the traces cannot be
> reproduced on it today. The guards are structural, so they apply to whichever
> model is behind them, but outcomes have only been verified on that one.

Say it once, in that form. It is a fact about the account, not an apology.

### Scopes not in the shipped traces

| scope | if asked |
|---|---|
| related-alert window | "Verified offline, and it has never fired live: the agent has not made that mistake. `selfcheck.py` asserts it refuses a `logs_clean` declared from a window that misses a known sibling alert, and ablating that guard fails 7 checks." |
| sibling verdict | "It fired live in an earlier recorded run, on scenario 5: `logs_clean` refused because case 5002 had already concluded SUCCEEDED on the same asset. It is not in today's traces because runs replace them. Ablating it fails 2 checks." |
| packet provenance | "It fired live in an earlier run, on scenario 3. And a known limitation: it confirms the case *read* its own alert's flow, not that the citation *is* that flow. Only scenario 5 case A reads two flows, so that is the one place it could matter." |

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
  block `fetch` on local files. Serve it over HTTP; that is the only cause.
- **If nothing animates:** `vendor/motion.js` did not load, or the machine has
  reduced-motion enabled. The viewer still reveals every card; motion is
  enhancement only and its absence breaks nothing.

### Fallback order

There is no live leg to fail, so this is the order if a *display* fails.

1. **Saved trace in the viewer**: local first, then the hosted copy at
   <https://soc-agent-trace-viewer.vercel.app/viewer.html#1>. Every scenario
   already has a passing trace committed.
2. **`reports/CASE-1001.md`**: the set piece reads just as well on the page as
   on screen; section 2, steps 9-11.
3. **`python selfcheck.py` and `python compliance.py`**: 99 and 22 checks, no
   API key, no network. These cannot fail for environmental reasons.

Decide which of these you are on *before* standing up, not during.
