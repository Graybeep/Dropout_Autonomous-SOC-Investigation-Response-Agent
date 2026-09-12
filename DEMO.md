# Demo script

Roughly 6–8 minutes. The viewer replays saved traces, so nothing can hang,
rate-limit, or go off-script in front of judges. Run the agent live once
(step 0) to prove it is real, then demo from the viewer.

## Setup (before you present)

```bash
python -m http.server 8000
# open http://localhost:8000/viewer.html
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

While it runs, say what it is doing: the agent is being handed ten tool schemas
and is choosing its own calls. Nothing about the order is scripted.

Then show the guardrails are checkable, not just claimed:

```bash
python compliance.py     # 12 structural checks
python selfcheck.py      # 84 behavioural checks
```

> "No outcome branches on scenario identity. No code branches on the alert's
> severity label. Outcome values are produced in exactly one file."

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
"Insufficient credits" — verified by probing each one, not assumed. DeepSeek
v4.1 Flash is the strongest model this key can actually reach: 1M context,
reasoning-capable.

**"How stable is it, really?"** — answer this with the number, not a hedge.

> Five of six clean on a full run, twice consecutively at the current bar. The
> one failure was Scenario 5 case A, and I know exactly what happened: the agent
> re-read the logs, saw all three injected exploitation entries — a UNION SELECT
> that executed, 38,402 rows returned, 1.7 MB egress — and still declined to
> swap `logs_clean` for `logs_consistent`. It added the corroboration factor and
> landed at 0.55 against a 0.75 threshold. That one swap is worth 0.50 and takes
> it to 0.95.

Then the *why*, which is the interesting half:

> Its reasoning was defensible in isolation. Case A is the 05:02 port scan; the
> exploitation is timestamped 07:14 and belongs to the sibling alert. "Clean for
> my window." What it missed is that both alerts are one source against one
> asset. That is now addressed in the `RELATED_CASE` prompt — judge whether THIS
> asset was compromised by THIS source, not whether one packet did damage alone.

Do not offer "a stronger model would fix it." It is a resource excuse dressed as
a robustness story, and it invites "so why didn't you?" — to which the honest
answer is that changing the model invalidates a passing 84/84 suite with no time
to re-verify it. Better not to raise it.

---

## Rehearsed set piece — the guard refusal (know this cold)

**Where:** `reports/CASE-1001.md`, section 2, steps **8–10**. Scenario 1.
Do not go looking for this live; it is here because it is the strongest single
artefact for the autonomy and verification criteria.

The agent submitted its assessment claiming `version_patched`. The bus refused:

> **Refused:** factor `version_patched` claims SRV-WEB-01 is outside ALL
> affected ranges, but you have not looked up **openssh** — service(s) this host
> runs that the CVE knowledge base covers.

The very next step is `get_vulnerabilities(service_name='openssh')`, then a
corrected resubmission that is accepted. Both the refusal and the correction are
steps in the evidence chain.

### The one sentence, if asked "isn't the bus deciding the verdict?"

> No — the bus refused the **form** of the claim, not its content. The agent said
> the host was outside *all* CVE ranges having looked up only two of its three
> services; you cannot say "all" after checking "some". The bus never decides
> whether MySQL 8.0.36 falls inside a range — that comparison is the agent's, and
> it is the whole point of §5.1.

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

### Follow-up only — "how do you know the evals themselves are sound?"

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
