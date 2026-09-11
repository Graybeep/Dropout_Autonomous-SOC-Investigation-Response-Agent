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

While it runs, say what it is doing: the agent is being handed ten tool schemas
and is choosing its own calls. Nothing about the order is scripted.

Then show the guardrails are checkable, not just claimed:

```bash
python compliance.py     # 12 structural checks
python selfcheck.py      # 62 behavioural checks
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
See `Toknow/DECISIONS.md` D-002. The architecture is Claude-native tool use; the
gateway is one config line, and swapping back is `SOC_BASE_URL` + `SOC_MODEL`.
