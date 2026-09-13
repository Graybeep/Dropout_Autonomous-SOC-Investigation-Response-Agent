# Four-minute demo script

**Run the whole thing on Scenario 3.** It contains every beat in the required
order, so there is no scenario switch and no re-establishing context halfway
through. Open `http://localhost:8000/viewer.html#3` and press **Show all**, then
scroll. Do not use Start/replay: 95 steps at 400ms is 38 seconds of your four
minutes spent watching cards appear.

Second screen or second tab: `reports/CASE-3001.md`, already scrolled to
section 6. You switch to it once, at 3:30.

---

## 0:00 – 0:30 · What it does, and the rule

Say, roughly:

> A detection tool fires an alert when traffic *looks* like an attack. It cannot
> tell you whether the attack actually worked. That question is what a SOC
> analyst spends their day on, and it is what this agent does: it investigates
> the alert and decides whether the attack succeeded, by correlating asset,
> vulnerability, configuration, log and packet evidence instead of trusting the
> alert's severity label.

Then the guard rule, which you will need at 2:00 and should plant now:

> Every conclusion it reaches has to survive one rule: **you cannot say ALL
> after checking SOME.**

Nothing on screen yet matters. Do not read the KPI row aloud.

---

## 0:30 – 1:00 · The alert, the hypothesis, the first call

Scroll to the top of the timeline. Three cards, in order.

**The alert.** A SQL-injection signature against `SRV-APP-03`, labelled
critical. Say the label is the sensor's opinion and earns nothing.

**The hypothesis.** The agent writes down what it believes *and what would prove
it wrong*, before looking anywhere:

> For this attack to have succeeded, the target must be running a vulnerable
> version, the injection must have actually executed on the host rather than
> been attempted or blocked, and data must have left.

Point out the second half explicitly. Deciding in advance what would change its
mind is what stops the investigation becoming a hunt for agreement.

**The first tool call, with its reason attached.** Every evidence tool takes a
required `reason` parameter, so the trace cannot contain an unexplained call:

> *Why:* Get the alert details: signature, source/destination IP, target asset,
> and severity label to understand the attack type and form an initial
> hypothesis.

The line to land: **the agent chose that call.** Nothing about the order is
scripted.

---

## 1:00 – 2:00 · Gather, and the thinking between calls

Scroll through the gather phase. Do not read every card. Land three things:

1. **Every call carries its reason**, and they are different reasons, not a
   template.
2. **Between calls the agent judges whether it has enough.** Stop on one
   `SUFFICIENCY ASSESSMENT` card and read a line of it aloud. This is the part
   that distinguishes an agent from a pipeline.
3. **The correlation.** The vulnerability database is keyed by service name and
   holds no per-host patch status, because a real CVE feed does not know what
   your host runs. So the agent has to join two independent facts and show the
   join: the host runs a version, the CVE covers a range, and it says out loud
   which side of the range the version falls on.

If you are running long, cut point 3 and pick it up at 2:30 where it recurs.

---

## 2:00 – 2:30 · The refusal

This is the set piece. Find the red-railed card (first one, around step 23).

**Submit.** The agent declares its evidence and submits.

**Rejected.** Read the refusal off the screen:

> factor `related_alert_corroborates` cannot be declared: it requires a
> successful result from `get_related_alerts`, which you have not obtained.

**The agent's own words**, on the very next card:

> The assessment was rejected because I included `related_alert_corroborates` as
> a factor even though `get_related_alerts` returned `no_data`. Per the rules, an
> empty or failed lookup establishes nothing and must not be cited as a factor.

**Resubmit, accepted.** It drops the claim and concludes `INCONCLUSIVE` at 0.40.

Then the sentence that answers the obvious objection before it is asked:

> The bus refuses the **form** of a claim, never its content. It never decides
> whether a version is in range — that comparison is the agent's. It refuses
> citing a source that came back empty, and claiming *all* having checked *some*.

**If asked "is it always being corrected?"** — do not get defensive. Every case
gets refused at least once; that is the bus working on the normal path, not a
stumble. And across every run measured, the agent has **never** resolved a
refusal by rewording the same claim. It either fetches what it was missing or
withdraws the claim. It does not negotiate.

---

## 2:30 – 3:30 · New evidence, and the case re-opens

Scroll to the purple dashed fork card.

**What lands:**

> Delayed log shipping delivered two entries for SRV-APP-03 that post-date your
> investigation. They indicate lateral movement from SRV-APP-03 to a second
> host, 10.20.2.99 (SRV-DB-09), using the svc_app service account.

**The point that matters, and it is the whole demo:** the case does not re-open
at the verdict. It re-opens at **HYPOTHESIZE**. New evidence, a tool failure and
a human override all route through one `reconsider()` function, and it puts the
agent back at the hypothesis stage.

So the agent does not re-score what it already had. **It goes and investigates
the second host.** Scroll through and count out loud if you like: **16 new tool
calls after the fork** — asset info for `SRV-DB-09`, its logs, its CVE ranges,
its configuration, related alerts on it.

That is the difference between adaptation and re-arithmetic, and the harness
asserts it: scenarios 3 and 5 must *gather new evidence* after reconsidering, and
a scenario with no reconsideration scores 0 as the negative control.

**The flip:** `INCONCLUSIVE` 0.40 becomes `SUCCEEDED` 0.95. The new hypothesis is
the interesting part — the original injection *did* fail, and the attack
succeeded anyway:

> While the initial SQL injection on SRV-APP-03 failed, the attacker used
> credentials obtained during that session to move laterally.

---

## 3:30 – 4:00 · The fork in the report

Switch to `reports/CASE-3001.md`, **section 6, Reconsideration events**.

Show the two conclusions **side by side**:

| | outcome | score | confidence |
|---|---|---|---|
| Before | `INCONCLUSIVE` | 0.40 | 0.40 |
| After | `SUCCEEDED` | 0.95 | 0.95 |

Then explain why that layout is the point, not a formatting choice:

> The prior conclusion is **preserved, never overwritten**. A system that
> silently replaced its answer would be indistinguishable from one that had been
> right all along. Here the trace records what it believed, what arrived, and
> what it believed afterwards — so you can audit the change of mind, not just
> the final answer.

Close on the same rule you opened with:

> It reached a verdict, acted on it, verified its own action took effect, and
> when new evidence arrived it went back and looked again rather than adjusting
> a number. And it never got to claim anything it had not actually checked.

---

## Practical notes

**Timing is tight.** The gather phase at 1:00–2:00 is where you will overrun.
Rehearse that minute specifically, and be willing to cut the correlation point.

**Do not press Start.** Use Show all and scroll. Replay is for a slower
walkthrough, not a four-minute slot.

**Fallback order**, in this order, no improvising on the day:

1. Local viewer at `http://localhost:8000/viewer.html#3`
2. The hosted viewer, <https://soc-agent-trace-viewer.vercel.app/viewer.html#3>
3. `reports/CASE-3001.md` read directly — every beat above is in the report text

**Do not open `viewer.html` from the folder.** `file://` blocks the trace from
loading. Start the server first.

**Bonus refusals if you have slack**, both later in Scenario 3: a two-family
refusal at step 72 (provenance *and* the openssh coverage rule, the "all after
some" case you planted at 0:00), and a contradiction refusal at step 78 where the
agent answers *"the system correctly flagged the contradiction"*. Neither is
needed for the four minutes.
