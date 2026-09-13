# Four-minute demo script

**Two scenarios, one switch.** Scenario 1 carries 0:00 to 2:30: the alert, the
hypothesis stated before any gathering, the reasoning between calls, and the
refusal. Scenario 3 carries 2:30 to 4:00: new evidence, the case re-opening, and
the fork. The switch lands exactly where the story turns from "how it
investigates" to "what happens when it was wrong".

Every quotation below is copied from the shipped traces, not paraphrased. If you
change a word while speaking, say it as your own summary, not as a quote.

**Set up before you start**

- Tab 1: `http://localhost:8000/viewer.html#1` with **Show all** pressed
- Tab 2: `http://localhost:8000/viewer.html#3` with **Show all** pressed
- Tab 3: `reports/CASE-3001.md`, scrolled to section 6

Do not press Start. Replaying 39 and then 93 cards at 400ms would eat a
minute of a four-minute slot.

---

## 0:00 – 0:30 · What it does, and the rule

> A detection tool fires an alert when traffic *looks* like an attack. It cannot
> tell you whether the attack actually worked. This agent answers that question:
> it investigates the alert and decides whether the attack succeeded, by
> correlating asset, vulnerability, configuration, log and packet evidence
> instead of trusting the alert's severity label.

Then plant the rule you will cash in at 2:00:

> Every conclusion it reaches has to survive one rule: **you cannot say ALL
> after checking SOME.**

---

## 0:30 – 1:00 · The alert, the hypothesis, the first call  *(Tab 1, Scenario 1)*

**The alert.** A SQL-injection signature against `SRV-WEB-01`, labelled
critical. Say the label is the sensor's opinion and earns nothing in the score.

**The first call, with its reason.** Every evidence tool requires a stated
reason, so the trace cannot contain an unexplained call:

> *Why:* Get the alert details: signature, source/destination IP, target asset,
> and severity label to understand the attack type and form an initial
> hypothesis.

**The hypothesis, stated before gathering.** This card appears after that single
call and before any evidence is fetched:

> **My hypothesis:** For this attack to have *succeeded*, the target must be
> running a vulnerable version of the web service, the SQL injection must have
> actually executed on the host (not just been attempted/blocked), and
> potentially data must have exfiltrated.

The point to land: it wrote down what would have to be true **before** looking,
including the case that would sink the hypothesis, an attempt that was blocked.

---

## 1:00 – 2:00 · Gather, and the thinking between calls  *(Tab 1)*

Scroll through the gather phase. Do not read every card. Land three things.

**Every call carries its own reason**, and they are different reasons, not a
template.

**Between calls it judges whether it has enough.** Stop on the sufficiency card
after the log fetch and read it:

> Excellent - the server logs are very revealing. The WAF **blocked** the SQL
> injection with a 403, and the only MySQL query that executed was benign. Let
> me still check CVEs to complete the picture on whether the host was even in a
> vulnerable range.

That word **"still"** is the agent part. The evidence already looks decisive and
it chooses to keep going rather than stop at the first convenient answer.

**The correlation.** The vulnerability database is keyed by service name and
holds no per-host patch status, so the agent has to join two independent facts:
the version the host runs and the range the CVE covers. If running long, cut
this point.

---

## 2:00 – 2:30 · The refusal  *(Tab 1)*

Find the red-railed card.

**Submit.** It declares the host patched and cites a related alert as
corroboration.

**Rejected, on two counts.** Read both off the screen:

> factor 'related_alert_corroborates' cannot be declared: it requires a
> successful result from get_related_alerts, which you have not obtained.

> factor 'version_patched' claims SRV-WEB-01 is outside ALL affected ranges, but
> you have not looked up openssh - service(s) this host runs that the CVE
> knowledge base covers.

The second one is the rule you planted at 0:00. Say so.

**The agent's own words**, on the next card:

> Good catch - I need to fix two issues. Let me check openssh CVEs and remove the
> `related_alert_corroborates` factor since `no_data` is not a finding.

**Resolves both, differently.** The next call is `get_vulnerabilities` on
`openssh`, so it *fetches* what it was missing, and it *drops* the claim it could
not support. It resubmits and is accepted: `FAILED`, confidence 0.95.

Then the line that heads off the obvious objection:

> The guard refuses the **form** of a claim, never its content. It never decides
> whether a version is in range; that comparison is the agent's.

---

## 2:30 – 3:30 · New evidence, and the case re-opens  *(switch to Tab 2, Scenario 3)*

> A harder case. On this one the agent's first pass came back inconclusive.

Scroll to the purple dashed fork card. What lands:

> Delayed log shipping delivered two entries for SRV-APP-03 that post-date your
> investigation. They indicate lateral movement from SRV-APP-03 to a second host,
> 10.20.2.99 (SRV-DB-09), using the svc_app service account.

**The point of the whole demo:** the case does not re-open at the verdict. It
re-opens at **HYPOTHESIZE**. New evidence, a tool failure and a human override
all route through one `reconsider()` function, which puts the agent back at the
hypothesis stage.

So it does not re-score what it already had. **It goes and investigates the
second host: 16 new tool calls after the fork**: asset information, logs,
configuration and related alerts for `SRV-DB-09`, plus CVE ranges for what it runs.

The harness enforces this: scenarios 3 and 5 must gather new evidence after
reconsidering, and a scenario with no reconsideration scores zero as the
negative control.

**The flip**, from `INCONCLUSIVE` 0.40 to `SUCCEEDED` 0.95. The new conclusion:

> The attack SUCCEEDED. While the initial SQL injection on SRV-APP-03 failed
> (syntax error, 0 rows), the attacker used credentials obtained during that
> session to pivot laterally to SRV-DB-09, where they successfully authenticated,
> exfiltrated sensitive payroll data, created a persistence backdoor account, and
> dumped all databases to the attacker's server.

Worth saying out loud: the original injection really did fail. The first verdict
was not wrong about what it saw. It just had not seen enough yet.

---

## 3:30 – 4:00 · The fork in the report  *(switch to Tab 3)*

`reports/CASE-3001.md`, section 6, **Reconsideration events**. Both conclusions,
side by side:

| | outcome | score | confidence |
|---|---|---|---|
| Before | `INCONCLUSIVE` | 0.40 | 0.40 |
| After | `SUCCEEDED` | 0.95 | 0.95 |

> The prior conclusion is **preserved, never overwritten**. A system that
> silently replaced its answer would look exactly like one that had been right
> all along. Here you can audit the change of mind, not just the final answer.

Close on the rule:

> It reached a verdict, acted on it, verified its own action took effect, and
> when new evidence arrived it went back and looked again rather than adjusting
> a number. And it never got to claim anything it had not checked.

---

## Practical notes

**Protect the last thirty seconds.** If you overrun, cut from 1:00–2:00 (the
correlation point first), never from 3:30–4:00.

**Fallback order**, fixed in advance:

1. Local viewer, `http://localhost:8000/viewer.html#1` and `#3`
2. Hosted viewer, <https://soc-agent-trace-viewer.vercel.app/viewer.html#1>
3. `reports/CASE-1001.md` and `reports/CASE-3001.md` read directly; every beat is
   in the report text

**Start the server before opening a browser.** Opening `viewer.html` from the
folder gives a `file://` page and the traces cannot load.

**If you have slack at 2:30**, Scenario 3 has two more refusals worth a line: at
step 72 the same openssh coverage rule fires on the second host, and at step 78
the agent declared a finding and its negation together and wrote *"The system
correctly flagged the contradiction."*
