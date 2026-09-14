# fixtures/probe: generalization probe (NOT part of the suite)

Scenario 2's **shape** over a fixture set where every surface detail differs.
It exists to answer one question an independent reviewer raised: every artifact
in this project came from six scenarios we wrote ourselves, so nothing tested
the system outside its own anticipated cases.

| | scenario 2 | probe |
|---|---|---|
| asset | SRV-DB-02 / db-prod-02 | SRV-RPT-31 / analytics-rpt-31 |
| service | mysql 5.7.21 | postgres 13.4 |
| CVE | CVE-2023-21980, `>=5.7.0,<5.7.30` | CVE-2021-32027, `>=13.0,<13.5` |
| source IP | 198.51.100.23 | 203.0.113.77 |
| attack in logs | `UNION SELECT` + `information_schema` | stacked query + `pg_catalog`, bulk export via `COPY … TO STDOUT` |

Log phrasing is the variable that matters. If `logs_consistent` were matched on
fixture vocabulary rather than read semantically, the probe would fail here:
the two log sets share only `after, bytes, from, select, where`.

## Result

Identical on every axis: same three factors (`version_in_range`,
`logs_consistent`, `exfil_indicators`), same raw **1.15 → 0.95**, same
`SUCCEEDED`, same `block_ip`, same tool order, same single provenance refusal.
No scenario 2 vocabulary appears anywhere in the probe's citations, and it
selected the sql_injection CVE over the privilege-escalation one whose range did
not match, a real version join on a service it had not seen.

## What this does and does not support

**Does:** the evidence classes generalise beyond the fixtures we wrote.

**Does not:** dynamic action selection. Identical tool ordering is evidence of
consistency, not adaptivity. The adaptive evidence is scenarios 3 and 6, where
the ordering genuinely diverges. Citing the probe for autonomy would be
overclaiming from a result that says something else.

## Rules

Not in `run_all.py`. Not a scenario. Never seeded by the suite; `run_all.py`
reseeds from `fixtures/seed` only. Nothing here was tuned to make it pass, and
it was run exactly once. See `Toknow/DECISIONS.md` N-37.
