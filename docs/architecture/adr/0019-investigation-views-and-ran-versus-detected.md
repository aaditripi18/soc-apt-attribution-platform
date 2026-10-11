# ADR-0019 — Investigation views (ATT&CK matrix, activity timeline) and ran versus detected

- **Status:** ACCEPTED (2026-10-11, owner instruction: "go through the recommended paths" — the three site
  additions recommended after the pre-publish review).
- **Builds on:** ADR-0009 (read model: joins of stored records, nothing computed at read time that a stored
  record does not hold), ADR-0016 (the frontend shows what the API returns and computes no attribution),
  ADR-0017 (no ordering, likelihood or confidence without a calibration version), ADR-0003 Amendment H (context
  Evidence), `docs/operations/lab-pilot-results.md` (the comparison this ADR automates was first done by hand).

## Context

An analyst opening an investigation could see its units and, per unit, everything about it. Three questions had
no direct answer:

1. **Which parts of ATT&CK did this recording touch?** Technique lists existed per unit only.
2. **What happened when, across units?** The investigation timeline drew one bar per unit per host; the unit
   sequence drew one unit. Nothing showed all Evidence over time.
3. **How much of what really ran did the platform detect?** For a lab recording the emulation tool knows the
   answer. `lab-pilot-results.md` compared it with the platform's output by hand, once.

## Decisions

### D1 — One activity route, two drawings

`GET /investigations/<id>/activity` returns every Evidence item of the investigation's units as one time-ordered
list: time, unit, host, a short label, the ATT&CK reference, whether the Evidence is context-tier, and whether its
technique is a decision feature **of its unit**. It is a join of stored records (investigation → units → Evidence
→ source Observation, and each unit's stored analysis). It holds no score and no order other than time.

The label is the process name, else the event action, else the source type. A command line is never included:
the route is an overview, and command lines stay on the per-Evidence view where their Observation is shown whole.

Evidence outside any unit (ADR-0003 Amendment H) is not listed; the response repeats the stored count so a
reader can see how much is left out.

The frontend draws that one response twice:

- **ATT&CK matrix.** Columns are the tactics of the pinned ATT&CK version in its own order; a cell is a technique
  with Evidence. A technique under several tactics appears under each, because the recording does not say which
  purpose the activity served. Empty tactics are kept and labelled "nothing observed"; the page says that this
  means no pinned rule matched, not that the tactic did not happen. A cell's colour is the strongest role the
  technique has in any unit — decision feature, core Evidence no Group or Campaign uses, or context only — the
  same three roles as the unit's Techniques tab. Its numbers are counts: Evidence items and units.
- **Activity timeline.** One lane per tactic with Evidence, plus a lane for actor-specific Evidence (ADR-0018).
  Time is cut into 96 equal intervals; a mark stands for the Evidence in one interval of one lane, coloured by
  the strongest role in it and sized by a logarithm of the count. Selecting a mark lists its Evidence with links
  to the units. Binning is what keeps a recording with thousands of Evidence items legible and is stated on the
  page with the interval length. The vertical order is ATT&CK's tactic order and is stated not to be a claim
  about the order of events.

Neither view is a kill chain. Causal order within a unit remains the unit's sequence (ADR-0004), which is built
from lineage, not from tactic order.

### D2 — Ran versus detected: an emulation report beside the Evidence

`python -m attribution_platform.investigation <recording> --emulation-report <report.json>` accepts the emulation
tool's own report of the run (a MITRE CALDERA operation report; one recording per report). After the
investigation is stored, `investigation/emulation.py` compares each reported step with the investigation's
Evidence and stores the result (`emulation-comparison/1`, index `attribution-platform-emulation-comparisons-v1`);
`GET /investigations/<id>/emulation` serves it, and answers 404 when no report was given.

Two questions are asked of each step, by fixed rules:

- **The step's own process.** Evidence grounded in an Observation whose process id or parent process id is the
  step's process id, on the step's host (short name or FQDN), between the time the step was issued and the time
  its result was collected, ± 10 s. This ties Evidence to *that* step.
- **The step's technique anywhere.** Evidence for the technique the report names, anywhere in the investigation,
  counted as core and context.

The outcome is a closed vocabulary, strongest first:

| Outcome | Rule |
|---|---|
| `technique_detected_in_step` | the step's own Evidence includes the technique the report names |
| `step_activity_detected` | the step's own process produced Evidence, for other techniques only |
| `technique_detected_elsewhere` | none from the step's process, but the investigation has Evidence for the technique |
| `not_detected` | neither |

`technique_detected_elsewhere` is kept apart because it cannot be tied to the step: on `pilot-02` most Evidence
for one discovery technique came from activity the plan did not issue.

**The report's command text and command output are never read, stored or served.** Only step name, ability id,
technique, tactic, host, executor name, status, times and process id are read. The comparison does not need
commands, and a read model has no business carrying attack commands. Tests feed a report whose command fields
hold a marker string and assert it appears nowhere in the stored record or any response; the served-model audit
checks that no key of either new route names a command or an output.

A report that is not a CALDERA operation report fails closed (`EmulationReportError`, exit 1) before anything is
stored. A report without process ids or times yields no step-level match — steps then fall to the technique-anywhere
rules — rather than a guess.

### D3 — What these views do not say

- The comparison is about **detection**, never attribution. An emulation profile's name is shown as the tool
  reports it and is not used by any verdict (ADR-0017 stays the only source of a verdict).
- One run on one host is an example, not a detection rate; the page says so.
- Nothing is ordered by support, and no number on these pages is a likelihood or a confidence.

## Consequences

- Investigation pages gain tabs: Overview, ATT&CK matrix, Timeline, Ran vs detected
  (`#/investigations/<id>/<tab>`). The last tab explains how to supply a report when there is none.
- `scripts/audit_served_read_model.py` now also recomputes the activity route from the units' Evidence (same
  items, same unit, same reference, same tier, same decision-feature flag, time-ordered) and, where a comparison
  exists, that each outcome follows from the served counts by the rules above.
- Only CALDERA reports are read. Another tool's report needs its own parser producing the same `EmulationRun`;
  the comparison and everything downstream are tool-independent.
- The step window depends on the tool recording a process id. Activity a step causes in a process that is not
  the step's own or its direct child (a service, a scheduled task) is not tied to the step; it can still count
  under "technique anywhere".

## Implementation record (2026-10-11)

`pilot-02` (the lab recording of `lab-pilot-results.md`: CALDERA Discovery profile, 8 steps, one Windows host),
run with `--emulation-report`:

| Measure | Result |
|---|---|
| Steps whose own process left Evidence | 8 of 8 |
| `technique_detected_in_step` | 3 |
| `step_activity_detected` | 5 |
| `technique_detected_elsewhere` / `not_detected` | 0 / 0 |
| Distinct techniques named by the report with Evidence anywhere | 4 of 7 |
| Activity route | 221 Evidence items of 2 units (3 more in no unit); 17 techniques under 4 of 15 tactics |

The comparison corrected the hand-made table it replaces: 115 Evidence items for T1069.001 belong to the process of
a step the report labels T1135, not to the step labelled T1069.001, and T1033 was detected by one low-level item
outside every unit. Both are recorded in `lab-pilot-results.md`.

Checks: `tests/test_emulation_comparison.py` (11 tests: each outcome, window and host mismatch, no command text
stored or served, routes, 404 without a report, CLI refusals); frontend `derive.test.ts` (matrix and timeline
shaping); `scripts/audit_served_read_model.py` on the running `pilot-02` server: 3,247 checks, all passing,
including the new `activity.*` and `emulation.*` checks.
