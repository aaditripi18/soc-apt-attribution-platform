# ADR-0021 — Behavioural profile match, clusters, response guidance, and the console built around them

- **Status:** ACCEPTED (2026-10-12, owner instruction: adopt the way SOC platforms handle groups that cannot be
  singled out — behavioural overlap scores, overlap shown visually, mitigations — and present the site as a
  detection-and-attribution platform without internal status wording).
- **Builds on:** ADR-0005 (diagnosticity `D = 1 − g`), ADR-0017 (the verdict), ADR-0018 / ADR-0013 (group-specific
  evidence), ADR-0016 (console), CLAUDE.md ("confidence scores must have an understandable methodology — never
  arbitrary numbers"; "prefer explainability over opaque scoring").
- **Changes:** ADR-0017's rule that candidates are never ordered. They are now ordered — by a similarity with one
  stated meaning — while its rule that overlap never *names* an actor stands unchanged.

## Context

For most intrusions no Group can be identified: 158 of 176 Groups have no group-specific content, and shared
techniques do not single one out. Until now the console answered "no actor can be singled out" and listed the
candidates alphabetically. That is correct and of little use to an analyst, who still wants to know which profiles
the behaviour resembles, why they cannot be told apart, and what to do.

The owner proposed the approach commercial platforms take: a match score per Group, the overlap visualised, and a
shift from "who" to "what to do". Two parts of the proposal are adopted as written; one is adopted with a
constraint that the project's own measurements impose.

## Decisions

### D1 — One overlap measure, with a stated meaning

For observed techniques `T` (ADR-0005's decision features, pooled over the investigation) and a Group or Campaign
with recorded techniques `P`:

```
weight(t) = 1 − (active Groups recorded using t) / (active Groups)        # ADR-0005's D
overlap   = Σ weight(t) for t in T ∩ P   ÷   Σ weight(t) for t in T
```

`overlap` is the share of the observed behaviour, weighted by rarity, that the profile contains: 0 to 1, no fitted
parameter, recomputable by hand from ATT&CK. The proposal's alternative — dividing by the size of the Group's
profile — is kept as a second, separately named figure (`profile_share`), because it answers a different question
(how much of the Group's known repertoire was seen) and penalises well-documented Groups.

### D2 — It is called overlap, and it is not a confidence

The proposal labels the number a confidence or probability ("84% match"). It is neither, and this is measured, not
a matter of caution: on the recordings whose actor is known, ordering candidates by this rarity-weighted overlap
put the actor at positions 14 to 121, never first and never in the top ten (ADR-0005 record 2026-10-11;
`data/validation/known-answer-checks.json`). A number presented as "the probability it is Group X" would be wrong
at exactly the moment an analyst trusted it — the failure of this project's previous version.

So:

- the field and every label say **behavioural overlap**; no key of the record contains `confidence`, `probability`,
  `likelihood`, `rank` or `score` (tested);
- candidates **are ordered** by overlap, because "which profiles is this closest to" is a fair question with a
  true answer;
- the first candidate is never called the answer. Who is responsible remains the stored verdict's statement
  (ADR-0017), and a Group named there on specific evidence is marked in the list (`named_by`) without being moved.

### D3 — Clusters instead of false precision

Candidates whose profiles contain exactly the same observed techniques have the same overlap for the same reason:
this evidence cannot separate them. They are returned as one **cluster** (labelled A, B, …; the id is a hash of the
matched technique set), and the console's headline for an unidentified intrusion is the closest cluster and its
size, not one name. This is the honest form of the "activity cluster" idea: it clusters Groups by what the evidence
can distinguish. Tracking clusters of *activity across incidents* (vendor UNC / Storm designations) needs a history
of incidents this project does not have and is not attempted.

### D4 — Response guidance from ATT&CK's own records

For the observed techniques the record lists ATT&CK's mitigations (`mitigates` relationships; a sub-technique also
takes its parent's), each with ATT&CK's name and first paragraph of description, ordered by how many observed
techniques it addresses. Techniques with no recorded mitigation are listed as such. No response text is written by
hand and none depends on who the actor is: the proposal's example playbook sentences are not adopted, because the
platform has no source for them.

### D5 — Stored and served like the other investigation records

`investigation/profile_match.py` computes the record from the stored assessment and the pinned ATT&CK version at
the end of a run (`profile-match/1`, investigation method 1.8) and `GET /investigations/<id>/profile-match` serves
it. `GET /attack/groups` serves every active Group as ATT&CK records it (aliases, description, techniques,
software) with the group-specific evidence the platform holds for it — accepted actor rules that run here and
attributed advisory bundles.

### D6 — The console is organised around detection, attribution and response

- Navigation: Overview, Investigations, Analyze Logs, Activity Search · Threat Actors, Technique Coverage · Reports,
  Methodology.
- An investigation has the tabs Overview, **Attribution** (headline, group-specific evidence, closest profiles,
  clusters, overlap matrix), ATT&CK matrix, Timeline, **Response**, Detection validation.
- **Internal status wording is removed from the working pages**: the "uncalibrated" badges, the service-status
  indicator, command-line instructions and method-version strips. What they said is not dropped: the
  **Methodology** page states in plain language how identification and overlap work, gives the formula, says what
  overlap does and does not mean, and shows the validation results. One sentence under the profile table repeats
  that overlap is similarity, not responsibility.

## Consequences

- An analyst always gets an answer with content: an identified Group, or the closest cluster with the reason it
  cannot be narrowed, plus mitigations.
- The stored assessment (ADR-0017) and unit analyses are unchanged; unit-level candidate lists stay alphabetical.
- The `calibration_status` fields remain in the API records (they are true); the console no longer displays them.
- A reader who skips the Methodology page can still over-read a high overlap. The label, the cluster framing and the
  sentence under the table are the mitigations; the measured positions on the Methodology page are the evidence.

## Checks

`tests/test_profile_match.py`: weights and overlap recomputed from ATT&CK for every candidate; ordering; clusters
partition the candidates by matched set; mitigations are ATT&CK's own for the observed techniques, citations
stripped; a Group named by specific evidence is marked and not moved; no key claims a likelihood; an empty
investigation gives an empty record.

## Amendment A (2026-10-12) — every overlap percentage states what it rests on

**Why.** ADR-0025 halved the techniques that count, and the top overlap percentages rose (one recording: 56% to
85%), because overlap is the matched share of what was counted. A high figure on eight techniques is weak
evidence, and the percentage alone did not show that.

**Decision (display only; the formula, the evidence rules and the verdicts are unchanged).** Wherever an overlap
percentage appears it is shown with the number of techniques matched and the number counted in the investigation,
in one wording produced by one function (`frontend/src/lib/derive.ts::overlapLabel`): `85% · 7 of 8 counted
techniques`. The denominator is the investigation's counted techniques — the denominator of the calculation — never
the size of the group's profile. Because the percentage is weighted towards rarer techniques it is not simply
matched divided by counted, and the page says so. Surfaces: the attribution headline, the profile table, the
cluster cards and the technique matrix; the assistant's digest (`rests_on`, and an instruction to state it,
`assistant/5`); the Kibana export (`counted_techniques`, `kibana-export/3`) and its profile table.

**Not decided.** No minimum number of techniques below which a percentage is hidden or flagged: any threshold
would be arbitrary until measured against more investigations. The count is shown; the reader judges.

**Checks.** `derive.test.ts` (wording, few techniques, one technique, none); `tests/test_kibana_export.py`
(counted techniques equal the profile match's, matched never exceeds counted); inspected on the live attribution
page of the uploaded recording (`85% · 7 of 8 counted techniques` in the headline, table, clusters and matrix).
