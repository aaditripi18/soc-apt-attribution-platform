# ADR-0017 — Investigation-level attribution assessment: a verdict that cannot name an actor it cannot support

- **Status:** ACCEPTED (2026-10-11, owner instruction: "do both, honest verdict first then the group-specific
  evidence").
- **Builds on:** ADR-0005 (the comparison and its implementation record of 2026-10-11), ADR-0006 (calibration),
  ADR-0009 D3 (no likelihood, confidence or ranking before a calibration version), ADR-0013 (indicators are
  context), ADR-0016 (the frontend displays what the backend stored), CLAUDE.md ("explain how strong the
  attribution is, what uncertainty remains"; "never hard-code attribution results"; "confidence scores must have
  an understandable methodology").

## Context

The platform analysed *units* — a few structurally linked events — and listed every consistent candidate per unit.
An analyst's question is about the intrusion: can this be attributed, and to whom? The owner asked for a "most
likely actor" and a confidence. Before building either, what a ranking would get right was measured.

## Measured (`scripts/measure_actor_ranking.py`, `data/validation/known-answer-checks.json`)

On the recordings whose answer is known — two emulations (APT29, APT3) and two single-tool tests with no actor:

- **Ordering candidates names the wrong actor.** Per unit and with all units pooled, at technique level and with
  sub-techniques folded into parents, under four orderings (overlap count, rarity-weighted overlap, overlap ÷
  profile size, F1): the emulated actor is never first and never in the top 10 (ADR-0005 record).
- **"Rare technique → that Group" names the wrong actor too.** A technique ATT&CK records for a single Group looks
  like a discriminator and is not: the APT29 recording's only such technique (T1548, the parent id) is recorded for
  UNC3886; both tool tests carry T1564.004 → APT32 and T1615 → Turla. Parent technique ids are rarely recorded in
  ATT&CK, so their "exclusivity" is a reporting artefact.
- **An ordering always names someone.** On the tool tests, where there is no actor, every ordering still puts a
  Group first — a false attribution each time.

## Decisions

### D1 — One assessment per investigation, computed at run time and stored

`investigation/assessment.py` pools the stored unit analyses of an investigation and stores an
`InvestigationAssessmentRecord` (own index; `GET /investigations/{id}/assessment`). The API still computes nothing.
It is built from the same JSON the read model holds for the units, so it can say nothing the units do not.

### D2 — The verdict vocabulary has no "attributed to"

| Verdict | Meaning |
|---|---|
| `no_decision_features` | Nothing observed is both supported by core Evidence and recorded for a Group or Campaign. |
| `not_distinguishable` | Many Groups and Campaigns are consistent; nothing observed is specific to one of them. |
| `third_party_lead` | As above, and an observed value equals an indicator a pinned government advisory attributes to a named actor. |

A lead is the publisher's claim about the indicator (ADR-0013), quoted with its validity window. It does not turn
into a conclusion, and it does not apply when there is no decision feature at all. There is no verdict that names
an actor on technique overlap, because the measurement above says such a verdict would be wrong. Adding one is a
future decision that requires evidence which discriminates **and** known-answer cases showing it does (D5).

### D3 — Overlap is a fact per candidate, never an ordering

Each consistent candidate carries which observed techniques its profile includes, its profile size and in how many
units it is a candidate. Candidates are stored and shown in name order. The record states *how many* candidates'
profiles include at least 1, ¼, ½, ¾ and all of the observed techniques — counts, no names. Neither the statement
nor the reasons may contain a candidate's name (tested; audited on served data). There is no field for a score,
rank, likelihood or confidence.

### D4 — The reasons are sentences made of counted facts

How many Groups and Campaigns are consistent, how many include at least half and how many all of the observed
techniques, and how many observed techniques are recorded for more than one actor. `limits` states what the
assessment does not establish: pooling assumes one intrusion; a profile is what was reported, not what a Group
does; only detectable techniques can appear.

### D5 — The track record is part of the product

`scripts/measure_actor_ranking.py --json` writes the known-answer checks from a running server: per recording the
verdict given, and what each ordering would have named. The file is tracked and served at `GET /validation`; the
investigation page quotes its summary beside the verdict and the About page shows it in full. It must be
regenerated when detection content, the ATT&CK version or the method changes (its `pinned` block says what it
was measured on).

## What this is not

- Not a calibrated decision (ADR-0006). `calibration_status` stays `uncalibrated`. A confidence level needs
  known-answer recordings from several actors (the readiness gate asks for 4 calibration actors and 12 families;
  there are 1 and 3), which only lab recordings can supply.
- Not a claim that attribution is impossible — a claim that *this evidence* does not support it. Evidence that can:
  software and tooling tied to a Group, infrastructure and indicators, procedures finer than a technique id. That
  is the next step (owner decision 2026-10-11) and gets its own ADR and its own known-answer checks.

## Verification

- `tests/test_investigation_assessment.py`: each verdict; candidates equal the actors whose profile includes an
  observed technique; name order; counts; a single-Group technique yields no verdict and no name; determinism and
  unit-order independence; no score-like field.
- `tests/test_frontend_api.py`: the route serves exactly `assess_investigation` over the stored analyses; the
  dossier quotes the statement.
- `scripts/audit_served_read_model.py` recomputes every assessment from the served units.
