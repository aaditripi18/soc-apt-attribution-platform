# C3.2 v1 corpus

**Tier-1 machinery only. This is NOT real-world attribution-accuracy evidence.**
Every result derived from this corpus (composition counts, split/provenance/
category-completeness reports, and — much later — any fitted parameter) is
**documentation-relative to this declared-provenance SYNTHETIC/REPLAY corpus**
(ADR-0006 §D11). It proves the machinery — corpus schema, split/leakage
control, blind-actor holdout, category coverage, evidence-type reachability —
works correctly against known-intent scenarios. It proves **nothing** about
real-world attribution accuracy or real-world false-attribution rates. Tier-2
real-incident data remains a separate, later, accuracy-validation-only
concern (§D14); it is not part of this corpus.

This is the first corpus to satisfy the C3.2 Stage 3 category-completeness
validator (`calibration.category_validation.validate_category_completeness`)
— it supersedes `data/calibration/corpus/seed/` (which remains on disk,
unmodified, as the earlier first-slice proof of the builder + replay path;
it does not satisfy category completeness and was never intended to).

## Layout

```
v1/
  README.md
  scenarios/<family>.fixture.json     # raw telemetry only (DetectionReplayFixture)
  annotations/<family>.annotation.json  # separately-authored labels + category metadata
  sources/sources.json                # generated audit snapshot of the source registry
  manifest.json                       # generated audit snapshot of the built manifest
```

**`scenarios/` and `annotations/` are the real inputs** — exactly the format
`calibration.corpus_builder.load_corpus_entries_from_dir` already reads (one
`.fixture.json` + one `.annotation.json` per family, unchanged from Stage 1).
Rebuilding the corpus (`build_corpus_from_dir`) from these two directories is
the authoritative operation; `sources/sources.json` and `manifest.json` are
**generated, human-readable audit snapshots** of that build's result —
`calibration_corpus_version` inside `manifest.json` is not a second identity:
it is `compute_calibration_corpus_version`'s own output (via
`CalibrationCorpusManifest.from_cases`), persisted for readability. Rebuild
from `scenarios/`+`annotations/` to independently verify it; do not hand-edit
`manifest.json`/`sources.json` as if they were inputs.

Each annotation additionally carries a `"categories"` array (the C3.2 Stage 3
`CaseCategoryRecord.categories`, by name) — read separately from
`load_scenario_annotation` (which ignores unknown keys) by the corpus's own
build tooling, never wired into the frozen `CalibrationCase` contract (see
Stage 3's own documented discrepancy note in `category_validation.py` and
`docs/architecture/14-c3.2-corpus-build.md` §D3). `CaseCategoryRecord.
evidence_types` is **not** stored in the annotation — it is captured from the
real replay's own `BehavioralStep.evidence_types` output when the corpus is
built, never hand-declared, so it can never silently drift from what the
pipeline actually emits.

## Families, actors, and splits

18 scenario families, one `CalibrationCase` each (the existing "one family,
one attribution unit" builder constraint). Actor roster (SYNTHETIC/emulated,
declared-provenance):

- **Attributable actors:** EMU-ALPHA, EMU-BRAVO, EMU-CHARLIE, EMU-DELTA,
  EMU-ECHO, EMU-FOXTROT, EMU-GOLF — each genuinely appears as the authored
  `ground_truth.actor_label` in at least one family.
- **Blind actor:** EMU-ZULU — exactly two independent `blind_actor_holdout`
  families (`v1-bah-zulu-1`, `v1-bah-zulu-2`), each a genuinely different
  technique combination; **zero** `calibration` families name EMU-ZULU
  (verified both by `split_validation.require_valid_split`'s
  `BLIND_ACTOR_IN_CALIBRATION` check and directly in the annotations).
- **Deliberate imitation:** EMU-ECHO reproduces EMU-ALPHA's own
  office-macro-to-ingress pattern (`v1-cal-echo-imitates-alpha`,
  `v1-hov-echo-imitates-alpha`) — the true authored actor is EMU-ECHO in
  both; this is the intended §D19 imitation category, not an accidental
  near-duplicate of EMU-ALPHA's families (different hosts, entity ids, and
  timestamps; independently replayed to independent `case_id`s).

Splits (`case_role`, one role per `scenario_family_id`, enforced by
`split_validation`):

| Role | Families |
|---|---|
| `calibration` | 7 |
| `held_out_validation` | 7 |
| `blind_actor_holdout` | 2 (EMU-ZULU) |
| `excluded` | 2 |

**`excluded` = the final-test-reserved population** (ADR-0006 §D9's "FINAL
TEST" set), per the C3.2 Stage 2 D2 convention: the existing `CaseRole.
EXCLUDED` member, not a new `FINAL_TEST` role. These two families
(`v1-exc-golf-reserved`, `v1-exc-negative-reserved`) are not consumed by any
calibration/validation operation in this corpus's own tooling — they are
reserved for a later, one-time final evaluation.

## Category metadata (C3.2 Stage 3)

Every `CaseCategoryTag` and every `LabelSemantics` value required by
`validate_category_completeness` is present in **both** the `calibration`
and `held_out_validation` populations independently (not merely
corpus-wide):

- `one_observation`, `repeated_behavior` + `repeated_detection` +
  `multiple_distinct_observation`, `correlated_detection` +
  `multiple_evidence_type` + `genuinely_distinct_evidence`,
  `deliberate_imitation`, `campaign_contextualization` — each present in a
  `calibration` family and, independently, in a `held_out_validation` family.
- `attributable`, `disputed`, `unknown`, `unattributable_by_design` — each
  present in a `calibration` family and, independently, in a
  `held_out_validation` family.

**Interpretation note (documented, not silently promoted into a new
methodology decision).** ADR-0006 §D19 states the repetition/evidence
category list in prose ("one-observation / repeated-behavior / repeated-
detection / multiple-distinct-observation / multiple-evidence-type /
correlated-detection / genuinely-distinct-evidence") without a machine-
checkable enumeration or a per-population presence rule; the Stage 3
validator's exact 9-tag taxonomy and its CALIBRATION+HELD_OUT_VALIDATION
presence requirement is this project's own operationalization of that prose,
carried over unchanged from Stage 3 (see that gate's own report for the
interpretation record). This corpus was authored to satisfy the *existing,
already-implemented* Stage 3 validator, not to re-derive a new taxonomy.

**"One observation" (interpretation).** The replay pipeline requires **at
least two** distinct pieces of technique/rule-matched evidence to form any
`CorrelationGroup`/`BehavioralSequence` at all (verified empirically against
the real pipeline; an isolated single piece of evidence with no correlated
partner never reaches group status). "One-observation" families therefore
mean **exactly one occurrence of each of two distinct techniques** (no
technique repeated) — the sparsest case the real pipeline can produce —
contrasted with "repeated-behavior"/"repeated-detection" families where the
**same** technique/rule fires multiple times. This is a platform-mechanism
consequence documented here, not a contract change.

## Evidence-type coverage (Stage 2 extension)

All four `EvidenceType` values are genuinely emitted by the real,
unmodified detection/evidence/correlation pipeline — never hand-labeled —
using the unmodified core pack (`fixtures/phase1_core_rules.json`, BEHAVIORAL
+ CONTEXTUAL) plus the unmodified Stage 2 calibration extension pack
(`data/calibration/rules/calibration_evidence_type_rules.json`, EVIDENTIARY +
PROCEDURAL). Reached at: `v1-cal-charlie-correlated` (BEHAVIORAL +
CONTEXTUAL + EVIDENTIARY in one family) and `v1-hov-delta-correlated`
(BEHAVIORAL + CONTEXTUAL + PROCEDURAL in one family). `CaseCategoryRecord.
evidence_types` for every family was captured directly from that family's own
real replay output (`BehavioralStep.evidence_types`), not authored by hand.

## Coverage (data-component) vocabulary

`coverage_assumptions` values are **canonical, active `x-mitre-data-component`
names**, computed via the existing, unmodified
`attack_knowledge.traversal.required_data_components(knowledge, technique_id)`
for each family's own scenario technique(s) — never a second vocabulary,
never invented, never inferred from `source_kind`. Families with no
technique-mapped evidence (the designed-negative, logon-only families) — and
one negative family deliberately kept minimal — declare an empty
`coverage_assumptions`, giving the corpus both a coverage-present and a
coverage-absent case (`v1-cal-negative-benign` / `v1-hov-negative-benign` /
`v1-exc-negative-reserved` are coverage-absent; every technique-bearing
family is coverage-present).

## Provenance / licensing

Single declared source, `epitaxy-v1-corpus@1.0` (`source_kind=synthetic`,
license `MIT` — an allowlisted SPDX identifier per B1.5), with non-placeholder
acquisition/transformation provenance recorded identically on every
annotation (enforced consistent by the existing builder's disagreeing-
provenance fail-closed check). No orphan source: every annotation references
this one `source_ref`, and `provenance_validation.require_valid_provenance`
confirms it is referenced by at least one case.

## Explicit non-goals (unchanged from Stages 1-3)

This corpus implements **no** fitting, `calibration_version`, likelihood,
confidence, WEP, abstention, or G3.6, and modifies **no** candidate
generation, ACH, comparative analysis, CoverageProfile, `evidence_type`
implementation, replay pipeline, ATT&CK knowledge, existing Type-A fixtures,
frozen calibration contracts, or frontend. Parameter fitting remains gated on
resolving F-1/F-3 and on a frozen `calibration_version` that does not yet
exist (ADR-0005 §D19).
