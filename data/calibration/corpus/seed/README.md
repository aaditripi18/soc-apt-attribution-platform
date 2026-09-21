# C3.2 seed corpus (first implementation slice — NOT the golden corpus)

**Tier-1 machinery only. This is NOT real-world attribution-accuracy evidence.**

This directory holds a tiny, illustrative, **declared-provenance SYNTHETIC** seed
corpus used only to prove the C3.2 corpus-builder + replay path end-to-end
(ADR-0006 §D5/§D6/§D13; B1-M/B1-D locks). It deliberately does **not** satisfy
the full §D19 category-completeness acceptance gate — that is the later,
full C3.2 corpus gate.

- `scenarios/<family>.fixture.json` — **raw telemetry only** (the existing
  `DetectionReplayFixture` format). No labels, no rule ids, no group assertions;
  what fires (against `fixtures/phase1_core_rules.json`, unmodified) and how it
  correlates is decided entirely by the real pipeline.
- `annotations/<family>.annotation.json` — the **separately-authored** ground
  truth, expected-output shape, coverage assumptions, and provenance. Kept apart
  from the telemetry so expected-output authorship stays independent of ATT&CK
  inference (§D6 anti-circularity). Labels are authored from the synthetic
  scenario's declared intent, **never** derived from ATT&CK `uses`.

Each family's telemetry is a small process-lineage chain authored to replay to
**exactly one** attribution unit (one `CorrelationGroup` + one
`BehavioralSequence`). Expected-output bands are **opaque authored tokens**, not
numbers; no fitting, `calibration_version`, or scoring is implied or performed by
this corpus.
