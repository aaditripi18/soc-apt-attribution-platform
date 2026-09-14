# fixtures/

Hand-authored, in-repo synthetic telemetry and detection-match fixtures used to
validate the pipeline **without** Elasticsearch, Docker, Windows, or external
network access.

Per [docs/architecture/13-phase-0-implementation-plan.md](../docs/architecture/13-phase-0-implementation-plan.md)
(CL-3): this directory holds small, deterministic, hand-authored fixtures —
**not** the external labeled validation corpus (Security-Datasets, EVTX
samples, CALDERA/Atomic captures). Acquiring that corpus is a later,
separately-gated step (Phase 1, open question Q6). Phase 0 fixtures exist only
to prove the ingestion → normalization → Observation → Evidence → ATT&CK
technique-reference pipeline works deterministically; they do not validate
attribution correctness.

No fixtures existed at gate G0.0 (repository scaffolding). G0.4 added the
source-adapter interface fixtures are written for (`SyntheticRecord`/
`SyntheticSourceAdapter`) but no fixture *file* yet. The first fixture file,
[`phase0_benign_scenarios.json`](phase0_benign_scenarios.json), is added at
**G0.9 (synthetic/replay ingestion path)**: a small, hand-authored JSON file
of benign scenarios (documented in
`src/attribution_platform/replay/fixtures.py`) that the replay pipeline
(`attribution_platform.replay`) loads and pushes through
`SourceAdapter -> extract_observations -> derive_evidence -> Elastic
persistence` — the same pipeline a real telemetry source will use.

**G0.11 (Windows/Sysmon ingestion boundary)** adds
[`sysmon_sample_events.ndjson`](sysmon_sample_events.ndjson): two small,
hand-authored, benign, deterministic Winlogbeat/Elastic-Agent Sysmon-module
JSON events (one Process Create, one Network Connection — newline-delimited
JSON, the shape a real capture export naturally takes), read by
`attribution_platform.sources.sysmon.load_ndjson_events` and converted by
`SysmonSourceAdapter` through the identical `SourceAdapter -> Observation`
boundary as every other source. Not a live capture; not a second
fixture/replay framework (see that module's docstring for why).

**G1.0 (Phase 1 — deterministic detection engine)** adds
[`phase1_core_rules.json`](phase1_core_rules.json): a small, hand-authored,
content-hashed rule pack (two rules — one behavioral, mapped to a real,
pinned-KB-validated ATT&CK technique; one contextual, with no technique
mapping) loaded by `attribution_platform.detection.load_rule_pack` and
evaluated by `DetectionEngine`. Demonstrative content only, proving the
loader/engine/ATT&CK-validation path works end to end — not real
detection-engineering content, and not used to validate detection efficacy.

**G1.2 (replay integrated with the DetectionEngine)** adds
[`phase1_detection_replay.json`](phase1_detection_replay.json): a small,
hand-authored, content-hashed **raw-telemetry** fixture (documented in
`src/attribution_platform/replay/detection_fixtures.py`), read by
`attribution_platform.replay.load_detection_replay_fixture_file` and pushed
through `SourceAdapter -> extract_observations -> the real G1.0
DetectionEngine -> derive_evidence_from_detection -> Elastic persistence`
(`attribution_platform.replay.replay_fixture_through_detection_engine`).
Unlike `phase0_benign_scenarios.json`, no scenario here asserts its own rule
id or ATT&CK mapping — three scenarios (one that matches the encoded-
PowerShell rule, one that matches the contextual logon rule, one that
matches neither) exist specifically to prove the engine, not the fixture,
decides what fires, evaluated against `phase1_core_rules.json`.
