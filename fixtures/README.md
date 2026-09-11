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

No fixtures exist yet at gate G0.0 (repository scaffolding). The first
fixtures are added in G0.4 (source abstraction) and used through G0.9
(synthetic/replay ingestion path).
