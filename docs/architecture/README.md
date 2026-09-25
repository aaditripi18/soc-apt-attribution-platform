# Architecture Documentation — SOC APT Attribution Platform

**Status: ADRs ACCEPTED (2026-09-11); not yet implemented.** ADR-0001 and ADR-0002 were accepted after the
[final architecture review](10-final-architecture-review.md) (with modifications M1/M2 applied). These
documents transform the research (`../research/`) into the adopted architecture. Acceptance does **not**
start implementation — Phase 0 remains gated on conditions C0.1–C0.3 in the final review, and no application
code exists. Read alongside [CLAUDE.md](../../CLAUDE.md).

## Reading order

| Doc | Purpose |
|---|---|
| [01-architecture-options.md](01-architecture-options.md) | Three compared architectures (A Elastic-Centric · B Evidence-Graph Core · C Provenance/ML) across all dimensions + a 14-criteria matrix |
| [02-recommended-architecture.md](02-recommended-architecture.md) | The recommendation — **Option B, Evidence-Graph Core** — in depth: layers, domain model, pipeline, modules, phasing |
| [03-system-data-flow.md](03-system-data-flow.md) | End-to-end data flow (live + offline-replay), stage-by-stage object transforms, provenance manifest |
| [04-component-boundaries.md](04-component-boundaries.md) | Who provides what: Elastic vs MITRE/authoritative vs reused OSS vs **our code** |
| [05-architecture-open-questions.md](05-architecture-open-questions.md) | The decisions to review (Q1–Q10); notes which are resolved by ADR-0002 |
| [06-evidence-model.md](06-evidence-model.md) | Precise definition of every entity in the attribution provenance chain (fields, provenance, validation, "must-not-infer") |
| [07-attribution-scoring-spec.md](07-attribution-scoring-spec.md) | The deterministic, explainable scoring mechanics (ACH, discriminating power, two axes, decision rule, worked examples) |
| [08-validation-and-calibration.md](08-validation-and-calibration.md) | Headless validation: golden corpus, case types, metrics, calibration procedure, reproducibility |
| [09-methodology-stress-test.md](09-methodology-stress-test.md) | Conceptual stress test of the methodology: full-ATT&CK scalability, 8 worked scenarios, D-metric critique, failure modes, integrity audit, corrections, recommendation |
| [10-final-architecture-review.md](10-final-architecture-review.md) | Acceptance-gate review: decision-by-decision verdicts on both ADRs, critical unresolved issues, required modifications, and the implementation-readiness assessment |
| [11-attack-knowledge-versioning.md](11-attack-knowledge-versioning.md) | Phase-0 gate C0.1 (**ACCEPTED**; **upgraded to v19.2 on 2026-09-24**, §0.1): ATT&CK KB versioning — pinned immutable STIX 2.1 **Enterprise v19.0** bundle, vendored + SHA-256 at acquisition, reproducibility, deliberate upgrade/rollback, calibration impact, Terms-of-Use attribution |
| [12-deployment-and-endpoint-scope.md](12-deployment-and-endpoint-scope.md) | Phase-0 gate C0.2 (**ACCEPTED**): hybrid deployment (containerized platform stack on WSL2/Docker-compatible runtime + **native Windows collector**), Windows-first endpoint scope (Linux architecture-only), **telemetry-source agnosticism (not Sysmon-only) + the source→collector→normalization→Observation→Evidence→Engine layering**, synthetic/replay path, portability, resources, isolation |
| [13-phase-0-implementation-plan.md](13-phase-0-implementation-plan.md) | **Phase 0 plan (IN PROGRESS — G0.0/G0.1/G0.2 IMPLEMENTED/PASSED; G0.3 IMPLEMENTED, AWAITING REVIEW)**: gates G0.0–G0.12 with dependency order, the Elastic-free logic core, the first attribution-free vertical slice (synthetic → Elastic → Observation → Evidence → ATT&CK technique ref → provenance → API), environment matrix, and what must NOT be built yet |
| [14-c3.2-corpus-build.md](14-c3.2-corpus-build.md) | C3.2 calibration corpus build: seed slice, evidence-type rules, category validator, frozen v1 corpus, and the Stage-5 corpus→decision-quantity harness with its findings F5-1..F5-4 |
| [15-corpus-v2-design.md](15-corpus-v2-design.md) | **ACCEPTED**: corpus v2 design — root cause (detection maps only 5 common techniques), Sigma-import detection content (resolves Q4), real-Group emulation-plan labels, S1/S2/S3 sources, APT29 blind actor, fitting-readiness gate, task order T1–T9 |

## Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [adr/0001-evidence-graph-core-architecture.md](adr/0001-evidence-graph-core-architecture.md) | Evidence-Graph Core architecture (Option B) | **ACCEPTED** (2026-09-11, D8 modified per M1) |
| [adr/0002-attribution-scoring-and-evidence-methodology.md](adr/0002-attribution-scoring-and-evidence-methodology.md) | Attribution scoring & evidence methodology | **ACCEPTED** (2026-09-11, D22 modified per M2) |
| [adr/0003-correlation-and-behavioral-chain-layer.md](adr/0003-correlation-and-behavioral-chain-layer.md) | Correlation and behavioral-chain layer (Phase 2) | **ACCEPTED** (2026-09-15, no decisions modified); **Amendment A ACCEPTED** (2026-09-25): remote-thread injection = structural `PROCESS_INTERACTION`, process access = contextual |
| [adr/0004-behavioral-sequence-reconstruction.md](adr/0004-behavioral-sequence-reconstruction.md) | Behavioral sequence reconstruction (Phase 2, gate G2.4) | **ACCEPTED** (2026-09-15, corrected twice during pre-acceptance review, no decisions modified at acceptance) |
| [adr/0007-detection-content-and-predicate-language.md](adr/0007-detection-content-and-predicate-language.md) | Detection content (pinned SigmaHQ generic rules via build-time importer) & predicate-language extension; full-universe scope principle and coverage report; resolves Q4 | **ACCEPTED** (2026-09-24) |
| [adr/0008-telemetry-source-formats.md](adr/0008-telemetry-source-formats.md) | Telemetry source formats: acceptance standard every format must pass, one-authoritative-source overlap policy, ECS-normalized adapter pattern, Wave-1 (Windows complete) / Wave-2 (network, Linux, cloud, macOS) order | **ACCEPTED** (2026-09-24) |

## The one-paragraph summary

Elastic (free tier) is the telemetry/detection **data plane**; a dedicated engine owns the differentiator —
a **provenance-first evidence graph** fused with pinned ATT&CK knowledge, feeding deterministic correlation,
tactic-ordered attack-chain reconstruction, and **ACH-based attribution** that reports **likelihood and
confidence as two separate, calibrated axes** and can answer "insufficient evidence." No arbitrary point
scoring, no opaque/LLM step on the correctness path, and every conclusion traces back to raw events.

## Accepted, but not started

ADR-0001 and ADR-0002 are **ACCEPTED** (2026-09-11) with modifications M1 (D8) and M2 (D22) applied.
**Implementation has not begun.** Phase 0 is still gated on the final review's conditions C0.1–C0.3 (pin a
specific ATT&CK version; owner confirms deployment shape and Windows-first scope), and the attribution engine
(Phase 3) remains gated on C3.1–C3.3. No application code exists. Several open questions in
[05](05-architecture-open-questions.md) remain to be resolved by phase.
