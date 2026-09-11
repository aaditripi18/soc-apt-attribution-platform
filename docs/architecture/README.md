# Architecture Documentation — SOC APT Attribution Platform

**Status: PROPOSED throughout.** Nothing here is implemented or accepted. These documents transform the
research (`../research/`) into a reviewable architecture. Read alongside [CLAUDE.md](../../CLAUDE.md).

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

## Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [adr/0001-evidence-graph-core-architecture.md](adr/0001-evidence-graph-core-architecture.md) | Evidence-Graph Core architecture (Option B) | **PROPOSED** |
| [adr/0002-attribution-scoring-and-evidence-methodology.md](adr/0002-attribution-scoring-and-evidence-methodology.md) | Attribution scoring & evidence methodology | **PROPOSED** |

## The one-paragraph summary

Elastic (free tier) is the telemetry/detection **data plane**; a dedicated engine owns the differentiator —
a **provenance-first evidence graph** fused with pinned ATT&CK knowledge, feeding deterministic correlation,
tactic-ordered attack-chain reconstruction, and **ACH-based attribution** that reports **likelihood and
confidence as two separate, calibrated axes** and can answer "insufficient evidence." No arbitrary point
scoring, no opaque/LLM step on the correctness path, and every conclusion traces back to raw events.

## Nothing is decided

All ADR decisions and open questions are PROPOSED pending the owner's review. No application code exists;
implementation does not begin until the architecture and the attribution methodology (ADR-0001 + ADR-0002)
are approved.
