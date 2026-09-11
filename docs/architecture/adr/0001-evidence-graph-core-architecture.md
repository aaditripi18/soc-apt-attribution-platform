# ADR-0001 — Evidence-Graph Core Architecture

- **Status:** ACCEPTED (2026-09-11)
- **Date:** 2026-09-11 (proposed) · 2026-09-11 (accepted)
- **Deciders:** project owner (accepted after the final architecture review)
- **Supersedes / superseded by:** —
- **Related:** [01 options](../01-architecture-options.md) · [02 recommended](../02-recommended-architecture.md)
  · [03 data flow](../03-system-data-flow.md) · [04 boundaries](../04-component-boundaries.md)
  · [05 open questions](../05-architecture-open-questions.md) · research
  [09](../../research/09-technology-decision-matrix.md)/[10](../../research/10-research-audit.md)

> The decisions below are **ACCEPTED** as of 2026-09-11 (following [10 final review](../10-final-architecture-review.md)),
> with **D8 modified per M1** (below). Reversibility is noted per decision. Acceptance does **not** start
> implementation: the phase conditions C0.1–C0.3 in the final review remain outstanding.
>
> **Acceptance rationale:** the final architecture review classified all 14 decisions ACCEPT except D8
> (MODIFY, now applied); no decision was rejected. The architecture concentrates build effort on the
> explainable evidence→attribution differentiator while reusing Elastic/MITRE for undifferentiated work, and
> is faithful to [CLAUDE.md](../../CLAUDE.md). Remaining gaps are specification/calibration work scheduled in
> later phases, not architectural flaws — so the architecture is sound to adopt now.

## Context

The SOC APT Attribution Platform must perform **explainable, evidence-based APT attribution** and avoid the
previous version's failures (opaque/hard-coded attribution, weak data modeling, a frontend not backed by
real functionality). Research established that Elastic (free tier) already provides storage, ECS
normalization, search, and ATT&CK-tagged detection; MITRE provides ATT&CK as pinned STIX; and no mature
open-source tool provides the explainable evidence→attribution reasoning that is the project's whole point.
Three architectures were compared ([01](../01-architecture-options.md)); Option B (Evidence-Graph Core)
scored highest on the criteria that encode the project's thesis.

## Decisions (all PROPOSED)

- **D1 — Adopt the Evidence-Graph Core (Option B).** Elastic = data plane; a dedicated Attribution Engine
  owns the differentiator. *Reversibility: low (foundational).*
- **D2 — Elastic is the data plane only.** Ingest/normalize/search/detect in Elastic; **no** custom SIEM;
  our code interprets, it does not re-implement Elastic. *Reversibility: medium.*
- **D3 — ATT&CK from pinned STIX.** Load a **versioned** `attack-stix-data` bundle via
  `mitreattack-python` into the evidence graph; never hand-copy techniques. *Reversibility: high.*
- **D4 — One provenance-first evidence graph** fusing ATT&CK knowledge nodes with case nodes; every derived
  node references its inputs; contradiction is a first-class edge. *Reversibility: low.*
- **D5 — Deterministic, explainable reasoning; ML deferred.** Correlation, attack-chain ordering, and
  attribution are deterministic and testable; any ML is later, optional, and interpretable, never on the
  correctness path. *Reversibility: medium.*
- **D6 — ACH competing hypotheses.** Attribution maintains multiple candidate hypotheses ranked by
  supporting **and** contradicting evidence; a single answer is an earned output, not a default.
  *Reversibility: medium.*
- **D7 — Two-axis confidence (ICD-203).** Report *likelihood* (WEP) and *confidence* (basis strength)
  separately; serialize to STIX 2.1 `confidence` via `stix2.confidence.scales` at the boundary only.
  *Reversibility: medium.*
- **D8 — Discriminating-power weighting (MODIFIED per final review M1).** Weight evidence by
  **discriminating power `D`**, a **documentation-relative separation heuristic** computed from the pinned
  ATT&CK Group×{Technique **and Software**} matrix — **never a probability or real-world rate**, and subject
  to ATT&CK reporting bias. **Rarity is a weight, not proof of attribution**; **no attribution may rest on a
  single technique** regardless of `D`. Discrimination is driven by **distinctive combinations** (honoring
  the profile-union / sparse-sequence limitations — combination/sequence signals are approximate and
  low-weight where data is thin), and support is **normalized against candidate profile size** so richly
  documented actors cannot win by volume. Validate on labeled scenarios before trust. *Reversibility: high
  (tunable).* (Aligns with ADR-0002 D16/D18/D19/D20/D21.)
- **D9 — Embedded graph first, `GraphStore` port.** Start with an embedded graph library; keep a port so a
  graph DB (Kùzu/Neo4j/Memgraph) can drop in later based on real query needs. *Reversibility: high.*
- **D10 — Reproducibility by construction.** Pinned ATT&CK version + content-hashed datasets + per-result
  provenance manifest + an offline replay path; determinism is a tested property. *Reversibility: low.*
- **D11 — Frontend renders, never computes.** The analyst UI consumes read-model JSON and shows results +
  provenance; it performs no attribution logic and deep-links to Kibana for raw telemetry.
  *Reversibility: medium.*
- **D12 — Detection content under a license split.** Elastic prebuilt rules (ELv2) for internal coverage;
  Sigma (DRL) via pySigma for redistributable content; conversion behind a boundary with Elastic rules as
  fallback. *Reversibility: high.*
- **D13 — Windows/endpoint-first scope for v1.** Broaden to network/cloud only after technique mapping is
  proven. *Reversibility: high.*
- **D14 — Personal-scale deployment.** Docker Compose single-node Elastic + Kibana + our service +
  frontend; no paid Elastic tier; graph DB deferred. *Reversibility: high.*

## Consequences

**Positive:** effort concentrates on the differentiator; every conclusion is traceable and explainable;
results are reproducible and testable; no paid tier required; modular layers are independently testable;
avoids the "thin UI over someone else's engine" failure.

**Negative / costs:** more code than the Elastic-centric option; requires disciplined scope control to not
drift into a SIEM; the scoring methodology (D7/D8) must be specified and calibrated carefully; a genuine
attack-chain/graph reasoning layer is non-trivial to get legible.

**Neutral:** Elastic remains swappable for replayed data downstream of ingestion; the graph substrate and
attribution weights are intentionally tunable/reversible.

## Alternatives considered (and why not, now)

- **Option A — Elastic-Centric Thin App:** lowest effort, best Elastic integration, but shallow/opaque
  attribution and poor reproducibility — reproduces the previous version's core failure. *Right only if the
  goal were a fast demo.*
- **Option C — Provenance-Graph / Research-Grade:** highest technical ceiling and best attack-chain
  reconstruction, but ML opacity conflicts with the explainability principle, multi-host provenance is an
  open research problem, and the scope risks never finishing the differentiator. *Right only for a funded
  research thesis.*

## Open questions that must be resolved alongside approval

See [05-architecture-open-questions.md](../05-architecture-open-questions.md). The gating ones: the
**attribution scoring spec (Q2)** must be written and reviewed before Phase 3 code; the **normalized-event
contract (Q1)**, **detection-content strategy (Q4)**, **telemetry scope (Q5)**, and **validation corpus
(Q6)** must be settled before Phase 1.

## Follow-up

On approval, record any amended decisions here (status → ACCEPTED with date), and open ADR-0002 for the
attribution scoring specification.
