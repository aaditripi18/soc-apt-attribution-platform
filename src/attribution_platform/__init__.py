"""SOC APT Attribution Platform.

An explainable, evidence-based APT attribution engine. See
docs/architecture/ for the accepted architecture (ADR-0001, ADR-0002,
ADR-0003) and docs/architecture/13-phase-0-implementation-plan.md for the
implementation roadmap this package structure follows.

Package layout (each submodule states which Phase-0 gate implements it):

- ``domain``          — core contracts (Observation, Evidence, TechniqueAssertion,
                         provenance). Source-agnostic; no other submodule's types
                         may leak into it. Implemented in G0.3.
- ``attack_knowledge`` — pinned MITRE ATT&CK STIX loading and knowledge access.
                         Implemented in G0.1 (acquisition) / G0.2 (loading).
- ``sources``          — telemetry-source adapters (SourceAdapter interface +
                         synthetic reference adapter). Source-native specifics
                         (e.g. Sysmon event IDs, Elastic field names) live only
                         here, never in ``domain`` or above. Implemented in G0.4.
- ``extraction``       — detection-match record -> Observation boundary.
                         Implemented in G0.5.
- ``dataplane``        — Elasticsearch client and persistence. Implemented in
                         G0.7 (deployment) / G0.8 (integration).
- ``replay``            — synthetic/replay ingestion: hand-authored fixtures
                         pushed through the same source-agnostic pipeline a
                         real telemetry source will use. Not part of the
                         original G0.0 module map (added when G0.9 needed a
                         home for this cross-cutting orchestration — it
                         composes ``sources``, ``extraction``, and
                         ``dataplane`` rather than belonging to any one of
                         them). Implemented in G0.9.
- ``api``              — read-model API (serves stored data; performs no
                         attribution logic). Implemented in G0.10.
- ``detection``        — deterministic detection rules/engine mapping
                         Observations to ATT&CK-technique-validated
                         DetectionResults, fanned out into ``extraction``'s
                         unmodified ``derive_evidence()``. Source-agnostic
                         and Elastic-free; the first Phase 1 gate (G1.0).
- ``elastic_detections`` — normalizes Elastic Detection Engine alerts into
                         the same ``detection.DetectionResult``, via a
                         bounded, read-only ``dataplane.ElasticClient``
                         query. Cross-cutting integration (composes
                         ``dataplane``, ``attack_knowledge``, and
                         ``detection`` — mirrors why ``replay`` is its own
                         package rather than living inside one of the layers
                         it composes). Implemented in G1.1.
- ``correlation``      — Phase 2: multi-event correlation domain contracts
                         (ADR-0003) — which Evidence items are structurally
                         part of the same underlying behavior, distinct from
                         merely-contextual shared environment/identity.
                         Source-agnostic; imports nothing from ``sources``,
                         ``dataplane``, or ``attack_knowledge`` at this gate.
                         **G2.0 (implemented): contracts only** — no
                         correlation is performed yet.

This package intentionally contains no attribution or attack-chain logic
yet, and no correlation *computation* yet (G2.0 is contracts only) — see
ADR-0001/ADR-0002/ADR-0003 and the Phase-0/Phase-2 plans for why.
"""

__version__ = "0.0.0"
