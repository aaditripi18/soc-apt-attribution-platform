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
- ``correlation``      — Phase 2: multi-event correlation (ADR-0003) — which
                         Evidence items are structurally part of the same
                         underlying behavior, distinct from merely-contextual
                         shared environment/identity. Source-agnostic;
                         imports nothing from ``sources``, ``dataplane``, or
                         ``attack_knowledge``. **G2.0 (implemented):**
                         domain contracts. **G2.1 (implemented):** the
                         structural correlation engine — exactly
                         SHARED_OBSERVATION/SAME_PROCESS_ENTITY/
                         PROCESS_LINEAGE, host-scoped process identity, and
                         connected-component CorrelationGroup formation.
                         **G2.2 (implemented):** the contextual engine —
                         exactly SAME_HOST_ID/SAME_HOST_NAME/SAME_USER_ID/
                         SAME_USER_NAME/SAME_DESTINATION_IP, attached as
                         context to G2.1's existing groups, never forming or
                         merging one. **G2.3 (implemented):** golden-corpus
                         replay integration
                         (``replay.replay_fixture_through_correlation``,
                         built on G1.2's detection replay unchanged) and
                         persistence
                         (``dataplane.persist_correlation_link``/
                         ``persist_correlation_group``, extending G0.8's
                         pattern) — no change to this package's own
                         matching logic. No temporal logic and no
                         ATT&CK-driven correlation exist yet.

This package intentionally contains no attribution or attack-chain logic
yet, and no temporal/ATT&CK-driven correlation yet (G2.2 completes the
structural + contextual correlation model; G2.3 validates it end to end
through real replay and persistence; ``BehavioralSequence`` and temporal
ordering are G2.4) — see ADR-0001/ADR-0002/ADR-0003 and the Phase-0/Phase-2
plans for why.
"""

__version__ = "0.0.0"
