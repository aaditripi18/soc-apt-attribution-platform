"""Multi-event correlation: the layer between Evidence and attribution
(Phase 2, ADR-0003 —
docs/architecture/adr/0003-correlation-and-behavioral-chain-layer.md).

Per ADR-0003: this package identifies *structurally* related Evidence items
(the same process instance, or a direct parent→child creation relationship)
so the future attribution layer can de-duplicate correlated evidence
(ADR-0002 D16/CR-1) without inventing its own grouping logic — and attaches
*contextual* facts (shared host/user/destination) as explanatory metadata
that can never create or merge a group. This package performs no
attribution, no maliciousness judgment, no actor/campaign reasoning, and no
scoring; ATT&CK is annotation-only here, never a correlation input.

Gate status:

- **G2.0 (implemented):** ``errors`` — ``CorrelationError``; ``contracts`` —
  :class:`~attribution_platform.correlation.contracts.LinkClass` (the closed
  eight-value vocabulary — three structural/group-forming, five
  contextual/attach-only),
  :class:`~attribution_platform.correlation.contracts.CorrelationBasis` (the
  machine-readable *why*),
  :class:`~attribution_platform.correlation.contracts.CorrelationProvenance`
  (non-empty, canonicalized back-links to Evidence/Observation ids, parallel
  to :class:`attribution_platform.domain.provenance.DerivationProvenance`),
  :class:`~attribution_platform.correlation.contracts.CorrelationLink` (one
  relationship between two distinct Evidence items),
  :class:`~attribution_platform.correlation.contracts.CorrelationGroup` (a
  connected component joined *only* through structural links — the CR-1
  de-duplication unit), plus deterministic id-composition helpers
  (:func:`~attribution_platform.correlation.contracts.compute_link_id`,
  :func:`~attribution_platform.correlation.contracts.compute_group_id`) and
  the one sanctioned class-membership-enforcing constructor
  (:func:`~attribution_platform.correlation.contracts.build_correlation_group`).
  **Contracts only** — no connected-component algorithm, no
  structural/contextual matching, no temporal/ordering logic, no ATT&CK
  annotation, no persistence, no attribution (see that module's docstring
  for the exact scope boundary).
- **G2.1 (implemented):** ``structural`` —
  :func:`~attribution_platform.correlation.structural.correlate_structurally`,
  the engine computing exactly the three structural dimensions
  (``SHARED_OBSERVATION``, ``SAME_PROCESS_ENTITY``, ``PROCESS_LINEAGE``)
  over caller-supplied ``(Evidence, Observation)`` pairs, and the
  connected-component ``CorrelationGroup``s those links form (a small,
  dedicated union-find — not a general graph framework). Process-entity
  identity is host-scoped internally (prefers ``host.id``, falls back to
  ``host.name``, fails closed otherwise) but host is never itself a
  correlation dimension. No contextual dimension, no temporal logic, no
  ATT&CK reasoning, and no scoring/attribution exists in this module (see
  that module's own docstring for the exact scope boundary).
- **G2.2 (implemented):** ``contextual`` —
  :func:`~attribution_platform.correlation.contextual.contextualize`, the
  engine computing exactly the five contextual dimensions
  (``SAME_HOST_ID``, ``SAME_HOST_NAME``, ``SAME_USER_ID``,
  ``SAME_USER_NAME``, ``SAME_DESTINATION_IP``) over caller-supplied
  ``(Evidence, Observation)`` pairs and attaching them, as
  ``contextual_link_ids``, to whichever *already-computed* structural
  groups (from G2.1) they touch — never forming, merging, or creating a
  group. Takes a ``StructuralCorrelationResult`` as input specifically so
  no code path in this module can build a group from scratch. Each
  contextual link carries an explicit, ADR-0003-derived ``uncertainty_note``
  (plain language, never numeric). No G2.1 matching/connected-component
  logic is imported or reimplemented; no temporal logic, no ATT&CK
  reasoning, and no scoring/attribution exists in this module (see that
  module's own docstring for the exact scope boundary).
- **G2.3 (implemented, outside this package):** replay integration + golden
  corpus + persistence — see
  :func:`attribution_platform.replay.replay_fixture_through_correlation` and
  :func:`attribution_platform.dataplane.persist_correlation_link`/
  :func:`~attribution_platform.dataplane.persist_correlation_group`. Nothing
  in *this* package changed for G2.3: it is purely a caller of
  :func:`correlate_structurally`/:func:`contextualize`, exactly as G2.1/G2.2
  already were designed to be called.
- **G2.4.0 (implemented, ADR-0004):** ``sequence`` — the behavioral-sequence
  domain contracts: :class:`~attribution_platform.correlation.sequence.BehavioralStep`,
  :class:`~attribution_platform.correlation.sequence.SequenceEdge`,
  :class:`~attribution_platform.correlation.sequence.SequenceGap`,
  :class:`~attribution_platform.correlation.sequence.SequenceParallelGroup`
  (the accepted branch-partition design), and
  :class:`~attribution_platform.correlation.sequence.BehavioralSequence` —
  plus :class:`~attribution_platform.correlation.sequence.OrderingBasis`/
  :class:`~attribution_platform.correlation.sequence.OrderingBasisKind`/
  :class:`~attribution_platform.correlation.sequence.GapReason`, the
  deterministic id-composition helpers, and the two sanctioned
  cross-group-validating constructors
  (:func:`~attribution_platform.correlation.sequence.build_behavioral_step`,
  :func:`~attribution_platform.correlation.sequence.build_behavioral_sequence`).
  **Contracts only** — no sequence-construction/ordering engine, no
  ``SHARED_OBSERVATION``-collapse, no branch/convergence discovery, no
  replay, no persistence, no ``TEMPORAL_PROXIMITY`` (see that module's own
  docstring for the exact scope boundary).
- **G2.4.1 (implemented, ADR-0004):** ``sequence_engine`` —
  :func:`~attribution_platform.correlation.sequence_engine.construct_behavioral_sequence`,
  the pure, deterministic engine reconstructing one
  :class:`~attribution_platform.correlation.sequence.BehavioralSequence` from
  an already-computed :class:`CorrelationGroup` and its real
  ``(Evidence, Observation)`` pairs / structural / contextual
  ``CorrelationLink``\\ s: ``SHARED_OBSERVATION`` collapse,
  ``technique_stix_ids`` derivation from real ``Evidence.attack_ref``,
  ``PROCESS_LINEAGE`` and ``TEMPORAL_SAME_ENTITY`` ordering (ADR-0004 D5–D8),
  and ``SequenceParallelGroup`` construction (ADR-0004 D9). No I/O, no
  ``TEMPORAL_PROXIMITY``, no attribution/scoring (see that module's own
  docstring for the exact scope boundary, including a found architectural
  ambiguity it handles fail-closed rather than silently resolving).
- **Not yet implemented:** golden corpus + replay + persistence for
  behavioral sequences (G2.4.2); ``TEMPORAL_PROXIMITY`` (G2.4.3); an
  optional Elastic EQL input adapter (G2.5); anything attribution-related
  (Phase 3, out of this package entirely).
"""

from __future__ import annotations

from attribution_platform.correlation.contextual import (
    CONTEXTUAL_CORRELATION_METHOD,
    CONTEXTUAL_CORRELATION_METHOD_VERSION,
    ContextualCorrelationResult,
    contextualize,
)
from attribution_platform.correlation.contracts import (
    CONTEXTUAL_LINK_CLASSES,
    CORRELATION_GROUP_SCHEMA_VERSION,
    CORRELATION_LINK_SCHEMA_VERSION,
    CorrelationBasis,
    CorrelationGroup,
    CorrelationLink,
    CorrelationProvenance,
    LinkClass,
    build_correlation_group,
    compute_group_id,
    compute_link_id,
)
from attribution_platform.correlation.errors import CorrelationError
from attribution_platform.correlation.sequence import (
    BEHAVIORAL_SEQUENCE_SCHEMA_VERSION,
    BEHAVIORAL_STEP_SCHEMA_VERSION,
    SEQUENCE_EDGE_SCHEMA_VERSION,
    SEQUENCE_GAP_SCHEMA_VERSION,
    SEQUENCE_PARALLEL_GROUP_SCHEMA_VERSION,
    BehavioralSequence,
    BehavioralStep,
    GapReason,
    OrderingBasis,
    OrderingBasisKind,
    SequenceEdge,
    SequenceGap,
    SequenceParallelGroup,
    build_behavioral_sequence,
    build_behavioral_step,
    compute_sequence_edge_id,
    compute_sequence_gap_id,
    compute_sequence_id,
    compute_sequence_parallel_group_id,
    compute_step_id,
)
from attribution_platform.correlation.sequence_engine import (
    SEQUENCE_ENGINE_METHOD,
    SEQUENCE_ENGINE_METHOD_VERSION,
    construct_behavioral_sequence,
)
from attribution_platform.correlation.structural import (
    STRUCTURAL_CORRELATION_METHOD,
    STRUCTURAL_CORRELATION_METHOD_VERSION,
    StructuralCorrelationResult,
    correlate_structurally,
)

__all__ = [
    "CorrelationError",
    "LinkClass",
    "CONTEXTUAL_LINK_CLASSES",
    "CorrelationBasis",
    "CorrelationProvenance",
    "CorrelationLink",
    "CorrelationGroup",
    "CORRELATION_LINK_SCHEMA_VERSION",
    "CORRELATION_GROUP_SCHEMA_VERSION",
    "compute_link_id",
    "compute_group_id",
    "build_correlation_group",
    "correlate_structurally",
    "StructuralCorrelationResult",
    "STRUCTURAL_CORRELATION_METHOD",
    "STRUCTURAL_CORRELATION_METHOD_VERSION",
    "contextualize",
    "ContextualCorrelationResult",
    "CONTEXTUAL_CORRELATION_METHOD",
    "CONTEXTUAL_CORRELATION_METHOD_VERSION",
    "OrderingBasisKind",
    "GapReason",
    "OrderingBasis",
    "BehavioralStep",
    "SequenceEdge",
    "SequenceGap",
    "SequenceParallelGroup",
    "BehavioralSequence",
    "BEHAVIORAL_STEP_SCHEMA_VERSION",
    "SEQUENCE_EDGE_SCHEMA_VERSION",
    "SEQUENCE_GAP_SCHEMA_VERSION",
    "SEQUENCE_PARALLEL_GROUP_SCHEMA_VERSION",
    "BEHAVIORAL_SEQUENCE_SCHEMA_VERSION",
    "build_behavioral_step",
    "build_behavioral_sequence",
    "compute_step_id",
    "compute_sequence_id",
    "compute_sequence_edge_id",
    "compute_sequence_gap_id",
    "compute_sequence_parallel_group_id",
    "construct_behavioral_sequence",
    "SEQUENCE_ENGINE_METHOD",
    "SEQUENCE_ENGINE_METHOD_VERSION",
]
