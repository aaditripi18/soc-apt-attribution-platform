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
- **Not yet implemented:** the structural correlation engine (G2.1); the
  contextual-association engine (G2.2); replay integration + golden corpus
  (G2.3); ``BehavioralSequence`` + temporal configuration (G2.4); an
  optional Elastic EQL input adapter (G2.5); anything attribution-related
  (Phase 3, out of this package entirely).
"""

from __future__ import annotations

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
]
