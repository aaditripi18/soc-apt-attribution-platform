"""Typed, idempotent persistence for BehavioralSequence (gate G2.4.2).

Additive extension of G0.8's ``persistence`` module (and G2.3's own
``correlation_persistence`` extension of it) to the G2.4.0
``BehavioralSequence`` contract, following that established pattern exactly
rather than inventing a new one: two operations
(:func:`persist_behavioral_sequence`, :func:`load_behavioral_sequence`), the
document body is exactly
:func:`attribution_platform.domain.to_serializable` applied to the
``BehavioralSequence`` (no second schema — that function is a fully generic
dataclass/Enum/datetime serializer and already handles every nested contract
here — ``BehavioralStep``, ``SequenceEdge``, ``SequenceGap``,
``SequenceParallelGroup``, ``OrderingBasis``, ``CorrelationProvenance`` —
unchanged), deserialization is a new, explicit, hand-written inverse of
``to_serializable`` scoped to this module (not a generic reflection-based
deserializer, not a new field on the sequence contracts themselves),
idempotent via ``client.index_document`` keyed by the object's own
``sequence_id`` (ADR-0004 D18: **one document per BehavioralSequence** —
steps/edges/gaps/parallel_groups all embedded within it, never a separate
document per nested object), and fail-closed
(:class:`~attribution_platform.dataplane.errors.ElasticIntegrationError` on
any malformed document, unrecognized ``schema_version``, or client failure).

**Deserialization reconstructs via the raw dataclass constructors**
(``BehavioralSequence(...)``, not
:func:`~attribution_platform.correlation.sequence.build_behavioral_sequence`),
mirroring ``correlation_persistence.py``'s own precedent for
``CorrelationGroup``/``CorrelationLink`` exactly: a loaded document is
trusted as already-validated (it could only have been persisted by a real,
already-checked ``BehavioralSequence``), not re-verified against a second,
independently-loaded ``CorrelationGroup`` object that this module never
loads. Each raw constructor's own ``__post_init__`` still re-runs every
*internal* consistency check (step/edge/gap/parallel-group referential
integrity, acyclicity, branch-partition well-formedness) on every load — only
the *cross-object* grounding check ``build_behavioral_sequence`` adds is
skipped here, exactly as ``_correlation_group_from_document`` already skips
re-verifying ``structural_link_ids`` against independently-loaded
``CorrelationLink`` documents.

**``SequenceParallelGroup.branches`` requires explicit nested
reconstruction.** ``to_serializable`` turns
``tuple[tuple[str, ...], ...]`` into ``list[list[str]]``; naively converting
only the outer container (``tuple(d["branches"])``) would yield a tuple of
*lists*, which is never equal to the original tuple of *tuples*
(``("A",) != ["A"]`` in Python) and would silently break every round-trip
equality check on this one field. The inverse here is therefore explicitly
two-level: ``tuple(tuple(branch) for branch in d["branches"])``.

**Each layer owns its own local reconstruction helpers.** This module
duplicates a local ``_correlation_provenance_from_dict``, matching
``correlation_persistence.py``'s own established convention of never
importing another persistence module's private helpers, even for an
identically-shaped value object.

**Dependency direction.** Imports only :mod:`attribution_platform.correlation`
(for the frozen G2.4.0 contracts — unchanged, never reconstructed via their
own sanctioned builders here) and this package's own ``client``/``errors``/
``mappings``/``persistence`` — the same shape ``correlation_persistence.py``
already established; no new dependency direction is introduced.

**What this module persists — and deliberately nothing else.** Only the
fields G2.4.0's ``BehavioralSequence``/``BehavioralStep``/``SequenceEdge``/
``SequenceGap``/``SequenceParallelGroup``/``OrderingBasis`` contracts define.
No likelihood, confidence, weight, APT-candidate, or ATT&CK-attribution
field exists on any of these contracts to persist — behavioral-sequence
reconstruction and attribution remain separate layers (ADR-0004 D15/D17).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attribution_platform.correlation import (
    BEHAVIORAL_SEQUENCE_SCHEMA_VERSION,
    BEHAVIORAL_STEP_SCHEMA_VERSION,
    SEQUENCE_EDGE_SCHEMA_VERSION,
    SEQUENCE_GAP_SCHEMA_VERSION,
    SEQUENCE_PARALLEL_GROUP_SCHEMA_VERSION,
    BehavioralSequence,
    BehavioralStep,
    CorrelationProvenance,
    GapReason,
    OrderingBasis,
    OrderingBasisKind,
    SequenceEdge,
    SequenceGap,
    SequenceParallelGroup,
)
from attribution_platform.correlation.errors import CorrelationError
from attribution_platform.dataplane.client import ElasticClient
from attribution_platform.dataplane.errors import ElasticIntegrationError
from attribution_platform.dataplane.mappings import (
    BEHAVIORAL_SEQUENCES_INDEX,
    BEHAVIORAL_SEQUENCES_MAPPING,
)
from attribution_platform.dataplane.persistence import PersistResult
from attribution_platform.domain import to_serializable


def _wrap_client_error(exc: Exception, context: str) -> ElasticIntegrationError:
    if isinstance(exc, ElasticIntegrationError):
        return exc
    return ElasticIntegrationError(f"{context}: {exc}")


def persist_behavioral_sequence(
    client: ElasticClient, sequence: BehavioralSequence
) -> PersistResult:
    """Write ``sequence`` to Elastic, keyed by its own ``sequence_id`` — one
    document, steps/edges/gaps/parallel_groups/provenance all embedded
    (ADR-0004 D18)."""
    if not isinstance(sequence, BehavioralSequence):
        raise ElasticIntegrationError(
            "persist_behavioral_sequence requires a BehavioralSequence, "
            f"got {type(sequence).__name__}"
        )
    document = to_serializable(sequence)
    try:
        client.ensure_index(BEHAVIORAL_SEQUENCES_INDEX, BEHAVIORAL_SEQUENCES_MAPPING)
        client.index_document(BEHAVIORAL_SEQUENCES_INDEX, sequence.sequence_id, document)
    except Exception as exc:  # noqa: BLE001 - re-raised as the one typed error below
        raise _wrap_client_error(
            exc, f"failed to persist BehavioralSequence {sequence.sequence_id!r}"
        ) from exc
    return PersistResult(index=BEHAVIORAL_SEQUENCES_INDEX, document_id=sequence.sequence_id)


def load_behavioral_sequence(client: ElasticClient, sequence_id: str) -> BehavioralSequence | None:
    """Load the BehavioralSequence stored under ``sequence_id``, or ``None``
    if absent."""
    try:
        doc = client.get_document(BEHAVIORAL_SEQUENCES_INDEX, sequence_id)
    except Exception as exc:  # noqa: BLE001
        raise _wrap_client_error(exc, f"failed to load BehavioralSequence {sequence_id!r}") from exc
    if doc is None:
        return None
    return _behavioral_sequence_from_document(doc)


def _behavioral_sequence_from_document(doc: Mapping[str, Any]) -> BehavioralSequence:
    try:
        schema_version = doc["schema_version"]
        if schema_version != BEHAVIORAL_SEQUENCE_SCHEMA_VERSION:
            raise ElasticIntegrationError(
                f"stored BehavioralSequence schema_version {schema_version!r} does not match "
                f"the current {BEHAVIORAL_SEQUENCE_SCHEMA_VERSION!r} (schema migration not "
                "implemented at this gate)"
            )
        return BehavioralSequence(
            sequence_id=doc["sequence_id"],
            group_id=doc["group_id"],
            steps=tuple(_behavioral_step_from_dict(s) for s in doc["steps"]),
            provenance=_correlation_provenance_from_dict(doc["provenance"]),
            edges=tuple(_sequence_edge_from_dict(e) for e in doc.get("edges", ())),
            gaps=tuple(_sequence_gap_from_dict(g) for g in doc.get("gaps", ())),
            parallel_groups=tuple(
                _sequence_parallel_group_from_dict(p) for p in doc.get("parallel_groups", ())
            ),
            schema_version=schema_version,
        )
    except ElasticIntegrationError:
        raise
    except (KeyError, TypeError, ValueError, CorrelationError) as exc:
        raise ElasticIntegrationError(
            f"stored document could not be reconstructed into a BehavioralSequence: {exc}"
        ) from exc


# ===========================================================================
# Shared value-type reconstruction (the explicit inverse of to_serializable
# for exactly the value types BehavioralSequence references). Reconstructed
# bottom-up: OrderingBasis -> SequenceEdge/SequenceGap/SequenceParallelGroup
# -> BehavioralStep -> BehavioralSequence.
# ===========================================================================


def _correlation_provenance_from_dict(d: Mapping[str, Any]) -> CorrelationProvenance:
    return CorrelationProvenance(
        method=d["method"],
        method_version=d["method_version"],
        source_evidence_ids=tuple(d.get("source_evidence_ids", ())),
        source_observation_ids=tuple(d.get("source_observation_ids", ())),
        method_content_hash=d.get("method_content_hash"),
    )


def _ordering_basis_from_dict(d: Mapping[str, Any]) -> OrderingBasis:
    return OrderingBasis(
        basis_kind=OrderingBasisKind(d["basis_kind"]),
        grounding_link_id=d["grounding_link_id"],
        timestamp_agreement=d.get("timestamp_agreement"),
        precision_uncertain=d.get("precision_uncertain", False),
    )


def _sequence_edge_from_dict(d: Mapping[str, Any]) -> SequenceEdge:
    return SequenceEdge(
        edge_id=d["edge_id"],
        from_step_id=d["from_step_id"],
        to_step_id=d["to_step_id"],
        basis=_ordering_basis_from_dict(d["basis"]),
        schema_version=d.get("schema_version", SEQUENCE_EDGE_SCHEMA_VERSION),
    )


def _sequence_gap_from_dict(d: Mapping[str, Any]) -> SequenceGap:
    return SequenceGap(
        gap_id=d["gap_id"],
        step_id_a=d["step_id_a"],
        step_id_b=d["step_id_b"],
        grounding_link_id=d["grounding_link_id"],
        reason=GapReason(d["reason"]),
        schema_version=d.get("schema_version", SEQUENCE_GAP_SCHEMA_VERSION),
    )


def _sequence_parallel_group_from_dict(d: Mapping[str, Any]) -> SequenceParallelGroup:
    # CRITICAL: to_serializable turns tuple[tuple[str, ...], ...] into
    # list[list[str]]; a shallow tuple(d["branches"]) would yield a tuple of
    # *lists*, which is never equal to the original tuple of *tuples*. Both
    # levels must be explicitly reconstructed.
    branches = tuple(tuple(branch) for branch in d["branches"])
    return SequenceParallelGroup(
        parallel_group_id=d["parallel_group_id"],
        source_step_id=d["source_step_id"],
        branches=branches,
        schema_version=d.get("schema_version", SEQUENCE_PARALLEL_GROUP_SCHEMA_VERSION),
    )


def _behavioral_step_from_dict(d: Mapping[str, Any]) -> BehavioralStep:
    return BehavioralStep(
        step_id=d["step_id"],
        group_id=d["group_id"],
        evidence_ids=tuple(d["evidence_ids"]),
        observation_id=d["observation_id"],
        technique_stix_ids=tuple(d.get("technique_stix_ids", ())),
        # B4: tolerant default so a pre-``behavioral-step/2`` document (no
        # evidence_types key) round-trips as ``()`` — same pattern as
        # technique_stix_ids above; no migration required.
        evidence_types=tuple(d.get("evidence_types", ())),
        contextual_annotations=tuple(d.get("contextual_annotations", ())),
        schema_version=d.get("schema_version", BEHAVIORAL_STEP_SCHEMA_VERSION),
    )
