"""Typed, idempotent persistence for CorrelationLink/CorrelationGroup (gate
G2.3).

Additive extension of G0.8's ``persistence`` module to the two G2.0
correlation contracts, following that module's pattern exactly rather than
inventing a new one: four operations (:func:`persist_correlation_link`,
:func:`load_correlation_link`, :func:`persist_correlation_group`,
:func:`load_correlation_group`), the document body is exactly
:func:`attribution_platform.domain.to_serializable` applied to the
correlation object (no second schema — that function is a fully generic
dataclass/Enum/datetime serializer, not Observation/Evidence-specific, so it
already handles ``CorrelationLink``/``CorrelationGroup`` unchanged),
deserialization is a new, explicit, hand-written inverse of
``to_serializable`` scoped to this module (not a generic reflection-based
deserializer, not a new field on the correlation contracts themselves),
idempotent via ``client.index_document`` keyed by the object's own
``link_id``/``group_id``, and fail-closed
(:class:`~attribution_platform.dataplane.errors.ElasticIntegrationError` on
any malformed document, unrecognized ``schema_version``, or client failure).

**New dependency direction, explicitly sanctioned.** This is the first
``dataplane`` module to import :mod:`attribution_platform.correlation`.
That import is one-directional and introduces no cycle (``correlation``
never imports ``dataplane`` — enforced by that package's own guard test),
precedented by G1.1's own additive extension of this package
(``elastic_detections`` importing ``dataplane``/``attack_knowledge``/
``detection`` together), and anticipated by ADR-0003's own G2.3 gate
description ("persistence of links/groups through the existing G0.8
pattern"). No other ``dataplane`` module (``client``, ``mappings``'s
Observation/Evidence entries, ``persistence``) is touched by this addition.

**What this module persists — and deliberately nothing else.** Only the
fields G2.0's ``CorrelationLink``/``CorrelationGroup``/``CorrelationBasis``/
``CorrelationProvenance`` contracts define: schema_version, the link/group
id, anchors/member ids, link_class, basis, provenance, structural/contextual
link id sets. There is no likelihood, confidence, weight, APT-candidate, or
ATT&CK-attribution-conclusion field on any of these contracts to persist —
correlation and attribution remain separate layers (ADR-0003 D3/D10).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attribution_platform.correlation import (
    CORRELATION_GROUP_SCHEMA_VERSION,
    CORRELATION_LINK_SCHEMA_VERSION,
    CorrelationBasis,
    CorrelationGroup,
    CorrelationLink,
    CorrelationProvenance,
    LinkClass,
)
from attribution_platform.correlation.errors import CorrelationError
from attribution_platform.dataplane.client import ElasticClient
from attribution_platform.dataplane.errors import ElasticIntegrationError
from attribution_platform.dataplane.mappings import (
    CORRELATION_GROUPS_INDEX,
    CORRELATION_GROUPS_MAPPING,
    CORRELATION_LINKS_INDEX,
    CORRELATION_LINKS_MAPPING,
)
from attribution_platform.dataplane.persistence import PersistResult
from attribution_platform.domain import to_serializable


def _wrap_client_error(exc: Exception, context: str) -> ElasticIntegrationError:
    if isinstance(exc, ElasticIntegrationError):
        return exc
    return ElasticIntegrationError(f"{context}: {exc}")


# ===========================================================================
# CorrelationLink
# ===========================================================================


def persist_correlation_link(client: ElasticClient, link: CorrelationLink) -> PersistResult:
    """Write ``link`` to Elastic, keyed by its own ``link_id``."""
    if not isinstance(link, CorrelationLink):
        raise ElasticIntegrationError(
            f"persist_correlation_link requires a CorrelationLink, got {type(link).__name__}"
        )
    document = to_serializable(link)
    try:
        client.ensure_index(CORRELATION_LINKS_INDEX, CORRELATION_LINKS_MAPPING)
        client.index_document(CORRELATION_LINKS_INDEX, link.link_id, document)
    except Exception as exc:  # noqa: BLE001 - re-raised as the one typed error below
        raise _wrap_client_error(
            exc, f"failed to persist CorrelationLink {link.link_id!r}"
        ) from exc
    return PersistResult(index=CORRELATION_LINKS_INDEX, document_id=link.link_id)


def load_correlation_link(client: ElasticClient, link_id: str) -> CorrelationLink | None:
    """Load the CorrelationLink stored under ``link_id``, or ``None`` if absent."""
    try:
        doc = client.get_document(CORRELATION_LINKS_INDEX, link_id)
    except Exception as exc:  # noqa: BLE001
        raise _wrap_client_error(exc, f"failed to load CorrelationLink {link_id!r}") from exc
    if doc is None:
        return None
    return _correlation_link_from_document(doc)


def _correlation_link_from_document(doc: Mapping[str, Any]) -> CorrelationLink:
    try:
        schema_version = doc["schema_version"]
        if schema_version != CORRELATION_LINK_SCHEMA_VERSION:
            raise ElasticIntegrationError(
                f"stored CorrelationLink schema_version {schema_version!r} does not match the "
                f"current {CORRELATION_LINK_SCHEMA_VERSION!r} (schema migration not implemented "
                "at this gate)"
            )
        return CorrelationLink(
            link_id=doc["link_id"],
            anchor_a=doc["anchor_a"],
            anchor_b=doc["anchor_b"],
            link_class=LinkClass(doc["link_class"]),
            basis=_correlation_basis_from_dict(doc["basis"]),
            provenance=_correlation_provenance_from_dict(doc["provenance"]),
            schema_version=schema_version,
        )
    except ElasticIntegrationError:
        raise
    except (KeyError, TypeError, ValueError, CorrelationError) as exc:
        raise ElasticIntegrationError(
            f"stored document could not be reconstructed into a CorrelationLink: {exc}"
        ) from exc


# ===========================================================================
# CorrelationGroup
# ===========================================================================


def persist_correlation_group(client: ElasticClient, group: CorrelationGroup) -> PersistResult:
    """Write ``group`` to Elastic, keyed by its own ``group_id``."""
    if not isinstance(group, CorrelationGroup):
        raise ElasticIntegrationError(
            f"persist_correlation_group requires a CorrelationGroup, got {type(group).__name__}"
        )
    document = to_serializable(group)
    try:
        client.ensure_index(CORRELATION_GROUPS_INDEX, CORRELATION_GROUPS_MAPPING)
        client.index_document(CORRELATION_GROUPS_INDEX, group.group_id, document)
    except Exception as exc:  # noqa: BLE001
        raise _wrap_client_error(
            exc, f"failed to persist CorrelationGroup {group.group_id!r}"
        ) from exc
    return PersistResult(index=CORRELATION_GROUPS_INDEX, document_id=group.group_id)


def load_correlation_group(client: ElasticClient, group_id: str) -> CorrelationGroup | None:
    """Load the CorrelationGroup stored under ``group_id``, or ``None`` if absent."""
    try:
        doc = client.get_document(CORRELATION_GROUPS_INDEX, group_id)
    except Exception as exc:  # noqa: BLE001
        raise _wrap_client_error(exc, f"failed to load CorrelationGroup {group_id!r}") from exc
    if doc is None:
        return None
    return _correlation_group_from_document(doc)


def _correlation_group_from_document(doc: Mapping[str, Any]) -> CorrelationGroup:
    try:
        schema_version = doc["schema_version"]
        if schema_version != CORRELATION_GROUP_SCHEMA_VERSION:
            raise ElasticIntegrationError(
                f"stored CorrelationGroup schema_version {schema_version!r} does not match the "
                f"current {CORRELATION_GROUP_SCHEMA_VERSION!r} (schema migration not implemented "
                "at this gate)"
            )
        return CorrelationGroup(
            group_id=doc["group_id"],
            member_evidence_ids=tuple(doc["member_evidence_ids"]),
            member_observation_ids=tuple(doc["member_observation_ids"]),
            structural_link_ids=tuple(doc["structural_link_ids"]),
            provenance=_correlation_provenance_from_dict(doc["provenance"]),
            contextual_link_ids=tuple(doc.get("contextual_link_ids", ())),
            schema_version=schema_version,
        )
    except ElasticIntegrationError:
        raise
    except (KeyError, TypeError, ValueError, CorrelationError) as exc:
        raise ElasticIntegrationError(
            f"stored document could not be reconstructed into a CorrelationGroup: {exc}"
        ) from exc


# ===========================================================================
# Shared value-type reconstruction (the explicit inverse of to_serializable
# for exactly the value types CorrelationLink/CorrelationGroup reference)
# ===========================================================================


def _correlation_basis_from_dict(d: Mapping[str, Any]) -> CorrelationBasis:
    return CorrelationBasis(
        link_class=LinkClass(d["link_class"]),
        field_path=d["field_path"],
        observed_value=d["observed_value"],
        observation_id_a=d["observation_id_a"],
        observation_id_b=d["observation_id_b"],
        uncertainty_note=d.get("uncertainty_note"),
    )


def _correlation_provenance_from_dict(d: Mapping[str, Any]) -> CorrelationProvenance:
    return CorrelationProvenance(
        method=d["method"],
        method_version=d["method_version"],
        source_evidence_ids=tuple(d.get("source_evidence_ids", ())),
        source_observation_ids=tuple(d.get("source_observation_ids", ())),
        method_content_hash=d.get("method_content_hash"),
    )
