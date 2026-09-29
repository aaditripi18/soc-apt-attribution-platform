"""ID-addressed reads of persisted Observation/Evidence (gate G0.10).

This is the entire "L3 -> L4" contract
(docs/architecture/04-component-boundaries.md): given a domain id, return the
stored domain object or a typed, HTTP-status-carrying error
(:mod:`attribution_platform.api.errors`) — **no computation**. Depends only
on the G0.8 :class:`~attribution_platform.dataplane.client.ElasticClient`
abstraction and ``load_observation``/``load_evidence``, never on a concrete
client — the same dependency-inversion the Attribution Engine will rely on.

Returns the domain object itself, not a re-shaped response body: serializing
it to deterministic JSON (preserving every field — provenance, timestamps,
``attack_ref``, ``schema_version``) is
:mod:`attribution_platform.api.server`'s job, via the existing
:func:`attribution_platform.domain.to_canonical_json` — no second read-model
schema is introduced here.

Error mapping (fail-closed, see :mod:`attribution_platform.api.errors` for
the full rationale):

- empty/malformed identifier -> :class:`~attribution_platform.api.errors.InvalidIdentifierError`
- no matching stored document -> :class:`~attribution_platform.api.errors.NotFoundError`
- any :class:`~attribution_platform.dataplane.errors.ElasticIntegrationError`
  (malformed stored data OR a transport/auth/connectivity failure) ->
  :class:`~attribution_platform.api.errors.BackendError`
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from attribution_platform.api.errors import BackendError, InvalidIdentifierError, NotFoundError
from attribution_platform.dataplane import (
    ElasticClient,
    ElasticIntegrationError,
    load_behavioral_sequence,
    load_correlation_group,
    load_evidence,
    load_observation,
)
from attribution_platform.domain import Evidence, Observation, to_serializable
from attribution_platform.investigation.records import (
    list_investigations,
    load_attribution_analysis,
    load_investigation,
    search_unit_summaries,
)


def _validate_identifier(identifier: str, *, field: str) -> str:
    if not isinstance(identifier, str) or not identifier.strip():
        raise InvalidIdentifierError(f"{field} must be a non-empty identifier")
    return identifier


def get_observation(client: ElasticClient, observation_id: str) -> Observation:
    """Return the stored Observation for ``observation_id``, or raise."""
    observation_id = _validate_identifier(observation_id, field="observation_id")
    try:
        observation = load_observation(client, observation_id)
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not load Observation {observation_id!r}: {exc}") from exc
    if observation is None:
        raise NotFoundError(f"no Observation found with observation_id={observation_id!r}")
    return observation


def get_evidence(client: ElasticClient, evidence_id: str) -> Evidence:
    """Return the stored Evidence for ``evidence_id``, or raise."""
    evidence_id = _validate_identifier(evidence_id, field="evidence_id")
    try:
        evidence = load_evidence(client, evidence_id)
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not load Evidence {evidence_id!r}: {exc}") from exc
    if evidence is None:
        raise NotFoundError(f"no Evidence found with evidence_id={evidence_id!r}")
    return evidence


# ---------------------------------------------------------------------------
# ADR-0009 v1: investigations, attribution units, uncalibrated analyses
# ---------------------------------------------------------------------------


def get_investigation(client: ElasticClient, investigation_id: str) -> Mapping[str, Any]:
    """The stored Investigation record (ADR-0009 D2), or raise."""
    investigation_id = _validate_identifier(investigation_id, field="investigation_id")
    try:
        record = load_investigation(client, investigation_id)
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not load Investigation {investigation_id!r}: {exc}") from exc
    if record is None:
        raise NotFoundError(f"no Investigation found with investigation_id={investigation_id!r}")
    return record


def list_investigation_summaries(client: ElasticClient) -> list[dict[str, Any]]:
    """One summary per stored Investigation, sorted by id."""
    try:
        records = list_investigations(client)
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not list investigations: {exc}") from exc
    return [
        {
            "investigation_id": r.get("investigation_id"),
            "source_id": r.get("source_id"),
            "source_kind": r.get("source_kind"),
            "attack_kb_version": r.get("attack_kb_version"),
            "evidence": r.get("evidence"),
            "units": len(r.get("units") or ()),
        }
        for r in records
    ]


def get_unit(client: ElasticClient, group_id: str) -> dict[str, Any]:
    """One attribution unit: its correlation group, its behavioral sequence
    and its (uncalibrated) attribution analysis — exactly as persisted."""
    group_id = _validate_identifier(group_id, field="group_id")
    try:
        group = load_correlation_group(client, group_id)
        analysis = load_attribution_analysis(client, group_id)
        sequence = (
            load_behavioral_sequence(client, str(analysis["sequence_id"]))
            if analysis is not None
            else None
        )
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not load unit {group_id!r}: {exc}") from exc
    if group is None or analysis is None or sequence is None:
        raise NotFoundError(f"no attribution unit found with group_id={group_id!r}")
    return {
        "group": to_serializable(group),
        "sequence": to_serializable(sequence),
        "attribution_analysis": dict(analysis),
    }


def get_health(client: ElasticClient) -> dict[str, Any]:
    """Service status and whether the backend answers (never raises)."""
    try:
        list_investigations(client, size=1)
        backend = "reachable"
    except ElasticIntegrationError:
        backend = "unreachable"
    return {"status": "ok", "backend": backend, "api": "read-model/1"}


# ---------------------------------------------------------------------------
# ADR-0009 Amendment A: unit search
# ---------------------------------------------------------------------------

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_CANDIDATE_ID = re.compile(r"^[GC]\d{4}$")
UNIT_SEARCH_PARAMETERS = frozenset({"investigation", "technique", "host", "candidate", "limit"})
DEFAULT_UNIT_LIMIT = 100
MAX_UNIT_LIMIT = 1000


def _unit_filters(params: Mapping[str, str]) -> tuple[dict[str, str], int]:
    unknown = sorted(set(params) - UNIT_SEARCH_PARAMETERS)
    if unknown:
        raise InvalidIdentifierError(f"unknown query parameter(s): {', '.join(unknown)}")
    filters: dict[str, str] = {}
    for name in ("investigation", "technique", "host", "candidate"):
        if name not in params:
            continue
        value = params[name].strip()
        if not value:
            raise InvalidIdentifierError(f"query parameter {name!r} must not be empty")
        if name == "technique" and not _TECHNIQUE_ID.match(value):
            raise InvalidIdentifierError(
                f"technique must look like T1234 or T1234.001, got {value!r}"
            )
        if name == "candidate" and not _CANDIDATE_ID.match(value):
            raise InvalidIdentifierError(f"candidate must look like G1234 or C1234, got {value!r}")
        filters[name] = value.lower() if name == "host" else value
    limit = DEFAULT_UNIT_LIMIT
    if "limit" in params:
        try:
            limit = int(params["limit"])
        except ValueError as exc:
            raise InvalidIdentifierError(
                f"limit must be an integer, got {params['limit']!r}"
            ) from exc
        if not 1 <= limit <= MAX_UNIT_LIMIT:
            raise InvalidIdentifierError(f"limit must be between 1 and {MAX_UNIT_LIMIT}")
    return filters, limit


#: Filter name -> the unit-summary field it matches (keyword, exact).
_FILTER_FIELDS = {
    "investigation": "investigation_id",
    "technique": "technique_ids",
    "host": "host_names",
    "candidate": "candidate_ids",
}


def _matches(summary: Mapping[str, Any], filters: Mapping[str, str]) -> bool:
    for name, value in filters.items():
        stored = summary.get(_FILTER_FIELDS[name])
        values = stored if isinstance(stored, list | tuple) else [stored]
        if value not in values:
            return False
    return True


def search_units(client: ElasticClient, params: Mapping[str, str]) -> dict[str, Any]:
    """Unit summaries matching every given filter (ADR-0009 Amendment A):
    filtered by Elasticsearch, then re-checked here so results are exact on
    every backend; sorted by (first event, group id)."""
    filters, limit = _unit_filters(params)
    query: dict[str, Any] = (
        {
            "bool": {
                "filter": [
                    {"term": {_FILTER_FIELDS[name]: value}}
                    for name, value in sorted(filters.items())
                ]
            }
        }
        if filters
        else {"match_all": {}}
    )
    try:
        hits = search_unit_summaries(client, query, size=limit)
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not search units: {exc}") from exc
    units = sorted(
        (dict(h) for h in hits if _matches(h, filters)),
        key=lambda u: (str(u.get("first_seen")), str(u.get("group_id"))),
    )
    return {
        "filters": filters,
        "limit": limit,
        "truncated": len(hits) >= limit,
        "units": units,
    }
