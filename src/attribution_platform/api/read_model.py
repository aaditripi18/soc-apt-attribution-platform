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

from attribution_platform.api.errors import BackendError, InvalidIdentifierError, NotFoundError
from attribution_platform.dataplane import (
    ElasticClient,
    ElasticIntegrationError,
    load_evidence,
    load_observation,
)
from attribution_platform.domain import Evidence, Observation


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
