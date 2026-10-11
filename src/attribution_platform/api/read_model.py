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

from attribution_platform.api.assistant import build_digest
from attribution_platform.api.context import ApiContext, rule_key
from attribution_platform.api.errors import BackendError, InvalidIdentifierError, NotFoundError
from attribution_platform.dataplane import (
    ElasticClient,
    ElasticIntegrationError,
    load_behavioral_sequence,
    load_correlation_group,
    load_evidence,
    load_observation,
)
from attribution_platform.domain import (
    Evidence,
    EvidenceQuality,
    Observation,
    to_serializable,
)
from attribution_platform.investigation.assessment import load_assessment
from attribution_platform.investigation.dossier import DOSSIER_VERSION, render_dossier
from attribution_platform.investigation.emulation import load_emulation_comparison
from attribution_platform.investigation.observables import KINDS as OBSERVABLE_KINDS
from attribution_platform.investigation.observables import (
    OBSERVABLES_METHOD_VERSION,
    collect_observables,
)
from attribution_platform.investigation.profile_match import load_profile_match
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


def get_assessment(client: ElasticClient, investigation_id: str) -> Mapping[str, Any]:
    """The stored attribution assessment of one investigation (ADR-0017), or raise."""
    investigation_id = _validate_identifier(investigation_id, field="investigation_id")
    try:
        record = load_assessment(client, investigation_id)
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not load the assessment of {investigation_id!r}: {exc}") from exc
    if record is None:
        raise NotFoundError(f"no assessment found for investigation_id={investigation_id!r}")
    return record


def get_profile_match(client: ElasticClient, investigation_id: str) -> Mapping[str, Any]:
    """The stored behavioural profile match of one investigation (ADR-0021)."""
    investigation_id = _validate_identifier(investigation_id, field="investigation_id")
    try:
        record = load_profile_match(client, investigation_id)
    except ElasticIntegrationError as exc:
        raise BackendError(
            f"could not load the profile match of {investigation_id!r}: {exc}"
        ) from exc
    if record is None:
        raise NotFoundError(f"no profile match for investigation_id={investigation_id!r}")
    return record


def get_emulation_comparison(client: ElasticClient, investigation_id: str) -> Mapping[str, Any]:
    """The stored ran-versus-detected comparison (ADR-0019), or 404 when the
    investigation was run without an emulation report."""
    investigation_id = _validate_identifier(investigation_id, field="investigation_id")
    try:
        record = load_emulation_comparison(client, investigation_id)
    except ElasticIntegrationError as exc:
        raise BackendError(
            f"could not load the emulation comparison of {investigation_id!r}: {exc}"
        ) from exc
    if record is None:
        raise NotFoundError(
            f"no emulation report was given for investigation_id={investigation_id!r}"
        )
    return record


def _label(observation: Observation | None) -> str | None:
    """A short name for what an Observation recorded (never its command line)."""
    if observation is None:
        return None
    process = observation.process
    if process is not None and (process.name or process.executable):
        return process.name or str(process.executable).replace("\\", "/").rsplit("/", 1)[-1]
    if observation.event is not None and observation.event.action:
        return observation.event.action
    return observation.raw_reference.source_type if observation.raw_reference else None


def get_investigation_activity(client: ElasticClient, investigation_id: str) -> dict[str, Any]:
    """Every Evidence item of an investigation's units as one time-ordered list
    (ADR-0019): when, on which host, in which unit, mapped to what, and whether
    it is a decision feature of its unit. A join of stored records — the ATT&CK
    matrix view and the investigation timeline are drawn from it."""
    record = get_investigation(client, investigation_id)
    events: list[dict[str, Any]] = []
    try:
        for group_id in record["units"]:
            group = load_correlation_group(client, str(group_id))
            analysis = load_attribution_analysis(client, str(group_id))
            if group is None or analysis is None:
                continue
            features = set(analysis["observed_feature_technique_ids"])
            for evidence_id in group.member_evidence_ids:
                evidence = load_evidence(client, evidence_id)
                if evidence is None:
                    continue
                observation = load_observation(
                    client, evidence.provenance.source_observation_ids[0]
                )
                ref = evidence.attack_ref
                when = evidence.time_span.start if evidence.time_span else None
                if when is None and observation is not None:
                    when = observation.timestamp
                host = observation.host if observation is not None else None
                events.append(
                    {
                        "time": when.isoformat() if when is not None else None,
                        "group_id": str(group_id),
                        "evidence_id": evidence.evidence_id,
                        "host": (host.name or host.id) if host is not None else None,
                        "label": _label(observation),
                        "attack_id": ref.external_id if ref is not None else None,
                        "attack_stix_id": ref.stix_id if ref is not None else None,
                        "attack_object_type": ref.object_type if ref is not None else None,
                        "context": evidence.quality is EvidenceQuality.LOW,
                        "decision_feature": ref is not None and ref.stix_id in features,
                    }
                )
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not load the activity of {investigation_id!r}: {exc}") from exc
    events.sort(key=lambda e: (e["time"] is None, e["time"] or "", e["evidence_id"]))
    return {
        "investigation_id": investigation_id,
        "evidence_in_units": len(events),
        "evidence_outside_units": record.get("evidence_outside_units"),
        "events": events,
    }


def get_investigation_observables(client: ElasticClient, investigation_id: str) -> dict[str, Any]:
    """The observables of an investigation's units (ADR-0022): hashes, addresses
    and domains stated by the events that ground its Evidence, each with where
    and when it was seen and any advisory indicator it equals. A join of stored
    records; nothing is judged malicious here."""
    record = get_investigation(client, investigation_id)
    members: list[tuple[str, Evidence, Observation]] = []
    advisory: dict[tuple[str, str], Mapping[str, Any]] = {}
    try:
        for group_id in record["units"]:
            group = load_correlation_group(client, str(group_id))
            analysis = load_attribution_analysis(client, str(group_id))
            if group is None:
                continue
            for match in (analysis or {}).get("indicator_matches") or ():
                advisory.setdefault((str(match["kind"]), str(match["value"])), match)
            for evidence_id in group.member_evidence_ids:
                evidence = load_evidence(client, evidence_id)
                if evidence is None:
                    continue
                observation = load_observation(
                    client, evidence.provenance.source_observation_ids[0]
                )
                if observation is not None:
                    members.append((str(group_id), evidence, observation))
    except ElasticIntegrationError as exc:
        raise BackendError(
            f"could not load the observables of {investigation_id!r}: {exc}"
        ) from exc
    observables = collect_observables(members, advisory)
    return {
        "investigation_id": investigation_id,
        "method_version": OBSERVABLES_METHOD_VERSION,
        "observables": observables,
        "counts": {
            kind: sum(1 for o in observables if o["kind"] == kind) for kind in OBSERVABLE_KINDS
        },
        "advisory_matches": sum(1 for o in observables if o["advisory"] is not None),
    }


def get_assistant_digest(
    client: ElasticClient, context: ApiContext, investigation_id: str
) -> dict[str, Any]:
    """The facts the analyst assistant may use about one investigation
    (ADR-0022): assembled from the stored records the pages show."""
    investigation = get_investigation(client, investigation_id)

    def optional(read: Any) -> Any:
        try:
            return read(client, investigation_id)
        except NotFoundError:
            return None

    catalogue = (context.techniques or {}).get("techniques") or ()
    return build_digest(
        investigation=investigation,
        assessment=optional(get_assessment),
        profile_match=optional(get_profile_match),
        activity=get_investigation_activity(client, investigation_id),
        observables=get_investigation_observables(client, investigation_id)["observables"],
        techniques={
            str(t["attack_id"]): {"name": t["name"], "tactics": t["tactics"]} for t in catalogue
        },
        emulation=optional(get_emulation_comparison),
    )


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
            "evidence_in_units": r.get("evidence_in_units"),
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


# ---------------------------------------------------------------------------
# ADR-0016: what the analyst frontend reads beside the stored records
# ---------------------------------------------------------------------------


def _reference(value: Any, what: str) -> Any:
    if value is None:
        raise NotFoundError(f"{what} is not available: the server was started without it")
    return value


def get_attack_techniques(context: ApiContext) -> Mapping[str, Any]:
    """Active ATT&CK techniques with tactics and Group prevalence."""
    return _reference(context.techniques, "the ATT&CK technique catalogue")  # type: ignore[no-any-return]


def get_attack_groups(context: ApiContext) -> Mapping[str, Any]:
    """Every active ATT&CK Group's profile and the group-specific evidence the
    platform holds for it (ADR-0021)."""
    return _reference(context.groups, "the ATT&CK Group catalogue")  # type: ignore[no-any-return]


def get_validation(context: ApiContext) -> Mapping[str, Any]:
    """Known-answer checks (ADR-0017): the verdicts given on recordings whose
    answer is known, and what ordering candidates would have named instead."""
    return _reference(context.validation, "the known-answer checks")  # type: ignore[no-any-return]


def get_coverage(context: ApiContext) -> Mapping[str, Any]:
    """The committed detection coverage report and content-source summaries."""
    return _reference(context.coverage, "the detection coverage report")  # type: ignore[no-any-return]


def get_unit_evidence(client: ElasticClient, context: ApiContext, group_id: str) -> dict[str, Any]:
    """Every Evidence of one unit, the Observations they are grounded in and the
    detection rules that produced them — each exactly as stored. Evidence is in
    (start time, id) order; a rule the pinned import reports do not list is
    simply absent from ``rules`` (never guessed)."""
    group_id = _validate_identifier(group_id, field="group_id")
    try:
        group = load_correlation_group(client, group_id)
        if group is None:
            raise NotFoundError(f"no attribution unit found with group_id={group_id!r}")
        evidence = [e for e in (load_evidence(client, i) for i in group.member_evidence_ids) if e]
        observations = [
            o for o in (load_observation(client, i) for i in group.member_observation_ids) if o
        ]
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not load the evidence of unit {group_id!r}: {exc}") from exc
    evidence.sort(
        key=lambda e: (e.time_span.start.isoformat() if e.time_span else "", e.evidence_id)
    )
    rules = {}
    for item in evidence:
        key = rule_key(item.provenance.method)
        if key in context.rules:
            rules[key] = dict(context.rules[key])
    return {
        "group_id": group_id,
        "evidence": [to_serializable(e) for e in evidence],
        "observations": {o.observation_id: to_serializable(o) for o in observations},
        "rules": rules,
    }


def get_dossier(
    client: ElasticClient, context: ApiContext, investigation_id: str
) -> dict[str, Any]:
    """The attribution dossier of one investigation as Markdown, rendered from
    the persisted read model (``investigation/dossier.py``)."""
    investigation_id = _validate_identifier(investigation_id, field="investigation_id")
    knowledge = _reference(context.knowledge, "the ATT&CK knowledge base")
    get_investigation(client, investigation_id)  # 404 if absent
    try:
        markdown = render_dossier(client, knowledge, investigation_id)
    except ElasticIntegrationError as exc:
        raise BackendError(f"could not render the dossier of {investigation_id!r}: {exc}") from exc
    return {
        "investigation_id": investigation_id,
        "dossier_version": DOSSIER_VERSION,
        "markdown": markdown,
    }
