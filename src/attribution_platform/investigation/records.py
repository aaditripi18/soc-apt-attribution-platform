"""Persisted read-model records of an investigation (ADR-0009 D2/D3).

Two new record types, each stored whole in its own index:

- :class:`InvestigationRecord` — one engine run over one source: the source
  identity and digest, every pinned version used, counts and the unit ids.
- :class:`AttributionAnalysisRecord` — the Gate 3.3-3.5 attribution analysis of
  one unit, **explicitly uncalibrated**: candidates, per-hypothesis supporting
  contributions exactly as ADR-0005 computes them, the observed decision
  features and the candidate-independent ``Unattributed`` baseline. There is no
  likelihood, confidence, WEP band, abstention verdict or rank field — the
  record type cannot carry one (ADR-0009 D3). Hypotheses are kept in id order.

Records are plain JSON (``to_canonical_json``-compatible dataclasses) so the
read-model API returns them unchanged.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from attribution_platform.dataplane import ElasticClient, ElasticIntegrationError

INVESTIGATIONS_INDEX = "attribution-platform-investigations-v1"
ATTRIBUTION_ANALYSES_INDEX = "attribution-platform-attribution-analyses-v1"
UNIT_SUMMARIES_INDEX = "attribution-platform-unit-summaries-v1"
#: /2 adds ``evidence_in_units`` / ``evidence_outside_units`` (ADR-0009 Amendment D);
#: /3 adds ``evidence_outside_unit_ids`` (ADR-0026 Amendment B).
INVESTIGATION_SCHEMA_VERSION = "investigation/3"
UNIT_SUMMARY_SCHEMA_VERSION = "unit-summary/1"
#: /2 adds ``collection_guidance`` (ADR-0005 Amendment E); /3 adds
#: ``indicator_matches`` (ADR-0013, contextual only); /4 adds
#: ``comparison_status`` / ``comparison_note`` and lets the baseline be absent
#: (ADR-0009 Amendment D: a unit beyond the exact search's work bound).
#: /5 adds ``actor_specific_evidence`` (ADR-0018).
ATTRIBUTION_ANALYSIS_SCHEMA_VERSION = "attribution-analysis/5"

# Field mappings in the same form as dataplane/mappings.py: the "properties"
# body itself (ensure_index wraps it); a "properties"-wrapped form would be
# double-nested on a real cluster.
_KEYWORD = {"type": "keyword"}
INVESTIGATIONS_MAPPING: Mapping[str, Any] = {
    "investigation_id": _KEYWORD,
    "source_id": _KEYWORD,
    "source_kind": _KEYWORD,
    "source_sha256": _KEYWORD,
    "attack_kb_version": _KEYWORD,
}
ATTRIBUTION_ANALYSES_MAPPING: Mapping[str, Any] = {
    "group_id": _KEYWORD,
    "investigation_id": _KEYWORD,
    "attack_kb_version": _KEYWORD,
}


UNIT_SUMMARIES_MAPPING: Mapping[str, Any] = {
    "group_id": _KEYWORD,
    "investigation_id": _KEYWORD,
    "host_names": _KEYWORD,
    "technique_ids": _KEYWORD,
    "candidate_ids": _KEYWORD,
    "first_seen": {"type": "date"},
    "last_seen": {"type": "date"},
}


class CalibrationStatus(Enum):
    """Whether a calibrated decision layer (ADR-0006) stands behind the
    analysis. Only ``UNCALIBRATED`` exists until a ``calibration_version``
    does."""

    UNCALIBRATED = "uncalibrated"


class ComparisonStatus(Enum):
    """Whether ADR-0005's comparison was computed for the unit. The exact search
    stops at a work bound instead of approximating, so a quantity can be absent
    — never estimated. The candidates and what would separate them are recorded
    in every case.

    - ``BASELINE_NOT_COMPUTED``: the per-candidate quantities exist; only the
      candidate-independent Unattributed baseline (one search over every
      observed feature at once) is absent.
    - ``NOT_COMPUTED``: the per-candidate quantities and the baseline are absent.
    """

    COMPUTED = "computed"
    BASELINE_NOT_COMPUTED = "baseline_not_computed"
    NOT_COMPUTED = "not_computed"


UNCALIBRATED_NOTE = (
    "No calibration_version exists yet (ADR-0006: the corpus has not passed the fitting-readiness "
    "gate), so no likelihood, confidence, WEP band, abstention verdict or ranking is emitted. The "
    "values below are ADR-0005's documented, explainable quantities: g = share of active ATT&CK "
    "Groups using the feature, D = 1 - g."
)


@dataclass(frozen=True)
class ContributionView:
    feature_technique_ids: tuple[str, ...]
    diagnosticity_outcome: str
    g_value: float | None
    d_value: float | None
    contribution_value: float
    assessment_ids: tuple[str, ...]


@dataclass(frozen=True)
class CandidateView:
    candidate_id: str
    kind: str  # "group" | "campaign"
    stix_id: str
    name: str
    attack_external_id: str | None
    generation_basis: tuple[str, ...]


@dataclass(frozen=True)
class HypothesisView:
    hypothesis_id: str
    candidate_id: str
    support_value: float
    profile_breadth: int | None
    contributions: tuple[ContributionView, ...]


@dataclass(frozen=True)
class CollectionQuestionView:
    """One evidence-collection question (ADR-0005 Amendment E): facts only."""

    technique_id: str
    technique_stix_id: str
    technique_name: str
    candidates_using: tuple[str, ...]
    candidates_total: int
    split: int
    data_components: tuple[str, ...]
    platform_detection_status: str | None
    platform_logsources: tuple[str, ...]
    platform_blocked_by: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class CollectionGuidanceView:
    method_version: str
    candidates_total: int
    questions_considered: int
    questions: tuple[CollectionQuestionView, ...]


@dataclass(frozen=True)
class IndicatorMatchView:
    """An observed value equal to a government advisory's indicator (ADR-0013).
    **Context only**: a third-party claim shown beside the unit, never part of
    any attribution quantity above."""

    indicator_id: str
    indicator_name: str
    kind: str
    value: str
    observation_id: str
    observed_at: str
    within_validity: bool | None
    bundle_file: str
    report_name: str | None
    named_actor: str | None
    named_actor_attack_id: str | None
    attribution_quote: str | None


@dataclass(frozen=True)
class ActorEvidenceView:
    """Evidence whose rule is specific to one ATT&CK Group (ADR-0018): a literal
    artefact published for that Group's own tooling matched, and the reviewed
    actor-tag decision accepted the rule. It is a lead with its basis in
    ``claim`` — never an input to the technique comparison above."""

    actor_stix_id: str
    actor_attack_id: str | None
    actor_name: str
    evidence_id: str
    rule_id: str
    claim: str
    observation_id: str
    observed_at: str | None


@dataclass(frozen=True)
class AttributionAnalysisRecord:
    group_id: str
    sequence_id: str
    investigation_id: str
    attack_kb_version: str
    min_profile_floor: int
    observed_feature_technique_ids: tuple[str, ...]
    unattributed_decision_support: float | None
    candidates: tuple[CandidateView, ...]
    hypotheses: tuple[HypothesisView, ...]
    collection_guidance: CollectionGuidanceView | None = None
    indicator_matches: tuple[IndicatorMatchView, ...] = ()
    actor_specific_evidence: tuple[ActorEvidenceView, ...] = ()
    comparison_status: ComparisonStatus = ComparisonStatus.COMPUTED
    comparison_note: str | None = None
    calibration_status: CalibrationStatus = CalibrationStatus.UNCALIBRATED
    calibration_version: None = None
    calibration_note: str = UNCALIBRATED_NOTE
    schema_version: str = field(default=ATTRIBUTION_ANALYSIS_SCHEMA_VERSION)


@dataclass(frozen=True)
class InvestigationRecord:
    investigation_id: str
    source_id: str
    source_kind: str  # "recording" | "fixture"
    source_sha256: str
    attack_kb_version: str
    detection_pack_content_hash: str
    method_versions: Mapping[str, str]
    observations_persisted: int
    evidence: int
    units: tuple[str, ...]
    #: Evidence that is a member of some unit, and Evidence that is not. The
    #: second is always low-level (enrich-tier) Evidence with no structural link
    #: to core Evidence: it never forms or joins a unit (ADR-0003 Amendment H).
    evidence_in_units: int = 0
    evidence_outside_units: int = 0
    #: ADR-0026 Amendment B: which Evidence that is, so it can be shown as context.
    evidence_outside_unit_ids: tuple[str, ...] = ()
    schema_version: str = field(default=INVESTIGATION_SCHEMA_VERSION)


@dataclass(frozen=True)
class UnitSummaryRecord:
    """The queryable facts of one attribution unit (ADR-0009 Amendment A1).
    ``technique_ids`` holds the observed ATT&CK technique ids and their parent
    techniques; ``host_names`` are lower-cased."""

    group_id: str
    investigation_id: str
    host_names: tuple[str, ...]
    first_seen: str
    last_seen: str
    technique_ids: tuple[str, ...]
    candidate_ids: tuple[str, ...]
    evidence: int
    steps: int
    schema_version: str = field(default=UNIT_SUMMARY_SCHEMA_VERSION)


def _to_json(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _to_json(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(k): _to_json(v) for k, v in sorted(value.items())}
    if isinstance(value, list | tuple):
        return [_to_json(v) for v in value]
    return value


def record_to_json(
    record: AttributionAnalysisRecord | InvestigationRecord | UnitSummaryRecord,
) -> dict[str, Any]:
    """The record as plain JSON-ready data."""
    return dict(_to_json(record))


def _persist(
    client: ElasticClient, index: str, mapping: Mapping[str, Any], key: str, doc: Any
) -> None:
    try:
        client.ensure_index(index, mapping)
        client.index_document(index, key, doc)
    except Exception as exc:  # noqa: BLE001 - one typed error for callers
        raise ElasticIntegrationError(f"failed to persist {index} document {key!r}: {exc}") from exc


def persist_investigation(client: ElasticClient, record: InvestigationRecord) -> None:
    _persist(
        client,
        INVESTIGATIONS_INDEX,
        INVESTIGATIONS_MAPPING,
        record.investigation_id,
        record_to_json(record),
    )


def persist_attribution_analysis(client: ElasticClient, record: AttributionAnalysisRecord) -> None:
    _persist(
        client,
        ATTRIBUTION_ANALYSES_INDEX,
        ATTRIBUTION_ANALYSES_MAPPING,
        record.group_id,
        record_to_json(record),
    )


def persist_unit_summary(client: ElasticClient, record: UnitSummaryRecord) -> None:
    _persist(
        client,
        UNIT_SUMMARIES_INDEX,
        UNIT_SUMMARIES_MAPPING,
        record.group_id,
        record_to_json(record),
    )


def search_unit_summaries(
    client: ElasticClient, query: Mapping[str, Any], *, size: int
) -> tuple[Mapping[str, Any], ...]:
    """The first ``size`` unit summaries matching ``query`` (Query DSL) in
    (first event, group id) order."""
    try:
        client.ensure_index(UNIT_SUMMARIES_INDEX, UNIT_SUMMARIES_MAPPING)
        return client.search(
            UNIT_SUMMARIES_INDEX, query, size=size, sort=("first_seen", "group_id")
        )
    except Exception as exc:  # noqa: BLE001
        raise ElasticIntegrationError(f"failed to search unit summaries: {exc}") from exc


def _load(client: ElasticClient, index: str, key: str) -> Mapping[str, Any] | None:
    try:
        return client.get_document(index, key)
    except Exception as exc:  # noqa: BLE001
        raise ElasticIntegrationError(f"failed to load {index} document {key!r}: {exc}") from exc


def load_investigation(client: ElasticClient, investigation_id: str) -> Mapping[str, Any] | None:
    """The stored Investigation record as JSON data, or ``None``."""
    return _load(client, INVESTIGATIONS_INDEX, investigation_id)


def load_attribution_analysis(client: ElasticClient, group_id: str) -> Mapping[str, Any] | None:
    """The stored attribution analysis of one unit as JSON data, or ``None``."""
    return _load(client, ATTRIBUTION_ANALYSES_INDEX, group_id)


#: Elasticsearch's default ``index.max_result_window``: the most one search returns.
MAX_LISTED_INVESTIGATIONS = 10_000


def list_investigations(
    client: ElasticClient, *, size: int = MAX_LISTED_INVESTIGATIONS
) -> tuple[Mapping[str, Any], ...]:
    """Stored Investigation records (up to ``size``), sorted by id. The default
    was 100, which a live session (one investigation per cycle, ADR-0028) passes
    within hours."""
    try:
        client.ensure_index(INVESTIGATIONS_INDEX, INVESTIGATIONS_MAPPING)
        return client.search(
            INVESTIGATIONS_INDEX, {"match_all": {}}, size=size, sort=("investigation_id",)
        )
    except Exception as exc:  # noqa: BLE001
        raise ElasticIntegrationError(f"failed to list investigations: {exc}") from exc


__all__ = [
    "ATTRIBUTION_ANALYSES_INDEX",
    "ActorEvidenceView",
    "INVESTIGATIONS_INDEX",
    "AttributionAnalysisRecord",
    "CalibrationStatus",
    "CandidateView",
    "ComparisonStatus",
    "ContributionView",
    "HypothesisView",
    "InvestigationRecord",
    "UNIT_SUMMARIES_INDEX",
    "UnitSummaryRecord",
    "list_investigations",
    "persist_unit_summary",
    "search_unit_summaries",
    "load_attribution_analysis",
    "load_investigation",
    "persist_attribution_analysis",
    "persist_investigation",
    "record_to_json",
]
