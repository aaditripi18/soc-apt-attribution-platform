"""Run an investigation and persist everything the read model serves
(ADR-0009 D2).

Source -> the unmodified pipeline (recording: ``analyze_recording``; fixture:
the replay pipeline, which persists as it goes) -> for every attribution unit
the Gate 3.3-3.5 stages (candidate generation, ACH matrix, comparative evidence
at the structural ``min_profile_floor`` 1, the ``Unattributed`` baseline) ->
persisted Evidence + Observations, links, groups, sequences, one uncalibrated
:class:`AttributionAnalysisRecord` per unit, and the
:class:`InvestigationRecord`. Deterministic: the investigation id is a hash of
the source digest and every pinned version, so a re-run overwrites the same
records.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attribution.ach_matrix import build_ach_matrix
from attribution_platform.attribution.candidate_generation import generate_candidates
from attribution_platform.attribution.collection_guidance import (
    CollectionGuidance,
    Detectability,
    compute_collection_guidance,
)
from attribution_platform.attribution.comparative_analysis import (
    HypothesisSupportSummary,
    compute_comparative_evidence,
    compute_unattributed_decision_support,
)
from attribution_platform.attribution.contracts import Candidate
from attribution_platform.attribution.errors import SearchBoundExceededError
from attribution_platform.correlation import (
    BehavioralSequence,
    CorrelationGroup,
)
from attribution_platform.correlation.contextual import CONTEXTUAL_CORRELATION_METHOD_VERSION
from attribution_platform.correlation.errors import CorrelationError
from attribution_platform.correlation.process_identity import PROCESS_IDENTITY_METHOD_VERSION
from attribution_platform.correlation.sequence_engine import SEQUENCE_ENGINE_METHOD_VERSION
from attribution_platform.correlation.structural import STRUCTURAL_CORRELATION_METHOD_VERSION
from attribution_platform.dataplane import (
    ElasticClient,
    persist_behavioral_sequence,
    persist_correlation_group,
    persist_correlation_link,
    persist_evidence,
    persist_observation,
)
from attribution_platform.detection import DetectionEngine
from attribution_platform.detection_content.technique_support import (
    EMPTY_REVIEW,
    TechniqueSupportReview,
)
from attribution_platform.domain import Evidence, EvidenceQuality, Observation
from attribution_platform.intel.indicators import (
    IndicatorMatch,
    IndicatorSet,
    match_observations,
)
from attribution_platform.investigation.assessment import (
    assess_investigation,
    assessment_to_json,
    persist_assessment,
)
from attribution_platform.investigation.emulation import (
    EmulationRun,
    compare_emulation,
    persist_emulation_comparison,
)
from attribution_platform.investigation.profile_match import match_profiles, persist_profile_match
from attribution_platform.investigation.records import (
    ActorEvidenceView,
    AttributionAnalysisRecord,
    CandidateView,
    CollectionGuidanceView,
    CollectionQuestionView,
    ComparisonStatus,
    ContributionView,
    HypothesisView,
    IndicatorMatchView,
    InvestigationRecord,
    UnitSummaryRecord,
    persist_attribution_analysis,
    persist_investigation,
    persist_unit_summary,
    record_to_json,
)
from attribution_platform.replay import (
    DetectionReplayFixture,
    replay_fixture_through_behavioral_sequences,
)
from attribution_platform.replay.recording_pipeline import RecordingSource, analyze_recording

#: 1.1: unit summaries (ADR-0009 Amendment A); 1.2: evidence-collection guidance
#: per unit (ADR-0005 Amendment E); 1.3: advisory indicator matches (ADR-0013);
#: 1.4: a unit beyond the exact comparison search's work bound is recorded as
#: "comparison not computed" instead of aborting the run, and the record says how
#: much Evidence is in units and how much is not (ADR-0009 Amendment D).
#: 1.5: the baseline search is kept apart from the per-candidate one; 1.6: an
#: investigation-level attribution assessment is stored (ADR-0017); 1.7:
#: actor-specific Evidence (ADR-0018); 1.8: behavioural profile match (ADR-0021).
INVESTIGATION_METHOD_VERSION = "1.9"
#: ADR-0005 §D16 structural lower bound; the fitted floor needs a calibration_version.
STRUCTURAL_MIN_PROFILE_FLOOR = 1


def _method_versions() -> dict[str, str]:
    return {
        "investigation": INVESTIGATION_METHOD_VERSION,
        "structural_correlation": STRUCTURAL_CORRELATION_METHOD_VERSION,
        "contextual_correlation": CONTEXTUAL_CORRELATION_METHOD_VERSION,
        "process_identity": PROCESS_IDENTITY_METHOD_VERSION,
        "sequence_engine": SEQUENCE_ENGINE_METHOD_VERSION,
    }


def _investigation_id(source_sha256: str, versions: Mapping[str, str]) -> str:
    identity = json.dumps({"source": source_sha256, **versions}, sort_keys=True)
    return "investigation::" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _external_id(stix_object: Mapping[str, object] | None) -> str | None:
    if stix_object is None:
        return None
    for reference in stix_object.get("external_references") or ():  # type: ignore[attr-defined]
        if reference.get("source_name") == "mitre-attack":
            return str(reference.get("external_id"))
    return None


def _candidate_view(candidate: Candidate, knowledge: AttackKnowledge) -> CandidateView:
    stix_id = candidate.actor_ref or candidate.campaign_ref or ""
    stix_object = knowledge.get_by_id(stix_id)
    return CandidateView(
        candidate_id=candidate.candidate_id,
        kind="group" if candidate.actor_ref else "campaign",
        stix_id=stix_id,
        name=str(stix_object.get("name")) if stix_object is not None else stix_id,
        attack_external_id=_external_id(stix_object),
        generation_basis=candidate.generation_basis,
    )


def _match_view(match: IndicatorMatch) -> IndicatorMatchView:
    return IndicatorMatchView(
        indicator_id=match.indicator_id,
        indicator_name=match.indicator_name,
        kind=match.kind,
        value=match.value,
        observation_id=match.observation_id,
        observed_at=match.observed_at,
        within_validity=match.within_validity,
        bundle_file=match.bundle_file,
        report_name=match.report_name,
        named_actor=match.actor_name,
        named_actor_attack_id=match.attack_group_id,
        attribution_quote=match.attribution_quote,
    )


def _guidance_view(guidance: CollectionGuidance) -> CollectionGuidanceView:
    return CollectionGuidanceView(
        method_version=guidance.method_version,
        candidates_total=guidance.candidates_total,
        questions_considered=guidance.questions_considered,
        questions=tuple(
            CollectionQuestionView(
                technique_id=q.technique_id,
                technique_stix_id=q.technique_stix_id,
                technique_name=q.technique_name,
                candidates_using=q.candidates_using,
                candidates_total=q.candidates_total,
                split=q.split,
                data_components=q.data_components,
                platform_detection_status=q.detectability.status if q.detectability else None,
                platform_logsources=q.detectability.logsources if q.detectability else (),
                platform_blocked_by=q.detectability.blocked_by if q.detectability else (),
                rationale=q.rationale,
            )
            for q in guidance.questions
        ),
    )


_TECHNIQUE_TYPE = "attack-pattern"
_GROUP_TYPE = "intrusion-set"


def _actor_view(
    evidence: Evidence, observation: Observation, knowledge: AttackKnowledge
) -> ActorEvidenceView:
    ref = evidence.attack_ref
    assert ref is not None  # the caller selects Group-referenced Evidence
    group = knowledge.get_by_id(ref.stix_id)
    return ActorEvidenceView(
        actor_stix_id=ref.stix_id,
        actor_attack_id=ref.external_id,
        actor_name=str(group.get("name")) if group is not None else ref.stix_id,
        evidence_id=evidence.evidence_id,
        rule_id=evidence.provenance.method,
        claim=evidence.claim,
        observation_id=observation.observation_id,
        observed_at=observation.timestamp.isoformat(),
    )


def _bound_detail(exc: SearchBoundExceededError) -> str:
    """The bound's own message without the raising function's name."""
    return str(exc).split(": ", 1)[-1]


def analyze_unit(
    group: CorrelationGroup,
    sequence: BehavioralSequence,
    *,
    investigation_id: str,
    knowledge: AttackKnowledge,
    detectability: Mapping[str, Detectability] | None = None,
) -> AttributionAnalysisRecord:
    """The uncalibrated attribution analysis of one unit (ADR-0009 D3), with
    its evidence-collection guidance (ADR-0005 Amendment E)."""
    candidates = generate_candidates(group, sequence, knowledge)
    matrix = build_ach_matrix(group, sequence, candidates, knowledge)
    summaries: tuple[HypothesisSupportSummary, ...] = ()
    baseline_support: float | None = None
    status = ComparisonStatus.COMPUTED
    comparison_note: str | None = None
    # Two exact searches, each kept when it completes: one per candidate (over
    # the observed features its profile includes) and one for the baseline (over
    # every observed feature at once — the larger problem). Neither is ever
    # approximated; the candidates and collection guidance below need neither.
    try:
        summaries = compute_comparative_evidence(
            matrix, knowledge, candidates, min_profile_floor=STRUCTURAL_MIN_PROFILE_FLOOR
        ).hypothesis_summaries  # already in id order
    except SearchBoundExceededError as exc:
        status = ComparisonStatus.NOT_COMPUTED
        comparison_note = (
            "The per-candidate comparison was not computed for this unit: "
            f"{_bound_detail(exc)}. Candidates and what would separate them are unaffected."
        )
    if status is ComparisonStatus.COMPUTED:
        try:
            baseline_support = compute_unattributed_decision_support(
                matrix, knowledge
            ).decision_support
        except SearchBoundExceededError as exc:
            status = ComparisonStatus.BASELINE_NOT_COMPUTED
            comparison_note = (
                "The unattributed baseline was not computed for this unit: "
                f"{_bound_detail(exc)}. The per-candidate quantities are unaffected."
            )
    hypotheses = tuple(
        HypothesisView(
            hypothesis_id=summary.hypothesis_id,
            candidate_id=summary.candidate_id,
            support_value=summary.support_value,
            profile_breadth=summary.profile_breadth,
            contributions=tuple(
                ContributionView(
                    feature_technique_ids=c.feature_stix_ids,
                    diagnosticity_outcome=c.diagnosticity_outcome.value,
                    g_value=c.g_value,
                    d_value=c.d_value,
                    contribution_value=c.contribution_value,
                    assessment_ids=c.assessment_ids,
                )
                for c in summary.contributions
            ),
        )
        for summary in summaries
    )
    observed = tuple(sorted({a.technique_stix_id for a in matrix.assessments}))
    guidance = compute_collection_guidance(
        knowledge,
        candidates=(
            (c.candidate_id, c.actor_ref or c.campaign_ref or "") for c in candidates.candidates
        ),
        observed_technique_stix_ids=observed,
        detectability=detectability,
    )
    return AttributionAnalysisRecord(
        group_id=group.group_id,
        sequence_id=sequence.sequence_id,
        investigation_id=investigation_id,
        attack_kb_version=knowledge.attack_kb_version,
        min_profile_floor=STRUCTURAL_MIN_PROFILE_FLOOR,
        observed_feature_technique_ids=observed,
        unattributed_decision_support=baseline_support,
        candidates=tuple(
            sorted(
                (_candidate_view(c, knowledge) for c in candidates.candidates),
                key=lambda view: view.candidate_id,
            )
        ),
        hypotheses=hypotheses,
        collection_guidance=_guidance_view(guidance),
        comparison_status=status,
        comparison_note=comparison_note,
    )


def summarize_unit(
    group: CorrelationGroup,
    sequence: BehavioralSequence,
    analysis: AttributionAnalysisRecord,
    members: Mapping[str, tuple[Evidence, Observation]],
) -> UnitSummaryRecord:
    """The queryable facts of one unit (ADR-0009 Amendment A1), read off its
    own Evidence and Observations and its attribution analysis."""
    pairs = [members[evidence_id] for evidence_id in group.member_evidence_ids]
    observations = {o.observation_id: o for _, o in pairs}
    techniques: set[str] = set()
    for evidence, _ in pairs:
        ref = evidence.attack_ref
        # a Group reference (ADR-0018 actor-specific Evidence) is not a technique
        external = ref.external_id if ref and ref.object_type == _TECHNIQUE_TYPE else None
        if external:
            techniques.add(external)
            techniques.add(external.split(".", 1)[0])  # parent technique
    times = sorted(o.timestamp for o in observations.values())
    return UnitSummaryRecord(
        group_id=group.group_id,
        investigation_id=analysis.investigation_id,
        host_names=tuple(
            sorted({o.host.name.lower() for o in observations.values() if o.host and o.host.name})
        ),
        first_seen=times[0].isoformat(),
        last_seen=times[-1].isoformat(),
        technique_ids=tuple(sorted(techniques)),
        candidate_ids=tuple(
            sorted({c.attack_external_id for c in analysis.candidates if c.attack_external_id})
        ),
        evidence=len(pairs),
        steps=len(sequence.steps),
    )


def run_investigation(
    source: RecordingSource | DetectionReplayFixture,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    detection_pack_content_hash: str,
    detectability: Mapping[str, Detectability] | None = None,
    indicators: IndicatorSet | None = None,
    emulation: EmulationRun | None = None,
    technique_support: TechniqueSupportReview = EMPTY_REVIEW,
) -> InvestigationRecord:
    """Run ``source`` end to end and persist every read-model object."""
    versions = {
        **_method_versions(),
        # ADR-0025: which declared techniques a reviewed rule establishes
        "technique_support_review": technique_support.sha256,
        "attack_kb_version": knowledge.attack_kb_version,
        "detection_pack": detection_pack_content_hash,
    }
    if isinstance(source, RecordingSource):
        source_id, kind, digest = source.recording_id, "recording", source.sha256
    else:
        source_id, kind, digest = source.fixture_id, "fixture", source.content_hash
    investigation_id = _investigation_id(digest, versions)

    if isinstance(source, RecordingSource):
        analysis = analyze_recording(
            source, engine=engine, knowledge=knowledge, technique_support=technique_support
        )
        observations = {o.observation_id: o for _, o in analysis.items.values()}
        for observation in observations.values():
            persist_observation(client, observation)
        for evidence, _ in analysis.items.values():
            persist_evidence(client, evidence)
        for link in (*analysis.structural_links, *analysis.contextual_links):
            persist_correlation_link(client, link)
        groups, sequences = analysis.groups, analysis.sequences
        evidence_count = len(analysis.items)
        members: dict[str, tuple[Evidence, Observation]] = dict(analysis.items)
    else:
        result = replay_fixture_through_behavioral_sequences(
            source, client=client, engine=engine, knowledge=knowledge
        )  # persists Observations, Evidence, links and sequences itself
        groups = result.correlation_result.contextual_result.groups
        sequences = result.sequences
        observations = {
            r.observation.observation_id: r.observation
            for r in result.correlation_result.detection_results
        }
        evidence_count = sum(len(r.evidences) for r in result.correlation_result.detection_results)
        members = {
            e.evidence_id: (e, r.observation)
            for r in result.correlation_result.detection_results
            for e in r.evidences
        }

    in_units = {evidence_id for group in groups for evidence_id in group.member_evidence_ids}
    stray_core = sorted(
        evidence_id
        for evidence_id, (evidence, _) in members.items()
        if evidence_id not in in_units and evidence.quality is not EvidenceQuality.LOW
    )
    if stray_core:
        # ADR-0003 Amendment H: every core Evidence belongs to exactly one unit.
        raise CorrelationError(
            f"{len(stray_core)} core Evidence item(s) belong to no unit, e.g. {stray_core[0]!r}"
        )

    sequence_by_group = {s.group_id: s for s in sequences}
    stored_analyses: list[dict[str, Any]] = []
    for group in groups:
        persist_correlation_group(client, group)
        sequence = sequence_by_group[group.group_id]
        if isinstance(source, RecordingSource):
            persist_behavioral_sequence(client, sequence)
        analysis_record = analyze_unit(
            group,
            sequence,
            investigation_id=investigation_id,
            knowledge=knowledge,
            detectability=detectability,
        )
        if indicators is not None:
            unit_observations = {
                members[e][1].observation_id: members[e][1]
                for e in group.member_evidence_ids
                if e in members
            }
            analysis_record = dataclasses.replace(
                analysis_record,
                indicator_matches=tuple(
                    _match_view(m)
                    for m in match_observations(indicators, unit_observations.values())
                ),
            )
        actor_evidence = tuple(
            _actor_view(evidence, observation, knowledge)
            for evidence, observation in sorted(
                (members[e] for e in group.member_evidence_ids if e in members),
                key=lambda pair: pair[0].evidence_id,
            )
            if evidence.attack_ref is not None and evidence.attack_ref.object_type == _GROUP_TYPE
        )
        if actor_evidence:
            analysis_record = dataclasses.replace(
                analysis_record, actor_specific_evidence=actor_evidence
            )
        persist_attribution_analysis(client, analysis_record)
        stored_analyses.append(record_to_json(analysis_record))
        persist_unit_summary(client, summarize_unit(group, sequence, analysis_record, members))

    record = InvestigationRecord(
        investigation_id=investigation_id,
        source_id=source_id,
        source_kind=kind,
        source_sha256=digest,
        attack_kb_version=knowledge.attack_kb_version,
        detection_pack_content_hash=detection_pack_content_hash,
        method_versions=_method_versions(),
        observations_persisted=len(observations),
        evidence=evidence_count,
        units=tuple(sorted(g.group_id for g in groups)),
        evidence_in_units=len(in_units),
        evidence_outside_units=evidence_count - len(in_units),
        evidence_outside_unit_ids=tuple(sorted(set(members) - in_units)),
    )
    persist_investigation(client, record)
    if emulation is not None:
        # ADR-0019: what the emulation tool reports having run, beside what was found.
        unit_of = {e: group.group_id for group in groups for e in group.member_evidence_ids}
        persist_emulation_comparison(
            client, compare_emulation(emulation, investigation_id, members, unit_of)
        )
    # ADR-0017: the verdict about the whole investigation, from the same JSON the
    # read model holds for its units.
    stored_analyses.sort(key=lambda analysis: str(analysis["group_id"]))
    assessment = assess_investigation(knowledge, investigation_id, stored_analyses)
    persist_assessment(client, assessment)
    # ADR-0021: how close the behaviour is to each profile, and what addresses it.
    persist_profile_match(client, match_profiles(knowledge, assessment_to_json(assessment)))
    return record


__all__ = ["INVESTIGATION_METHOD_VERSION", "analyze_unit", "run_investigation", "summarize_unit"]
