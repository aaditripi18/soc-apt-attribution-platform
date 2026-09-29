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

import hashlib
import json
from collections.abc import Mapping

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attribution.ach_matrix import build_ach_matrix
from attribution_platform.attribution.candidate_generation import generate_candidates
from attribution_platform.attribution.comparative_analysis import (
    compute_comparative_evidence,
    compute_unattributed_decision_support,
)
from attribution_platform.attribution.contracts import Candidate
from attribution_platform.correlation import (
    BehavioralSequence,
    CorrelationGroup,
)
from attribution_platform.correlation.contextual import CONTEXTUAL_CORRELATION_METHOD_VERSION
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
from attribution_platform.domain import Evidence, Observation
from attribution_platform.investigation.records import (
    AttributionAnalysisRecord,
    CandidateView,
    ContributionView,
    HypothesisView,
    InvestigationRecord,
    UnitSummaryRecord,
    persist_attribution_analysis,
    persist_investigation,
    persist_unit_summary,
)
from attribution_platform.replay import (
    DetectionReplayFixture,
    replay_fixture_through_behavioral_sequences,
)
from attribution_platform.replay.recording_pipeline import RecordingSource, analyze_recording

INVESTIGATION_METHOD_VERSION = "1.1"  # 1.1: unit summaries (ADR-0009 Amendment A)
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


def analyze_unit(
    group: CorrelationGroup,
    sequence: BehavioralSequence,
    *,
    investigation_id: str,
    knowledge: AttackKnowledge,
) -> AttributionAnalysisRecord:
    """The uncalibrated attribution analysis of one unit (ADR-0009 D3)."""
    candidates = generate_candidates(group, sequence, knowledge)
    matrix = build_ach_matrix(group, sequence, candidates, knowledge)
    comparative = compute_comparative_evidence(
        matrix, knowledge, candidates, min_profile_floor=STRUCTURAL_MIN_PROFILE_FLOOR
    )
    baseline = compute_unattributed_decision_support(matrix, knowledge)
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
        for summary in comparative.hypothesis_summaries  # already in id order
    )
    return AttributionAnalysisRecord(
        group_id=group.group_id,
        sequence_id=sequence.sequence_id,
        investigation_id=investigation_id,
        attack_kb_version=knowledge.attack_kb_version,
        min_profile_floor=STRUCTURAL_MIN_PROFILE_FLOOR,
        observed_feature_technique_ids=tuple(
            sorted({a.technique_stix_id for a in matrix.assessments})
        ),
        unattributed_decision_support=baseline.decision_support,
        candidates=tuple(
            sorted(
                (_candidate_view(c, knowledge) for c in candidates.candidates),
                key=lambda view: view.candidate_id,
            )
        ),
        hypotheses=hypotheses,
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
        external = evidence.attack_ref.external_id if evidence.attack_ref else None
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
) -> InvestigationRecord:
    """Run ``source`` end to end and persist every read-model object."""
    versions = {
        **_method_versions(),
        "attack_kb_version": knowledge.attack_kb_version,
        "detection_pack": detection_pack_content_hash,
    }
    if isinstance(source, RecordingSource):
        source_id, kind, digest = source.recording_id, "recording", source.sha256
    else:
        source_id, kind, digest = source.fixture_id, "fixture", source.content_hash
    investigation_id = _investigation_id(digest, versions)

    if isinstance(source, RecordingSource):
        analysis = analyze_recording(source, engine=engine, knowledge=knowledge)
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

    sequence_by_group = {s.group_id: s for s in sequences}
    for group in groups:
        persist_correlation_group(client, group)
        sequence = sequence_by_group[group.group_id]
        if isinstance(source, RecordingSource):
            persist_behavioral_sequence(client, sequence)
        analysis_record = analyze_unit(
            group, sequence, investigation_id=investigation_id, knowledge=knowledge
        )
        persist_attribution_analysis(client, analysis_record)
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
    )
    persist_investigation(client, record)
    return record


__all__ = ["INVESTIGATION_METHOD_VERSION", "analyze_unit", "run_investigation", "summarize_unit"]
