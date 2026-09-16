"""Tests for gate G3.2: attribution domain contracts (ADR-0005 §D2/§D5/§D9/§D10).

Covers: valid Group/Campaign ``Candidate`` construction and the exactly-one-
of-actor_ref/campaign_ref invariant; unknown/malformed candidate identity
fails closed; the explicit, deterministic "Unattributed" representation via
:data:`UNATTRIBUTED_CANDIDATE_ID` (never a missing/``None`` candidate);
``EvidenceAssessment`` referencing stable upstream ids and categorical
relevance/role; the Likelihood/Confidence separation (never merged, never a
percentage/probability/combined score); ``CoverageProfile``'s four-state
behavior; ``AttributionAssessment`` with supporting/contradicting evidence
via ``AttributionResult``; ``AttributionResult`` tied to exactly one
attribution unit (structurally, via deterministic ``result_id``);
empty/invalid collections failing closed where required; deterministic
identity/serialization (including via the existing, unmodified
``domain.to_canonical_json``); immutability; ``AttributionProvenance``
structure; required version fields; and guards proving no analyst-facing
numeric attribution score exists anywhere in this module, and that nothing
here creates/mutates a Phase 0–2 object.

This file tests contract *behavior* only — no candidate generation, ACH
scoring, diagnosticity computation, likelihood/confidence calculation,
abstention, or calibration is implemented or exercised here (that machinery
does not exist yet; see ``attribution.contracts``'s own module docstring).

Offline, deterministic, no Elastic/Docker/Windows/network required.
"""

from __future__ import annotations

import ast
import dataclasses
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.attribution import (
    UNATTRIBUTED_CANDIDATE_ID,
    AttributionAssessment,
    AttributionError,
    AttributionProvenance,
    AttributionResult,
    Candidate,
    CandidateType,
    Confidence,
    ConfidenceBand,
    ConfidenceReason,
    CoverageProfile,
    CoverageState,
    EvidenceAssessment,
    EvidenceRole,
    Hypothesis,
    Likelihood,
    NextEvidence,
    Relevance,
    SeparationBand,
    compute_attribution_assessment_id,
    compute_attribution_result_id,
    compute_candidate_id,
    compute_coverage_profile_id,
    compute_evidence_assessment_id,
    compute_hypothesis_id,
    compute_next_evidence_id,
    is_unattributed_hypothesis,
)
from attribution_platform.attribution import contracts as contracts_module
from attribution_platform.domain import to_canonical_json
from attribution_platform.domain.entities import TimeSpan

REPO_ROOT = Path(__file__).resolve().parents[1]
ATTRIBUTION_DIR = REPO_ROOT / "src" / "attribution_platform" / "attribution"

_GROUP_STIX_ID = "intrusion-set--11111111-1111-1111-1111-111111111111"
_CAMPAIGN_STIX_ID = "campaign--22222222-2222-2222-2222-222222222222"
_TECHNIQUE_STIX_ID_A = "attack-pattern--33333333-3333-3333-3333-333333333333"
_TECHNIQUE_STIX_ID_B = "attack-pattern--44444444-4444-4444-4444-444444444444"
_KB_VERSION = "enterprise-attack-19.0"


# ===========================================================================
# Fixtures / helpers
# ===========================================================================


def _provenance(**overrides: object) -> AttributionProvenance:
    kwargs: dict[str, object] = {
        "method": "attribution-contracts-test",
        "method_version": "1.0",
        "source_group_id": "group-1",
        "source_sequence_id": "sequence-1",
        "source_evidence_ids": ("ev-1", "ev-2"),
        "source_observation_ids": ("obs-1", "obs-2"),
    }
    kwargs.update(overrides)
    return AttributionProvenance(**kwargs)  # type: ignore[arg-type]


def _group_candidate(**overrides: object) -> Candidate:
    kwargs: dict[str, object] = {
        "candidate_id": compute_candidate_id(_GROUP_STIX_ID),
        "attack_kb_version": _KB_VERSION,
        "generation_basis": (_TECHNIQUE_STIX_ID_A,),
        "actor_ref": _GROUP_STIX_ID,
    }
    kwargs.update(overrides)
    return Candidate(**kwargs)  # type: ignore[arg-type]


def _campaign_candidate(**overrides: object) -> Candidate:
    kwargs: dict[str, object] = {
        "candidate_id": compute_candidate_id(_CAMPAIGN_STIX_ID),
        "attack_kb_version": _KB_VERSION,
        "generation_basis": (_TECHNIQUE_STIX_ID_A,),
        "campaign_ref": _CAMPAIGN_STIX_ID,
    }
    kwargs.update(overrides)
    return Candidate(**kwargs)  # type: ignore[arg-type]


def _hypothesis(candidate_id: str, group_id: str = "group-1", **overrides: object) -> Hypothesis:
    kwargs: dict[str, object] = {
        "hypothesis_id": compute_hypothesis_id(group_id, candidate_id),
        "group_id": group_id,
        "candidate_id": candidate_id,
    }
    kwargs.update(overrides)
    return Hypothesis(**kwargs)  # type: ignore[arg-type]


def _evidence_assessment(hypothesis_id: str, **overrides: object) -> EvidenceAssessment:
    kwargs: dict[str, object] = {
        "assessment_id": compute_evidence_assessment_id(
            hypothesis_id, "step-1", _TECHNIQUE_STIX_ID_A
        ),
        "hypothesis_id": hypothesis_id,
        "step_id": "step-1",
        "technique_stix_id": _TECHNIQUE_STIX_ID_A,
        "role": EvidenceRole.SUPPORTING,
        "relevance": Relevance.CONSISTENT,
        "diagnosticity_ref": "diagnosticity-ref-1",
    }
    kwargs.update(overrides)
    return EvidenceAssessment(**kwargs)  # type: ignore[arg-type]


def _likelihood(**overrides: object) -> Likelihood:
    kwargs: dict[str, object] = {
        "wep_band": "likely",
        "separation_from_null": SeparationBand.CLEAR,
        "separation_from_next": SeparationBand.MARGINAL,
    }
    kwargs.update(overrides)
    return Likelihood(**kwargs)  # type: ignore[arg-type]


def _confidence(**overrides: object) -> Confidence:
    kwargs: dict[str, object] = {
        "band": ConfidenceBand.MODERATE,
        "reasons": (ConfidenceReason.CORROBORATION,),
    }
    kwargs.update(overrides)
    return Confidence(**kwargs)  # type: ignore[arg-type]


def _attribution_assessment(hypothesis_id: str, **overrides: object) -> AttributionAssessment:
    kwargs: dict[str, object] = {
        "assessment_id": compute_attribution_assessment_id(hypothesis_id, "calib-1"),
        "hypothesis_id": hypothesis_id,
        "likelihood": _likelihood(),
        "confidence": _confidence(),
        "uncertainty": "residual uncertainty statement",
        "calibration_version": "calib-1",
        "attack_kb_version": _KB_VERSION,
        "methodology_version": "adr-0005/1",
    }
    kwargs.update(overrides)
    return AttributionAssessment(**kwargs)  # type: ignore[arg-type]


def _next_evidence(group_id: str, affected: tuple[str, ...], **overrides: object) -> NextEvidence:
    kwargs: dict[str, object] = {
        "next_evidence_id": compute_next_evidence_id(group_id, _TECHNIQUE_STIX_ID_B, "calib-1"),
        "group_id": group_id,
        "target_technique_stix_id": _TECHNIQUE_STIX_ID_B,
        "rationale": "would separate the top two hypotheses",
        "affected_hypothesis_ids": affected,
    }
    kwargs.update(overrides)
    return NextEvidence(**kwargs)  # type: ignore[arg-type]


def _attribution_result(
    group_id: str,
    leading_hypothesis_id: str,
    candidate_hypothesis_ids: tuple[str, ...],
    **overrides: object,
) -> AttributionResult:
    kwargs: dict[str, object] = {
        "result_id": compute_attribution_result_id(group_id, "calib-1", _KB_VERSION),
        "group_id": group_id,
        "sequence_id": "sequence-1",
        "leading_hypothesis_id": leading_hypothesis_id,
        "uncertainty": "residual uncertainty statement",
        "ranking_explanation": "explanation of the ranking",
        "provenance": _provenance(source_group_id=group_id),
        "attack_kb_version": _KB_VERSION,
        "methodology_version": "adr-0005/1",
        "calibration_version": "calib-1",
        "dataset_ref": "dataset-1@abc123",
        "engine_version": "engine-0.0.0",
        "determinism_hash": "a" * 64,
        "candidate_hypothesis_ids": candidate_hypothesis_ids,
    }
    kwargs.update(overrides)
    return AttributionResult(**kwargs)  # type: ignore[arg-type]


# ===========================================================================
# 1. Candidate
# ===========================================================================


def test_valid_group_candidate() -> None:
    candidate = _group_candidate()
    assert candidate.candidate_type == CandidateType.GROUP
    assert candidate.actor_ref == _GROUP_STIX_ID
    assert candidate.campaign_ref is None


def test_valid_campaign_candidate() -> None:
    candidate = _campaign_candidate()
    assert candidate.candidate_type == CandidateType.CAMPAIGN
    assert candidate.campaign_ref == _CAMPAIGN_STIX_ID
    assert candidate.actor_ref is None


def test_candidate_requires_exactly_one_of_actor_ref_campaign_ref_both_none() -> None:
    with pytest.raises(AttributionError, match="exactly one of actor_ref/campaign_ref"):
        _group_candidate(actor_ref=None, campaign_ref=None)


def test_candidate_requires_exactly_one_of_actor_ref_campaign_ref_both_set() -> None:
    with pytest.raises(AttributionError, match="exactly one of actor_ref/campaign_ref"):
        _group_candidate(actor_ref=_GROUP_STIX_ID, campaign_ref=_CAMPAIGN_STIX_ID)


def test_candidate_fails_closed_on_malformed_actor_ref() -> None:
    with pytest.raises(AttributionError):
        _group_candidate(actor_ref="not-a-stix-id")


def test_candidate_fails_closed_on_wrong_type_prefix_for_actor_ref() -> None:
    with pytest.raises(AttributionError, match="STIX type-prefix"):
        _group_candidate(actor_ref=_CAMPAIGN_STIX_ID)


def test_candidate_fails_closed_on_wrong_type_prefix_for_campaign_ref() -> None:
    with pytest.raises(AttributionError, match="STIX type-prefix"):
        _campaign_candidate(campaign_ref=_GROUP_STIX_ID)


def test_candidate_requires_nonempty_generation_basis() -> None:
    with pytest.raises(AttributionError, match="generation_basis"):
        _group_candidate(generation_basis=())


def test_candidate_generation_basis_is_canonicalized() -> None:
    candidate = _group_candidate(
        generation_basis=(_TECHNIQUE_STIX_ID_B, _TECHNIQUE_STIX_ID_A, _TECHNIQUE_STIX_ID_A)
    )
    assert candidate.generation_basis == tuple(sorted({_TECHNIQUE_STIX_ID_A, _TECHNIQUE_STIX_ID_B}))


def test_candidate_id_is_stable_kb_version_scoped_not_case_scoped() -> None:
    """Same actor -> same candidate_id, regardless of which case considers it."""
    id_a = compute_candidate_id(_GROUP_STIX_ID)
    id_b = compute_candidate_id(_GROUP_STIX_ID)
    assert id_a == id_b
    assert id_a != compute_candidate_id(_CAMPAIGN_STIX_ID)


def test_unattributed_candidate_id_never_collides_with_a_real_candidate_id() -> None:
    """UNATTRIBUTED_CANDIDATE_ID is not SHA-256-shaped, so no real
    compute_candidate_id(...) output (always 'candidate::' + 64 hex chars)
    can ever equal it."""
    real_id = compute_candidate_id(_GROUP_STIX_ID)
    assert real_id != UNATTRIBUTED_CANDIDATE_ID
    digest_part = UNATTRIBUTED_CANDIDATE_ID.split("::", 1)[1]
    assert not (len(digest_part) == 64 and all(c in "0123456789abcdef" for c in digest_part))


# ===========================================================================
# 2. Hypothesis / Unattributed
# ===========================================================================


def test_hypothesis_preserves_candidate_identity_and_state_distinctly() -> None:
    candidate = _group_candidate()
    hyp = _hypothesis(candidate.candidate_id, evidence_assessment_ids=("ea-1",))
    assert hyp.candidate_id == candidate.candidate_id
    assert hyp.evidence_assessment_ids == ("ea-1",)


def test_explicit_unattributed_hypothesis() -> None:
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    assert hyp.candidate_id == UNATTRIBUTED_CANDIDATE_ID
    assert hyp.is_unattributed is True
    assert is_unattributed_hypothesis(hyp) is True


def test_non_unattributed_hypothesis_is_not_flagged_unattributed() -> None:
    hyp = _hypothesis(_group_candidate().candidate_id)
    assert hyp.is_unattributed is False
    assert is_unattributed_hypothesis(hyp) is False


def test_hypothesis_candidate_id_can_never_be_empty_or_none() -> None:
    with pytest.raises(AttributionError):
        _hypothesis("")
    with pytest.raises(AttributionError):
        Hypothesis(hypothesis_id="h-1", group_id="group-1", candidate_id=None)  # type: ignore[arg-type]


def test_is_unattributed_hypothesis_rejects_non_hypothesis_input() -> None:
    with pytest.raises(AttributionError):
        is_unattributed_hypothesis("not-a-hypothesis")  # type: ignore[arg-type]


def test_hypothesis_tuple_fields_are_canonicalized() -> None:
    hyp = _hypothesis(
        UNATTRIBUTED_CANDIDATE_ID,
        evidence_assessment_ids=("ea-2", "ea-1", "ea-1"),
        coverage_notes=("cov-2", "cov-1"),
        alternative_explanations=("possible deception", "possible deception"),
    )
    assert hyp.evidence_assessment_ids == ("ea-1", "ea-2")
    assert hyp.coverage_notes == ("cov-1", "cov-2")
    assert hyp.alternative_explanations == ("possible deception",)


# ===========================================================================
# 3. EvidenceAssessment
# ===========================================================================


def test_evidence_assessment_references_stable_upstream_ids() -> None:
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    ea = _evidence_assessment(hyp.hypothesis_id)
    assert ea.hypothesis_id == hyp.hypothesis_id
    assert ea.step_id == "step-1"
    assert ea.technique_stix_id == _TECHNIQUE_STIX_ID_A


def test_evidence_assessment_categorical_relevance_and_role() -> None:
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    ea = _evidence_assessment(hyp.hypothesis_id, role=EvidenceRole.CONTRADICTING)
    assert ea.role is EvidenceRole.CONTRADICTING
    assert ea.relevance is Relevance.CONSISTENT
    with pytest.raises(AttributionError):
        _evidence_assessment(hyp.hypothesis_id, role="supporting")
    with pytest.raises(AttributionError):
        _evidence_assessment(hyp.hypothesis_id, relevance="consistent")


def test_evidence_assessment_technique_stix_id_must_be_well_formed() -> None:
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    with pytest.raises(AttributionError):
        _evidence_assessment(hyp.hypothesis_id, technique_stix_id="T1059")
    with pytest.raises(AttributionError):
        _evidence_assessment(hyp.hypothesis_id, technique_stix_id="intrusion-set--not-a-technique")


def test_evidence_assessment_diagnosticity_ref_is_the_accepted_bare_str_shape() -> None:
    """Faithful to ADR-0005's still-accepted (not the discussed-but-not-
    adopted Diagnosticity value-object refinement) EvidenceAssessment shape."""
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    ea = _evidence_assessment(
        hyp.hypothesis_id, diagnosticity_ref="g=0.12, 22/180 groups, kb=v19.0"
    )
    assert isinstance(ea.diagnosticity_ref, str)


def test_evidence_assessment_diagnosticity_ref_rejects_a_bare_number() -> None:
    """diagnosticity_ref must be a str reference/explanation, never a bare
    float pretending to be one (ADR-0005 §D5's own explicit comment)."""
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    with pytest.raises(AttributionError):
        _evidence_assessment(hyp.hypothesis_id, diagnosticity_ref=0.12)
    with pytest.raises(AttributionError):
        _evidence_assessment(hyp.hypothesis_id, diagnosticity_ref=True)


def test_evidence_assessment_coverage_id_optional() -> None:
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    ea = _evidence_assessment(hyp.hypothesis_id)
    assert ea.coverage_id is None
    ea_with_coverage = _evidence_assessment(hyp.hypothesis_id, coverage_id="coverage-1")
    assert ea_with_coverage.coverage_id == "coverage-1"


# ===========================================================================
# 4. Likelihood / Confidence separation
# ===========================================================================


def test_likelihood_is_categorical_never_a_raw_number() -> None:
    likelihood = _likelihood()
    assert isinstance(likelihood.wep_band, str)
    assert likelihood.separation_from_null is SeparationBand.CLEAR
    with pytest.raises(AttributionError):
        _likelihood(separation_from_null=0.9)


def test_confidence_is_categorical_band_plus_reasons() -> None:
    confidence = _confidence()
    assert confidence.band is ConfidenceBand.MODERATE
    assert ConfidenceReason.CORROBORATION in confidence.reasons
    with pytest.raises(AttributionError):
        _confidence(band="moderate")
    with pytest.raises(AttributionError):
        _confidence(reasons=("corroboration",))


def test_confidence_reasons_are_canonicalized() -> None:
    confidence = _confidence(
        reasons=(
            ConfidenceReason.CONTRADICTION_LOAD,
            ConfidenceReason.CORROBORATION,
            ConfidenceReason.CORROBORATION,
        )
    )
    assert confidence.reasons == (
        ConfidenceReason.CONTRADICTION_LOAD,
        ConfidenceReason.CORROBORATION,
    )


def test_attribution_assessment_keeps_likelihood_and_confidence_as_separate_typed_fields() -> None:
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    assessment = _attribution_assessment(hyp.hypothesis_id)
    assert isinstance(assessment.likelihood, Likelihood)
    assert isinstance(assessment.confidence, Confidence)


def test_attribution_assessment_field_names_never_use_a_merged_score_name() -> None:
    field_names = {f.name for f in dataclasses.fields(AttributionAssessment)}
    forbidden = {"score", "percentage", "probability", "combined_score", "confidence_score"}
    assert field_names.isdisjoint(forbidden)


# ===========================================================================
# 5. CoverageProfile
# ===========================================================================


@pytest.mark.parametrize(
    "state",
    [
        CoverageState.OBSERVED_PRESENT,
        CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE,
        CoverageState.NOT_OBSERVABLE,
        CoverageState.UNKNOWN,
    ],
)
def test_coverage_profile_four_states(state: CoverageState) -> None:
    coverage = CoverageProfile(
        coverage_id=compute_coverage_profile_id("group-1", _TECHNIQUE_STIX_ID_A),
        group_id="group-1",
        technique_stix_id=_TECHNIQUE_STIX_ID_A,
        attack_kb_version=_KB_VERSION,
        state=state,
        provenance=_provenance(),
    )
    assert coverage.state is state


def test_coverage_profile_distinguishes_adequate_absence_from_insufficient_coverage() -> None:
    absent = CoverageProfile(
        coverage_id=compute_coverage_profile_id("group-1", _TECHNIQUE_STIX_ID_A),
        group_id="group-1",
        technique_stix_id=_TECHNIQUE_STIX_ID_A,
        attack_kb_version=_KB_VERSION,
        state=CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE,
        provenance=_provenance(),
    )
    unknown_coverage = CoverageProfile(
        coverage_id=compute_coverage_profile_id("group-1", _TECHNIQUE_STIX_ID_B),
        group_id="group-1",
        technique_stix_id=_TECHNIQUE_STIX_ID_B,
        attack_kb_version=_KB_VERSION,
        state=CoverageState.NOT_OBSERVABLE,
        provenance=_provenance(),
    )
    assert absent.state != unknown_coverage.state
    assert absent.state is CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE
    assert unknown_coverage.state is CoverageState.NOT_OBSERVABLE


def test_coverage_profile_rejects_invalid_state() -> None:
    with pytest.raises(AttributionError):
        CoverageProfile(
            coverage_id=compute_coverage_profile_id("group-1", _TECHNIQUE_STIX_ID_A),
            group_id="group-1",
            technique_stix_id=_TECHNIQUE_STIX_ID_A,
            attack_kb_version=_KB_VERSION,
            state="unknown",  # type: ignore[arg-type]
            provenance=_provenance(),
        )


def test_coverage_profile_with_observation_interval() -> None:
    interval = TimeSpan(
        start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC)
    )
    coverage = CoverageProfile(
        coverage_id=compute_coverage_profile_id("group-1", _TECHNIQUE_STIX_ID_A),
        group_id="group-1",
        technique_stix_id=_TECHNIQUE_STIX_ID_A,
        attack_kb_version=_KB_VERSION,
        state=CoverageState.OBSERVED_PRESENT,
        provenance=_provenance(),
        observation_interval=interval,
    )
    assert coverage.observation_interval == interval


def test_coverage_profile_data_source_tuples_are_canonicalized() -> None:
    coverage = CoverageProfile(
        coverage_id=compute_coverage_profile_id("group-1", _TECHNIQUE_STIX_ID_A),
        group_id="group-1",
        technique_stix_id=_TECHNIQUE_STIX_ID_A,
        attack_kb_version=_KB_VERSION,
        state=CoverageState.NOT_OBSERVABLE,
        provenance=_provenance(),
        data_sources_required=("Process Creation", "Command Execution", "Process Creation"),
    )
    assert coverage.data_sources_required == ("Command Execution", "Process Creation")


# ===========================================================================
# 6. AttributionAssessment + AttributionResult (supporting/contradicting)
# ===========================================================================


def test_attribution_assessment_with_supporting_and_contradicting_evidence_via_result() -> None:
    candidate = _group_candidate()
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    leading = _hypothesis(candidate.candidate_id)
    ea_support = _evidence_assessment(leading.hypothesis_id, role=EvidenceRole.SUPPORTING)
    ea_contradict = _evidence_assessment(
        leading.hypothesis_id,
        step_id="step-2",
        role=EvidenceRole.CONTRADICTING,
        assessment_id=compute_evidence_assessment_id(
            leading.hypothesis_id, "step-2", _TECHNIQUE_STIX_ID_A
        ),
    )
    result = _attribution_result(
        "group-1",
        leading.hypothesis_id,
        (unattributed.hypothesis_id, leading.hypothesis_id),
        supporting_evidence_ids=(ea_support.assessment_id,),
        contradicting_evidence_ids=(ea_contradict.assessment_id,),
        discriminating_evidence_ids=(ea_support.assessment_id,),
    )
    assert result.supporting_evidence_ids == (ea_support.assessment_id,)
    assert result.contradicting_evidence_ids == (ea_contradict.assessment_id,)
    assert result.discriminating_evidence_ids == (ea_support.assessment_id,)


def test_attribution_result_supporting_and_contradicting_must_be_disjoint() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    with pytest.raises(AttributionError, match="both supporting_evidence_ids and contradicting"):
        _attribution_result(
            "group-1",
            unattributed.hypothesis_id,
            (unattributed.hypothesis_id,),
            supporting_evidence_ids=("ea-shared",),
            contradicting_evidence_ids=("ea-shared",),
        )


def test_attribution_result_discriminating_evidence_must_be_a_subset_of_evidence() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    with pytest.raises(AttributionError, match="discriminating_evidence_ids"):
        _attribution_result(
            "group-1",
            unattributed.hypothesis_id,
            (unattributed.hypothesis_id,),
            discriminating_evidence_ids=("ea-not-in-either-set",),
        )


# ===========================================================================
# 7. AttributionResult tied to exactly one attribution unit
# ===========================================================================


def test_attribution_result_id_is_a_pure_function_of_group_calibration_kb_version() -> None:
    id_a = compute_attribution_result_id("group-1", "calib-1", _KB_VERSION)
    id_b = compute_attribution_result_id("group-1", "calib-1", _KB_VERSION)
    assert id_a == id_b
    assert id_a != compute_attribution_result_id("group-2", "calib-1", _KB_VERSION)
    assert id_a != compute_attribution_result_id("group-1", "calib-2", _KB_VERSION)


def test_attribution_result_represents_insufficient_evidence_without_forcing_a_winner() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    result = _attribution_result(
        "group-1", unattributed.hypothesis_id, (unattributed.hypothesis_id,)
    )
    assert result.leading_hypothesis_id == unattributed.hypothesis_id


def test_attribution_result_leading_hypothesis_must_be_in_candidate_hypothesis_ids() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    with pytest.raises(AttributionError, match="leading_hypothesis_id"):
        _attribution_result("group-1", "not-a-member-hypothesis", (unattributed.hypothesis_id,))


def test_attribution_result_candidate_hypothesis_ids_must_be_non_empty() -> None:
    with pytest.raises(AttributionError, match="candidate_hypothesis_ids"):
        _attribution_result("group-1", "h-1", ())


def test_attribution_result_attack_techniques_involved_canonicalized_and_validated() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    result = _attribution_result(
        "group-1",
        unattributed.hypothesis_id,
        (unattributed.hypothesis_id,),
        attack_techniques_involved=(_TECHNIQUE_STIX_ID_B, _TECHNIQUE_STIX_ID_A),
    )
    assert result.attack_techniques_involved == (_TECHNIQUE_STIX_ID_A, _TECHNIQUE_STIX_ID_B)
    with pytest.raises(AttributionError):
        _attribution_result(
            "group-1",
            unattributed.hypothesis_id,
            (unattributed.hypothesis_id,),
            attack_techniques_involved=("T1059",),
        )


def test_attribution_result_ti_kb_version_optional() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    result = _attribution_result(
        "group-1", unattributed.hypothesis_id, (unattributed.hypothesis_id,)
    )
    assert result.ti_kb_version is None


# ===========================================================================
# 8. NextEvidence
# ===========================================================================


def test_next_evidence_requires_non_empty_affected_hypothesis_ids() -> None:
    with pytest.raises(AttributionError, match="affected_hypothesis_ids"):
        _next_evidence("group-1", ())


def test_next_evidence_valid_representation() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    ne = _next_evidence("group-1", (unattributed.hypothesis_id,))
    assert ne.affected_hypothesis_ids == (unattributed.hypothesis_id,)
    assert ne.target_technique_stix_id == _TECHNIQUE_STIX_ID_B


# ===========================================================================
# 9. Empty/invalid collections fail closed where required
# ===========================================================================


def test_evidence_assessment_ids_reject_empty_string_members() -> None:
    hyp = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    with pytest.raises(AttributionError):
        _hypothesis(UNATTRIBUTED_CANDIDATE_ID, group_id="g2", evidence_assessment_ids=("",))
    assert hyp  # keep flake happy; primary assertion is the raise above


def test_attribution_provenance_requires_non_empty_evidence_and_observation_ids() -> None:
    with pytest.raises(AttributionError, match="source_evidence_ids"):
        _provenance(source_evidence_ids=())
    with pytest.raises(AttributionError, match="source_observation_ids"):
        _provenance(source_observation_ids=())


# ===========================================================================
# 10. Deterministic serialization / identity
# ===========================================================================


def test_id_functions_are_deterministic_and_input_sensitive() -> None:
    assert compute_hypothesis_id("g1", "c1") == compute_hypothesis_id("g1", "c1")
    assert compute_hypothesis_id("g1", "c1") != compute_hypothesis_id("g1", "c2")
    assert compute_evidence_assessment_id("h1", "s1", _TECHNIQUE_STIX_ID_A) == (
        compute_evidence_assessment_id("h1", "s1", _TECHNIQUE_STIX_ID_A)
    )
    assert compute_next_evidence_id("g1", _TECHNIQUE_STIX_ID_A, "c1") != compute_next_evidence_id(
        "g1", _TECHNIQUE_STIX_ID_B, "c1"
    )


def test_id_functions_never_produce_a_naive_delimiter_join() -> None:
    """Real ids in this project already contain '::' themselves -- a naive
    join would let two different inputs collide. sha256-hashing each
    component first (as every id function here does) avoids that."""
    collision_a = compute_hypothesis_id("g1::x", "c1")
    collision_b = compute_hypothesis_id("g1", "x::c1")
    assert collision_a != collision_b


def test_attribution_result_serializes_deterministically_via_domain_to_canonical_json() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    result = _attribution_result(
        "group-1", unattributed.hypothesis_id, (unattributed.hypothesis_id,)
    )
    json_a = to_canonical_json(result)
    json_b = to_canonical_json(result)
    assert json_a == json_b

    result_again = _attribution_result(
        "group-1", unattributed.hypothesis_id, (unattributed.hypothesis_id,)
    )
    assert to_canonical_json(result) == to_canonical_json(result_again)


def test_candidate_serializes_deterministically() -> None:
    candidate_a = _group_candidate()
    candidate_b = _group_candidate()
    assert to_canonical_json(candidate_a) == to_canonical_json(candidate_b)


# ===========================================================================
# 11. Immutability
# ===========================================================================


def test_all_contracts_are_frozen_dataclasses() -> None:
    for cls in (
        AttributionProvenance,
        CoverageProfile,
        Candidate,
        Hypothesis,
        EvidenceAssessment,
        Likelihood,
        Confidence,
        AttributionAssessment,
        NextEvidence,
        AttributionResult,
    ):
        params = dataclasses.fields(cls)
        assert params, f"{cls.__name__} has no fields"
        assert cls.__dataclass_params__.frozen is True, f"{cls.__name__} not frozen"  # type: ignore[union-attr]


def test_candidate_rejects_field_mutation() -> None:
    candidate = _group_candidate()
    with pytest.raises(dataclasses.FrozenInstanceError):
        candidate.actor_ref = "intrusion-set--other"  # type: ignore[misc]


def test_attribution_result_rejects_field_mutation() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    result = _attribution_result(
        "group-1", unattributed.hypothesis_id, (unattributed.hypothesis_id,)
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.leading_hypothesis_id = "other"  # type: ignore[misc]


# ===========================================================================
# 12. Provenance structure / required version fields
# ===========================================================================


def test_attribution_provenance_structure() -> None:
    prov = _provenance()
    assert prov.method
    assert prov.method_version
    assert prov.source_group_id
    assert prov.source_sequence_id
    assert prov.source_evidence_ids == ("ev-1", "ev-2")
    assert prov.source_observation_ids == ("obs-1", "obs-2")
    assert prov.method_content_hash is None


def test_attribution_result_carries_every_required_version_stamp() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    result = _attribution_result(
        "group-1", unattributed.hypothesis_id, (unattributed.hypothesis_id,)
    )
    assert result.attack_kb_version
    assert result.methodology_version
    assert result.calibration_version
    assert result.dataset_ref
    assert result.engine_version
    assert result.determinism_hash
    assert result.ti_kb_version is None  # explicitly permitted per ADR-0005 §D5


def test_attribution_result_rejects_missing_version_fields() -> None:
    unattributed = _hypothesis(UNATTRIBUTED_CANDIDATE_ID)
    with pytest.raises(AttributionError):
        _attribution_result(
            "group-1",
            unattributed.hypothesis_id,
            (unattributed.hypothesis_id,),
            calibration_version="",
        )


# ===========================================================================
# 13. No numeric analyst-facing attribution score anywhere
# ===========================================================================


def test_no_contract_field_is_a_raw_numeric_score() -> None:
    """None of the eight ADR-0005 contracts expose a bare int/float field —
    every quantity is categorical (an Enum) or a plain reference string."""
    contracts = (
        AttributionProvenance,
        CoverageProfile,
        Candidate,
        Hypothesis,
        EvidenceAssessment,
        Likelihood,
        Confidence,
        AttributionAssessment,
        NextEvidence,
        AttributionResult,
    )
    for cls in contracts:
        for f in dataclasses.fields(cls):
            annotation = str(f.type)
            assert "float" not in annotation, f"{cls.__name__}.{f.name} is a float: {annotation}"
            assert annotation not in ("int",) and not annotation.startswith(
                "int "
            ), f"{cls.__name__}.{f.name} is a bare int: {annotation}"


def test_source_contains_no_percentage_or_probability_vocabulary() -> None:
    source_text = (ATTRIBUTION_DIR / "contracts.py").read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    forbidden = {"percent", "percentage", "probability", "score", "combined_score"}
    identifiers = (
        {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
        | {node.attr.lower() for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        | {
            node.arg.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.arg) and node.arg is not None
        }
    )
    field_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    field_names.add(stmt.target.id.lower())
    for identifier in identifiers | field_names:
        for term in forbidden:
            assert term not in identifier, f"forbidden vocabulary {term!r} found in {identifier!r}"


# ===========================================================================
# 14. No mutation of upstream Phase 0-2 objects / no algorithm creep
# ===========================================================================


def test_contracts_module_imports_no_phase_0_2_or_correlation_or_attack_knowledge_modules() -> None:
    """This module references Phase 0-2/correlation objects only by bare str
    id -- it must never import a Phase 0-2 domain entity type, a
    correlation/sequence contract, or attack_knowledge (no ATT&CK traversal,
    per the module's own scope boundary). The one deliberate exception is
    ``domain.entities.TimeSpan``, a plain, identity-free value type."""
    source_text = (ATTRIBUTION_DIR / "contracts.py").read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)

    forbidden_modules = {
        "attribution_platform.domain.evidence",
        "attribution_platform.domain.observation",
        "attribution_platform.correlation",
        "attribution_platform.correlation.contracts",
        "attribution_platform.correlation.sequence",
        "attribution_platform.attack_knowledge",
        "attribution_platform.attack_knowledge.loader",
        "attribution_platform.attack_knowledge.traversal",
        "attribution_platform.dataplane",
    }
    assert imported_modules.isdisjoint(forbidden_modules)
    assert "attribution_platform.domain.entities" in imported_modules


def test_contracts_module_never_references_algorithm_vocabulary() -> None:
    """Structural guard mirroring the Gate 3.1 traversal guard: no
    candidate-generation/ACH/likelihood-calculation/calibration identifier
    exists in this module -- only representation types."""
    source_text = (ATTRIBUTION_DIR / "contracts.py").read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    forbidden_substrings = (
        "generate_candidate",
        "compute_diagnosticity",
        "compute_likelihood",
        "compute_confidence",
        "compute_support",
        "abstain",
        "run_calibration",
        "fit_calibration",
        "elasticsearch",
        "elastic_client",
    )
    identifiers = (
        {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
        | {node.attr.lower() for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        | {
            node.name.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.ClassDef)
        }
    )
    for identifier in identifiers:
        for forbidden in forbidden_substrings:
            assert forbidden not in identifier, (
                f"contracts.py binds identifier {identifier!r} referencing "
                f"out-of-scope algorithm vocabulary {forbidden!r}"
            )


def test_contracts_module_imports_no_networking_or_database_libraries() -> None:
    for name in ("socket", "urllib", "http", "requests", "sqlite3", "psycopg2"):
        assert not hasattr(contracts_module, name), f"contracts.py must not import {name!r}"
