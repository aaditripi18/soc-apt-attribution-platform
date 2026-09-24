"""Corpus → decision-quantity harness tests (B1-M fitting input).

Runs the real v1 corpus through the real pipeline and Gate 3.3–3.5 attribution
stages. Tier-1 machinery only (ADR-0006 §D11) — no fitting, no
``calibration_version``, no decision.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attribution.ach_matrix import build_ach_matrix
from attribution_platform.attribution.candidate_generation import generate_candidates
from attribution_platform.attribution.comparative_analysis import compute_comparative_evidence
from attribution_platform.attribution.decision_quantities import compute_decision_quantities
from attribution_platform.calibration.contracts import CaseRole, ExpectedOutcome, LabelSemantics
from attribution_platform.calibration.corpus_builder import (
    CorpusBuildResult,
    CorpusScenarioAnnotation,
    build_corpus,
    load_corpus_entries_from_dir,
)
from attribution_platform.calibration.decision_inputs import (
    CorpusDecisionInputs,
    build_case_decision_input,
    build_corpus_decision_inputs,
    compute_case_decision_quantities,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.replay import (
    DetectionReplayFixture,
    replay_fixture_through_behavioral_sequences,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_PACK = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
CALIBRATION_PACK = (
    REPO_ROOT / "data" / "calibration" / "rules" / "calibration_evidence_type_rules.json"
)
V1_ROOT = REPO_ROOT / "data" / "calibration" / "corpus" / "v1"

EVALUABLE_ROLES = (
    CaseRole.CALIBRATION,
    CaseRole.HELD_OUT_VALIDATION,
    CaseRole.BLIND_ACTOR_HOLDOUT,
)

Entries = tuple[tuple[CorpusScenarioAnnotation, DetectionReplayFixture], ...]


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    core = load_rule_pack(CORE_PACK, knowledge=knowledge)
    calibration = load_rule_pack(CALIBRATION_PACK, knowledge=knowledge)
    return DetectionEngine(rules=core.rules + calibration.rules)


@pytest.fixture(scope="module")
def entries() -> Entries:
    return load_corpus_entries_from_dir(V1_ROOT)


@pytest.fixture(scope="module")
def corpus(
    knowledge: AttackKnowledge, engine: DetectionEngine, entries: Entries
) -> CorpusBuildResult:
    return build_corpus(
        entries, client_factory=FakeElasticClient, engine=engine, knowledge=knowledge
    )


@pytest.fixture(scope="module")
def inputs(
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> CorpusDecisionInputs:
    return build_corpus_decision_inputs(
        corpus,
        entries,
        roles=EVALUABLE_ROLES,
        client_factory=FakeElasticClient,
        engine=engine,
        knowledge=knowledge,
    )


def _fixture_for(entries: Entries, family: str) -> DetectionReplayFixture:
    return next(f for a, f in entries if a.scenario_family_id == family)


# ===========================================================================
# Population selection
# ===========================================================================


def test_builds_one_input_per_case_in_requested_roles(
    inputs: CorpusDecisionInputs, corpus: CorpusBuildResult
) -> None:
    expected = sorted(c.case_id for c in corpus.cases if c.case_role in EVALUABLE_ROLES)
    assert [i.case_id for i in inputs.cases] == expected
    assert len(inputs.cases) == 16
    assert inputs.calibration_corpus_version == corpus.calibration_corpus_version
    assert set(inputs.roles) == set(EVALUABLE_ROLES)


def test_role_filter_selects_only_requested_role(
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    result = build_corpus_decision_inputs(
        corpus,
        entries,
        roles=[CaseRole.CALIBRATION],
        client_factory=FakeElasticClient,
        engine=engine,
        knowledge=knowledge,
    )
    assert len(result.cases) == 7
    assert {i.case_role for i in result.cases} == {CaseRole.CALIBRATION}


@pytest.mark.parametrize(
    "roles", [[CaseRole.EXCLUDED], [CaseRole.CALIBRATION, CaseRole.EXCLUDED], []]
)
def test_rejects_excluded_or_empty_roles(
    roles: list[CaseRole],
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    with pytest.raises(CalibrationError):
        build_corpus_decision_inputs(
            corpus,
            entries,
            roles=roles,
            client_factory=FakeElasticClient,
            engine=engine,
            knowledge=knowledge,
        )


def test_missing_fixture_fails_closed(
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    without_one = tuple(e for e in entries if e[0].scenario_family_id != "v1-cal-alpha-ingress")
    with pytest.raises(CalibrationError, match="no fixture supplied"):
        build_corpus_decision_inputs(
            corpus,
            without_one,
            roles=[CaseRole.CALIBRATION],
            client_factory=FakeElasticClient,
            engine=engine,
            knowledge=knowledge,
        )


def test_duplicate_family_entry_fails_closed(
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    with pytest.raises(CalibrationError, match="duplicate entry"):
        build_corpus_decision_inputs(
            corpus,
            entries + entries[:1],
            roles=[CaseRole.CALIBRATION],
            client_factory=FakeElasticClient,
            engine=engine,
            knowledge=knowledge,
        )


# ===========================================================================
# Fail-closed reproduction checks
# ===========================================================================


def test_drifted_sequence_id_fails_closed(
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    case = next(c for c in corpus.cases if c.scenario_family_id == "v1-cal-alpha-ingress")
    drifted = dataclasses.replace(case, sequence_id="sequence::not-what-replay-produces")
    with pytest.raises(CalibrationError, match="no longer reproduces"):
        build_case_decision_input(
            drifted,
            _fixture_for(entries, case.scenario_family_id),
            client=FakeElasticClient(),
            engine=engine,
            knowledge=knowledge,
        )


def test_fixture_from_another_family_fails_closed(
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    case = next(c for c in corpus.cases if c.scenario_family_id == "v1-cal-alpha-ingress")
    with pytest.raises(CalibrationError, match="no longer reproduces"):
        build_case_decision_input(
            case,
            _fixture_for(entries, "v1-hov-delta-correlated"),
            client=FakeElasticClient(),
            engine=engine,
            knowledge=knowledge,
        )


def test_kb_version_mismatch_fails_closed(
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    case = next(c for c in corpus.cases if c.scenario_family_id == "v1-cal-alpha-ingress")
    other = dataclasses.replace(case, attack_kb_version="enterprise-attack-0.0")
    with pytest.raises(CalibrationError, match="attack_kb_version"):
        build_case_decision_input(
            other,
            _fixture_for(entries, case.scenario_family_id),
            client=FakeElasticClient(),
            engine=engine,
            knowledge=knowledge,
        )


# ===========================================================================
# Labels and attribution outputs
# ===========================================================================


def test_authored_labels_copied_verbatim(
    inputs: CorpusDecisionInputs, corpus: CorpusBuildResult
) -> None:
    case_by_id = {c.case_id: c for c in corpus.cases}
    for item in inputs.cases:
        case = case_by_id[item.case_id]
        assert item.scenario_family_id == case.scenario_family_id
        assert item.case_role is case.case_role
        assert item.label_semantics is case.ground_truth.label_semantics
        assert item.expected_outcome is case.expected_output_shape.outcome
        assert item.actor_label == case.ground_truth.actor_label
        assert item.group_id == case.correlation_group_id
        assert item.sequence_id == case.sequence_id


def test_outputs_share_case_identity(inputs: CorpusDecisionInputs) -> None:
    for item in inputs.cases:
        assert item.comparative.group_id == item.group_id
        assert item.unattributed_baseline.group_id == item.group_id
        assert item.comparative.attack_kb_version == inputs.attack_kb_version
        assert item.unattributed_baseline.attack_kb_version == inputs.attack_kb_version


def test_negative_benign_cases_have_no_candidates_and_zero_baseline(
    inputs: CorpusDecisionInputs,
) -> None:
    negatives = [
        i for i in inputs.cases if i.label_semantics is LabelSemantics.UNATTRIBUTABLE_BY_DESIGN
    ]
    assert negatives
    for item in negatives:
        assert item.expected_outcome is ExpectedOutcome.INSUFFICIENT_EVIDENCE
        assert item.candidates == ()
        assert item.unattributed_baseline.decision_support == 0.0
        assert item.unattributed_baseline.observed_feature_count == 0


def test_attributable_cases_produce_real_candidates_and_positive_baseline(
    inputs: CorpusDecisionInputs,
) -> None:
    attributable = [i for i in inputs.cases if i.label_semantics is LabelSemantics.ATTRIBUTABLE]
    assert attributable
    for item in attributable:
        assert item.candidates
        assert item.unattributed_baseline.observed_feature_count >= 1
        assert item.unattributed_baseline.decision_support > 0.0


def test_matches_direct_stage_composition(
    inputs: CorpusDecisionInputs,
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    """The harness adds nothing of its own: its outputs equal the stages run
    directly on the same replay."""
    item = next(i for i in inputs.cases if i.scenario_family_id == "v1-cal-alpha-ingress")
    replay = replay_fixture_through_behavioral_sequences(
        _fixture_for(entries, item.scenario_family_id),
        client=FakeElasticClient(),
        engine=engine,
        knowledge=knowledge,
    )
    sequence = replay.sequences[0]
    group = next(
        g
        for g in replay.correlation_result.contextual_result.groups
        if g.group_id == sequence.group_id
    )
    candidates = generate_candidates(group, sequence, knowledge)
    matrix = build_ach_matrix(group, sequence, candidates, knowledge)
    direct = compute_comparative_evidence(matrix, knowledge, candidates, min_profile_floor=1)
    assert item.comparative == direct
    assert item.candidates == candidates.candidates


# ===========================================================================
# Floor independence and quantity computation
# ===========================================================================


def test_decision_inputs_are_floor_independent(
    inputs: CorpusDecisionInputs,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    """The fields the decision layer reads do not depend on the floor used to
    run comparative analysis — so one replay serves every grid floor."""
    item = next(i for i in inputs.cases if i.scenario_family_id == "v1-hov-unresolved-actor")
    replay = replay_fixture_through_behavioral_sequences(
        _fixture_for(entries, item.scenario_family_id),
        client=FakeElasticClient(),
        engine=engine,
        knowledge=knowledge,
    )
    sequence = replay.sequences[0]
    group = next(
        g
        for g in replay.correlation_result.contextual_result.groups
        if g.group_id == sequence.group_id
    )
    candidates = generate_candidates(group, sequence, knowledge)
    matrix = build_ach_matrix(group, sequence, candidates, knowledge)
    high_floor = compute_comparative_evidence(matrix, knowledge, candidates, min_profile_floor=500)
    for low, high in zip(
        item.comparative.hypothesis_summaries, high_floor.hypothesis_summaries, strict=True
    ):
        assert low.hypothesis_id == high.hypothesis_id
        assert low.contributions == high.contributions
        assert low.profile_breadth == high.profile_breadth
    for floor in (1, 25, 500):
        assert compute_decision_quantities(
            high_floor, min_profile_floor=floor, unattributed_baseline=item.unattributed_baseline
        ) == compute_case_decision_quantities(item, min_profile_floor=floor)


def test_floor_only_changes_normalized_support(inputs: CorpusDecisionInputs) -> None:
    item = next(i for i in inputs.cases if i.scenario_family_id == "v1-cal-alpha-ingress")
    low = compute_case_decision_quantities(item, min_profile_floor=1)
    high = compute_case_decision_quantities(item, min_profile_floor=10_000)
    for a, b in zip(low.hypotheses, high.hypotheses, strict=True):
        assert a.decision_support == b.decision_support
        assert a.separation_from_null == b.separation_from_null
        assert a.contributor_separation == b.contributor_separation
        assert a.concentration == b.concentration
    assert any(
        a.decision_support_norm != b.decision_support_norm
        for a, b in zip(low.hypotheses, high.hypotheses, strict=True)
        if a.decision_support_norm is not None
    )


def test_invalid_floor_fails_closed(inputs: CorpusDecisionInputs) -> None:
    from attribution_platform.attribution.errors import AttributionError

    with pytest.raises(AttributionError):
        compute_case_decision_quantities(inputs.cases[0], min_profile_floor=0)


# ===========================================================================
# Determinism
# ===========================================================================


def test_rebuild_is_identical(
    inputs: CorpusDecisionInputs,
    corpus: CorpusBuildResult,
    entries: Entries,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> None:
    again = build_corpus_decision_inputs(
        corpus,
        tuple(reversed(entries)),
        roles=tuple(reversed(EVALUABLE_ROLES)),
        client_factory=FakeElasticClient,
        engine=engine,
        knowledge=knowledge,
    )
    assert again == inputs
