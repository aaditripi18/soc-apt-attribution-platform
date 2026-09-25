"""Corpus v2 T5 (doc 15 DC-4 / DC-5): multi-unit families and the
fitting-readiness gate.

Multi-unit families are exercised on real v1 content: two v1 family fixtures
merged into one fixture genuinely replay to two attribution units. The
readiness gate is run on the frozen v1 corpus, where it must rediscover every
Stage-5 finding (doc 14 F5-1..F5-4) on its own, and on constructed inputs for
the checks v1 cannot reach.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.calibration.category_validation import (
    CaseCategoryRecord,
    CaseCategoryTag,
    validate_category_completeness,
)
from attribution_platform.calibration.contracts import (
    ActorLabelSource,
    CalibrationCase,
    CaseRole,
    GroundTruth,
    LabelConfidence,
    LabelSemantics,
)
from attribution_platform.calibration.corpus_builder import (
    CorpusBuildResult,
    CorpusScenarioAnnotation,
    UnitAnnotation,
    build_calibration_case,
    build_calibration_cases,
    build_corpus,
    load_corpus_entries_from_dir,
    load_scenario_annotation,
)
from attribution_platform.calibration.decision_inputs import (
    CorpusDecisionInputs,
    build_corpus_decision_inputs,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.calibration.provenance_validation import validate_provenance
from attribution_platform.calibration.readiness import (
    FittingReadinessReport,
    ReadinessThresholds,
    ReadinessViolationType,
    require_fitting_ready,
    validate_fitting_readiness,
)
from attribution_platform.calibration.split_validation import validate_split
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain import EvidenceType, ProcessRef
from attribution_platform.replay import (
    DetectionReplayFixture,
    replay_fixture_through_behavioral_sequences,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"  # v1 corpus is frozen against it
CORE_PACK = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
CALIBRATION_PACK = (
    REPO_ROOT / "data" / "calibration" / "rules" / "calibration_evidence_type_rules.json"
)
V1_ROOT = REPO_ROOT / "data" / "calibration" / "corpus" / "v1"
EVALUABLE = (CaseRole.CALIBRATION, CaseRole.HELD_OUT_VALIDATION, CaseRole.BLIND_ACTOR_HOLDOUT)
ALPHA = "v1-cal-alpha-ingress"
BRAVO = "v1-cal-bravo-lsass-repeat"

Entries = tuple[tuple[CorpusScenarioAnnotation, DetectionReplayFixture], ...]
V1 = tuple[CorpusBuildResult, CorpusDecisionInputs, tuple[CaseCategoryRecord, ...]]


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


@pytest.fixture(scope="module")
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    core = load_rule_pack(CORE_PACK, knowledge=knowledge)
    calibration = load_rule_pack(CALIBRATION_PACK, knowledge=knowledge)
    return DetectionEngine(rules=core.rules + calibration.rules)


@pytest.fixture(scope="module")
def entries() -> Entries:
    return load_corpus_entries_from_dir(V1_ROOT)


def _entry(
    entries: Entries, family: str
) -> tuple[CorpusScenarioAnnotation, DetectionReplayFixture]:
    return next(e for e in entries if e[0].scenario_family_id == family)


def _merged(entries: Entries) -> tuple[DetectionReplayFixture, str, str]:
    """ALPHA + BRAVO scenarios in one fixture, and one anchor scenario of each."""
    _, alpha = _entry(entries, ALPHA)
    _, bravo = _entry(entries, BRAVO)
    ids = [s.scenario_id for s in (*alpha.scenarios, *bravo.scenarios)]
    assert len(ids) == len(set(ids))
    merged = dataclasses.replace(
        alpha, fixture_id="merged-alpha-bravo", scenarios=alpha.scenarios + bravo.scenarios
    )
    return merged, alpha.scenarios[0].scenario_id, bravo.scenarios[0].scenario_id


def _multi(
    entries: Entries, units: tuple[UnitAnnotation, ...], family: str = "merged"
) -> CorpusScenarioAnnotation:
    annotation, _ = _entry(entries, ALPHA)
    return dataclasses.replace(
        annotation, scenario_family_id=family, expected_output_shape=None, units=units
    )


def _units(entries: Entries, alpha_anchor: str, bravo_anchor: str) -> tuple[UnitAnnotation, ...]:
    alpha_shape = _entry(entries, ALPHA)[0].expected_output_shape
    bravo_shape = _entry(entries, BRAVO)[0].expected_output_shape
    assert alpha_shape is not None and bravo_shape is not None
    return (
        UnitAnnotation("u-alpha", (alpha_anchor,), alpha_shape),
        UnitAnnotation("u-bravo", (bravo_anchor,), bravo_shape, ("bravo host only",)),
    )


def _build(
    annotation: CorpusScenarioAnnotation,
    fixture: DetectionReplayFixture,
    knowledge: AttackKnowledge,
    engine: DetectionEngine,
) -> tuple[CalibrationCase, ...]:
    return build_calibration_cases(
        annotation, fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )


# ===========================================================================
# Multi-unit families
# ===========================================================================


def test_multi_unit_family_builds_one_case_per_unit(
    entries: Entries, knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    fixture, a, b = _merged(entries)
    cases = _build(_multi(entries, _units(entries, a, b)), fixture, knowledge, engine)
    assert len(cases) == 2
    assert {c.scenario_family_id for c in cases} == {"merged"}
    # each unit is the very same attribution unit its family replays to alone
    alone = {
        build_calibration_case(
            annotation, own, client=FakeElasticClient(), engine=engine, knowledge=knowledge
        ).correlation_group_id
        for annotation, own in (_entry(entries, ALPHA), _entry(entries, BRAVO))
    }
    assert {c.correlation_group_id for c in cases} == alone
    bravo_case = next(c for c in cases if "bravo host only" in c.coverage_assumptions)
    assert bravo_case.expected_output_shape == _entry(entries, BRAVO)[0].expected_output_shape


def test_multi_unit_build_is_deterministic(
    entries: Entries, knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    fixture, a, b = _merged(entries)
    units = _units(entries, a, b)
    first = _build(_multi(entries, units), fixture, knowledge, engine)
    second = _build(_multi(entries, tuple(reversed(units))), fixture, knowledge, engine)
    assert first == second


@pytest.mark.parametrize(
    "case",
    ["single_unit", "undeclared", "spanning", "double_claim", "unknown_anchor"],
)
def test_multi_unit_fails_closed(
    case: str, entries: Entries, knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    fixture, a, b = _merged(entries)
    alpha_unit, bravo_unit = _units(entries, a, b)
    annotation: CorpusScenarioAnnotation
    if case == "single_unit":
        annotation, match = _entry(entries, ALPHA)[0], "requires exactly one"
    elif case == "undeclared":
        annotation, match = _multi(entries, (alpha_unit,)), "no authored unit declares"
    elif case == "spanning":
        spanning = dataclasses.replace(alpha_unit, anchor_scenario_ids=(a, b))
        annotation, match = _multi(entries, (spanning,)), "fall in 2"
    elif case == "double_claim":
        twin = dataclasses.replace(bravo_unit, anchor_scenario_ids=(a,))
        annotation, match = _multi(entries, (alpha_unit, twin)), "both claim"
    else:
        ghost = dataclasses.replace(alpha_unit, anchor_scenario_ids=("no-such-scenario",))
        annotation, match = _multi(entries, (ghost, bravo_unit)), "does not contain"
    with pytest.raises(CalibrationError, match=match):
        _build(annotation, fixture, knowledge, engine)


def test_anchor_without_evidence_fails_closed(
    entries: Entries, knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    fixture, a, b = _merged(entries)
    template = fixture.scenarios[0]
    benign = dataclasses.replace(
        template,
        scenario_id="benign-notepad",
        raw_record=dataclasses.replace(
            template.raw_record, record_id="rec-benign", observation_id="obs-benign"
        ),
        process=ProcessRef(name="notepad.exe", entity_id="benign-1"),
    )
    with_benign = dataclasses.replace(fixture, scenarios=(*fixture.scenarios, benign))
    alpha_unit, bravo_unit = _units(entries, a, b)
    quiet = UnitAnnotation("u-quiet", ("benign-notepad",), alpha_unit.expected_output_shape)
    with pytest.raises(CalibrationError, match="produced no correlated evidence"):
        _build(_multi(entries, (alpha_unit, bravo_unit, quiet)), with_benign, knowledge, engine)


def test_annotation_contract_fails_closed(entries: Entries) -> None:
    annotation, _ = _entry(entries, ALPHA)
    shape = annotation.expected_output_shape
    assert shape is not None
    with pytest.raises(CalibrationError, match="exactly one of"):
        dataclasses.replace(annotation, units=(UnitAnnotation("u", ("x",), shape),))
    with pytest.raises(CalibrationError, match="exactly one of"):
        dataclasses.replace(annotation, expected_output_shape=None)
    with pytest.raises(CalibrationError, match="duplicate unit_id"):
        dataclasses.replace(
            annotation,
            expected_output_shape=None,
            units=(UnitAnnotation("u", ("x",), shape), UnitAnnotation("u", ("y",), shape)),
        )
    with pytest.raises(CalibrationError, match="anchor_scenario_ids"):
        UnitAnnotation("u", (), shape)


def test_units_load_from_annotation_json(tmp_path: Path, entries: Entries) -> None:
    raw = json.loads((V1_ROOT / "annotations" / f"{ALPHA}.annotation.json").read_text("utf-8"))
    shape = raw.pop("expected_output_shape")
    raw["units"] = [
        {"unit_id": "u1", "anchor_scenario_ids": ["s1"], "expected_output_shape": shape},
        {
            "unit_id": "u2",
            "anchor_scenario_ids": ["s2", "s3"],
            "expected_output_shape": shape,
            "coverage_assumptions": ["x"],
        },
    ]
    path = tmp_path / "a.annotation.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    loaded = load_scenario_annotation(path)
    assert loaded.expected_output_shape is None
    assert [u.unit_id for u in loaded.units] == ["u1", "u2"]
    assert loaded.units[1].anchor_scenario_ids == ("s2", "s3")


def test_decision_inputs_replay_each_family_once(
    entries: Entries, knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    fixture, a, b = _merged(entries)
    annotation = _multi(entries, _units(entries, a, b))
    corpus = build_corpus(
        [(annotation, fixture)],
        client_factory=FakeElasticClient,
        engine=engine,
        knowledge=knowledge,
    )
    calls = 0

    def counting_client() -> FakeElasticClient:
        nonlocal calls
        calls += 1
        return FakeElasticClient()

    inputs = build_corpus_decision_inputs(
        corpus,
        [(annotation, fixture)],
        roles=(CaseRole.CALIBRATION,),
        client_factory=counting_client,
        engine=engine,
        knowledge=knowledge,
    )
    assert calls == 1
    assert len(inputs.cases) == 2
    assert {ci.group_id for ci in inputs.cases} == {c.correlation_group_id for c in corpus.cases}
    for ci in inputs.cases:
        assert ci.observed_features  # candidate-independent decision features recorded
        assert ci.unattributed_baseline.observed_feature_count == len(ci.observed_features)


def test_build_corpus_refuses_a_family_twice(
    entries: Entries, knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    pair = _entry(entries, ALPHA)
    with pytest.raises(CalibrationError, match="appears twice"):
        build_corpus(
            [pair, pair], client_factory=FakeElasticClient, engine=engine, knowledge=knowledge
        )


# ===========================================================================
# Readiness gate on the frozen v1 corpus: it rediscovers F5-1..F5-4
# ===========================================================================


@pytest.fixture(scope="module")
def v1(
    entries: Entries, knowledge: AttackKnowledge, engine: DetectionEngine
) -> tuple[CorpusBuildResult, CorpusDecisionInputs, tuple[CaseCategoryRecord, ...]]:
    corpus = build_corpus(
        entries, client_factory=FakeElasticClient, engine=engine, knowledge=knowledge
    )
    inputs = build_corpus_decision_inputs(
        corpus,
        entries,
        roles=EVALUABLE,
        client_factory=FakeElasticClient,
        engine=engine,
        knowledge=knowledge,
    )
    case_by_family = {c.scenario_family_id: c for c in corpus.cases}
    records = []
    for annotation, fixture in entries:
        raw = json.loads(
            (
                V1_ROOT / "annotations" / f"{annotation.scenario_family_id}.annotation.json"
            ).read_text("utf-8")
        )
        replay = replay_fixture_through_behavioral_sequences(
            fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
        )
        evidence_types = {
            EvidenceType(e) for step in replay.sequences[0].steps for e in step.evidence_types
        }
        records.append(
            CaseCategoryRecord(
                case_id=case_by_family[annotation.scenario_family_id].case_id,
                categories=tuple(CaseCategoryTag(c) for c in raw["categories"]),
                evidence_types=tuple(evidence_types),
            )
        )
    return corpus, inputs, tuple(records)


def _gate(v1: V1, knowledge: AttackKnowledge, **kwargs: Any) -> FittingReadinessReport:
    corpus, inputs, records = v1
    return validate_fitting_readiness(
        corpus,
        inputs,
        knowledge=knowledge,
        category_records=records,
        category_report=validate_category_completeness(corpus.manifest, corpus.cases, records),
        split_report=validate_split(corpus.cases, corpus.manifest),
        provenance_report=validate_provenance(corpus.manifest),
        **kwargs,
    )


def test_gate_rediscovers_every_stage_5_finding_on_v1(v1: V1, knowledge: AttackKnowledge) -> None:
    report = _gate(v1, knowledge)
    kinds = {v.violation_type for v in report.violations}
    assert not report.is_ready
    assert ReadinessViolationType.UNRESOLVED_LABEL in kinds  # F5-1: EMU-* labels
    assert ReadinessViolationType.CONSTANT_CONCENTRATION in kinds  # F5-2
    assert ReadinessViolationType.CROSS_SPLIT_IDENTICAL_FEATURES in kinds  # F5-3
    assert ReadinessViolationType.CALIBRATION_HARD_NEGATIVES in kinds  # F5-4
    assert ReadinessViolationType.HELD_OUT_HARD_NEGATIVES in kinds
    assert ReadinessViolationType.CALIBRATION_FAMILIES in kinds  # 7 < 12
    assert ReadinessViolationType.HELD_OUT_FAMILIES in kinds  # 7 < 8
    assert ReadinessViolationType.EXISTING_VALIDATOR_INVALID not in kinds  # v1 is valid
    assert ReadinessViolationType.MISSING_DECISION_INPUT not in kinds
    measurements = dict(report.measurements)
    assert (measurements["calibration_families"], measurements["held_out_families"]) == (7, 7)
    assert measurements["distinct_top_concentrations"] <= 1
    with pytest.raises(CalibrationError, match="not ready for fitting"):
        require_fitting_ready(report)


def test_declared_imitation_is_exempt_from_cross_split_identity(
    v1: V1, knowledge: AttackKnowledge
) -> None:
    corpus, _, records = v1
    report = _gate(v1, knowledge)
    imitation = {
        c.case_id
        for c in corpus.cases
        if any(
            r.case_id == c.case_id and CaseCategoryTag.DELIBERATE_IMITATION in r.categories
            for r in records
        )
    }
    assert imitation  # v1 declares imitation families
    for violation in report.violations:
        if violation.violation_type is ReadinessViolationType.CROSS_SPLIT_IDENTICAL_FEATURES:
            assert not set(violation.case_ids) & imitation
    # without the declaration, the imitation pairs are flagged too
    stripped = tuple(
        dataclasses.replace(
            r,
            categories=tuple(
                t for t in r.categories if t is not CaseCategoryTag.DELIBERATE_IMITATION
            ),
        )
        for r in records
    )
    corpus, inputs, _ = v1
    strict = validate_fitting_readiness(
        corpus,
        inputs,
        knowledge=knowledge,
        category_records=stripped,
        category_report=validate_category_completeness(corpus.manifest, corpus.cases, records),
        split_report=validate_split(corpus.cases, corpus.manifest),
        provenance_report=validate_provenance(corpus.manifest),
    )

    def count(r: FittingReadinessReport) -> int:
        return sum(
            v.violation_type is ReadinessViolationType.CROSS_SPLIT_IDENTICAL_FEATURES
            for v in r.violations
        )

    assert count(strict) > count(report)


def test_gate_is_deterministic_and_checks_versions(v1: V1, knowledge: AttackKnowledge) -> None:
    assert _gate(v1, knowledge) == _gate(v1, knowledge)
    corpus, inputs, records = v1
    with pytest.raises(CalibrationError, match="not"):
        validate_fitting_readiness(
            corpus,
            dataclasses.replace(inputs, calibration_corpus_version="other"),
            knowledge=knowledge,
            category_records=records,
            category_report=validate_category_completeness(corpus.manifest, corpus.cases, records),
            split_report=validate_split(corpus.cases, corpus.manifest),
            provenance_report=validate_provenance(corpus.manifest),
        )
    with pytest.raises(CalibrationError, match="split report"):
        validate_fitting_readiness(
            corpus,
            inputs,
            knowledge=knowledge,
            category_records=records,
            category_report=validate_category_completeness(corpus.manifest, corpus.cases, records),
            split_report=validate_split(corpus.cases),  # no manifest: not tied to this corpus
            provenance_report=validate_provenance(corpus.manifest),
        )


def test_missing_decision_inputs_are_a_violation(v1: V1, knowledge: AttackKnowledge) -> None:
    corpus, inputs, records = v1
    partial = dataclasses.replace(inputs, cases=inputs.cases[1:])
    report = validate_fitting_readiness(
        corpus,
        partial,
        knowledge=knowledge,
        category_records=records,
        category_report=validate_category_completeness(corpus.manifest, corpus.cases, records),
        split_report=validate_split(corpus.cases, corpus.manifest),
        provenance_report=validate_provenance(corpus.manifest),
    )
    assert ReadinessViolationType.MISSING_DECISION_INPUT in {
        v.violation_type for v in report.violations
    }


def test_thresholds_are_the_accepted_dc5_minimums() -> None:
    t = ReadinessThresholds()
    assert (t.min_calibration_families, t.min_calibration_actors, t.min_held_out_families) == (
        12,
        4,
        8,
    )
    assert (
        t.min_calibration_hard_negative_families,
        t.min_held_out_hard_negative_families,
        t.min_hard_negative_features,
    ) == (3, 2, 2)
    assert (t.multi_feature_min_features, t.min_multi_feature_unit_fraction) == (3, 0.30)


def test_real_group_labels_resolve_by_alias(v1: V1, knowledge: AttackKnowledge) -> None:
    """Relabel one attributable family with a real Group alias: its label now
    resolves (alias identity only) and the unresolved-label violation for it
    disappears — F5-1 is fixed by real labels, as doc 15 DC-2 designs."""
    corpus, inputs, records = v1
    target = next(
        c for c in corpus.cases if c.ground_truth.label_semantics is LabelSemantics.ATTRIBUTABLE
    )
    relabelled_cases = tuple(
        dataclasses.replace(
            c,
            ground_truth=GroundTruth(
                actor_label_source=ActorLabelSource.EMULATION_PLAN,
                label_semantics=LabelSemantics.ATTRIBUTABLE,
                label_confidence=LabelConfidence.HIGH,
                actor_label="APT29",
            ),
        )
        if c.case_id == target.case_id
        else c
        for c in corpus.cases
    )
    report = validate_fitting_readiness(
        dataclasses.replace(corpus, cases=relabelled_cases),
        inputs,
        knowledge=knowledge,
        category_records=records,
        category_report=validate_category_completeness(corpus.manifest, corpus.cases, records),
        split_report=validate_split(corpus.cases, corpus.manifest),
        provenance_report=validate_provenance(corpus.manifest),
    )
    resolved = dict(report.resolved_labels)
    group = knowledge.get_by_id(resolved["APT29"])
    refs = group["external_references"]  # type: ignore[index]
    assert any(
        r.get("source_name") == "mitre-attack" and r.get("external_id") == "G0016" for r in refs
    )
