"""C3.2 Stage 4 — v1 corpus tests (ADR-0006 §D5/§D6/§D8/§D9/§D10/§D13/§D19).

Proves the actual v1 corpus under data/calibration/corpus/v1/ builds through
the existing, unmodified corpus builder, passes the existing Stage 3
(category completeness), B1.4 (split/leakage/blind-actor), and B1.5
(provenance/license) validators, genuinely exercises all four EvidenceType
values and both coverage-present/absent cases through the real pipeline, is
deterministic and PYTHONHASHSEED-independent, and never mutates its inputs.

Tier-1 machinery only; NOT real-world accuracy evidence (ADR-0006 §D11). No
fitting, no ``calibration_version``, no scoring, no G3.6.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.calibration.category_validation import (
    CaseCategoryRecord,
    CaseCategoryTag,
    CategoryCompletenessReport,
    validate_category_completeness,
)
from attribution_platform.calibration.composition import describe_corpus_composition
from attribution_platform.calibration.contracts import ActorLabelSource, CaseRole, LabelSemantics
from attribution_platform.calibration.corpus_builder import (
    CorpusBuildResult,
    build_corpus_from_dir,
    load_corpus_entries_from_dir,
)
from attribution_platform.calibration.provenance_validation import require_valid_provenance
from attribution_platform.calibration.split_validation import require_valid_split
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain.enums import EvidenceType
from attribution_platform.replay import replay_fixture_through_behavioral_sequences

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The fixture rule packs, Phase-0 scenarios and calibration corpus v1 used here are
#: frozen against this ATT&CK release (doc 11 §0 upgrade record); they load it by name.
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"
CORE_PACK = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
CALIBRATION_PACK = (
    REPO_ROOT / "data" / "calibration" / "rules" / "calibration_evidence_type_rules.json"
)
V1_ROOT = REPO_ROOT / "data" / "calibration" / "corpus" / "v1"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


@pytest.fixture()
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    core = load_rule_pack(CORE_PACK, knowledge=knowledge)
    calibration = load_rule_pack(CALIBRATION_PACK, knowledge=knowledge)
    return DetectionEngine(rules=core.rules + calibration.rules)


def _build(knowledge: AttackKnowledge, engine: DetectionEngine) -> CorpusBuildResult:
    return build_corpus_from_dir(
        V1_ROOT, client_factory=FakeElasticClient, engine=engine, knowledge=knowledge
    )


def _category_records(
    knowledge: AttackKnowledge, engine: DetectionEngine, result: CorpusBuildResult
) -> tuple[CaseCategoryRecord, ...]:
    """Build CaseCategoryRecord objects the same way the corpus was authored:
    authored ``categories`` read from each annotation's own JSON, and
    ``evidence_types`` captured from that family's *real* independent replay
    output — never hand-declared, never inferred from ATT&CK."""
    entries = load_corpus_entries_from_dir(V1_ROOT)
    case_by_family = {c.scenario_family_id: c for c in result.cases}
    records = []
    for annotation, fixture in entries:
        raw = json.loads(
            (
                V1_ROOT / "annotations" / f"{annotation.scenario_family_id}.annotation.json"
            ).read_text(encoding="utf-8")
        )
        replay = replay_fixture_through_behavioral_sequences(
            fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
        )
        assert len(replay.sequences) == 1
        evidence_types: set[EvidenceType] = set()
        for step in replay.sequences[0].steps:
            evidence_types.update(EvidenceType(e) for e in step.evidence_types)
        case = case_by_family[annotation.scenario_family_id]
        records.append(
            CaseCategoryRecord(
                case_id=case.case_id,
                categories=tuple(CaseCategoryTag(c) for c in raw["categories"]),
                evidence_types=tuple(evidence_types),
            )
        )
    return tuple(records)


# ===========================================================================
# 1. v1 corpus loads / builds through the existing builder
# ===========================================================================


def test_v1_corpus_builds_18_cases(knowledge: AttackKnowledge, engine: DetectionEngine) -> None:
    result = _build(knowledge, engine)
    assert len(result.cases) == 18
    for case in result.cases:
        assert case.attack_kb_version == knowledge.attack_kb_version
        assert case.correlation_group_id and case.sequence_id
        assert case.telemetry_provenance


def test_v1_role_counts_match_design(knowledge: AttackKnowledge, engine: DetectionEngine) -> None:
    result = _build(knowledge, engine)
    composition = describe_corpus_composition(result.manifest, result.cases)
    assert dict(composition.role_distribution) == {
        "calibration": 7,
        "held_out_validation": 7,
        "blind_actor_holdout": 2,
        "excluded": 2,
    }


# ===========================================================================
# 2. Category completeness passes
# ===========================================================================


def test_v1_category_completeness_passes(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    records = _category_records(knowledge, engine, result)
    report = validate_category_completeness(result.manifest, result.cases, records)
    assert isinstance(report, CategoryCompletenessReport)
    assert report.is_valid, [v.reason for v in report.violations]
    assert report.violations == ()


# ===========================================================================
# 3. Split / provenance validation passes
# ===========================================================================


def test_v1_split_and_provenance_pass(knowledge: AttackKnowledge, engine: DetectionEngine) -> None:
    result = _build(knowledge, engine)
    require_valid_split(result.cases, result.manifest)  # no raise
    require_valid_provenance(result.manifest)  # no raise


# ===========================================================================
# 4. All four EvidenceTypes genuinely represented
# ===========================================================================


def test_v1_all_evidence_types_genuinely_emitted(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    records = _category_records(knowledge, engine, result)
    present = {e for r in records for e in r.evidence_types}
    assert present == set(EvidenceType)


# ===========================================================================
# 5. Coverage present / absent
# ===========================================================================


def test_v1_has_coverage_present_and_absent_cases(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    assert any(len(c.coverage_assumptions) > 0 for c in result.cases)
    assert any(len(c.coverage_assumptions) == 0 for c in result.cases)


# ===========================================================================
# 6. Blind actor isolation
# ===========================================================================


def test_v1_blind_actor_isolation(knowledge: AttackKnowledge, engine: DetectionEngine) -> None:
    result = _build(knowledge, engine)
    blind_cases = [c for c in result.cases if c.case_role is CaseRole.BLIND_ACTOR_HOLDOUT]
    assert len(blind_cases) == 2
    for case in blind_cases:
        assert case.ground_truth.label_semantics is LabelSemantics.ATTRIBUTABLE
        assert case.ground_truth.actor_label == "EMU-ZULU"
    calibration_actors = {
        c.ground_truth.actor_label for c in result.cases if c.case_role is CaseRole.CALIBRATION
    }
    assert "EMU-ZULU" not in calibration_actors


# ===========================================================================
# 7. EXCLUDED final-test convention
# ===========================================================================


def test_v1_excluded_is_final_test_reserved(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    excluded = [c for c in result.cases if c.case_role is CaseRole.EXCLUDED]
    assert len(excluded) == 2
    assert not hasattr(CaseRole, "FINAL_TEST")


# ===========================================================================
# 8. Replay identity preservation (not fabricated)
# ===========================================================================


def test_v1_replay_ids_are_preserved_not_fabricated(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    entries = load_corpus_entries_from_dir(V1_ROOT)
    annotation, fixture = next(e for e in entries if e[1].fixture_id == "v1-cal-alpha-ingress")
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
    result = _build(knowledge, engine)
    case = next(c for c in result.cases if c.scenario_family_id == "v1-cal-alpha-ingress")
    assert case.correlation_group_id == direct_group.group_id
    assert case.sequence_id == direct_sequence.sequence_id
    expected_provenance = tuple(
        sorted(set(direct_group.member_observation_ids) | set(direct_group.member_evidence_ids))
    )
    assert case.telemetry_provenance == expected_provenance


# ===========================================================================
# 9. Deterministic corpus version (via the EXISTING mechanism only)
# ===========================================================================


def test_v1_corpus_version_via_existing_mechanism_only(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    from attribution_platform.calibration.manifest import CalibrationCorpusManifest

    a = _build(knowledge, engine)
    b = _build(knowledge, engine)
    assert a.calibration_corpus_version == b.calibration_corpus_version
    assert a.cases == b.cases
    recomputed = CalibrationCorpusManifest.from_cases(
        a.cases, a.manifest.source_entries, attack_kb_version=knowledge.attack_kb_version
    )
    assert recomputed.calibration_corpus_version == a.calibration_corpus_version


# ===========================================================================
# 10. PYTHONHASHSEED independence
# ===========================================================================

_SUBPROCESS = """
from pathlib import Path
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.calibration.corpus_builder import build_corpus_from_dir
kb = load_attack_knowledge("enterprise-attack-19.0")  # corpus frozen against it
core = load_rule_pack(Path("fixtures/phase1_core_rules.json"), knowledge=kb)
calib_path = Path("data/calibration/rules/calibration_evidence_type_rules.json")
calib = load_rule_pack(calib_path, knowledge=kb)
eng = DetectionEngine(rules=core.rules + calib.rules)
res = build_corpus_from_dir(
    Path("data/calibration/corpus/v1"), client_factory=FakeElasticClient, engine=eng, knowledge=kb
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


def test_v1_corpus_version_pythonhashseed_independent() -> None:
    first = _run_under_seed("0")
    assert first
    assert first == _run_under_seed("1") == _run_under_seed("424242")


# ===========================================================================
# 11. No mutation of source fixtures / ATT&CK knowledge
# ===========================================================================


def test_v1_build_does_not_mutate_knowledge_or_fixtures(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    fingerprint = knowledge.object_fingerprint
    entries = load_corpus_entries_from_dir(V1_ROOT)
    fixtures_before = tuple(fixture for _annotation, fixture in entries)

    _build(knowledge, engine)

    assert knowledge.object_fingerprint is fingerprint
    reloaded = tuple(fixture for _annotation, fixture in load_corpus_entries_from_dir(V1_ROOT))
    assert fixtures_before == reloaded


# ===========================================================================
# 12. No ATT&CK-derived expected-output authorship
# ===========================================================================


def test_v1_expected_output_shapes_are_not_att_ck_derived(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    for case in result.cases:
        shape = case.expected_output_shape
        assert shape.authorship_provenance.strip()
        assert "not att&ck-derived" in shape.authorship_provenance.lower()
        assert "att&ck group" not in shape.authorship_provenance.lower()
        assert shape.discriminating_evidence == ()


def test_v1_actor_labels_are_dataset_or_emulation_sourced_never_att_ck(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    for case in result.cases:
        assert case.ground_truth.actor_label_source in (
            ActorLabelSource.EMULATION_PLAN,
            ActorLabelSource.DATASET_ANNOTATION,
            ActorLabelSource.INCIDENT_REPORT,
            ActorLabelSource.UNKNOWN,
        )


# ===========================================================================
# 13. Declared-provenance SYNTHETIC only (no real incident / live emulation)
# ===========================================================================


def test_v1_all_cases_are_synthetic_source(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    from attribution_platform.calibration.contracts import SourceKind

    result = _build(knowledge, engine)
    assert {c.source_kind for c in result.cases} == {SourceKind.SYNTHETIC}


# ===========================================================================
# 14. Full actor roster represented
# ===========================================================================


def test_v1_full_attributable_actor_roster_represented(
    knowledge: AttackKnowledge, engine: DetectionEngine
) -> None:
    result = _build(knowledge, engine)
    composition = describe_corpus_composition(result.manifest, result.cases)
    actors = {a for a, _count in composition.attributable_actor_distribution}
    assert actors == {
        "EMU-ALPHA",
        "EMU-BRAVO",
        "EMU-CHARLIE",
        "EMU-DELTA",
        "EMU-ECHO",
        "EMU-FOXTROT",
        "EMU-GOLF",
        "EMU-ZULU",
    }
