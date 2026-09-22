"""Tests for the C3.2 calibration evidence-type rule extension (D1).

The core detection pack (``fixtures/phase1_core_rules.json``, a Type-A
structural fixture that is **not** modified) emits only BEHAVIORAL and
CONTEXTUAL evidence types. The C3.2 corpus must exercise all four
``EvidenceType`` values (ADR-0006 §D19). These tests prove that the small,
isolated calibration rule pack
(``data/calibration/rules/calibration_evidence_type_rules.json``) makes
EVIDENTIARY and PROCEDURAL genuinely reachable through the real, unmodified
detection/evidence/correlation pipeline and that they flow onto
``BehavioralStep.evidence_types`` (B4) — with no pipeline, contract, or
core-pack change. Offline, deterministic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.domain import (
    EvidenceType,
    HostRef,
    NetworkEndpoint,
    NetworkInfo,
    ProcessRef,
)
from attribution_platform.replay import (
    DetectionReplayFixture,
    DetectionReplayScenario,
    replay_fixture_through_behavioral_sequences,
)
from attribution_platform.sources.synthetic import SyntheticRecord

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_PACK_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
CALIB_PACK_PATH = (
    REPO_ROOT / "data" / "calibration" / "rules" / "calibration_evidence_type_rules.json"
)
T0 = datetime(2026, 8, 1, 10, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture()
def core_pack(knowledge: AttackKnowledge) -> RulePack:
    return load_rule_pack(CORE_PACK_PATH, knowledge=knowledge)


@pytest.fixture()
def calib_pack(knowledge: AttackKnowledge) -> RulePack:
    return load_rule_pack(CALIB_PACK_PATH, knowledge=knowledge)


def test_calibration_pack_declares_evidentiary_and_procedural(calib_pack: RulePack) -> None:
    by_id = {r.rule_ref.rule_id: r.evidence_type for r in calib_pack.rules}
    assert by_id["calibration-evidentiary-c2-infrastructure-ip"] is EvidenceType.EVIDENTIARY
    assert by_id["calibration-procedural-downloadstring-cradle"] is EvidenceType.PROCEDURAL


def test_evidentiary_rule_maps_no_technique(calib_pack: RulePack) -> None:
    # EVIDENTIARY = corroborating IOC/infrastructure artifact, no confident technique.
    evidentiary = next(r for r in calib_pack.rules if r.evidence_type is EvidenceType.EVIDENTIARY)
    assert evidentiary.technique_mappings == ()


def test_core_pack_only_emits_behavioral_and_contextual(core_pack: RulePack) -> None:
    # Guards the boundary: the core Type-A pack is unmodified and still emits
    # only these two types (so the other two genuinely come from the extension).
    assert {r.evidence_type for r in core_pack.rules} == {
        EvidenceType.BEHAVIORAL,
        EvidenceType.CONTEXTUAL,
    }


def test_all_four_evidence_types_reachable_across_packs(
    core_pack: RulePack, calib_pack: RulePack
) -> None:
    combined = {r.evidence_type for r in core_pack.rules} | {
        r.evidence_type for r in calib_pack.rules
    }
    assert combined == set(EvidenceType)


def test_extension_emits_types_through_the_real_pipeline(
    knowledge: AttackKnowledge, core_pack: RulePack, calib_pack: RulePack
) -> None:
    # A parent behavioral detection with two separate lineage children — one
    # firing the procedural rule, one the evidentiary rule — forms one group
    # whose steps carry all three evidence types via the real pipeline (B4).
    engine = DetectionEngine(rules=core_pack.rules + calib_pack.rules)
    scenarios = (
        DetectionReplayScenario(
            scenario_id="p",
            raw_record=SyntheticRecord(record_id="rp", timestamp=T0, observation_id="obs-p"),
            process=ProcessRef(
                name="procdump.exe",
                command_line="procdump.exe -ma lsass.exe out.dmp",
                entity_id="p",
            ),
            host=HostRef(id="h"),
        ),
        DetectionReplayScenario(
            scenario_id="c1",
            raw_record=SyntheticRecord(
                record_id="rc1", timestamp=T0.replace(second=1), observation_id="obs-c1"
            ),
            process=ProcessRef(
                name="powershell.exe",
                command_line="powershell -c IEX(New-Object Net.WebClient).DownloadString(x)",
                parent_entity_id="p",
                entity_id="c1",
            ),
            host=HostRef(id="h"),
        ),
        DetectionReplayScenario(
            scenario_id="c2",
            raw_record=SyntheticRecord(
                record_id="rc2", timestamp=T0.replace(second=2), observation_id="obs-c2"
            ),
            process=ProcessRef(name="svchost.exe", parent_entity_id="p", entity_id="c2"),
            network=NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.66")),
            host=HostRef(id="h"),
        ),
    )
    fixture = DetectionReplayFixture(
        fixture_id="calib-evtype-probe", content_hash="0" * 64, scenarios=scenarios
    )
    result = replay_fixture_through_behavioral_sequences(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )

    detection_types = {
        evidence.evidence_type
        for detection in result.correlation_result.detection_results
        for evidence in detection.evidences
    }
    assert EvidenceType.EVIDENTIARY in detection_types
    assert EvidenceType.PROCEDURAL in detection_types

    assert len(result.sequences) == 1
    step_types: set[str] = set()
    for step in result.sequences[0].steps:
        step_types |= set(step.evidence_types)
    assert step_types == {"behavioral", "evidentiary", "procedural"}
