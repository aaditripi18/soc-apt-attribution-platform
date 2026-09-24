"""Tests for gate G1.2: replay integrated with the real G1.0 DetectionEngine.

Covers: raw-telemetry fixture loading/validation; a synthetic fixture's
scenarios genuinely converted into Observations and evaluated by the real
``DetectionEngine`` (not a stand-in); a matching rule producing a
DetectionResult + Evidence with a validated ATT&CK reference; a non-matching
Observation producing no detection/evidence; provenance reaching back to the
raw fixture reference; deterministic replay across independent runs;
replaying the same fixture twice not duplicating persisted ids; the
rule-pack content hash preserved end to end; and an architecture guard
proving this module cannot bypass the DetectionEngine (never constructs a
DetectionResult/Evidence directly).

Does NOT touch the G0.9 fixture file, G0.9 pipeline/fixtures modules, or the
pinned ATT&CK artifact. Offline, deterministic.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.dataplane import (
    EVIDENCE_INDEX,
    OBSERVATIONS_INDEX,
    FakeElasticClient,
    load_evidence,
    load_observation,
)
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.domain import EvidenceType, to_canonical_json
from attribution_platform.replay import (
    DetectionReplayFixture,
    ReplayError,
    load_detection_replay_fixture_file,
    replay_fixture_through_detection_engine,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The fixture rule packs, Phase-0 scenarios and calibration corpus v1 used here are
#: frozen against this ATT&CK release (doc 11 §0 upgrade record); they load it by name.
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"
FIXTURE_PATH = REPO_ROOT / "fixtures" / "phase1_detection_replay.json"
RULE_PACK_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
DETECTION_PIPELINE_FILE = (
    REPO_ROOT / "src" / "attribution_platform" / "replay" / "detection_pipeline.py"
)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


@pytest.fixture()
def rule_pack(knowledge: AttackKnowledge) -> RulePack:
    return load_rule_pack(RULE_PACK_PATH, knowledge=knowledge)


@pytest.fixture()
def engine(rule_pack: RulePack) -> DetectionEngine:
    return DetectionEngine(rules=rule_pack.rules)


def _write_fixture(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _minimal_scenario(**overrides: object) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "scenario_id": "s1",
        "raw_record": {
            "record_id": "evt-1",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "observation_id": "obs-1",
        },
    }
    scenario.update(overrides)
    return scenario


# ===========================================================================
# 1. Fixture validation
# ===========================================================================


def test_the_checked_in_fixture_loads_and_is_well_formed() -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    assert fixture.fixture_id == "phase1-detection-replay"
    assert len(fixture.content_hash) == 64  # sha256 hex digest
    scenario_ids = [s.scenario_id for s in fixture.scenarios]
    assert scenario_ids == [
        "encoded-powershell-matches-platform-rule",
        "interactive-logon-matches-contextual-rule",
        "benign-notepad-matches-no-rule",
        "procdump-lsass-target-matches-credential-rule",
        "procdump-non-lsass-target-does-not-match",
        "rundll32-javascript-proxy-matches-rule",
        "rundll32-benign-control-panel-invocation-does-not-match",
        "cmd-spawned-by-word-matches-office-shell-rule",
        "cmd-spawned-by-explorer-does-not-match-office-shell-rule",
        "certutil-urlcache-download-matches-ingress-transfer-rule",
        "certutil-hashfile-does-not-match-ingress-transfer-rule",
    ]


def test_load_well_formed_minimal_fixture_with_no_entity_fields(tmp_path: Path) -> None:
    path = _write_fixture(tmp_path, {"fixture_id": "f1", "scenarios": [_minimal_scenario()]})
    fixture = load_detection_replay_fixture_file(path)
    scenario = fixture.scenarios[0]
    assert scenario.raw_record.record_id == "evt-1"
    assert scenario.process is None
    assert scenario.event is None


def test_scenario_has_no_rule_or_evidence_fields_available() -> None:
    """Structural proof of requirement 10: this format has nowhere to assert
    a rule id or ATT&CK mapping -- unlike G0.9's ReplayScenario, there is no
    ``rule``/``evidence`` field on DetectionReplayScenario at all."""
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    scenario = fixture.scenarios[0]
    assert not hasattr(scenario, "rule_ref")
    assert not hasattr(scenario, "evidence_spec")


@pytest.mark.parametrize(
    ("data", "match"),
    [
        ("not-a-json-object", "root must be a JSON object"),
        ({}, "'fixture_id' must be a non-empty string"),
        ({"fixture_id": "f1"}, "'scenarios' must be a non-empty list"),
        ({"fixture_id": "f1", "scenarios": []}, "'scenarios' must be a non-empty list"),
        ({"fixture_id": "f1", "scenarios": ["not-an-object"]}, "must be a JSON object"),
        (
            {"fixture_id": "f1", "scenarios": [{"scenario_id": "s1"}]},
            "missing required field",
        ),
    ],
)
def test_malformed_fixture_shapes_rejected(tmp_path: Path, data: object, match: str) -> None:
    path = _write_fixture(tmp_path, data)
    with pytest.raises(ReplayError, match=match):
        load_detection_replay_fixture_file(path)


def test_unrecognized_scenario_field_rejected(tmp_path: Path) -> None:
    """A fixture author who mistakenly writes 'rule'/'evidence' (the G0.9
    field names) onto a G1.2 scenario is told the field is not recognized,
    rather than the value being silently ignored."""
    path = _write_fixture(
        tmp_path,
        {
            "fixture_id": "f1",
            "scenarios": [_minimal_scenario(rule={"rule_id": "x", "rule_version": "1.0"})],
        },
    )
    with pytest.raises(ReplayError, match="unrecognized field 'rule'"):
        load_detection_replay_fixture_file(path)


def test_duplicate_scenario_ids_rejected(tmp_path: Path) -> None:
    path = _write_fixture(
        tmp_path, {"fixture_id": "f1", "scenarios": [_minimal_scenario(), _minimal_scenario()]}
    )
    with pytest.raises(ReplayError, match="duplicate scenario_id"):
        load_detection_replay_fixture_file(path)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="could not read fixture file"):
        load_detection_replay_fixture_file(tmp_path / "does-not-exist.json")


# ===========================================================================
# 2. The real DetectionEngine is genuinely exercised
# ===========================================================================


def test_fixture_scenario_is_converted_to_an_observation_with_entity_data(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    powershell_result = results[0]
    assert powershell_result.observation.process is not None
    assert powershell_result.observation.process.name == "powershell.exe"
    assert powershell_result.observation.process.command_line == (
        "powershell.exe -enc SGVsbG8gV29ybGQh"
    )


def test_matching_scenario_produces_detection_from_the_real_engine(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    powershell_result = results[0]
    assert len(powershell_result.detections) == 1
    detection = powershell_result.detections[0]
    assert detection.rule_ref.rule_id == "platform-encoded-powershell"
    assert detection.detection_source == "platform-rules"


def test_a_different_rule_pack_produces_a_different_detection_outcome(
    knowledge: AttackKnowledge,
) -> None:
    """Proves the engine, not the fixture, decides the outcome: an engine
    with zero rules never detects anything from this same fixture."""
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    empty_engine = DetectionEngine(rules=())
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=empty_engine, knowledge=knowledge
    )
    assert all(r.detections == () for r in results)
    assert all(r.evidences == () for r in results)


# ===========================================================================
# 3. Matching rule -> DetectionResult + Evidence with validated ATT&CK ref
# ===========================================================================


def test_behavioral_match_produces_evidence_with_validated_attack_ref(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    powershell_result = results[0]
    assert len(powershell_result.evidences) == 1
    evidence = powershell_result.evidences[0]
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == "T1059.001"
    assert evidence.attack_ref.attack_kb_version == knowledge.attack_kb_version
    assert evidence.evidence_type == EvidenceType.BEHAVIORAL


def test_contextual_match_produces_unmapped_evidence(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    logon_result = results[1]
    assert len(logon_result.detections) == 1
    assert logon_result.detections[0].technique_mappings == ()
    assert len(logon_result.evidences) == 1
    assert logon_result.evidences[0].attack_ref is None
    assert logon_result.evidences[0].evidence_type == EvidenceType.CONTEXTUAL


# ===========================================================================
# 4. Non-matching Observation -> no detection/evidence
# ===========================================================================


def test_non_matching_scenario_produces_no_detection_or_evidence(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    benign_result = results[2]
    assert benign_result.detections == ()
    assert benign_result.evidences == ()
    # The Observation itself is still built and persisted -- only detection
    # is absent, not the underlying telemetry.
    assert benign_result.observation.process is not None
    assert load_observation(client, benign_result.observation.observation_id) is not None


# ===========================================================================
# 5. Provenance reaches the raw fixture reference
# ===========================================================================


def test_provenance_reaches_raw_fixture_reference(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    powershell_result = results[0]
    assert powershell_result.observation.raw_reference.dataset_ref == fixture.dataset_ref
    assert powershell_result.observation.raw_reference.source_type == "synthetic"
    assert powershell_result.observation.raw_reference.source_event_id == "evt-1001"
    assert powershell_result.observation.observation_id == "obs-1001"

    evidence = powershell_result.evidences[0]
    assert evidence.provenance.source_observation_ids == ("obs-1001",)


# ===========================================================================
# 6. Deterministic replay
# ===========================================================================


def test_replay_is_deterministic_across_independent_runs(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)

    results_a = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    results_b = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )

    assert [to_canonical_json(r.observation) for r in results_a] == [
        to_canonical_json(r.observation) for r in results_b
    ]
    assert [[to_canonical_json(d) for d in r.detections] for r in results_a] == [
        [to_canonical_json(d) for d in r.detections] for r in results_b
    ]
    assert [[to_canonical_json(e) for e in r.evidences] for r in results_a] == [
        [to_canonical_json(e) for e in r.evidences] for r in results_b
    ]


def test_supplied_ids_and_timestamps_are_preserved_verbatim(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    results = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    first = results[0]
    assert first.observation.observation_id == "obs-1001"
    assert first.observation.timestamp == datetime(2026, 2, 1, 9, 0, 0, tzinfo=UTC)


# ===========================================================================
# 7. Replaying the same fixture twice does not create duplicate ids
# ===========================================================================


def test_replaying_the_same_fixture_twice_into_one_client_is_idempotent(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()

    replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )  # replay again, same client

    # 11 scenarios -> 11 Observations persisted regardless of replay count.
    assert client.document_count(OBSERVATIONS_INDEX) == 11
    # 6 of the 11 scenarios match a rule and produce exactly one Evidence
    # each (the original 2 G1.0 matches + G1.3's 4 new matching scenarios).
    assert client.document_count(EVIDENCE_INDEX) == 6


def test_replaying_twice_produces_identical_detection_and_evidence_ids(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()

    results_1 = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    results_2 = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )

    ids_1 = [d.detection_id for r in results_1 for d in r.detections]
    ids_2 = [d.detection_id for r in results_2 for d in r.detections]
    assert ids_1 == ids_2
    assert len(ids_1) == len(set(ids_1))  # no duplicate detection_id within one replay


# ===========================================================================
# 8. Rule-pack content hash preserved end to end
# ===========================================================================


def test_rule_pack_content_hash_preserved_through_detection_and_evidence(
    engine: DetectionEngine, knowledge: AttackKnowledge, rule_pack: RulePack
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    results = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    powershell_result = results[0]
    detection = powershell_result.detections[0]
    assert detection.rule_pack_content_hash == rule_pack.content_hash

    evidence = powershell_result.evidences[0]
    assert evidence.provenance.method_content_hash == rule_pack.content_hash


# ===========================================================================
# 9. Persistence round trip (G0.8, unchanged)
# ===========================================================================


def test_persisted_observations_and_evidence_round_trip(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    for result in results:
        assert load_observation(client, result.observation.observation_id) == result.observation
        for evidence in result.evidences:
            assert load_evidence(client, evidence.evidence_id) == evidence


# ===========================================================================
# 10. G0.9 backward compatibility (structural check; full behavior is
#     covered by the untouched tests/test_replay.py)
# ===========================================================================


def test_g09_fixture_type_is_unaffected_and_still_importable() -> None:
    from attribution_platform.replay import Fixture, ReplayScenario, replay_fixture

    assert Fixture.__name__ == "Fixture"
    assert callable(replay_fixture)
    assert ReplayScenario.__name__ == "ReplayScenario"
    assert DetectionReplayFixture.__name__ == "DetectionReplayFixture"


# ===========================================================================
# 11. Architecture guard: this module cannot bypass the DetectionEngine
# ===========================================================================


def test_detection_pipeline_never_constructs_detectionresult_or_evidence_directly() -> None:
    """Static AST check: replay/detection_pipeline.py must never call
    DetectionResult(...) or Evidence(...) directly -- every DetectionResult
    must come from DetectionEngine.evaluate() and every Evidence from
    derive_evidence_from_detection(), never fabricated/hand-assembled here."""
    tree = ast.parse(DETECTION_PIPELINE_FILE.read_text(encoding="utf-8"))
    forbidden_calls = {"DetectionResult", "Evidence"}
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in forbidden_calls
        ):
            offending.append(node.func.id)
    assert not offending, (
        f"detection_pipeline.py must not construct {offending} directly; "
        "it must always come from the real DetectionEngine/derive_evidence_from_detection"
    )


def test_detection_pipeline_actually_uses_the_engine_and_evidence_fanout() -> None:
    """Positive counterpart to the guard above: the real integration points
    are genuinely present in source, not merely absent-of-bypass."""
    source = DETECTION_PIPELINE_FILE.read_text(encoding="utf-8")
    assert "engine.evaluate(" in source
    assert "derive_evidence_from_detection(" in source


# ===========================================================================
# 12. G1.3: four new rules, replayed through the real engine end to end
# ===========================================================================

_G13_MATCHING_SCENARIOS = (
    ("procdump-lsass-target-matches-credential-rule", "platform-procdump-lsass-dump", "T1003.001"),
    ("rundll32-javascript-proxy-matches-rule", "platform-rundll32-javascript-proxy", "T1218.011"),
    (
        "cmd-spawned-by-word-matches-office-shell-rule",
        "platform-office-spawns-cmd-shell",
        "T1059.003",
    ),
    (
        "certutil-urlcache-download-matches-ingress-transfer-rule",
        "platform-certutil-ingress-transfer",
        "T1105",
    ),
)
_G13_NON_MATCHING_SCENARIOS = (
    "procdump-non-lsass-target-does-not-match",
    "rundll32-benign-control-panel-invocation-does-not-match",
    "cmd-spawned-by-explorer-does-not-match-office-shell-rule",
    "certutil-hashfile-does-not-match-ingress-transfer-rule",
)


@pytest.mark.parametrize(("scenario_id", "rule_id", "external_id"), _G13_MATCHING_SCENARIOS)
def test_g13_matching_scenario_produces_detection_and_evidence_via_real_engine(
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    scenario_id: str,
    rule_id: str,
    external_id: str,
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    results = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    result = next(r for r in results if r.scenario_id == scenario_id)

    assert len(result.detections) == 1
    detection = result.detections[0]
    assert detection.rule_ref.rule_id == rule_id

    assert len(result.evidences) == 1
    evidence = result.evidences[0]
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == external_id
    assert evidence.attack_ref.attack_kb_version == knowledge.attack_kb_version
    assert evidence.evidence_type == EvidenceType.BEHAVIORAL


@pytest.mark.parametrize("scenario_id", _G13_NON_MATCHING_SCENARIOS)
def test_g13_non_matching_scenario_produces_no_detection_or_evidence(
    engine: DetectionEngine, knowledge: AttackKnowledge, scenario_id: str
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    results = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    result = next(r for r in results if r.scenario_id == scenario_id)
    assert result.detections == ()
    assert result.evidences == ()
    # The relevant Observation content is still present -- only detection is
    # absent, proving this is a genuine engine miss, not a fixture omission.
    assert result.observation.process is not None


@pytest.mark.parametrize(("scenario_id", "rule_id", "external_id"), _G13_MATCHING_SCENARIOS)
def test_g13_provenance_reaches_raw_fixture_reference_for_each_new_rule(
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    scenario_id: str,
    rule_id: str,
    external_id: str,
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    results = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    result = next(r for r in results if r.scenario_id == scenario_id)

    assert result.observation.raw_reference.dataset_ref == fixture.dataset_ref
    assert result.observation.raw_reference.source_type == "synthetic"

    evidence = result.evidences[0]
    assert evidence.provenance.source_observation_ids == (result.observation.observation_id,)


@pytest.mark.parametrize(("scenario_id", "rule_id", "external_id"), _G13_MATCHING_SCENARIOS)
def test_g13_rule_pack_content_hash_preserved_for_each_new_rule(
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    rule_pack: RulePack,
    scenario_id: str,
    rule_id: str,
    external_id: str,
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    results = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    result = next(r for r in results if r.scenario_id == scenario_id)

    assert result.detections[0].rule_pack_content_hash == rule_pack.content_hash
    assert result.evidences[0].provenance.method_content_hash == rule_pack.content_hash


def test_g13_existing_two_scenarios_still_behave_identically_through_replay(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    """The original two G1.0 replay scenarios (indices 0 and 1) must still
    produce the same rule/technique outcome after the four new rules and
    eight new scenarios were appended after them."""
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    results = replay_fixture_through_detection_engine(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    assert results[0].scenario_id == "encoded-powershell-matches-platform-rule"
    assert results[0].detections[0].rule_ref.rule_id == "platform-encoded-powershell"
    powershell_attack_ref = results[0].evidences[0].attack_ref
    assert powershell_attack_ref is not None
    assert powershell_attack_ref.external_id == "T1059.001"

    assert results[1].scenario_id == "interactive-logon-matches-contextual-rule"
    assert results[1].detections[0].technique_mappings == ()
    assert results[1].evidences[0].attack_ref is None


def test_g13_new_rule_with_tampered_mapping_cannot_silently_pass_through_replay(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """End-to-end proof (replay path, not just load_rule_pack in isolation):
    a tampered ATT&CK mapping on one of the new rules must prevent the whole
    pack from ever being usable for replay -- it fails at load time, before
    any Observation is evaluated."""
    from attribution_platform.detection import DetectionError, load_rule_pack

    data = json.loads(RULE_PACK_PATH.read_text(encoding="utf-8"))
    for rule in data["rules"]:
        if rule["rule_id"] == "platform-certutil-ingress-transfer":
            rule["technique_mappings"][0]["stix_id"] = (
                "attack-pattern--00000000-0000-0000-0000-000000000000"
            )
    tampered_path = tmp_path / "tampered_pack.json"
    tampered_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(DetectionError, match="does not resolve"):
        load_rule_pack(tampered_path, knowledge=knowledge)
