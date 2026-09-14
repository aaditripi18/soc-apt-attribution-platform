"""Tests for gate G0.9: synthetic/replay ingestion.

Covers: fixture validation (well-formed load, every malformed-fixture
rejection path); deterministic, repeatable replay (identical canonical JSON
across independent runs against fresh clients); the full
adapter -> Observation -> Evidence flow (G0.4 SourceAdapter ->
G0.5 extract_observations -> G0.6 derive_evidence, using the real pinned
ATT&CK KB for the scenario that declares an attack_ref); provenance
preservation (supplied ids/timestamps preserved verbatim; the fixture's
content-hash lands in SourceRef.dataset_ref; Evidence provenance points back
at the replayed Observation); and persistence through a fake Elastic client
(the G0.8 abstraction — no live Elasticsearch).

Does NOT touch the G0.0-G0.8 test files, the checked-in fixture file's
content, or the pinned ATT&CK artifact. Offline, deterministic.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient, load_evidence, load_observation
from attribution_platform.domain import EvidenceType, to_canonical_json
from attribution_platform.extraction.evidence_derivation import EvidenceDerivationError
from attribution_platform.replay import ReplayError, load_fixture_file, replay_fixture
from attribution_platform.sources.errors import SourceAdapterError

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "fixtures" / "phase0_benign_scenarios.json"


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
        "rule": {"rule_id": "rule-1", "rule_version": "1.0"},
        "evidence": {
            "evidence_id": "ev-1",
            "evidence_type": "behavioral",
            "claim": "a claim",
        },
    }
    scenario.update(overrides)
    return scenario


# ===========================================================================
# 1. Fixture validation
# ===========================================================================


def test_the_checked_in_fixture_loads_and_is_well_formed() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    assert fixture.fixture_id == "phase0-benign-scenarios"
    assert len(fixture.content_hash) == 64  # sha256 hex digest
    scenario_ids = [s.scenario_id for s in fixture.scenarios]
    assert scenario_ids == ["benign-powershell-script", "benign-user-logon"]


def test_load_well_formed_minimal_fixture(tmp_path: Path) -> None:
    path = _write_fixture(tmp_path, {"fixture_id": "f1", "scenarios": [_minimal_scenario()]})
    fixture = load_fixture_file(path)
    assert fixture.fixture_id == "f1"
    assert len(fixture.scenarios) == 1
    scenario = fixture.scenarios[0]
    assert scenario.raw_record.record_id == "evt-1"
    assert scenario.rule_ref.rule_id == "rule-1"
    assert scenario.evidence_spec.evidence_type == EvidenceType.BEHAVIORAL
    assert scenario.evidence_spec.attack_ref is None


@pytest.mark.parametrize(
    ("data", "match"),
    [
        ("not-a-json-object", "root must be a JSON object"),
        ({}, "'fixture_id' must be a non-empty string"),
        ({"fixture_id": ""}, "'fixture_id' must be a non-empty string"),
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
        load_fixture_file(path)


def test_invalid_json_rejected(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ReplayError, match="not valid JSON"):
        load_fixture_file(path)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="could not read fixture file"):
        load_fixture_file(tmp_path / "does-not-exist.json")


def test_duplicate_scenario_ids_rejected(tmp_path: Path) -> None:
    path = _write_fixture(
        tmp_path,
        {"fixture_id": "f1", "scenarios": [_minimal_scenario(), _minimal_scenario()]},
    )
    with pytest.raises(ReplayError, match="duplicate scenario_id"):
        load_fixture_file(path)


def test_bad_timestamp_rejected(tmp_path: Path) -> None:
    scenario = _minimal_scenario()
    scenario["raw_record"] = dict(scenario["raw_record"], timestamp="not-a-timestamp")
    path = _write_fixture(tmp_path, {"fixture_id": "f1", "scenarios": [scenario]})
    with pytest.raises(ReplayError, match="not a valid ISO-8601 timestamp"):
        load_fixture_file(path)


def test_unrecognized_evidence_type_rejected(tmp_path: Path) -> None:
    scenario = _minimal_scenario()
    scenario["evidence"] = dict(scenario["evidence"], evidence_type="not-a-real-type")
    path = _write_fixture(tmp_path, {"fixture_id": "f1", "scenarios": [scenario]})
    with pytest.raises(ReplayError, match="evidence_type invalid"):
        load_fixture_file(path)


def test_malformed_attack_ref_rejected(tmp_path: Path) -> None:
    scenario = _minimal_scenario()
    scenario["evidence"] = dict(
        scenario["evidence"],
        attack_ref={
            "stix_id": "attack-pattern--x",
            "object_type": "intrusion-set",  # deliberately mismatched prefix
            "attack_kb_version": "enterprise-attack-19.0",
        },
    )
    path = _write_fixture(tmp_path, {"fixture_id": "f1", "scenarios": [scenario]})
    with pytest.raises(ReplayError, match="attack_ref invalid"):
        load_fixture_file(path)


# ===========================================================================
# 2. Deterministic, repeatable replay
# ===========================================================================


def test_replay_is_deterministic_across_independent_runs() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    knowledge = load_attack_knowledge()

    results_a = replay_fixture(fixture, client=FakeElasticClient(), knowledge=knowledge)
    results_b = replay_fixture(fixture, client=FakeElasticClient(), knowledge=knowledge)

    assert [to_canonical_json(r.observation) for r in results_a] == [
        to_canonical_json(r.observation) for r in results_b
    ]
    assert [to_canonical_json(r.evidence) for r in results_a] == [
        to_canonical_json(r.evidence) for r in results_b
    ]
    assert [r.scenario_id for r in results_a] == [r.scenario_id for r in results_b]


def test_replaying_the_same_fixture_twice_into_one_client_is_idempotent() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    knowledge = load_attack_knowledge()
    client = FakeElasticClient()

    replay_fixture(fixture, client=client, knowledge=knowledge)
    replay_fixture(fixture, client=client, knowledge=knowledge)  # replay again, same client

    from attribution_platform.dataplane import EVIDENCE_INDEX, OBSERVATIONS_INDEX

    assert client.document_count(OBSERVATIONS_INDEX) == len(fixture.scenarios)
    assert client.document_count(EVIDENCE_INDEX) == len(fixture.scenarios)


# ===========================================================================
# 3. Full adapter -> Observation -> Evidence flow, using the real ATT&CK KB
# ===========================================================================


def test_replay_fixture_runs_full_pipeline_with_attack_ref() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    knowledge = load_attack_knowledge()
    client = FakeElasticClient()

    results = replay_fixture(fixture, client=client, knowledge=knowledge)

    assert [r.scenario_id for r in results] == ["benign-powershell-script", "benign-user-logon"]

    powershell_result = results[0]
    assert powershell_result.evidence.attack_ref is not None
    assert powershell_result.evidence.attack_ref.external_id == "T1059.001"
    assert powershell_result.evidence.attack_ref.attack_kb_version == knowledge.attack_kb_version

    logon_result = results[1]
    assert logon_result.evidence.attack_ref is None
    assert logon_result.evidence.evidence_type == EvidenceType.CONTEXTUAL


def test_attack_ref_absent_from_kb_fails_closed(tmp_path: Path) -> None:
    scenario = _minimal_scenario(
        evidence={
            "evidence_id": "ev-1",
            "evidence_type": "behavioral",
            "claim": "a claim",
            "attack_ref": {
                "stix_id": "attack-pattern--00000000-0000-0000-0000-000000000000",
                "object_type": "attack-pattern",
                "attack_kb_version": "enterprise-attack-19.0",
            },
        }
    )
    path = _write_fixture(tmp_path, {"fixture_id": "f1", "scenarios": [scenario]})
    fixture = load_fixture_file(path)
    knowledge = load_attack_knowledge()

    from attribution_platform.attack_knowledge.resolution import AttackReferenceError

    with pytest.raises(AttackReferenceError):
        replay_fixture(fixture, client=FakeElasticClient(), knowledge=knowledge)


# ===========================================================================
# 4. Provenance preservation
# ===========================================================================


def test_supplied_ids_and_timestamps_are_preserved_verbatim() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    knowledge = load_attack_knowledge()
    results = replay_fixture(fixture, client=FakeElasticClient(), knowledge=knowledge)

    first = results[0]
    assert first.observation.observation_id == "obs-0001"
    assert first.observation.timestamp == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert first.evidence.evidence_id == "ev-0001"


def test_dataset_content_hash_lands_in_provenance() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    knowledge = load_attack_knowledge()
    results = replay_fixture(fixture, client=FakeElasticClient(), knowledge=knowledge)

    for result in results:
        assert result.observation.raw_reference.dataset_ref == fixture.dataset_ref
        assert result.observation.raw_reference.source_type == "synthetic"


def test_evidence_provenance_points_back_to_the_replayed_observation() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    knowledge = load_attack_knowledge()
    results = replay_fixture(fixture, client=FakeElasticClient(), knowledge=knowledge)

    for result in results:
        assert result.evidence.provenance.source_observation_ids == (
            result.observation.observation_id,
        )
        # method/method_version come from the scenario's RuleRef (G0.5/G0.6 contract).
        assert result.evidence.provenance.method
        assert result.evidence.provenance.method_version


# ===========================================================================
# 5. Persistence through a fake Elastic client (G0.8 abstraction)
# ===========================================================================


def test_replayed_observations_and_evidence_round_trip_through_persistence() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    knowledge = load_attack_knowledge()
    client = FakeElasticClient()

    results = replay_fixture(fixture, client=client, knowledge=knowledge)

    for result in results:
        assert load_observation(client, result.observation.observation_id) == result.observation
        assert load_evidence(client, result.evidence.evidence_id) == result.evidence


def test_replay_fails_closed_without_knowledge_when_attack_ref_present() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    with pytest.raises(EvidenceDerivationError, match="no loaded ATT&CK knowledge"):
        replay_fixture(fixture, client=FakeElasticClient(), knowledge=None)


class _RejectingAdapter:
    """A SourceAdapter double that always raises, to prove replay_fixture
    surfaces the adapter's own typed error unmodified."""

    @property
    def source_type(self) -> str:
        return "rejecting"

    def to_observations(self, raw_record: object) -> tuple[Any, ...]:
        raise SourceAdapterError("synthetic rejection for testing")


def test_replay_surfaces_source_adapter_errors_unmodified() -> None:
    fixture = load_fixture_file(FIXTURE_PATH)
    with pytest.raises(SourceAdapterError, match="synthetic rejection"):
        replay_fixture(fixture, client=FakeElasticClient(), adapter=_RejectingAdapter())
