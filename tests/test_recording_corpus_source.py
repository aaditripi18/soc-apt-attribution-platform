"""Real recordings as corpus sources (doc 15 DC-3/DC-4): the recording
pipeline, SHA-256 pinning, recording anchors (Observation ids), and declared
excluded (background) units."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
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
    CorpusScenarioAnnotation,
    UnitAnnotation,
    build_calibration_cases,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.replay.errors import ReplayError
from attribution_platform.replay.recording_pipeline import RecordingSource, analyze_recording

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
HOST = "WS01.example.local"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _process_create(
    record_id: int, second: int, guid: str, parent: str, image: str, cmd: str
) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-01-01T12:00:{second:02d}.000Z",
        "winlog": {
            "channel": SYSMON,
            "event_id": 1,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "UtcTime": f"2026-01-01 12:00:{second:02d}.000",
                "ProcessGuid": guid,
                "ProcessId": str(1000 + record_id),
                "Image": image,
                "CommandLine": cmd,
                "ParentProcessGuid": parent,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
        },
    }


def _recording(tmp_path: Path) -> RecordingSource:
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    whoami = "C:\\Windows\\System32\\whoami.exe"
    records = [
        # one process tree: encoded PowerShell -> two whoami discovery children
        _process_create(1, 1, "{P}", "{ROOT}", ps, "powershell.exe -nop -w hidden -enc SQBFAFgA"),
        _process_create(2, 2, "{A}", "{P}", whoami, "whoami /all -all"),
        _process_create(3, 3, "{B}", "{P}", whoami, "whoami /all -all"),
        # an unrelated benign event: no detection, context only
        _process_create(
            4, 4, "{N}", "{ROOT2}", "C:\\Windows\\System32\\notepad.exe", "notepad.exe"
        ),
    ]
    path = tmp_path / "rec.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("rec.json", "\n".join(json.dumps(r) for r in records) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return RecordingSource(
        recording_id="rec-test",
        path=path,
        sha256=digest,
        declared_sources={HOST: ("sysmon",)},
    )


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)


def test_recording_runs_the_full_pipeline(
    tmp_path: Path, engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    analysis = analyze_recording(_recording(tmp_path), engine=engine, knowledge=knowledge)
    assert analysis.observations == 4
    assert analysis.evidence > 0
    assert len(analysis.sequences) == len(analysis.groups) >= 1
    members = {
        analysis.items[e][1].observation_id for g in analysis.groups for e in g.member_evidence_ids
    }
    assert "sysmon:WS01.example.local:4" not in members  # benign notepad: context only


def test_recording_digest_is_enforced(
    tmp_path: Path, engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    source = dataclasses.replace(_recording(tmp_path), sha256="0" * 64)
    with pytest.raises(ReplayError, match="SHA-256"):
        analyze_recording(source, engine=engine, knowledge=knowledge)


def _annotation(units: tuple[UnitAnnotation, ...]) -> CorpusScenarioAnnotation:
    return CorpusScenarioAnnotation(
        scenario_family_id="rec-family",
        case_role=CaseRole.CALIBRATION,
        source_kind=SourceKind.REPLAY,
        source_ref="test:rec",
        license="MIT",
        acquisition_provenance="test",
        transformation_provenance="test",
        ground_truth=GroundTruth(
            actor_label_source=ActorLabelSource.DATASET_ANNOTATION,
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            label_confidence=LabelConfidence.HIGH,
            actor_label="APT3",
        ),
        units=units,
    )


SHAPE = ExpectedOutputShape(
    outcome=ExpectedOutcome.INSUFFICIENT_EVIDENCE, authorship_provenance="test"
)


def test_recording_units_anchor_by_observation_id_and_can_be_excluded(
    tmp_path: Path, engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    source = _recording(tmp_path)
    analysis = analyze_recording(source, engine=engine, knowledge=knowledge)
    anchors = [analysis.items[g.member_evidence_ids[0]][1].observation_id for g in analysis.groups]
    units = tuple(UnitAnnotation(f"u{i}", (anchor,), SHAPE) for i, anchor in enumerate(anchors))
    cases = build_calibration_cases(
        _annotation(units), source, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    assert len(cases) == len(analysis.groups)
    # declaring the first unit as background excludes it, with its reason
    excluded = (
        UnitAnnotation("u0", (anchors[0],), None, exclusion_reason="background: test"),
        *units[1:],
    )
    fewer = build_calibration_cases(
        _annotation(excluded),
        source,
        client=FakeElasticClient(),
        engine=engine,
        knowledge=knowledge,
    )
    assert len(fewer) == len(cases) - 1
    # but an undeclared unit is still refused
    if len(units) > 1:
        with pytest.raises(CalibrationError, match="no authored unit declares"):
            build_calibration_cases(
                _annotation(units[1:]),
                source,
                client=FakeElasticClient(),
                engine=engine,
                knowledge=knowledge,
            )


def test_excluded_unit_contract() -> None:
    with pytest.raises(CalibrationError, match="exclusion_reason"):
        UnitAnnotation("u", ("a",), SHAPE, exclusion_reason="background")
    with pytest.raises(CalibrationError, match="exclusion_reason"):
        UnitAnnotation("u", ("a",), None, exclusion_reason=" ")
    with pytest.raises(CalibrationError, match="expected_output_shape"):
        UnitAnnotation("u", ("a",), None)
