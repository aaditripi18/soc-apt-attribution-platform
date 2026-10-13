"""ADR-0026: the platform's own rules. A file saved by a browser and then run is
context; it counts as User Execution and Double File Extension only when its
name passes for a document. A name alone, or a run alone, detects nothing."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import DetectionEngine, DetectionError, load_rule_pack
from attribution_platform.detection.aggregation import aggregation_from_dict
from attribution_platform.detection.evidence import derive_evidence_from_detection
from attribution_platform.detection.stateful import (
    AggregatedMatch,
    evaluate_aggregations,
    source_starts,
)
from attribution_platform.detection_content.technique_support import load_technique_support_review
from attribution_platform.domain import EvidenceQuality, Observation
from attribution_platform.sources.sysmon import SysmonSourceAdapter

REPO = Path(__file__).resolve().parents[1]
PACK = REPO / "data" / "detection" / "platform" / "platform-rules.json"
REVIEW = REPO / "data" / "detection" / "technique-support-review.json"
sys.path.insert(0, str(REPO / "scripts"))

import build_platform_rules as builder  # noqa: E402

START = datetime(2026, 1, 1, tzinfo=UTC)
BS = "\\"
DOWNLOADS = "C:" + BS + "Users" + BS + "u" + BS + "Downloads" + BS
EDGE = "C:" + BS + "Program Files (x86)" + BS + "Microsoft" + BS + "Edge" + BS + "msedge.exe"
EXPLORER = "C:" + BS + "Windows" + BS + "explorer.exe"
DECOY = DOWNLOADS + "holiday.jpeg.exe"
INSTALLER = DOWNLOADS + "setup.exe"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(PACK, knowledge=knowledge).rules)


def _event(record: int, at: float, event_id: int, host: str = "host", **data: str) -> Observation:
    (observation,) = SysmonSourceAdapter().to_observations(
        {
            "@timestamp": (START + timedelta(seconds=at)).isoformat().replace("+00:00", "Z"),
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": event_id,
                "record_id": record,
                "computer_name": host,
                "event_data": {"ProcessId": str(100 + record), **data},
            },
        }
    )
    return observation


def _saved(record: int, at: float, path: str, by: str = EDGE, host: str = "host") -> Observation:
    return _event(record, at, 11, host, Image=by, TargetFilename=path)


def _run(record: int, at: float, path: str, host: str = "host") -> Observation:
    return _event(record, at, 1, host, Image=path, CommandLine=f'"{path}"', ParentImage=EXPLORER)


def _detect(engine: DetectionEngine, observations: list[Observation]) -> list[Any]:
    pending = []
    for observation in observations:
        fired, matched = engine.evaluate_split(observation)
        assert fired == ()  # neither event detects on its own
        pending.extend(AggregatedMatch(rule, result, observation) for rule, result in matched)
    return list(evaluate_aggregations(pending, source_start=source_starts(observations)))


def _families(detections: list[Any]) -> dict[str, Any]:
    return {result.detection_source: (result, anchor) for result, anchor in detections}


def test_a_deceptively_named_download_that_is_run(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    saved = _saved(1, 0, DECOY + ":Zone.Identifier")  # the browser's download marker
    run = _run(2, 14, DECOY.upper())  # paths compare without case
    found = _families(_detect(engine, [saved, run]))
    assert set(found) == {builder.DECEPTIVE, builder.DOWNLOADED}
    result, anchor = found[builder.DECEPTIVE]
    assert anchor is run and result.evidence_quality is None  # core tier, on the execution
    assert result.supporting_observation_ids == (saved.observation_id, run.observation_id)
    assert "14s earlier" in str(result.aggregate_note) and "msedge.exe" in str(
        result.aggregate_note
    )
    assert sorted(m.attack_ref.external_id for m in result.technique_mappings) == [
        "T1036.007",
        "T1204.002",
    ]
    # the rule's logic is known in full: its review establishes both techniques
    reviewed = load_technique_support_review(REVIEW).for_source(builder.DECEPTIVE)
    evidence = derive_evidence_from_detection(result, run, knowledge=knowledge, reviewed=reviewed)
    assert [e.technique_ambiguous for e in evidence] == [False, False]
    # the same pair without a review would be declared only (ADR-0025)
    unreviewed = derive_evidence_from_detection(result, run, knowledge=knowledge)
    assert all(e.technique_ambiguous for e in unreviewed)


def test_an_ordinary_download_that_is_run_is_context_only(engine: DetectionEngine) -> None:
    found = _families(_detect(engine, [_saved(1, 0, INSTALLER), _run(2, 30, INSTALLER)]))
    assert set(found) == {builder.DOWNLOADED}  # no double extension: nothing at core tier
    result, _ = found[builder.DOWNLOADED]
    assert result.evidence_quality is EvidenceQuality.LOW
    assert [m.attack_ref.external_id for m in result.technique_mappings] == ["T1204.002"]


@pytest.mark.parametrize(
    "observations",
    [
        [_run(1, 0, DECOY)],  # run, never saved by a browser: the name alone is nothing
        [_saved(1, 0, DECOY)],  # saved, never run
        [_run(1, 0, DECOY), _saved(2, 5, DECOY)],  # run before it was saved
        [_saved(1, 0, DECOY), _run(2, 86_401, DECOY)],  # more than a day later
        [_saved(1, 0, DECOY, host="a"), _run(2, 5, DECOY, host="b")],  # another host
        [_saved(1, 0, DECOY, by=EXPLORER), _run(2, 5, DECOY)],  # not saved by a browser
        [_saved(1, 0, DECOY), _run(2, 5, INSTALLER)],  # a different file was run
    ],
)
def test_what_does_not_detect(engine: DetectionEngine, observations: list[Observation]) -> None:
    assert _detect(engine, observations) == []


def test_the_tracked_pack_is_what_the_builder_writes(knowledge: AttackKnowledge) -> None:
    assert PACK.read_text(encoding="utf-8") == builder.render()
    rules = load_rule_pack(PACK, knowledge=knowledge).rules
    assert {r.rule_source for r in rules} == {builder.DECEPTIVE, builder.DOWNLOADED}
    assert all(r.aggregation is not None and r.aggregation.kind == "sequence" for r in rules)
    # only the detecting stage maps to techniques; the first stage is a precondition
    for rule in rules:
        assert bool(rule.technique_mappings) == (rule.aggregation.stage == 2)


@pytest.mark.parametrize(
    "raw",
    [
        {
            "kind": "sequence",
            "stage": 3,
            "span_seconds": 60,
            "fields": [{"name": "a", "field_path": "x"}],
        },
        {
            "kind": "sequence",
            "stage": 1,
            "span_seconds": 0,
            "fields": [{"name": "a", "field_path": "x"}],
        },
        {"kind": "sequence", "stage": 1, "span_seconds": 60, "fields": []},
        {
            "kind": "sequence",
            "stage": 1,
            "span_seconds": 60,
            "key_form": "regex",
            "fields": [{"name": "a", "field_path": "x"}],
        },
    ],
)
def test_a_malformed_sequence_is_refused(raw: dict[str, Any]) -> None:
    with pytest.raises(DetectionError):
        aggregation_from_dict(raw, where="pack: rules[0]")


def test_the_site_labels_each_rule_with_its_own_tier() -> None:
    import json

    from attribution_platform.api.context import _platform_rule_index

    labels = _platform_rule_index(json.loads(PACK.read_text(encoding="utf-8")))
    assert {k: (v["origin"], v["content_tier"]) for k, v in labels.items()} == {
        builder.DECEPTIVE: ("platform", "core"),
        builder.DOWNLOADED: ("platform", "enrich"),  # from its detecting stage, not the first
    }
    assert all(v["title"] and v["url"] is None for v in labels.values())
