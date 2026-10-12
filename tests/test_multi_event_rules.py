"""ADR-0015 Amendment C: threshold and new-terms rules. A multi-event rule never
detects on one event; a threshold detects only what Elastic would under every
schedule; a value is new only when the recording holds the history to say so."""

from __future__ import annotations

import dataclasses
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import DetectionEngine, DetectionError
from attribution_platform.detection.aggregation import (
    Aggregation,
    AggregationField,
    aggregation_from_dict,
)
from attribution_platform.detection.evidence import derive_evidence_from_detection
from attribution_platform.detection.stateful import (
    AggregatedMatch,
    evaluate_aggregations,
    source_starts,
)
from attribution_platform.domain import Observation
from attribution_platform.sources.sysmon import SysmonSourceAdapter

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_elastic_import import BS, _import, _toml  # noqa: E402

START = datetime(2026, 1, 1, tzinfo=UTC)
CMD = "C:" + BS + "Windows" + BS + "System32" + BS + "cmd.exe"
SVCHOST = "C:" + BS + "Windows" + BS + "System32" + BS + "svchost.exe"
WMIPRVSE = "C:" + BS + "Windows" + BS + "System32" + BS + "wbem" + BS + "WmiPrvSE.exe"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _process(record: int, at: timedelta, parent: str = SVCHOST, image: str = CMD) -> Observation:
    (observation,) = SysmonSourceAdapter().to_observations(
        {
            "@timestamp": (START + at).isoformat().replace("+00:00", "Z"),
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "record_id": record,
                "computer_name": "host",
                "event_data": {
                    "ProcessId": str(100 + record),
                    "Image": image,
                    "ParentImage": parent,
                    "CommandLine": "cmd.exe /c echo",
                },
            },
        }
    )
    return observation


def _detect(
    engine: DetectionEngine, observations: list[Observation]
) -> list[tuple[str, tuple[str, ...], str]]:
    pending = []
    for observation in observations:
        fired, matched = engine.evaluate_split(observation)
        assert fired == ()  # a multi-event rule never detects on one event
        pending.extend(AggregatedMatch(rule, result, observation) for rule, result in matched)
    out = evaluate_aggregations(pending, source_start=source_starts(observations))
    assert out == evaluate_aggregations(
        list(reversed(pending)), source_start=source_starts(observations)
    )
    assert engine.evaluate(observations) == ()
    return [
        (anchor.observation_id, result.supporting_observation_ids, str(result.aggregate_note))
        for result, anchor in out
    ]


# inline tables: the helper writes ``query`` after this, still inside ``[rule]``
THRESHOLD = 'from = "now-9m"\nthreshold = { field = ["process.parent.name"], value = 3 }\n'
QUERY = 'event.category:process and process.name:"cmd.exe"'


def test_a_threshold_counts_events_close_enough_for_every_schedule(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    rules = {"th": _toml("th", QUERY, rule_type="threshold", language="kuery", extra=THRESHOLD)}
    pack, report, engine = _import(tmp_path, knowledge, rules)
    assert report["th"]["status"] == "imported" and report["th"]["multi_event"] == "threshold"
    (aggregation,) = {str(r["aggregation"]) for r in pack["rules"]}
    # look-back 9 minutes, default interval 5: only 4 minutes are inside every window
    assert "'span_seconds': 240" in aggregation and "'count': 3" in aggregation

    minute = timedelta(minutes=1)
    # three in four minutes: detected, on the third, naming all three
    burst = [_process(i, i * 2 * minute) for i in range(3)]
    ((anchor, supporting, note),) = _detect(engine, burst)
    assert anchor == burst[2].observation_id
    assert supporting == tuple(o.observation_id for o in burst)
    assert "3 matching events (needs 3)" in note and "process.parent.name='svchost.exe'" in note
    assert "within 240s" in note and "first at 2026-01-01T00:00:00Z" in note
    # three in five minutes: Elastic may or may not see them together, so nothing
    assert _detect(engine, [_process(i, i * 2.5 * minute) for i in range(3)]) == []
    # a different parent is a different group; a non-matching process is not counted
    mixed = [
        _process(1, 0 * minute),
        _process(2, 1 * minute, parent=WMIPRVSE),
        _process(3, 2 * minute, image=SVCHOST),
        _process(4, 3 * minute),
    ]
    assert _detect(engine, mixed) == []
    # after a detection the group starts again: six events are two detections
    six = [_process(i, i * timedelta(seconds=30)) for i in range(6)]
    assert [a for a, _, _ in _detect(engine, six)] == [six[2].observation_id, six[5].observation_id]


def test_a_cardinality_needs_distinct_values(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    extra = (
        'from = "now-9m"\nthreshold = { field = [], value = 2, '
        'cardinality = [{ field = "process.parent.name", value = 2 }] }\n'
    )
    rules = {"card": _toml("card", QUERY, rule_type="threshold", language="kuery", extra=extra)}
    _, report, engine = _import(tmp_path, knowledge, rules)
    assert report["card"]["status"] == "imported"
    same = [_process(i, timedelta(seconds=i)) for i in range(4)]
    assert _detect(engine, same) == []  # four events, one parent
    two = [*same, _process(9, timedelta(seconds=9), parent=WMIPRVSE)]
    ((anchor, supporting, note),) = _detect(engine, two)
    assert anchor == two[-1].observation_id and len(supporting) == 5
    assert "for all events" in note and "2 distinct process.parent.name (needs 2)" in note


NEW_TERMS = (
    'new_terms = { field = "new_terms_fields", value = ["process.parent.name"], '
    'history_window_start = [{ field = "history_window_start", value = "now-7d" }] }\n'
)


def test_a_value_is_new_only_when_the_recording_holds_the_history(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    rules = {"nt": _toml("nt", QUERY, rule_type="new_terms", language="kuery", extra=NEW_TERMS)}
    pack, report, engine = _import(tmp_path, knowledge, rules)
    assert report["nt"]["status"] == "imported" and report["nt"]["multi_event"] == "new_terms"
    assert all(r["aggregation"]["history_seconds"] == 7 * 86400 for r in pack["rules"])
    day = timedelta(days=1)

    # a short recording: the history is unknown, so nothing is called new
    assert _detect(engine, [_process(1, 0 * day), _process(2, timedelta(minutes=5))]) == []

    recording = [
        _process(1, 0 * day, image=SVCHOST),  # the log source is recorded from here
        _process(2, 1 * day),  # svchost -> cmd: history is only one day deep
        _process(3, 8 * day),  # the same value 7 days later: seen within the window
        _process(4, 8 * day + timedelta(hours=1), parent=WMIPRVSE),  # never seen, 8 days known
        _process(5, 9 * day, parent=WMIPRVSE),  # seen an hour less than a day ago
        _process(6, 17 * day),  # svchost -> cmd again, 9 days after the last
    ]
    fired = _detect(engine, recording)
    assert [anchor for anchor, _, _ in fired] == sorted(
        [recording[3].observation_id, recording[5].observation_id]
    )
    notes = {anchor: note for anchor, _, note in fired}
    assert "process.parent.name='WmiPrvSE.exe'" in notes[recording[3].observation_id]
    assert "7 days before" in notes[recording[3].observation_id]
    assert "recorded since 2026-01-01T00:00:00Z" in notes[recording[3].observation_id]
    assert all(supporting == (anchor,) for anchor, supporting, _ in fired)


def test_an_incompletely_translated_new_terms_rule_is_not_imported(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    # one OR branch reads a field this platform does not have: the events it would
    # match are history the platform cannot see
    query = 'event.category:process and (process.name:"cmd.exe" or no.such.field:"x")'
    missing = NEW_TERMS.replace("process.parent.name", "no.such.field")
    rules = {
        "branch": _toml("branch", query, rule_type="new_terms", language="kuery", extra=NEW_TERMS),
        "field": _toml("field", QUERY, rule_type="new_terms", language="kuery", extra=missing),
        "bare": _toml("bare", QUERY, rule_type="new_terms", language="kuery"),
        # the same OR under a threshold only counts fewer events: imported in part
        "th": _toml("th", query, rule_type="threshold", language="kuery", extra=THRESHOLD),
        "tight": _toml(
            "tight",
            QUERY,
            rule_type="threshold",
            language="kuery",
            extra=THRESHOLD.replace("now-9m", "now-5m"),
        ),
    }
    pack, report, _ = _import(tmp_path, knowledge, rules)
    assert report["branch"]["status"] == "rejected"
    assert report["branch"]["gap_reasons"]["new_terms:incomplete_query"] == 1
    assert "telemetry_gap:field:no.such.field" in report["field"]["gap_reasons"]
    assert "translation_gap:new_terms:unreadable_specification" in report["bare"]["gap_reasons"]
    assert report["th"]["status"] == "partial"
    assert set(report["tight"]["gap_reasons"]) == {"translation_gap:threshold:no_guaranteed_window"}
    assert {r["rule_source"] for r in pack["rules"]} == {"elastic:th"}


def test_the_evidence_says_what_was_counted(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    rules = {"th": _toml("th", QUERY, rule_type="threshold", language="kuery", extra=THRESHOLD)}
    _, _, engine = _import(tmp_path, knowledge, rules)
    burst = [_process(i, timedelta(seconds=i)) for i in range(3)]
    pending = [
        AggregatedMatch(rule, result, observation)
        for observation in burst
        for rule, result in engine.evaluate_split(observation)[1]
    ]
    ((detection, anchor),) = evaluate_aggregations(pending, source_start={})
    (evidence,) = derive_evidence_from_detection(detection, anchor, knowledge=knowledge)
    assert "[threshold: 3 matching events (needs 3)" in evidence.claim
    assert evidence.provenance.source_observation_ids == (anchor.observation_id,)
    with pytest.raises(ValueError, match="aggregated rules only"):
        evaluate_aggregations([_plain(pending[0])], source_start={})


def _plain(match: AggregatedMatch) -> AggregatedMatch:
    return AggregatedMatch(
        dataclasses.replace(match.rule, aggregation=None), match.result, match.observation
    )


@pytest.mark.parametrize(
    "raw",
    [
        "threshold",
        {"kind": "sequence"},
        {"kind": "threshold", "count": 0, "span_seconds": 60},
        {"kind": "threshold", "count": 2, "span_seconds": 0},
        {"kind": "threshold", "count": 2.5, "span_seconds": 60},
        {"kind": "threshold", "count": True, "span_seconds": 60},
        {"kind": "threshold", "count": 2, "span_seconds": 60, "fields": [{"name": "a"}]},
        {
            "kind": "threshold",
            "count": 2,
            "span_seconds": 60,
            "fields": [{"name": "a", "field_path": "x", "constant": "y"}],
        },
        {
            "kind": "threshold",
            "count": 2,
            "span_seconds": 60,
            "cardinality": [{"field": {"name": "a", "constant": "y"}, "count": 0}],
        },
        {"kind": "new_terms", "fields": [], "history_seconds": 60},
        {"kind": "new_terms", "fields": [{"name": "a", "constant": "y"}]},
    ],
)
def test_a_malformed_aggregation_is_refused_at_load(raw: Any) -> None:
    with pytest.raises(DetectionError):
        aggregation_from_dict(raw, where="pack: rules[0]")


def test_a_well_formed_aggregation_loads() -> None:
    loaded = aggregation_from_dict(
        {
            "kind": "threshold",
            "count": 5,
            "span_seconds": 240,
            "fields": [{"name": "user.name", "field_path": "elastic_okta.user.name"}],
            "cardinality": [{"field": {"name": "x", "constant": "y"}, "count": 2}],
        },
        where="t",
    )
    assert loaded == Aggregation(
        kind="threshold",
        fields=(AggregationField("user.name", field_path="elastic_okta.user.name"),),
        count=5,
        span_seconds=240.0,
        cardinality=((AggregationField("x", constant="y"), 2),),
    )
