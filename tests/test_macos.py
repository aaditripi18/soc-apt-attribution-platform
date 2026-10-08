"""macOS telemetry (ADR-0014): osquery ``es_process_events`` exec rows (Apple
Endpoint Security) — the adapter, its routing and persistence.

The golden file holds every real macOS record of the pinned selection
(``splunk/attack_data``, Apache-2.0, 25 rows), so these tests run the whole real
dataset: exact fields, osquery's argument separator, refusals, routing and
persistence.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.dataplane.persistence import _observation_from_document
from attribution_platform.domain import Observation, TimePrecision, to_serializable
from attribution_platform.replay.recording_pipeline import (
    DEFAULT_CHANNEL_ADAPTERS,
    OSQUERY_ES_CHANNEL,
    _channel,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.osquery_es import OsqueryEsSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
MACOS = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-macos"
ROWS: list[dict[str, Any]] = [
    json.loads(line)
    for line in (MACOS / "golden-records.jsonl").read_text(encoding="utf-8").splitlines()
]
RECORDS: dict[str, dict[str, Any]] = {r["golden_id"]: json.loads(r["record"]) for r in ROWS}
ADAPTER = OsqueryEsSourceAdapter()


def _convert(record: dict[str, Any]) -> Observation:
    (obs,) = ADAPTER.to_observations(record)
    return obs


def _with_columns(golden_id: str, **changes: Any) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(json.dumps(RECORDS[golden_id]))
    record["columns"].update(changes)
    return record


# ===========================================================================
# Exact fields
# ===========================================================================


def test_every_real_record_converts_as_a_macos_process_start() -> None:
    observations = [_convert(record) for record in RECORDS.values()]
    assert len(observations) == 25
    assert len({o.observation_id for o in observations}) == 25
    for obs in observations:
        assert obs.host is not None and obs.host.os_type == "macos"
        assert obs.event is not None
        assert (obs.event.category, obs.event.type) == (("process",), ("start",))
        assert obs.process is not None and obs.process.command_line is not None
        assert not obs.process.command_line.endswith(" ")  # osquery's separator removed


def test_plistbuddy_record_is_exact() -> None:
    golden_id = next(g for g in RECORDS if "LSFileQuarantineEnabled" in g)
    record = RECORDS[golden_id]
    obs = _convert(record)
    columns = record["columns"]
    # the Endpoint Security event time, not the query's run time
    assert obs.timestamp == datetime.fromtimestamp(int(columns["time"]), tz=UTC)
    assert int(columns["time"]) != record["unixTime"]
    assert obs.timestamp_precision is TimePrecision.SECOND
    process = obs.process
    assert process is not None
    assert process.executable == "/usr/libexec/PlistBuddy"
    assert process.name == "PlistBuddy"
    assert process.command_line == columns["cmdline"][:-1]
    assert process.command_line.endswith("/Contents/Info.plist")
    assert (process.pid, process.parent_pid) == (int(columns["pid"]), int(columns["parent"]))
    assert obs.host is not None and obs.host.name == record["hostIdentifier"]


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"event_type": "fork"}, "is not a process start"),
        ({"cmdline": "xattr -c myapp.app"}, "lacks osquery's argument separator"),
        ({"time": "2025-12-15"}, "not a non-negative integer"),
        ({"pid": "-1"}, "not a non-negative integer"),
    ],
)
def test_records_fail_closed(changes: dict[str, Any], match: str) -> None:
    golden_id = next(iter(RECORDS))
    with pytest.raises(SourceAdapterError, match=match):
        _convert(_with_columns(golden_id, **changes))


def test_query_name_does_not_matter_but_columns_do() -> None:
    golden_id = next(iter(RECORDS))
    renamed = {**RECORDS[golden_id], "name": "any_operator_name"}
    assert _convert(renamed) == _convert(RECORDS[golden_id])
    record = json.loads(json.dumps(RECORDS[golden_id]))
    del record["columns"]["global_seq_num"]
    with pytest.raises(SourceAdapterError, match="not an osquery es_process_events row"):
        _convert(record)


@pytest.mark.parametrize("golden_id", sorted(RECORDS))
def test_records_route_and_round_trip(golden_id: str) -> None:
    assert _channel(RECORDS[golden_id]) == OSQUERY_ES_CHANNEL
    assert isinstance(DEFAULT_CHANNEL_ADAPTERS[OSQUERY_ES_CHANNEL], OsqueryEsSourceAdapter)
    obs = _convert(RECORDS[golden_id])
    assert _observation_from_document(json.loads(json.dumps(to_serializable(obs)))) == obs
