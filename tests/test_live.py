"""ADR-0028: live mode is a rolling capture analysed as reproducible snapshots.

The end-to-end check replays a real recording (OTRF comsvcs LSASS dump, tracked
in ``data/telemetry-samples/otrf``) into a followed file in two parts, and
requires each cycle's result to be exactly the investigation of the same
records run as a recording."""

from __future__ import annotations

import json
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from attribution_platform.api.server import create_server
from attribution_platform.dataplane import SharedMemoryClient
from attribution_platform.investigation.__main__ import investigation_runner, load_workbench
from attribution_platform.live.__main__ import read_model_summary
from attribution_platform.live.capture import CaptureStore, FileFollower
from attribution_platform.live.session import (
    ANALYSED,
    EMPTY,
    UNCHANGED,
    LiveSession,
    changes_between,
)
from attribution_platform.replay.recording_check import check_recording
from attribution_platform.replay.recording_pipeline import DetectionMemo, RecordingSource

REPO = Path(__file__).resolve().parents[1]
RECORDING = REPO / "data" / "telemetry-samples" / "otrf" / "psh_lsass_memory_dump_comsvcs.zip"
T0 = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def test_a_follower_returns_complete_lines_once(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_bytes(b'{"a": 1}\n{"b"')
    follower = FileFollower(log)
    assert follower.read() == ['{"a": 1}']
    assert follower.read() == []  # the partial line waits for its newline
    with log.open("ab") as handle:
        handle.write(b": 2}\r\n")
    assert follower.read() == ['{"b": 2}']


def test_a_follower_restarts_on_truncation_and_drops_a_partial_line(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_bytes(b"one\ntwo\nthr")
    follower = FileFollower(log)
    assert follower.read() == ["one", "two"]
    log.write_bytes(b"new\n")  # rotated: shorter than what was read
    assert follower.read() == ["new"]
    assert follower.dropped_partial_lines == 1
    assert FileFollower(tmp_path / "missing.log").read() == []


def test_snapshots_cover_the_window_and_are_hashed(tmp_path: Path) -> None:
    store = CaptureStore(tmp_path, "t")
    store.append(["old"], T0 - timedelta(hours=30))
    store.append(["recent"], T0 - timedelta(hours=2))
    store.append(["now"], T0)
    snapshot = store.snapshot(T0, hours=24)
    assert snapshot is not None
    assert snapshot.path.read_text(encoding="utf-8") == "recent\nnow\n"
    assert snapshot.lines == 2 and len(snapshot.sha256) == 64
    assert CaptureStore(tmp_path / "empty", "t").snapshot(T0, hours=24) is None


def test_changes_compare_two_stored_summaries() -> None:
    before = {"counted_techniques": ["T1003"], "units": 1, "verdict": "v1", "named_actors": []}
    after = {
        "counted_techniques": ["T1003.001"],
        "units": 2,
        "verdict": "v2",
        "named_actors": ["X"],
    }
    assert changes_between(None, before) == {"first_cycle": True}
    changes = changes_between(before, after)
    assert changes["techniques_newly_counted"] == ["T1003.001"]
    assert changes["techniques_no_longer_in_window"] == ["T1003"]
    assert changes["verdict"] == ["v1", "v2"] and changes["named_actors_added"] == ["X"]
    assert "verdict" not in changes_between(before, before)


def _lines() -> list[str]:
    with zipfile.ZipFile(RECORDING) as archive:
        (name,) = archive.namelist()
        return archive.read(name).decode("utf-8").splitlines()


@pytest.fixture(scope="module")
def workbench() -> Any:
    return load_workbench()


def test_each_cycle_is_the_investigation_of_its_snapshot(tmp_path: Path, workbench: Any) -> None:
    lines = _lines()
    half = len(lines) // 2
    followed = tmp_path / "followed.log"
    client = SharedMemoryClient()
    clock = iter(
        [T0, T0 + timedelta(minutes=1), T0 + timedelta(minutes=2), T0 + timedelta(minutes=3)]
    )
    memo = DetectionMemo()
    session = LiveSession(
        name="t",
        followers=[FileFollower(followed)],
        store=CaptureStore(tmp_path / "live", "t"),
        check=check_recording,
        run=investigation_runner(client, workbench, detection_memo=memo),
        summarise=lambda investigation_id: read_model_summary(client, investigation_id),
        clock=lambda: next(clock),
    )
    assert session.cycle().state == EMPTY  # nothing written yet

    followed.write_text("\n".join(lines[:half]) + "\n", encoding="utf-8", newline="\n")
    first = session.cycle()
    evaluated_first = memo.evaluated
    with followed.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines[half:]) + "\n")
    second = session.cycle()
    third = session.cycle()  # nothing new arrived
    assert (first.state, second.state, third.state) == (ANALYSED, ANALYSED, UNCHANGED)
    assert first.changes == {"first_cycle": True}
    assert second.changes is not None and third.investigation_id is None

    # the live result is exactly the recording run of the same records
    batch = tmp_path / "batch.log"
    batch.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    report = check_recording(batch)
    reference_client = SharedMemoryClient()
    reference = investigation_runner(reference_client, workbench)(
        RecordingSource("batch", batch, report.sha256, report.declared_sources)
    )
    assert second.snapshot_sha256 == report.sha256
    # the second cycle evaluated only what arrived; the first half was reused, unchanged
    assert memo.reused == evaluated_first > 0
    assert 0 < memo.evaluated - evaluated_first < memo.evaluated
    assert second.evidence and "T1003.001" in second.summary["counted_techniques"]  # type: ignore[index]
    assert (second.evidence, second.units) == (reference.evidence, reference.units)
    assert second.summary is not None
    expected = {**read_model_summary(reference_client, reference.investigation_id)}
    assert second.summary["counted_techniques"] == expected["counted_techniques"]
    assert second.summary["verdict"] == expected["verdict"]

    # the console reads the status, and the cycle's investigation like any other
    server = create_server(client, live=session)
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/api"
        with urllib.request.urlopen(base + "/live") as response:
            status = json.loads(response.read())
        assert status["enabled"] and [c["state"] for c in status["cycles"]][:3] == [
            UNCHANGED,
            ANALYSED,
            ANALYSED,
        ]
        with urllib.request.urlopen(base + "/investigations") as response:
            served = {i["investigation_id"] for i in json.loads(response.read())}
        assert {first.investigation_id, second.investigation_id} <= served
    finally:
        server.shutdown()
        server.server_close()


def test_without_a_live_session_the_status_says_so() -> None:
    server = create_server(SharedMemoryClient())
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/live"
        with urllib.request.urlopen(url) as response:
            assert json.loads(response.read()) == {"enabled": False}
    finally:
        server.shutdown()
        server.server_close()


class _Index:
    """An in-memory index answering the one query shape the source sends:
    documents with the time field, at or after a time, ascending, one page."""

    def __init__(self) -> None:
        self.documents: list[tuple[str, dict[str, Any]]] = []
        self.queries: list[dict[str, Any]] = []

    def search_hits(
        self, index: str, query: Any, *, size: int, sort: Any
    ) -> tuple[tuple[str, Any], ...]:
        self.queries.append(query)
        (field,) = sort
        filters = query["bool"]["filter"]
        floor = filters[1]["range"][field]["gte"] if len(filters) > 1 else None
        excluded = set(query["bool"].get("must_not", [{"ids": {"values": []}}])[0]["ids"]["values"])
        found = sorted(
            (
                (d[field], i, d)
                for i, d in self.documents
                if field in d and (floor is None or d[field] >= floor) and i not in excluded
            ),
            key=lambda row: (row[0], row[1]),
        )
        return tuple((i, d) for _, i, d in found[:size])


def test_elasticsearch_documents_are_read_once_in_time_order() -> None:
    from attribution_platform.live.elastic_source import ElasticsearchSource

    index = _Index()
    index.documents += [
        ("a", {"event.ingested": "2026-10-19T10:00:00Z", "n": 1}),
        ("b", {"event.ingested": "2026-10-19T10:00:00Z", "n": 2}),
        ("c", {"event.ingested": "2026-10-19T10:00:01Z", "n": 3}),
        ("x", {"n": 0}),  # no time: never read
    ]
    source = ElasticsearchSource(index, "logs-*", page_size=2)
    assert [json.loads(line)["n"] for line in source.read()] == [1, 2, 3]
    assert source.read() == []  # nothing new
    # a document arriving at the time already read is read, and only it
    index.documents.append(("d", {"event.ingested": "2026-10-19T10:00:01Z", "n": 4}))
    assert [json.loads(line)["n"] for line in source.read()] == [4]
    # more documents at one time than a page holds: all read, none twice
    index.documents += [
        (f"s{k}", {"event.ingested": "2026-10-19T11:00:00Z", "n": k}) for k in range(5)
    ]
    assert sorted(json.loads(line)["n"] for line in source.read()) == [0, 1, 2, 3, 4]
    assert source.read() == [] and source.documents_read == 9


def test_search_hits_is_a_bounded_read_only_search() -> None:
    from attribution_platform.dataplane.errors import ElasticIntegrationError
    from attribution_platform.dataplane.http_client import ElasticsearchHttpClient

    client = ElasticsearchHttpClient.__new__(ElasticsearchHttpClient)
    sent: list[tuple[str, str, Any]] = []

    def answer(method: str, path: str, body: Any) -> tuple[int, Any]:
        sent.append((method, path, body))
        return 200, {"hits": {"hits": [{"_id": "1", "_source": {"a": 1}}]}}

    client._request = answer  # type: ignore[method-assign]
    hits = client.search_hits("logs-*", {"match_all": {}}, size=5, sort=("event.ingested",))
    assert hits == (("1", {"a": 1}),)
    method, path, body = sent[0]
    assert (method, path) == ("POST", "/logs-%2A/_search")
    assert body["size"] == 5 and body["sort"] == [{"event.ingested": {"order": "asc"}}]
    client._request = lambda *_: (200, {"hits": {"hits": [{"_source": {}}]}})  # type: ignore[method-assign]
    with pytest.raises(ElasticIntegrationError):
        client.search_hits("logs-*", {}, size=1, sort=("t",))
