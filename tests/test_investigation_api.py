"""ADR-0009: investigation runs persist every read-model object, and the API
serves them unchanged — with attribution analyses that are explicitly
uncalibrated (no likelihood, confidence, WEP, verdict or rank field anywhere)."""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api import create_server
from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.investigation import (
    load_attribution_analysis,
    load_investigation,
    run_investigation,
)
from attribution_platform.replay import load_detection_replay_fixture_file
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
HOST = "WS01.example.local"
FORBIDDEN_KEYS = ("likelihood", "confidence", "wep", "verdict", "rank", "probability")


def _process_create(
    record_id: int, second: int, guid: str, parent: str, image: str, cmd: str
) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-01-01T12:00:{second:02d}.000Z",
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
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
            },
        },
    }


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def pack(knowledge: AttackKnowledge) -> RulePack:
    return load_rule_pack(SIGMA_PACK, knowledge=knowledge)


@pytest.fixture(scope="module")
def recording(tmp_path_factory: pytest.TempPathFactory) -> RecordingSource:
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    whoami = "C:\\Windows\\System32\\whoami.exe"
    records = [
        _process_create(1, 1, "{P}", "{ROOT}", ps, "powershell.exe -nop -w hidden -enc SQBFAFgA"),
        _process_create(2, 2, "{A}", "{P}", whoami, "whoami /all -all"),
        _process_create(3, 3, "{B}", "{P}", whoami, "whoami /all -all"),
    ]
    path = tmp_path_factory.mktemp("rec") / "rec.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("rec.json", "\n".join(json.dumps(r) for r in records) + "\n")
    return RecordingSource(
        recording_id="rec-api-test",
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        declared_sources={HOST: ("sysmon",)},
    )


@pytest.fixture(scope="module")
def investigated(
    recording: RecordingSource, knowledge: AttackKnowledge, pack: RulePack
) -> tuple[FakeElasticClient, str, tuple[str, ...]]:
    client = FakeElasticClient()
    record = run_investigation(
        recording,
        client=client,
        engine=DetectionEngine(rules=pack.rules),
        knowledge=knowledge,
        detection_pack_content_hash=pack.content_hash,
    )
    return client, record.investigation_id, record.units


def _keys(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key).lower()
            yield from _keys(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _keys(inner)


# ===========================================================================
# Engine side: the investigation run
# ===========================================================================


def test_investigation_persists_record_and_one_analysis_per_unit(
    investigated: tuple[FakeElasticClient, str, tuple[str, ...]],
) -> None:
    client, investigation_id, units = investigated
    record = load_investigation(client, investigation_id)
    assert record is not None and record["source_kind"] == "recording"
    assert units and tuple(record["units"]) == units
    for group_id in units:
        analysis = load_attribution_analysis(client, group_id)
        assert analysis is not None
        assert analysis["investigation_id"] == investigation_id
        assert analysis["calibration_status"] == "uncalibrated"
        assert analysis["calibration_version"] is None
        assert analysis["candidates"], "a whoami + encoded-PowerShell unit has ATT&CK candidates"


def test_analysis_carries_no_uncalibrated_decision_fields(
    investigated: tuple[FakeElasticClient, str, tuple[str, ...]],
) -> None:
    client, _, units = investigated
    for group_id in units:
        analysis = dict(load_attribution_analysis(client, group_id) or {})
        keys = set(_keys(analysis))
        assert not [k for k in keys if any(f in k for f in FORBIDDEN_KEYS)]
        hypothesis_ids = [h["hypothesis_id"] for h in analysis["hypotheses"]]
        assert hypothesis_ids == sorted(hypothesis_ids)  # id order, never by support
        for hypothesis in analysis["hypotheses"]:
            for contribution in hypothesis["contributions"]:
                if contribution["g_value"] is not None:
                    assert contribution["d_value"] == pytest.approx(1 - contribution["g_value"])


def test_investigation_id_is_deterministic(
    recording: RecordingSource,
    knowledge: AttackKnowledge,
    pack: RulePack,
    investigated: tuple[FakeElasticClient, str, tuple[str, ...]],
) -> None:
    again = run_investigation(
        recording,
        client=FakeElasticClient(),
        engine=DetectionEngine(rules=pack.rules),
        knowledge=knowledge,
        detection_pack_content_hash=pack.content_hash,
    )
    assert again.investigation_id == investigated[1]
    assert again.units == investigated[2]


def test_fixture_sources_investigate_too() -> None:
    fixture_kb = load_attack_knowledge("enterprise-attack-19.0")
    core = load_rule_pack(REPO_ROOT / "fixtures" / "phase1_core_rules.json", knowledge=fixture_kb)
    fixture = load_detection_replay_fixture_file(
        REPO_ROOT
        / "data"
        / "calibration"
        / "corpus"
        / "v1"
        / "scenarios"
        / "v1-cal-alpha-ingress.fixture.json"
    )
    client = FakeElasticClient()
    record = run_investigation(
        fixture,
        client=client,
        engine=DetectionEngine(rules=core.rules),
        knowledge=fixture_kb,
        detection_pack_content_hash=core.content_hash,
    )
    assert record.source_kind == "fixture" and record.units
    assert load_attribution_analysis(client, record.units[0]) is not None


# ===========================================================================
# API side: served unchanged over HTTP
# ===========================================================================


@pytest.fixture(scope="module")
def base_url(
    investigated: tuple[FakeElasticClient, str, tuple[str, ...]],
) -> Iterator[str]:
    server = create_server(investigated[0])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _get(url: str) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - local test server
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_health(base_url: str) -> None:
    status, body = _get(f"{base_url}/health")
    assert status == 200 and body == {"api": "read-model/1", "backend": "reachable", "status": "ok"}


def test_investigations_list_and_detail(
    base_url: str, investigated: tuple[FakeElasticClient, str, tuple[str, ...]]
) -> None:
    _, investigation_id, units = investigated
    status, listing = _get(f"{base_url}/investigations")
    assert status == 200
    assert [i["investigation_id"] for i in listing] == [investigation_id]
    assert listing[0]["units"] == len(units)
    status, detail = _get(f"{base_url}/investigations/{investigation_id}")
    assert status == 200 and detail["source_id"] == "rec-api-test"


def test_unit_serves_group_sequence_and_analysis(
    base_url: str, investigated: tuple[FakeElasticClient, str, tuple[str, ...]]
) -> None:
    client, _, units = investigated
    status, unit = _get(f"{base_url}/units/{units[0]}")
    assert status == 200
    assert unit["group"]["group_id"] == units[0]
    assert unit["sequence"]["group_id"] == units[0]
    assert unit["attribution_analysis"] == dict(load_attribution_analysis(client, units[0]) or {})


def test_errors_are_typed(base_url: str) -> None:
    assert _get(f"{base_url}/units/no-such-unit")[0] == 404
    assert _get(f"{base_url}/investigations/no-such-investigation")[0] == 404
    assert _get(f"{base_url}/units/")[0] == 400
    assert _get(f"{base_url}/nothing-here")[0] == 404
    request = urllib.request.Request(f"{base_url}/investigations", method="POST", data=b"{}")
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(request, timeout=10)  # noqa: S310 - local test server
    assert raised.value.code == 501  # no mutation routes exist
