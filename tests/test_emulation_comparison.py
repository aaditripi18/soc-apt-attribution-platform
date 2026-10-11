"""ADR-0019: ran versus detected, and the investigation activity view.

An emulation tool's report says what was run; the platform is given telemetry
only. The comparison ties each reported step to the Evidence of that step's own
process, by fixed rules, and never reads the report's command text.
"""

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
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.pinned import SIGMA_PACK
from attribution_platform.investigation import run_investigation
from attribution_platform.investigation.__main__ import main
from attribution_platform.investigation.emulation import (
    NOT_DETECTED,
    OUTCOMES,
    STEP_ACTIVITY_DETECTED,
    TECHNIQUE_DETECTED_ELSEWHERE,
    TECHNIQUE_DETECTED_IN_STEP,
    EmulationReportError,
    load_emulation_comparison,
    parse_caldera_report,
)
from attribution_platform.replay.recording_pipeline import RecordingSource

HOST = "WS01.example.local"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
WHOAMI = "C:\\Windows\\System32\\whoami.exe"
SECRET = "do-not-store-this-command-text"


def _process_create(record_id: int, guid: str, parent: str, image: str, cmd: str) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-01-01T12:00:{record_id:02d}.000Z",
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "UtcTime": f"2026-01-01 12:00:{record_id:02d}.000",
                "ProcessGuid": guid,
                "ProcessId": str(1000 + record_id),
                "Image": image,
                "CommandLine": cmd,
                "ParentProcessGuid": parent,
            },
        },
    }


def _step(name: str, technique: str, issued: int, pid: int, status: int = 0) -> dict[str, Any]:
    return {
        "ability_id": f"ability-{name}",
        "name": name,
        "attack": {"tactic": "discovery", "technique_id": technique, "technique_name": name},
        "delegated": f"2026-01-01T12:00:{issued:02d}Z",
        "run": f"2026-01-01T12:00:{issued + 3:02d}Z",
        "status": status,
        "pid": pid,
        "executor": "psh",
        "command": SECRET,
        "plaintext_command": SECRET,
        "output": {"stdout": SECRET},
    }


def _report() -> dict[str, Any]:
    """Four steps: one whose process the recording shows doing that technique, one
    whose process shows other activity, one whose technique shows up elsewhere
    only, and one the recording holds nothing of."""
    return {
        "name": "op-test",
        "start": "2026-01-01T12:00:00Z",
        "finish": "2026-01-01T12:01:00Z",
        "adversary": {"name": "Test profile"},
        "host_group": [{"paw": "abc", "host": "WS01"}],
        "steps": {
            "abc": {
                "steps": [
                    _step("whoami in its own process", "T1033", 1, 1002),
                    _step("launcher only", "T1135", 1, 1001),
                    _step("technique elsewhere", "T1033", 40, 4242),
                    _step("nothing recorded", "T1518.001", 50, 5555, status=1),
                ]
            }
        },
    }


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def recording(tmp_path_factory: pytest.TempPathFactory) -> Path:
    records = [
        _process_create(
            1, "{P}", "{ROOT}", POWERSHELL, "powershell.exe -nop -w hidden -enc SQBFAFgA"
        ),
        _process_create(2, "{A}", "{P}", WHOAMI, "whoami /all -all"),
    ]
    path = tmp_path_factory.mktemp("rec") / "lab-run.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("run.json", "\n".join(json.dumps(r) for r in records) + "\n")
    return path


@pytest.fixture(scope="module")
def compared(
    knowledge: AttackKnowledge, recording: Path
) -> tuple[FakeElasticClient, str, tuple[str, ...]]:
    raw = json.dumps(_report()).encode()
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    client = FakeElasticClient()
    record = run_investigation(
        RecordingSource(
            recording_id="lab-run.zip",
            path=recording,
            sha256=hashlib.sha256(recording.read_bytes()).hexdigest(),
            declared_sources={HOST: ("sysmon",)},
        ),
        client=client,
        engine=DetectionEngine(rules=pack.rules),
        knowledge=knowledge,
        detection_pack_content_hash=pack.content_hash,
        emulation=parse_caldera_report(raw, sha256=hashlib.sha256(raw).hexdigest()),
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
# The report
# ===========================================================================


def test_report_is_read_for_what_ran_and_never_for_its_commands() -> None:
    raw = json.dumps(_report()).encode()
    run = parse_caldera_report(raw, sha256="x")
    assert (run.tool, run.operation_name, run.profile_name) == (
        "MITRE CALDERA",
        "op-test",
        "Test profile",
    )
    assert [s.order for s in run.steps] == [1, 2, 3, 4]
    assert {s.host for s in run.steps} == {"WS01"}
    assert [s.status for s in run.steps] == ["success", "success", "success", "failed"]
    assert run.steps[0].technique_id == "T1033" and run.steps[0].pid == 1002
    assert SECRET not in repr(run)


@pytest.mark.parametrize("bad", [b"not json", b"[]", b'{"steps": []}', b'{"steps": {"a": {}}}'])
def test_another_shape_is_refused(bad: bytes) -> None:
    with pytest.raises(EmulationReportError):
        parse_caldera_report(bad, sha256="x")


# ===========================================================================
# The comparison
# ===========================================================================


def test_each_step_gets_the_outcome_its_evidence_supports(
    compared: tuple[FakeElasticClient, str, tuple[str, ...]],
) -> None:
    client, investigation_id, units = compared
    record = dict(load_emulation_comparison(client, investigation_id) or {})
    steps = {s["name"]: s for s in record["steps"]}

    own = steps["whoami in its own process"]
    assert own["outcome"] == TECHNIQUE_DETECTED_IN_STEP
    assert "T1033" in own["step_technique_ids"] and own["step_evidence"] >= 1
    assert set(own["step_unit_ids"]) <= set(units) and own["step_unit_ids"]

    launcher = steps["launcher only"]  # its process is seen, its technique (T1135) is not
    assert launcher["outcome"] == STEP_ACTIVITY_DETECTED
    assert launcher["step_evidence"] >= 1 and "T1135" not in launcher["step_technique_ids"]
    assert launcher["technique_evidence_core"] + launcher["technique_evidence_context"] == 0

    elsewhere = steps["technique elsewhere"]  # T1033 was found, but not in this step's process
    assert elsewhere["outcome"] == TECHNIQUE_DETECTED_ELSEWHERE
    assert elsewhere["step_evidence"] == 0
    assert elsewhere["technique_evidence_core"] + elsewhere["technique_evidence_context"] >= 1

    nothing = steps["nothing recorded"]
    assert nothing["outcome"] == NOT_DETECTED and nothing["status"] == "failed"
    assert nothing["step_evidence"] == 0

    assert record["outcome_counts"] == {
        TECHNIQUE_DETECTED_IN_STEP: 1,
        STEP_ACTIVITY_DETECTED: 1,
        TECHNIQUE_DETECTED_ELSEWHERE: 1,
        NOT_DETECTED: 1,
    }
    assert set(record["outcome_counts"]) == set(OUTCOMES)
    assert (record["distinct_techniques"], record["distinct_techniques_with_evidence"]) == (3, 1)


def test_the_stored_comparison_carries_no_command_text_and_no_decision_field(
    compared: tuple[FakeElasticClient, str, tuple[str, ...]],
) -> None:
    client, investigation_id, _ = compared
    record = load_emulation_comparison(client, investigation_id)
    text = json.dumps(record)
    assert SECRET not in text
    keys = set(_keys(record))
    assert not keys & {"command", "plaintext_command", "output"}
    assert not [
        k for k in keys if any(w in k for w in ("likelihood", "confidence", "rank", "score"))
    ]


def test_a_step_outside_its_time_window_or_on_another_host_is_not_matched(
    knowledge: AttackKnowledge, recording: Path
) -> None:
    report = _report()
    report["steps"]["abc"]["steps"] = [_step("late", "T1033", 30, 1002)]  # right pid, wrong time
    report["host_group"] = [{"paw": "abc", "host": "WS01"}]
    other = json.loads(json.dumps(report))
    other["steps"]["abc"]["steps"] = [_step("other host", "T1033", 1, 1002)]
    other["host_group"] = [{"paw": "abc", "host": "SERVER9"}]
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    for document in (report, other):
        raw = json.dumps(document).encode()
        client = FakeElasticClient()
        record = run_investigation(
            RecordingSource(
                recording_id="lab-run.zip",
                path=recording,
                sha256=hashlib.sha256(recording.read_bytes()).hexdigest(),
                declared_sources={HOST: ("sysmon",)},
            ),
            client=client,
            engine=DetectionEngine(rules=pack.rules),
            knowledge=knowledge,
            detection_pack_content_hash=pack.content_hash,
            emulation=parse_caldera_report(raw, sha256="x"),
        )
        (step,) = dict(load_emulation_comparison(client, record.investigation_id) or {})["steps"]
        assert step["step_evidence"] == 0 and step["outcome"] == TECHNIQUE_DETECTED_ELSEWHERE


# ===========================================================================
# Routes and the command line
# ===========================================================================


def _get(url: str) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - localhost
            return int(response.status), json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_routes_serve_the_comparison_and_the_activity(
    compared: tuple[FakeElasticClient, str, tuple[str, ...]],
) -> None:
    client, investigation_id, units = compared
    server = create_server(client)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    base = f"http://{host!s}:{port}/api/investigations/{investigation_id}"
    try:
        status, body = _get(base + "/emulation")
        assert status == 200 and body == json.loads(
            json.dumps(load_emulation_comparison(client, investigation_id))
        )
        status, activity = _get(base + "/activity")
        assert status == 200
        events = activity["events"]
        _, record = _get(base)
        assert len(events) == activity["evidence_in_units"] == record["evidence_in_units"]
        assert {e["group_id"] for e in events} <= set(units)
        times = [e["time"] for e in events]
        assert times == sorted(times)
        features: set[str] = set()
        for group_id in units:
            _, unit = _get(f"http://{host!s}:{port}/api/units/{group_id}")
            features |= set(unit["attribution_analysis"]["observed_feature_technique_ids"])
        assert {e["attack_stix_id"] for e in events if e["decision_feature"]} == features
        assert all(e["label"] and "whoami /all" not in e["label"] for e in events)
        assert not set(_keys(activity)) & {"command", "command_line"}
        assert _get(base.rsplit("/", 1)[0] + "/absent/activity")[0] == 404
    finally:
        server.shutdown()
        server.server_close()


def test_an_investigation_without_a_report_has_no_comparison(
    knowledge: AttackKnowledge, recording: Path
) -> None:
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    client = FakeElasticClient()
    record = run_investigation(
        RecordingSource(
            recording_id="lab-run.zip",
            path=recording,
            sha256=hashlib.sha256(recording.read_bytes()).hexdigest(),
            declared_sources={HOST: ("sysmon",)},
        ),
        client=client,
        engine=DetectionEngine(rules=pack.rules),
        knowledge=knowledge,
        detection_pack_content_hash=pack.content_hash,
    )
    assert load_emulation_comparison(client, record.investigation_id) is None
    server = create_server(client)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    try:
        status, body = _get(
            f"http://{host!s}:{port}/api/investigations/{record.investigation_id}/emulation"
        )
        assert status == 404 and "no emulation report" in body["error"]
    finally:
        server.shutdown()
        server.server_close()


def test_command_line_takes_one_report_for_one_recording(recording: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report()), encoding="utf-8")
    assert main([str(recording), "--emulation-report", str(report)], env={}) == 0
    assert main([str(recording), str(recording), "--emulation-report", str(report)], env={}) == 2
    assert main([str(recording), "--emulation-report", str(tmp_path / "absent.json")], env={}) == 1
    report.write_text("[]", encoding="utf-8")
    assert main([str(recording), "--emulation-report", str(report)], env={}) == 1
