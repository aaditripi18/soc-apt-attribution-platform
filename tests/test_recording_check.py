"""Recording intake check: accepts a well-formed multi-source recording, blocks
unreadable / host-less / Sysmon-less / unconvertible ones, warns (never fixes)
on missing Security / PowerShell and on Sysmon clock gaps, and drafts the D3
declaration from the hosts' own records."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from attribution_platform.replay.recording_check import check_recording

HOST = "WS01.lab.local"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _sysmon(
    record_id: int, *, host: str | None = HOST, stamp: str = "2026-01-01T12:00:01.000Z"
) -> dict[str, Any]:
    return {
        "@timestamp": stamp,
        "winlog": {
            "channel": SYSMON,
            "event_id": 1,
            "record_id": record_id,
            "computer_name": host,
            "event_data": {
                "UtcTime": "2026-01-01 12:00:01.000",
                "ProcessGuid": f"{{G{record_id}}}",
                "ProcessId": str(100 + record_id),
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe",
            },
        },
    }


def _security(record_id: int) -> dict[str, Any]:
    return {
        "@timestamp": "2026-01-01T12:00:02.000Z",
        "winlog": {
            "channel": "Security",
            "event_id": 4624,
            "record_id": record_id,
            "computer_name": HOST,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data": {"LogonType": "3", "TargetUserName": "bob"},
        },
    }


def _powershell(record_id: int) -> dict[str, Any]:
    return {
        "@timestamp": "2026-01-01T12:00:03.000Z",
        "winlog": {
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4104,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {"ScriptBlockText": "Get-Date"},
        },
    }


def _archive(tmp_path: Path, lines: list[str]) -> Path:
    path = tmp_path / "rec.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("rec.json", "\n".join(lines) + "\n")
    return path


def _json(records: list[dict[str, Any]]) -> list[str]:
    return [json.dumps(r) for r in records]


def test_well_formed_recording_is_accepted(tmp_path: Path) -> None:
    report = check_recording(_archive(tmp_path, _json([_sysmon(1), _security(2), _powershell(3)])))
    assert report.accepted and report.problems == () and report.warnings == ()
    assert report.records == 3 and report.shapes == {"collector": 3}
    assert report.converted_by_source == {
        "sysmon": 1,
        "windows_powershell": 1,
        "windows_security": 1,
    }
    assert report.declared_sources == {HOST: ("sysmon", "windows_security")}
    assert report.sysmon_clock_gaps == {"within_1s": 1}


def test_unparseable_lines_block(tmp_path: Path) -> None:
    report = check_recording(_archive(tmp_path, [*_json([_sysmon(1)]), "{not json", "[1, 2]"]))
    assert not report.accepted
    assert any("2 line(s) are not JSON objects" in p for p in report.problems)


def test_host_without_sysmon_blocks(tmp_path: Path) -> None:
    report = check_recording(_archive(tmp_path, _json([_security(2)])))
    assert any("has no Sysmon records" in p for p in report.problems)


def test_record_without_host_blocks(tmp_path: Path) -> None:
    report = check_recording(_archive(tmp_path, _json([_sysmon(1), _sysmon(2, host=None)])))
    assert any("carry no host name" in p for p in report.problems)


def test_nothing_converted_blocks(tmp_path: Path) -> None:
    other = {"winlog": {"channel": "Application", "event_id": 1, "computer_name": HOST}}
    report = check_recording(_archive(tmp_path, _json([other])))
    assert any("no record converted" in p for p in report.problems)


def test_missing_sources_and_clock_gaps_are_warnings_not_fixes(tmp_path: Path) -> None:
    late = _sysmon(1, stamp="2026-01-12T12:00:01.000Z")  # 11 days after UtcTime
    report = check_recording(_archive(tmp_path, _json([late])))
    assert report.accepted
    assert report.sysmon_clock_gaps == {"beyond_60s": 1}
    text = " ".join(report.warnings)
    assert "no Security-channel records" in text
    assert "no PowerShell/Operational records" in text
    assert "more than 60 s from the collector clock" in text
    assert report.first_event == "2026-01-01T12:00:01+00:00"  # Sysmon's own time


def test_non_windows_records_are_routed_like_the_pipeline(tmp_path: Path) -> None:
    """A raw auditd line is read by the auditd adapter (not counted as broken
    JSON); without ``node=`` it names no host, so the check warns that the
    source declaration must state it — and, having no declared host here, the
    adapter refuses it (fail closed, ADR-0010 D4)."""
    golden = Path(__file__).resolve().parents[1] / "data" / "telemetry-samples"
    rows = (golden / "splunk-attack-data" / "golden-records.jsonl").read_text("utf-8")
    audit = next(json.loads(r)["record"] for r in rows.splitlines() if '"auditd-syscall"' in r)
    path = tmp_path / "audit.log"
    path.write_text(audit + "\n", encoding="utf-8")
    report = check_recording(path)
    assert report.unparseable_lines == 0
    assert report.records_by_channel == {"<auditd>": 1}
    assert any("name no host" in w for w in report.warnings)
    assert report.problems == (
        "no record converted to an Observation — unsupported shape or channels",
    )
