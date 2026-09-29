"""The investigation command line: resolves a pinned recording id or a
recording archive (which must pass the intake check), runs and persists the
investigation, prints per-unit facts only, and fails closed on refusals."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.investigation.__main__ import (
    CliError,
    investigate,
    main,
    resolve_source,
    summary,
)

HOST = "WS01.example.local"


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


@pytest.fixture()
def archive(tmp_path: Path) -> Path:
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    whoami = "C:\\Windows\\System32\\whoami.exe"
    records = [
        _process_create(1, 1, "{P}", "{ROOT}", ps, "powershell.exe -nop -w hidden -enc SQBFAFgA"),
        _process_create(2, 2, "{A}", "{P}", whoami, "whoami /all -all"),
    ]
    path = tmp_path / "lab-run.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("run.json", "\n".join(json.dumps(r) for r in records) + "\n")
    return path


def test_unpinned_archive_is_checked_then_resolved(archive: Path, tmp_path: Path) -> None:
    source = resolve_source(str(archive), recordings=tmp_path / "missing.json")
    assert source.recording_id == "lab-run.zip"
    assert source.sha256 == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert source.declared_sources == {HOST: ("sysmon",)}  # from the intake check


def test_pinned_recording_id_is_resolved(archive: Path, tmp_path: Path) -> None:
    recordings = tmp_path / "recordings.json"
    recordings.write_text(
        json.dumps(
            {
                "recordings": [
                    {
                        "recording_id": "pinned-run",
                        "cache_path": str(archive),
                        "sha256": "a" * 64,
                        "declared_sources": {HOST: ["sysmon"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    source = resolve_source("pinned-run", recordings=recordings)
    assert source.recording_id == "pinned-run" and source.sha256 == "a" * 64


def test_archive_failing_intake_is_refused(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("run.json", "{not json\n")
    with pytest.raises(CliError, match="intake check"):
        resolve_source(str(bad), recordings=tmp_path / "missing.json")
    with pytest.raises(CliError, match="neither a pinned recording id"):
        resolve_source(str(tmp_path / "absent.zip"), recordings=tmp_path / "missing.json")


def test_investigate_and_summarize_without_ranking(archive: Path, tmp_path: Path) -> None:
    session = investigate(str(archive), client=FakeElasticClient(), recordings=tmp_path / "m.json")
    report = summary(session)
    assert report["units"] and report["source_id"] == "lab-run.zip"
    for unit in report["units"]:  # type: ignore[attr-defined]
        assert set(unit) == {"group_id", "observed_techniques", "candidates", "calibration_status"}
        assert unit["calibration_status"] == "uncalibrated"


def test_main_runs_end_to_end_and_writes_json(archive: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    assert main([str(archive), "--json", str(out)], env={}) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["investigation_id"].startswith("investigation::")


def test_main_exit_codes(tmp_path: Path) -> None:
    assert main([], env={}) == 2
    assert main([str(tmp_path / "absent.zip")], env={}) == 1
    assert main(["anything", "--elasticsearch"], env={}) == 1  # no ELASTIC_PASSWORD
