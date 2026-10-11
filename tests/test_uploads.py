"""Recording upload (ADR-0020): bounded input, one job at a time, the same
check and investigation as the command line, and no other mutation route."""

from __future__ import annotations

import io
import json
import sys
import threading
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api.errors import InvalidIdentifierError, NotFoundError
from attribution_platform.api.server import create_server
from attribution_platform.api.uploads import (
    LengthRequiredError,
    RunResult,
    UploadService,
    UploadTooLargeError,
    is_loopback,
    safe_name,
    same_origin,
)
from attribution_platform.dataplane import FakeElasticClient, SharedMemoryClient
from attribution_platform.investigation.__main__ import load_workbench, upload_service
from attribution_platform.replay.recording_check import RecordingCheckReport
from attribution_platform.replay.recording_pipeline import RecordingSource

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_end_to_end_formats import RECORDINGS  # noqa: E402


def _report(path: Path, *, problems: tuple[str, ...] = ()) -> RecordingCheckReport:
    return RecordingCheckReport(
        path=str(path),
        sha256="ab" * 32,
        size_bytes=path.stat().st_size,
        records=3,
        unparseable_lines=0,
        shapes={},
        channels_by_host={},
        records_by_channel={},
        converted_by_source={"sysmon": 2},
        refused_by_reason={"sysmon: unsupported": 1},
        sysmon_clock_gaps={},
        first_event="2026-01-01T00:00:00+00:00",
        last_event="2026-01-01T00:01:00+00:00",
        declared_sources={"host": ("sysmon",)},
        problems=problems,
    )


def _service(tmp_path: Path, **overrides: Any) -> tuple[UploadService, list[RecordingSource]]:
    ran: list[RecordingSource] = []

    def run(source: RecordingSource) -> RunResult:
        ran.append(source)
        return RunResult(investigation_id="investigation::x", evidence=5, units=2)

    options: dict[str, Any] = {
        "directory": tmp_path / "uploads",
        "check": _report,
        "run": run,
        "start_worker": False,
    }
    options.update(overrides)
    return UploadService(**options), ran


def _receive(service: UploadService, name: str, body: bytes) -> dict[str, Any]:
    return service.receive(name, io.BytesIO(body), len(body))


# --- names and origins -------------------------------------------------------


def test_file_name_is_reduced_to_a_safe_base_name() -> None:
    assert safe_name("run 01 (final).zip") == "run_01_final_.zip"
    assert safe_name("C:\\Users\\a\\logs.tar.gz") == "logs.tar.gz"
    assert safe_name("../../etc/events.jsonl") == "events.jsonl"
    for bad in ("", "..", "payload.exe", "archive.zip.exe", "/", "notes.txt"):
        with pytest.raises(InvalidIdentifierError):
            safe_name(bad)


def test_only_this_machine_and_this_console_may_upload() -> None:
    assert is_loopback("127.0.0.1") and is_loopback("::1")
    assert not is_loopback("10.10.10.20") and not is_loopback("example.org")
    assert same_origin(None, "127.0.0.1:8000")  # a command-line client
    assert same_origin("http://127.0.0.1:8000", "127.0.0.1:8000")
    assert not same_origin("https://evil.example", "127.0.0.1:8000")
    assert not same_origin("http://127.0.0.1:9999", "127.0.0.1:8000")
    assert not same_origin("null", "127.0.0.1:8000")


# --- the service -------------------------------------------------------------


def test_an_accepted_upload_is_checked_then_investigated(tmp_path: Path) -> None:
    service, ran = _service(tmp_path)
    job = _receive(service, "my run.jsonl", b"{}\n")
    assert job["state"] == "queued" and job["file_name"] == "my_run.jsonl"
    assert job["size_bytes"] == 3 and len(job["sha256"]) == 64
    service.process_next()
    done = service.job(job["job_id"])
    assert done["state"] == "done"
    assert done["investigation_id"] == "investigation::x"
    assert (done["evidence"], done["units"], done["records"]) == (5, 2, 3)
    assert done["refused_records"] == 1 and done["converted_by_source"] == {"sysmon": 2}
    # the recording is named by the uploaded file, and read from the stored copy
    assert ran[0].recording_id == "my_run.jsonl"
    assert ran[0].path.parent == tmp_path / "uploads" and ran[0].path.read_bytes() == b"{}\n"
    assert ran[0].sha256 == "ab" * 32  # the intake check's digest, not a guess
    assert service.describe()["jobs"][0]["job_id"] == job["job_id"]


def test_a_recording_failing_intake_is_refused_and_never_investigated(tmp_path: Path) -> None:
    service, ran = _service(
        tmp_path, check=lambda path: _report(path, problems=("no supported records",))
    )
    job = _receive(service, "empty.jsonl", b"x\n")
    service.process_next()
    refused = service.job(job["job_id"])
    assert refused["state"] == "refused" and refused["problems"] == ["no supported records"]
    assert refused["investigation_id"] is None and ran == []
    # a refused upload may be tried again
    assert _receive(service, "empty.jsonl", b"x\n")["state"] == "queued"


def test_a_failing_run_is_a_job_state_not_a_dead_worker(tmp_path: Path) -> None:
    def run(_source: RecordingSource) -> RunResult:
        raise RuntimeError("boom")

    service, _ = _service(tmp_path, run=run)
    job = _receive(service, "a.jsonl", b"1\n")
    other = _receive(service, "b.jsonl", b"2\n")
    service.process_next()
    service.process_next()
    assert service.job(job["job_id"])["state"] == "failed"
    assert service.job(job["job_id"])["problems"] == ["RuntimeError: boom"]
    assert service.job(other["job_id"])["state"] == "failed"  # the worker went on


def test_the_same_bytes_are_one_job(tmp_path: Path) -> None:
    service, ran = _service(tmp_path)
    first = _receive(service, "a.jsonl", b"same\n")
    again = _receive(service, "renamed.jsonl", b"same\n")
    assert again["job_id"] == first["job_id"] and again["file_name"] == "a.jsonl"
    service.process_next()
    assert len(ran) == 1
    assert _receive(service, "a.jsonl", b"same\n")["state"] == "done"
    assert not [p for p in (tmp_path / "uploads").iterdir() if p.name.startswith(".incoming")]


def test_bounds_are_enforced_before_the_file_is_used(tmp_path: Path) -> None:
    service, ran = _service(tmp_path, max_bytes=10)
    with pytest.raises(UploadTooLargeError):
        service.receive("big.jsonl", io.BytesIO(b"x" * 11), 11)
    with pytest.raises(LengthRequiredError):
        service.receive("a.jsonl", io.BytesIO(b"x"), None)
    with pytest.raises(InvalidIdentifierError):
        service.receive("a.jsonl", io.BytesIO(b""), 0)
    with pytest.raises(InvalidIdentifierError):  # the body is shorter than declared
        service.receive("a.jsonl", io.BytesIO(b"abc"), 8)
    with pytest.raises(InvalidIdentifierError):
        service.receive("a.exe", io.BytesIO(b"abc"), 3)
    with pytest.raises(NotFoundError):
        service.job("upload-none")
    assert service.describe()["jobs"] == [] and ran == []
    assert not list((tmp_path / "uploads").glob("*"))


def test_a_zip_that_expands_beyond_the_limit_is_refused(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("events.json", "0" * 100_000)
    service, ran = _service(tmp_path, max_expanded_bytes=50_000)
    job = _receive(service, "bomb.zip", buffer.getvalue())
    service.process_next()
    refused = service.job(job["job_id"])
    assert refused["state"] == "refused" and "expands to 100,000 bytes" in refused["problems"][0]
    garbage = _receive(service, "broken.zip", b"not a zip")
    service.process_next()
    assert service.job(garbage["job_id"])["state"] == "refused"
    assert ran == []


def test_a_finished_run_is_published_in_one_step() -> None:
    shared, scratch = SharedMemoryClient(), FakeElasticClient()
    scratch.ensure_index("i", {"a": {"type": "keyword"}})
    scratch.index_document("i", "1", {"a": "x"})
    assert shared.get_document("i", "1") is None
    shared.absorb(scratch)
    assert shared.get_document("i", "1") == {"a": "x"}
    assert shared.search("i", {}, size=5) == ({"a": "x"},)


# --- HTTP ----------------------------------------------------------------------


def _call(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


@pytest.fixture
def served(tmp_path: Path) -> Iterator[tuple[str, UploadService]]:
    service, _ = _service(tmp_path)
    server = create_server(FakeElasticClient(), uploads=service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", service
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_upload_over_http(served: tuple[str, UploadService]) -> None:
    base, service = served
    status, described = _call(base + "/api/uploads")
    assert status == 200 and described["enabled"] is True and described["jobs"] == []

    status, job = _call(base + "/api/uploads?name=run.jsonl", method="POST", body=b"{}\n")
    assert status == 202 and job["state"] == "queued"
    service.process_next()
    status, done = _call(base + f"/api/uploads/{job['job_id']}")
    assert status == 200 and done["state"] == "done"
    assert _call(base + "/uploads")[1]["jobs"][0]["investigation_id"] == "investigation::x"
    assert _call(base + "/api/uploads/upload-missing")[0] == 404


def test_upload_refusals_over_http(served: tuple[str, UploadService]) -> None:
    base, service = served
    post: dict[str, Any] = {"method": "POST", "body": b"{}\n"}
    assert _call(base + "/api/uploads", **post)[0] == 400  # no name
    assert _call(base + "/api/uploads?name=a.jsonl&x=1", **post)[0] == 400
    assert _call(base + "/api/uploads?name=a.exe", **post)[0] == 400
    status, body = _call(
        base + "/api/uploads?name=a.jsonl", headers={"Origin": "https://evil.example"}, **post
    )
    assert status == 403 and "this console only" in body["error"]
    # no other route accepts input, and no other method does anything
    assert _call(base + "/api/investigations", **post)[0] == 501
    assert _call(base + "/api/uploads/upload-x", **post)[0] == 501
    for method in ("PUT", "PATCH", "DELETE"):
        assert _call(base + "/api/uploads?name=a.jsonl", method=method, body=b"x")[0] == 501
    assert service.describe()["jobs"] == []


def test_a_server_without_the_service_stays_read_only() -> None:
    server = create_server(FakeElasticClient())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert _call(base + "/api/uploads")[1] == {
            "enabled": False,
            "jobs": [],
            "max_bytes": 0,
            "supported_suffixes": [".zip", ".tar.gz", ".log", ".json", ".jsonl"],
        }
        assert _call(base + "/api/uploads?name=a.jsonl", method="POST", body=b"x")[0] == 501
        assert _call(base + "/api/uploads/upload-x")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --- end to end ----------------------------------------------------------------


def test_an_uploaded_recording_becomes_an_investigation(tmp_path: Path) -> None:
    """The real intake check and the real investigation, through the service
    the serving command builds."""
    name, text = RECORDINGS["cloud"]
    client = SharedMemoryClient()
    service = upload_service(client, load_workbench(), directory=tmp_path / "uploads")
    server = create_server(client, uploads=service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert _call(base + "/api/investigations")[1] == []
        _, job = _call(base + f"/api/uploads?name={name}", method="POST", body=text.encode("utf-8"))
        done: dict[str, Any] = {}
        for _ in range(600):
            done = _call(base + f"/api/uploads/{job['job_id']}")[1]
            if done["state"] not in ("queued", "checking", "analysing"):
                break
            threading.Event().wait(0.2)
        assert done["state"] == "done", done
        listed = _call(base + "/api/investigations")[1]
        assert [i["investigation_id"] for i in listed] == [done["investigation_id"]]
        assert listed[0]["source_id"] == name and listed[0]["units"] == done["units"] == 7
        from urllib.parse import quote

        record = _call(base + f"/api/investigations/{quote(done['investigation_id'], safe='')}")[1]
        assert record["source_sha256"] == job["sha256"] and record["evidence"] == done["evidence"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
