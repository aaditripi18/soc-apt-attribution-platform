"""Recording upload: the one way to hand the server new input (ADR-0020).

An analyst gives the server a recording archive; the server stores it, runs
the same intake check and the same investigation the command line runs, and
the result appears in the read model like any other. Nothing here analyses
anything: the service receives bytes, keeps a job record, and calls the two
functions it was given (``check`` and ``run``).

Bounds, each enforced before the file is used:

- the request must come from this machine, and from the console's own origin;
- the body's declared length must be present and within ``max_bytes``;
- the file name is reduced to a safe base name with a supported extension and
  is never used as a path;
- a ``.zip`` whose members declare more than ``max_expanded_bytes`` is refused
  (recordings are read as streams and never extracted to disk).

One recording is investigated at a time, in arrival order: the detection
engine is CPU-bound and a second concurrent run would only slow both.
"""

from __future__ import annotations

import hashlib
import ipaddress
import queue
import re
import threading
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from attribution_platform.api.errors import ApiError, InvalidIdentifierError, NotFoundError
from attribution_platform.replay.recording_check import RecordingCheckReport
from attribution_platform.replay.recording_pipeline import RecordingSource

#: Largest accepted upload (compressed), and largest declared expansion of a zip.
DEFAULT_MAX_BYTES = 1 << 30
DEFAULT_MAX_EXPANDED_BYTES = 16 << 30
SUPPORTED_SUFFIXES = (".zip", ".tar.gz", ".log", ".json", ".jsonl")
_CHUNK = 1 << 20
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")

QUEUED, CHECKING, ANALYSING, DONE, REFUSED, FAILED = (
    "queued",
    "checking",
    "analysing",
    "done",
    "refused",
    "failed",
)
ACTIVE = frozenset({QUEUED, CHECKING, ANALYSING})


class _Readable(Protocol):
    def read(self, size: int, /) -> bytes: ...


class UploadRefusedError(ApiError):
    """The request may not upload (wrong origin, not this machine)."""

    status_code = 403


class UploadTooLargeError(ApiError):
    status_code = 413


class LengthRequiredError(ApiError):
    status_code = 411


class UploadsDisabledError(ApiError):
    """This server was started without the upload service."""

    status_code = 501


def safe_name(name: str) -> str:
    """The base name of ``name`` restricted to ``[A-Za-z0-9._-]``, with a
    supported extension; refuses anything else. The result names the recording
    in the read model and is part of the stored file's name — never a path."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    cleaned = _UNSAFE.sub("_", base).strip("._")[:120]
    if not cleaned or not any(cleaned.lower().endswith(s) for s in SUPPORTED_SUFFIXES):
        raise InvalidIdentifierError(
            "the file must be a recording archive: " + ", ".join(SUPPORTED_SUFFIXES)
        )
    return cleaned


def is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def same_origin(origin: str | None, host: str | None) -> bool:
    """A browser sends ``Origin`` on a cross-site POST; it must be this server.
    No ``Origin`` (a command-line client) is accepted."""
    if origin is None:
        return True
    return host is not None and origin in (f"http://{host}", f"https://{host}")


@dataclass
class UploadJob:
    job_id: str
    file_name: str
    size_bytes: int
    sha256: str
    received_at: str
    state: str = QUEUED
    started_at: str | None = None
    finished_at: str | None = None
    #: Why the recording was refused or the run failed.
    problems: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    records: int | None = None
    converted_by_source: Mapping[str, int] = field(default_factory=dict)
    refused_records: int | None = None
    first_event: str | None = None
    last_event: str | None = None
    investigation_id: str | None = None
    evidence: int | None = None
    units: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "file_name": self.file_name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "received_at": self.received_at,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "problems": list(self.problems),
            "warnings": list(self.warnings),
            "records": self.records,
            "converted_by_source": dict(sorted(self.converted_by_source.items())),
            "refused_records": self.refused_records,
            "first_event": self.first_event,
            "last_event": self.last_event,
            "investigation_id": self.investigation_id,
            "evidence": self.evidence,
            "units": self.units,
        }


@dataclass(frozen=True)
class RunResult:
    investigation_id: str
    evidence: int
    units: int


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class UploadService:
    """Receives recordings and investigates them one at a time.

    ``check`` is the intake check; ``run`` investigates an accepted recording
    and returns what was stored. Both are the command line's own functions.
    """

    def __init__(
        self,
        *,
        directory: Path,
        check: Callable[[Path], RecordingCheckReport],
        run: Callable[[RecordingSource], RunResult],
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
        start_worker: bool = True,
    ) -> None:
        self.directory = directory
        self.max_bytes = max_bytes
        self.max_expanded_bytes = max_expanded_bytes
        self._check = check
        self._run = run
        self._jobs: dict[str, UploadJob] = {}
        self._paths: dict[str, Path] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        if start_worker:
            threading.Thread(target=self._work, name="upload-worker", daemon=True).start()

    # --- receiving ---------------------------------------------------------

    def receive(self, name: str, stream: _Readable, length: int | None) -> dict[str, Any]:
        """Store ``length`` bytes of ``stream`` and queue their investigation.
        The same bytes uploaded again return the existing job unless it ended
        in a refusal or a failure (then it is tried again)."""
        file_name = safe_name(name)
        if length is None:
            raise LengthRequiredError("the upload must declare its Content-Length")
        if length <= 0:
            raise InvalidIdentifierError("the upload is empty")
        if length > self.max_bytes:
            raise UploadTooLargeError(
                f"the upload is {length:,} bytes; the limit is {self.max_bytes:,}"
            )
        self.directory.mkdir(parents=True, exist_ok=True)
        partial = self.directory / f".incoming-{threading.get_ident()}-{id(stream)}"
        digest = hashlib.sha256()
        remaining = length
        try:
            with partial.open("wb") as out:
                while remaining > 0:
                    chunk = stream.read(min(_CHUNK, remaining))
                    if not chunk:
                        raise InvalidIdentifierError("the upload ended before its declared length")
                    digest.update(chunk)
                    out.write(chunk)
                    remaining -= len(chunk)
            sha256 = digest.hexdigest()
            job_id = f"upload-{sha256[:24]}"
            stored = self.directory / f"{sha256[:24]}-{file_name}"
            with self._lock:
                existing = self._jobs.get(job_id)
                if existing is not None and existing.state not in (REFUSED, FAILED):
                    return existing.to_json()
                partial.replace(stored)
                job = UploadJob(
                    job_id=job_id,
                    file_name=file_name,
                    size_bytes=length,
                    sha256=sha256,
                    received_at=_now(),
                )
                self._jobs[job_id] = job
                self._paths[job_id] = stored
            self._queue.put(job_id)
            return job.to_json()
        finally:
            partial.unlink(missing_ok=True)

    # --- reading -----------------------------------------------------------

    def describe(self) -> dict[str, Any]:
        with self._lock:
            jobs = [job.to_json() for job in self._jobs.values()]
        jobs.sort(key=lambda job: (job["received_at"], job["job_id"]), reverse=True)
        return {
            "enabled": True,
            "max_bytes": self.max_bytes,
            "supported_suffixes": list(SUPPORTED_SUFFIXES),
            "jobs": jobs,
        }

    def job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            found = self._jobs.get(job_id)
            if found is None:
                raise NotFoundError(f"no upload with job_id={job_id!r}")
            return found.to_json()

    # --- working -----------------------------------------------------------

    def _update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for name, value in changes.items():
                setattr(job, name, value)

    def _work(self) -> None:
        while True:
            self.process_next()

    def process_next(self) -> None:
        """Investigate the next queued upload (blocks until there is one)."""
        job_id = self._queue.get()
        path = self._paths[job_id]
        self._update(job_id, state=CHECKING, started_at=_now())
        try:
            if path.suffix == ".zip":
                self._refuse_oversized_zip(path)
            report = self._check(path)
            self._update(
                job_id,
                records=report.records,
                converted_by_source=dict(report.converted_by_source),
                refused_records=sum(report.refused_by_reason.values()),
                first_event=report.first_event,
                last_event=report.last_event,
                warnings=tuple(report.warnings),
            )
            if not report.accepted:
                self._update(
                    job_id, state=REFUSED, problems=tuple(report.problems), finished_at=_now()
                )
                return
            self._update(job_id, state=ANALYSING)
            with self._lock:
                file_name = self._jobs[job_id].file_name
            result = self._run(
                RecordingSource(
                    recording_id=file_name,
                    path=path,
                    sha256=report.sha256,
                    declared_sources=report.declared_sources,
                )
            )
            self._update(
                job_id,
                state=DONE,
                investigation_id=result.investigation_id,
                evidence=result.evidence,
                units=result.units,
                finished_at=_now(),
            )
        except _Refusal as exc:
            self._update(job_id, state=REFUSED, problems=(str(exc),), finished_at=_now())
        except Exception as exc:  # noqa: BLE001 - a failed run is a job state, never a dead worker
            self._update(
                job_id,
                state=FAILED,
                problems=(f"{type(exc).__name__}: {exc}"[:500],),
                finished_at=_now(),
            )

    def _refuse_oversized_zip(self, path: Path) -> None:
        try:
            with zipfile.ZipFile(path) as archive:
                expanded = sum(info.file_size for info in archive.infolist())
        except zipfile.BadZipFile as exc:
            raise _Refusal(f"not a readable zip archive: {exc}") from exc
        if expanded > self.max_expanded_bytes:
            raise _Refusal(
                f"the archive expands to {expanded:,} bytes; "
                f"the limit is {self.max_expanded_bytes:,}"
            )


class _Refusal(Exception):
    """The stored file is not acceptable input (a job outcome, not an error)."""


def disabled() -> dict[str, Any]:
    return {
        "enabled": False,
        "max_bytes": 0,
        "supported_suffixes": list(SUPPORTED_SUFFIXES),
        "jobs": [],
    }


__all__ = [
    "ACTIVE",
    "DEFAULT_MAX_BYTES",
    "SUPPORTED_SUFFIXES",
    "LengthRequiredError",
    "RunResult",
    "UploadJob",
    "UploadRefusedError",
    "UploadService",
    "UploadTooLargeError",
    "UploadsDisabledError",
    "disabled",
    "is_loopback",
    "safe_name",
    "same_origin",
]
