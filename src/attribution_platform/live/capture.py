"""Live capture (ADR-0028 D1): follow files, append raw lines to a rolling store,
and cut frozen, hashed snapshots of a time window.

Nothing here interprets a record. Lines are kept exactly as written (line
ending removed); the recording pipeline's adapters read the snapshot exactly
as they read any recording.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

#: Capture files are partitioned by the UTC hour lines *arrived* in.
_HOUR = "%Y%m%dT%H"


@dataclass
class FileFollower:
    """Reads the lines appended to one file since the last read.

    A line is returned only once its newline has been written, so a record
    being written is never cut. When the file is replaced (rotation) or
    truncated, reading starts again from its beginning; a partial last line of
    the previous file is dropped and counted, never joined to the new file."""

    path: Path
    offset: int = 0
    identity: tuple[int, int] | None = None
    pending: bytes = b""
    dropped_partial_lines: int = 0
    undecodable_lines: int = 0

    def read(self) -> list[str]:
        try:
            status = os.stat(self.path)
        except FileNotFoundError:
            return []
        identity = (status.st_dev, status.st_ino)
        replaced = identity != self.identity or status.st_size < self.offset
        if self.identity is not None and replaced:
            if self.pending:
                self.dropped_partial_lines += 1
            self.offset, self.pending = 0, b""
        self.identity = identity
        if status.st_size == self.offset:
            return []
        with open(self.path, "rb") as handle:
            handle.seek(self.offset)
            chunk = handle.read(status.st_size - self.offset)
        self.offset += len(chunk)
        *complete, self.pending = (self.pending + chunk).split(b"\n")
        lines = []
        for raw in complete:
            try:
                lines.append(raw.decode("utf-8").rstrip("\r"))
            except UnicodeDecodeError:
                self.undecodable_lines += 1
        return lines


@dataclass(frozen=True)
class Snapshot:
    path: Path
    sha256: str
    window_start: datetime
    window_end: datetime
    lines: int


class CaptureStore:
    """Append-only capture files under ``directory/capture`` and frozen
    snapshots under ``directory/snapshots``."""

    def __init__(self, directory: Path, name: str) -> None:
        self.name = name
        self.capture = directory / "capture"
        self.snapshots = directory / "snapshots"
        self.capture.mkdir(parents=True, exist_ok=True)
        self.snapshots.mkdir(parents=True, exist_ok=True)

    def append(self, lines: list[str], arrived: datetime) -> None:
        if not lines:
            return
        target = self.capture / f"{arrived.astimezone(UTC).strftime(_HOUR)}.log"
        with open(target, "a", encoding="utf-8", newline="\n") as handle:
            for line in lines:
                handle.write(line + "\n")

    def window_files(self, end: datetime, hours: int) -> list[Path]:
        """The capture files of the hours overlapping ``(end - hours, end]``."""
        first = (end - timedelta(hours=hours)).astimezone(UTC).strftime(_HOUR)
        last = end.astimezone(UTC).strftime(_HOUR)
        return sorted(p for p in self.capture.glob("*.log") if first <= p.stem <= last)

    def snapshot(self, end: datetime, hours: int) -> Snapshot | None:
        """Freeze the window into one file; ``None`` when the window is empty."""
        files = self.window_files(end, hours)
        content = b"".join(path.read_bytes() for path in files)
        if not content:
            return None
        digest = hashlib.sha256(content).hexdigest()
        stamp = end.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = self.snapshots / f"{self.name}-{stamp}.log"
        path.write_bytes(content)
        return Snapshot(
            path=path,
            sha256=digest,
            window_start=end - timedelta(hours=hours),
            window_end=end,
            lines=content.count(b"\n"),
        )

    def prune_snapshots(self, keep: int) -> None:
        """Keep the newest ``keep`` snapshots (bounded retention, D2)."""
        for old in sorted(self.snapshots.glob(f"{self.name}-*.log"))[:-keep]:
            old.unlink()


__all__ = ["CaptureStore", "FileFollower", "Snapshot"]
