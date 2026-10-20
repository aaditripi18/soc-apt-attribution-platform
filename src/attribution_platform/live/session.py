"""The live cycle (ADR-0028 D2-D4): capture what arrived, freeze the window,
investigate the snapshot with the command line's own functions, and record
what changed since the previous cycle.

A cycle's result is an ordinary stored investigation over a hashed snapshot,
so any live result can be re-run from its snapshot byte-for-byte. The change
record compares two stored summaries; it computes no score of its own.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from attribution_platform.api.uploads import RunResult
from attribution_platform.live.capture import CaptureStore
from attribution_platform.replay.recording_check import RecordingCheckReport
from attribution_platform.replay.recording_pipeline import RecordingSource

ANALYSED, UNCHANGED, EMPTY, REFUSED, FAILED = "analysed", "unchanged", "empty", "refused", "failed"
#: Cycles kept in memory for the status view.
_HISTORY = 50


class LiveSource(Protocol):
    """Something that returns the records that arrived since it was last read:
    a followed file (:class:`~attribution_platform.live.capture.FileFollower`) or
    an Elasticsearch index pattern
    (:class:`~attribution_platform.live.elastic_source.ElasticsearchSource`)."""

    @property
    def path(self) -> Any: ...
    @property
    def offset(self) -> int: ...
    @property
    def dropped_partial_lines(self) -> int: ...
    @property
    def undecodable_lines(self) -> int: ...
    def read(self) -> list[str]: ...


@dataclass(frozen=True)
class CycleOutcome:
    cycle: int
    at: str
    state: str
    seconds: float
    snapshot_sha256: str | None = None
    snapshot_lines: int | None = None
    window_start: str | None = None
    investigation_id: str | None = None
    evidence: int | None = None
    units: int | None = None
    summary: Mapping[str, Any] | None = None
    changes: Mapping[str, Any] | None = None
    problems: tuple[str, ...] = field(default=())

    def to_json(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}


def changes_between(
    previous: Mapping[str, Any] | None, current: Mapping[str, Any]
) -> dict[str, Any]:
    """What differs between two cycles' stored summaries (D3)."""
    if previous is None:
        return {"first_cycle": True}
    before, after = set(previous["counted_techniques"]), set(current["counted_techniques"])
    named_before, named_after = set(previous["named_actors"]), set(current["named_actors"])
    changes: dict[str, Any] = {
        "techniques_newly_counted": sorted(after - before),
        "techniques_no_longer_in_window": sorted(before - after),
        "units": [previous["units"], current["units"]],
        "named_actors_added": sorted(named_after - named_before),
        "named_actors_removed": sorted(named_before - named_after),
    }
    if previous["verdict"] != current["verdict"]:
        changes["verdict"] = [previous["verdict"], current["verdict"]]
    return changes


class LiveSession:
    """One live source set, analysed cycle by cycle.

    ``check`` is the intake check and ``run`` the investigation, as for an
    upload (ADR-0020); ``summarise`` reads a stored investigation's counted
    techniques, unit count, verdict and named actors from the read model."""

    def __init__(
        self,
        *,
        name: str,
        followers: Sequence[LiveSource],
        store: CaptureStore,
        check: Callable[[Any], RecordingCheckReport],
        run: Callable[[RecordingSource], RunResult],
        summarise: Callable[[str], Mapping[str, Any]],
        window_hours: int = 24,
        keep_snapshots: int = 48,
        release: Callable[[str], int] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.name = name
        self.followers = list(followers)
        self.store = store
        self.window_hours = window_hours
        self.keep_snapshots = keep_snapshots
        self._check, self._run, self._summarise, self._clock = check, run, summarise, clock
        self._cycles: list[CycleOutcome] = []
        self._last_sha: str | None = None
        self._last_summary: Mapping[str, Any] | None = None
        #: ADR-0028 Amendment B: the investigations of the newest ``keep_snapshots``
        #: analysed cycles stay served; older ones are released with their snapshots.
        self._release = release
        self._retained: list[str] = []
        self._lock = threading.Lock()

    def cycle(self) -> CycleOutcome:
        started = time.monotonic()
        now = self._clock()
        number = len(self._cycles) + 1
        for follower in self.followers:
            self.store.append(follower.read(), now)

        def done(state: str, **facts: Any) -> CycleOutcome:
            outcome = CycleOutcome(
                cycle=number,
                at=now.isoformat(timespec="seconds"),
                state=state,
                seconds=round(time.monotonic() - started, 3),
                **facts,
            )
            with self._lock:
                self._cycles = [*self._cycles, outcome][-_HISTORY:]
            return outcome

        snapshot = self.store.snapshot(now, self.window_hours)
        if snapshot is None:
            return done(EMPTY)
        facts: dict[str, Any] = {
            "snapshot_sha256": snapshot.sha256,
            "snapshot_lines": snapshot.lines,
            "window_start": snapshot.window_start.isoformat(timespec="seconds"),
        }
        if snapshot.sha256 == self._last_sha:
            snapshot.path.unlink()
            return done(UNCHANGED, **facts)
        try:
            report = self._check(snapshot.path)
            if not report.accepted:
                return done(REFUSED, problems=tuple(report.problems), **facts)
            stamp = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            result = self._run(
                RecordingSource(
                    recording_id=f"live:{self.name}@{stamp}",
                    path=snapshot.path,
                    sha256=snapshot.sha256,
                    declared_sources=report.declared_sources,
                )
            )
            summary = {**self._summarise(result.investigation_id), "units": result.units}
        except Exception as exc:  # noqa: BLE001 - a failed cycle is recorded, the loop goes on
            return done(FAILED, problems=(f"{type(exc).__name__}: {exc}"[:500],), **facts)
        changes = changes_between(self._last_summary, summary)
        self._last_sha, self._last_summary = snapshot.sha256, summary
        self.store.prune_snapshots(self.keep_snapshots)
        self._retained.append(result.investigation_id)
        while len(self._retained) > self.keep_snapshots:
            oldest = self._retained.pop(0)
            if self._release is not None:
                self._release(oldest)
        return done(
            ANALYSED,
            investigation_id=result.investigation_id,
            evidence=result.evidence,
            units=result.units,
            summary=summary,
            changes=changes,
            **facts,
        )

    def run_forever(self, interval_seconds: float, stop: threading.Event) -> None:
        while not stop.is_set():
            self.cycle()
            stop.wait(interval_seconds)

    def describe(self) -> dict[str, Any]:
        """The status view: sources, window and recent cycles (newest first)."""
        with self._lock:
            cycles = [c.to_json() for c in reversed(self._cycles)]
        return {
            "enabled": True,
            "name": self.name,
            "window_hours": self.window_hours,
            "investigations_retained": len(self._retained),
            "sources": [
                {
                    "source": str(f.path),
                    "read_so_far": f.offset,
                    "dropped_partial_lines": f.dropped_partial_lines,
                    "undecodable_lines": f.undecodable_lines,
                }
                for f in self.followers
            ],
            "cycles": cycles,
        }


__all__ = [
    "ANALYSED",
    "EMPTY",
    "FAILED",
    "REFUSED",
    "UNCHANGED",
    "CycleOutcome",
    "LiveSession",
    "LiveSource",
    "changes_between",
]
