"""The macOS Endpoint Security (via osquery) SourceAdapter (ADR-0014).

One Observation per row of osquery's ``es_process_events`` table — Apple's
Endpoint Security process events, a table that exists only on macOS — as
osquery's results log writes it: ``{"name": <query name>, "hostIdentifier",
"unixTime", "columns": {...}, "action": "added"}``. The query name is chosen by
whoever configures osquery, so a row is recognised by the table's own columns
(``path``, ``cmdline``, ``pid``, ``parent``, ``event_type``, ``time``,
``global_seq_num``), not by its name. Only ``exec`` events are process starts;
other event types (``fork``, ``exit``) are refused, counted by the caller.

**Event time:** the row's ``time`` — the Endpoint Security event time, epoch
seconds (UTC by definition) — not ``unixTime``, which is when the scheduled
query ran.

**Values:** ``process.executable`` = ``path``; ``process.command_line`` =
``cmdline`` with osquery's trailing argument separator removed (osquery appends
one space after every argument, so a non-empty ``cmdline`` ends in exactly one
space — that separator, and nothing else, is removed); ``process.pid`` /
``parent_pid`` = ``pid`` / ``parent``; ``process.working_directory`` = ``cwd``;
``user`` = ``uid`` / ``username``; ``host.name`` = ``hostIdentifier`` and
``host.os_type`` = ``macos`` (the table is macOS-only). The parent's executable
is not in the row and is not guessed (Sigma ``ParentImage`` stays a gap).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import scalar_text

OSQUERY_ES_SOURCE_TYPE = "osquery_es_process_events"
OSQUERY_ES_DATASET = "osquery.es_process_events"
_ADAPTER = "OsqueryEsSourceAdapter"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_COLUMNS = frozenset({"path", "cmdline", "pid", "parent", "event_type", "time", "global_seq_num"})


def is_osquery_es_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is one osquery result row of ``es_process_events``."""
    columns = record.get("columns")
    return (
        isinstance(columns, Mapping) and "hostIdentifier" in record and columns.keys() >= _COLUMNS
    )


def _text(value: Any) -> str | None:
    return scalar_text(value, _ADAPTER)


def _int(value: Any, field: str) -> int | None:
    text = _text(value)
    if text is None:
        return None
    if not text.isdigit():
        raise SourceAdapterError(f"{_ADAPTER}: {field}={value!r} is not a non-negative integer")
    return int(text)


class OsqueryEsSourceAdapter:
    """osquery ``es_process_events`` exec rows -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return OSQUERY_ES_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_osquery_es_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not an osquery es_process_events row")
        columns: Mapping[str, Any] = raw_record["columns"]
        if columns.get("event_type") != "exec":
            raise SourceAdapterError(
                f"{_ADAPTER}: event_type {columns.get('event_type')!r} is not a process start"
            )
        if raw_record.get("action") not in (None, "added"):
            raise SourceAdapterError(f"{_ADAPTER}: action {raw_record.get('action')!r} refused")
        seconds = _int(columns["time"], "time")
        host = _text(raw_record["hostIdentifier"])
        sequence = _text(columns["global_seq_num"])
        if seconds is None or host is None or sequence is None:
            raise SourceAdapterError(
                f"{_ADAPTER}: time, hostIdentifier and global_seq_num required"
            )
        cmdline = columns.get("cmdline")
        if not isinstance(cmdline, str):
            raise SourceAdapterError(f"{_ADAPTER}: cmdline is not text")
        if cmdline and not cmdline.endswith(" "):
            raise SourceAdapterError(f"{_ADAPTER}: cmdline lacks osquery's argument separator")
        command_line = cmdline[:-1] if cmdline else None
        executable = _text(columns["path"])
        uid = _text(columns.get("uid"))
        observation_id = f"osquery-es:{host}:{sequence}:{seconds}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=_EPOCH + timedelta(seconds=seconds),
                timestamp_precision=TimePrecision.SECOND,
                raw_reference=SourceRef(
                    source_type=OSQUERY_ES_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(
                    kind="event",
                    category=("process",),
                    type=("start",),
                    action="exec",
                    dataset=OSQUERY_ES_DATASET,
                ),
                host=HostRef(name=host, os_type="macos"),
                user=UserRef(id=uid, name=_text(columns.get("username"))) if uid else None,
                process=ProcessRef(
                    pid=_int(columns["pid"], "pid"),
                    parent_pid=_int(columns["parent"], "parent"),
                    executable=executable,
                    name=executable.rsplit("/", 1)[-1] or None if executable else None,
                    command_line=command_line,
                    working_directory=_text(columns.get("cwd")),
                ),
            ),
        )


__all__ = [
    "OSQUERY_ES_DATASET",
    "OSQUERY_ES_SOURCE_TYPE",
    "OsqueryEsSourceAdapter",
    "is_osquery_es_record",
]
