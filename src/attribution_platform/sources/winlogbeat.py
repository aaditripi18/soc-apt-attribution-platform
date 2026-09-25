"""Shared record-shape helpers for the Windows event-log adapters (ADR-0008 D4).

**Winlogbeat 6 records.** Winlogbeat before 7.0 wrote the event envelope at the
top level (``log_name``, ``event_id``, ``record_number``, ``computer_name``,
``source_name``, ``event_data``, ``process_id``, ``user``); 7.0 moved the same
fields under ``winlog.*`` (``channel``, ``event_id``, ``record_id``,
``computer_name``, ``provider_name``, ``event_data``, ``process.pid``,
``user``). :func:`normalize_winlogbeat6` performs exactly that rename, so each
adapter reads one collector shape. The record's top-level ``host`` is **not**
carried over: in a Windows Event Forwarding pipeline it names the forwarding
server (real OTRF APT3 data: ``WECserver`` for events from four different
hosts), never the host the event happened on — that is ``computer_name``.

**Channel names.** Windows event-log channel names are case-insensitive; real
exports carry both ``Security`` and ``security`` for distinct records (OTRF
APT29: ≈37 k non-duplicate lower-case records). :func:`channel_matches`
compares case-insensitively and nothing else.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Winlogbeat 6 top-level field -> Winlogbeat 7 ``winlog`` field.
_WINLOG_RENAMES = {
    "log_name": "channel",
    "event_id": "event_id",
    "record_number": "record_id",
    "computer_name": "computer_name",
    "source_name": "provider_name",
    "event_data": "event_data",
    "user": "user",
    "provider_guid": "provider_guid",
    "task": "task",
    "opcode": "opcode",
}


def is_winlogbeat6(record: Mapping[str, Any]) -> bool:
    """A Winlogbeat 6 record: no ``winlog`` envelope, ``log_name`` and
    ``event_id`` at the top level."""
    return "winlog" not in record and "log_name" in record and "event_id" in record


def normalize_winlogbeat6(record: Mapping[str, Any]) -> dict[str, Any]:
    """The same record in the Winlogbeat 7 ``winlog`` shape (see module docstring).
    Never mutates ``record``."""
    winlog: dict[str, Any] = {
        new: record[old] for old, new in _WINLOG_RENAMES.items() if old in record
    }
    if "process_id" in record:
        winlog["process"] = {"pid": record["process_id"]}
    out: dict[str, Any] = {"winlog": winlog}
    if "@timestamp" in record:
        out["@timestamp"] = record["@timestamp"]
    return out


def channel_matches(actual: Any, expected: str) -> bool:
    """Case-insensitive Windows channel-name equality."""
    return isinstance(actual, str) and actual.casefold() == expected.casefold()


__all__ = ["channel_matches", "is_winlogbeat6", "normalize_winlogbeat6"]
