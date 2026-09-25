"""The Windows PowerShell logging SourceAdapter (ADR-0008 Wave 1).

Converts ``Microsoft-Windows-PowerShell/Operational`` events into Observations:

- **4104 — script-block logging:** the text of a script block PowerShell
  compiled (``ScriptBlockText``; a long block is logged in several parts,
  ``MessageNumber`` of ``MessageTotal``), its ``ScriptBlockId`` and ``Path``.
- **4103 — module/pipeline logging:** ``Payload`` (the logged invocation) and
  ``ContextInfo`` (the host context block).

Any other channel or event ID fails closed. This module is the only place
PowerShell/Windows-event-native field names appear (doc 12 §D.1); nothing above
the adapter boundary sees them.

**Two record shapes (ADR-0008 D4):**

- *Collector records* (Winlogbeat / Elastic Agent): ``winlog`` envelope
  (``channel``, ``event_id``, ``record_id``, ``computer_name``,
  ``event_data``); ``@timestamp`` is the event time.
- *Flat NXLog/Logstash exports* (real OTRF samples): fields at top level.
  PowerShell events carry no UTC event time there — ``EventTime`` is the
  host's local time with no zone, ``@timestamp`` is when the pipeline
  *received* the event. The adapter derives the event time **exactly from the
  record itself**: ``EventReceivedTime`` (local) and ``@timestamp`` (UTC) mark
  the same reception instant, so their difference is the host's UTC offset;
  real UTC offsets are multiples of 15 minutes and pipeline delay is seconds,
  so rounding to 15 minutes recovers it exactly. The record is refused if the
  residual is implausible (over 5 minutes) or any of the three fields is
  missing. Precision is one second (``EventTime`` has second resolution).
  Validated on all 93,426 records of the three OTRF Empire samples (offset
  −4 h throughout; delays ≤ 16 s). Implemented once, in
  :mod:`attribution_platform.sources.nxlog_time`.

The acting PowerShell host process is recorded by pid only (the event
envelope's execution process id): these events carry no process GUID, so they
form no structural correlation link (ADR-0003 rejects pid matching) — a
recorded limitation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    Observation,
    PowerShellRef,
    ProcessRef,
    SourceRef,
    TimePrecision,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.nxlog_time import nxlog_event_time, parse_timestamp

#: This adapter's stable source identifier.
POWERSHELL_SOURCE_TYPE = "windows_powershell"
POWERSHELL_OPERATIONAL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

SCRIPT_BLOCK_EVENT_ID = 4104
MODULE_LOGGING_EVENT_ID = 4103
_SUPPORTED_EVENT_IDS = (MODULE_LOGGING_EVENT_ID, SCRIPT_BLOCK_EVENT_ID)

#: Neutral actions (detection scopes need them exact).
SCRIPT_BLOCK_ACTION = "powershell_script_block"
MODULE_LOGGING_ACTION = "powershell_module"

_ADAPTER = "PowerShellSourceAdapter"


def _get(record: Mapping[str, Any], *path: str) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def _optional_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise SourceAdapterError(
            f"PowerShellSourceAdapter: {field} {value!r} is not an integer"
        ) from exc


def _flat_record_id(record: Mapping[str, Any]) -> str:
    record_id = record.get("EventRecordID", record.get("RecordNumber"))
    if record_id is not None:
        return str(record_id)
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PowerShellSourceAdapter:
    """PowerShell/Operational 4103/4104 -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return POWERSHELL_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping):
            raise SourceAdapterError(
                "PowerShellSourceAdapter expects a Mapping (a parsed event), "
                f"got {type(raw_record).__name__}"
            )
        collector = "winlog" in raw_record
        # Identify the event first: a record from another channel or of an
        # unsupported type is refused for that reason, before anything else.
        if collector:
            channel = _get(raw_record, "winlog", "channel")
            event_id_raw = _get(raw_record, "winlog", "event_id")
        else:
            channel = raw_record.get("Channel")
            event_id_raw = raw_record.get("EventID")
        if channel != POWERSHELL_OPERATIONAL_CHANNEL:
            raise SourceAdapterError(
                f"PowerShellSourceAdapter: channel {channel!r} is not "
                f"{POWERSHELL_OPERATIONAL_CHANNEL!r}"
            )
        event_id = _optional_int(event_id_raw, "event id")
        if event_id not in _SUPPORTED_EVENT_IDS:
            raise SourceAdapterError(
                f"PowerShellSourceAdapter: unsupported event id {event_id!r} "
                f"(supported: {_SUPPORTED_EVENT_IDS})"
            )

        if collector:
            record_id_raw = _get(raw_record, "winlog", "record_id")
            if record_id_raw is None:
                raise SourceAdapterError(
                    "PowerShellSourceAdapter: missing required field winlog.record_id"
                )
            record_id = str(record_id_raw)
            computer = _get(raw_record, "winlog", "computer_name") or _get(
                raw_record, "host", "name"
            )
            data: Mapping[str, Any] = _get(raw_record, "winlog", "event_data") or {}
            timestamp = parse_timestamp(
                raw_record.get("@timestamp"), "@timestamp", adapter=_ADAPTER
            )
            precision = None
            pid = _get(raw_record, "winlog", "process", "pid")
            user_sid = _get(raw_record, "winlog", "user", "identifier")
        else:
            record_id = _flat_record_id(raw_record)
            computer = raw_record.get("Hostname")
            data = raw_record
            timestamp = nxlog_event_time(raw_record, adapter=_ADAPTER)
            precision = TimePrecision.SECOND
            pid = raw_record.get("ExecutionProcessID")
            user_sid = raw_record.get("UserID")

        if timestamp.tzinfo is None:
            raise SourceAdapterError("PowerShellSourceAdapter: event time has no zone")
        if not isinstance(computer, str) or not computer.strip():
            raise SourceAdapterError("PowerShellSourceAdapter: missing required host name")

        if event_id == SCRIPT_BLOCK_EVENT_ID:
            text = data.get("ScriptBlockText")
            if not isinstance(text, str) or not text:
                raise SourceAdapterError(
                    "PowerShellSourceAdapter: script block event without ScriptBlockText"
                )
            powershell = PowerShellRef(
                script_block_text=text,
                script_block_id=data.get("ScriptBlockId"),
                script_path=data.get("Path") or None,
                message_number=_optional_int(data.get("MessageNumber"), "MessageNumber"),
                message_total=_optional_int(data.get("MessageTotal"), "MessageTotal"),
            )
            action = SCRIPT_BLOCK_ACTION
        else:
            payload = data.get("Payload")
            if not isinstance(payload, str) or not payload:
                raise SourceAdapterError(
                    "PowerShellSourceAdapter: module logging event without Payload"
                )
            powershell = PowerShellRef(payload=payload, context_info=data.get("ContextInfo"))
            action = MODULE_LOGGING_ACTION

        pid_value = _optional_int(pid, "process id")
        return (
            Observation(
                observation_id=f"powershell:{computer}:{record_id}",
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(source_type=self.source_type, source_event_id=record_id),
                event=EventMetadata(
                    kind="event", category=("process",), type=("info",), action=action
                ),
                host=HostRef(name=computer),
                user=UserRef(id=user_sid) if isinstance(user_sid, str) and user_sid else None,
                process=ProcessRef(pid=pid_value) if pid_value is not None else None,
                powershell=powershell,
            ),
        )


__all__ = [
    "POWERSHELL_SOURCE_TYPE",
    "POWERSHELL_OPERATIONAL_CHANNEL",
    "SCRIPT_BLOCK_EVENT_ID",
    "MODULE_LOGGING_EVENT_ID",
    "SCRIPT_BLOCK_ACTION",
    "MODULE_LOGGING_ACTION",
    "PowerShellSourceAdapter",
]
