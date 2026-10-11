"""The Windows System event log SourceAdapter (ADR-0008 Amendment: System log).

Converts Windows ``System`` channel events into Observations. Supported —
verified on real OTRF samples; any other event fails closed:

- **7045** (provider ``Service Control Manager``): a service was installed →
  ``service`` (``ServiceName``, ``ImagePath``, ``ServiceType``, ``StartType``,
  ``AccountName``).

**Why this event.** It is what Sigma's ``windows/system`` content is written
against (41 of the 58 Core++ rules, and every accepted actor-specific System
rule), and service installation is how much lateral movement and persistence
shows up when Sysmon is absent.

**Exact values.** Everything is kept exactly as logged. 7045 renders the type
and start type as text (``user mode service``, ``auto start``) where Security
4697 logs codes (``0x10``, ``2``); neither is converted to the other.

**7045 and Security 4697 record the same installation and are both kept.**
They are not duplicates of one fact: on the real samples 4697's ``ServiceName``
is the service's key name (``javamtsup``) and 7045's is its display name
(``Java(TM) Virtual Machine Support Service``), and detection content is
written against each event's own fields. They carry different ``event.dataset``
and ``event.code`` values, so no rule fires twice on one of them, and a
technique observed through both is one technique in every comparison.

**Record shapes (ADR-0008 D4).** Collector records (``winlog`` envelope;
Winlogbeat 6 records are normalised first) and flat NXLog exports, whose exact
UTC event time comes from :mod:`attribution_platform.sources.nxlog_time`.

In a flat NXLog record the collector's own ``AccountName`` / ``Domain`` (the
account of the event's ``UserID``) share their names with 7045's
``AccountName`` event field (the account the *service* runs as), and one
overwrote the other before the record reached us. Which, cannot be told from
the record, so in that shape neither the service account nor the acting
user's name is taken: the acting user is its SID (``UserID``) alone.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    Observation,
    ServiceRef,
    SourceRef,
    TimePrecision,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.nxlog_time import nxlog_event_time, parse_timestamp
from attribution_platform.sources.winlogbeat import (
    channel_matches,
    is_winlogbeat6,
    normalize_winlogbeat6,
)

#: This adapter's stable source identifier.
WINDOWS_SYSTEM_SOURCE_TYPE = "windows_system"
SYSTEM_CHANNEL = "System"
#: ``event.dataset`` for the Windows System channel (Elastic's dataset name).
SYSTEM_DATASET = "system.system"
SERVICE_CONTROL_MANAGER = "Service Control Manager"

_ADAPTER = "WindowsSystemSourceAdapter"
#: event id -> (required provider, action).
_EVENTS = {7045: (SERVICE_CONTROL_MANAGER, "service_installed")}
SUPPORTED_EVENT_IDS = tuple(sorted(_EVENTS))


def _get(record: Mapping[str, Any], *path: str) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def _text(data: Mapping[str, Any], key: str) -> str | None:
    """A field exactly as logged (strings only; absent/empty -> None)."""
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value if value != "" else None


class WindowsSystemSourceAdapter:
    """Windows System channel events -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return WINDOWS_SYSTEM_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping):
            raise SourceAdapterError(
                f"{_ADAPTER} expects a Mapping (a parsed event), got {type(raw_record).__name__}"
            )
        if is_winlogbeat6(raw_record):
            raw_record = normalize_winlogbeat6(raw_record)
        collector = "winlog" in raw_record
        if collector:
            channel = _get(raw_record, "winlog", "channel")
            event_id_raw = _get(raw_record, "winlog", "event_id")
            provider = _get(raw_record, "winlog", "provider_name")
        else:
            channel = raw_record.get("Channel")
            event_id_raw = raw_record.get("EventID")
            provider = raw_record.get("SourceName")
        if not channel_matches(channel, SYSTEM_CHANNEL):
            raise SourceAdapterError(f"{_ADAPTER}: channel {channel!r} is not {SYSTEM_CHANNEL!r}")
        try:
            event_id = int(event_id_raw)
        except (TypeError, ValueError) as exc:
            raise SourceAdapterError(f"{_ADAPTER}: event id {event_id_raw!r} is invalid") from exc
        if event_id not in _EVENTS:
            raise SourceAdapterError(
                f"{_ADAPTER}: unsupported event id {event_id} (supported: {SUPPORTED_EVENT_IDS})"
            )
        required_provider, action = _EVENTS[event_id]
        if provider != required_provider:
            # Event ids are per provider: another provider's 7045 is another event.
            raise SourceAdapterError(
                f"{_ADAPTER}: event {event_id} of provider {provider!r} is not supported "
                f"(only {required_provider!r})"
            )

        timestamp: datetime
        precision: TimePrecision | None
        user: UserRef | None
        if collector:
            record_id_raw = _get(raw_record, "winlog", "record_id")
            computer = _get(raw_record, "winlog", "computer_name")
            data: Mapping[str, Any] = _get(raw_record, "winlog", "event_data") or {}
            timestamp = parse_timestamp(
                raw_record.get("@timestamp"), "@timestamp", adapter=_ADAPTER
            )
            precision = None
            account = _text(data, "AccountName")
            logged: Mapping[str, Any] = _get(raw_record, "winlog", "user") or {}
            sid, name, domain = (
                _text(logged, "identifier"),
                _text(logged, "name"),
                _text(logged, "domain"),
            )
            user = (
                UserRef(id=sid, name=name, domain=domain)
                if (sid or name or domain) is not None
                else None
            )
        else:
            if "EventTime" not in raw_record:
                raise SourceAdapterError(
                    f"{_ADAPTER}: flat record has no EventTime; no trustworthy UTC event time"
                )
            record_id_raw = raw_record.get("RecordNumber", raw_record.get("EventRecordID"))
            computer = raw_record.get("Hostname")
            data = raw_record
            timestamp = nxlog_event_time(raw_record, adapter=_ADAPTER)
            precision = TimePrecision.SECOND
            account = None  # collides with the collector's AccountName (module docstring)
            sid = _text(raw_record, "UserID")
            user = UserRef(id=sid) if sid is not None else None
        if record_id_raw is None or str(record_id_raw) == "":
            raise SourceAdapterError(f"{_ADAPTER}: missing required event record id")
        record_id = str(record_id_raw)
        if timestamp.tzinfo is None:
            raise SourceAdapterError(f"{_ADAPTER}: event time has no zone")
        if not isinstance(computer, str) or not computer.strip():
            raise SourceAdapterError(f"{_ADAPTER}: missing required host name")
        service_name = _text(data, "ServiceName")
        if service_name is None:
            raise SourceAdapterError(f"{_ADAPTER}: event {event_id} has no ServiceName")

        return (
            Observation(
                observation_id=f"{WINDOWS_SYSTEM_SOURCE_TYPE}:{computer}:{record_id}",
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(source_type=self.source_type, source_event_id=record_id),
                event=EventMetadata(
                    kind="event",
                    category=(),
                    type=(),
                    action=action,
                    provider=required_provider,
                    code=str(event_id),
                    dataset=SYSTEM_DATASET,
                ),
                host=HostRef(name=computer, os_type="windows"),
                user=user,
                service=ServiceRef(
                    name=service_name,
                    file_name=_text(data, "ImagePath"),
                    type=_text(data, "ServiceType"),
                    start_type=_text(data, "StartType"),
                    account=account,
                ),
            ),
        )


__all__ = [
    "SERVICE_CONTROL_MANAGER",
    "SUPPORTED_EVENT_IDS",
    "SYSTEM_CHANNEL",
    "SYSTEM_DATASET",
    "WINDOWS_SYSTEM_SOURCE_TYPE",
    "WindowsSystemSourceAdapter",
]
