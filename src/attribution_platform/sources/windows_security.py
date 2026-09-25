"""The Windows Security event log SourceAdapter (ADR-0008 Wave 1, batch A).

Converts Windows ``Security`` channel events into Observations. Supported
(each verified on real OTRF samples; any other event ID fails closed):

- **4688** process creation → ``process`` (start). No process GUID exists in
  this event, so it forms no structural correlation link; where Sysmon is
  also collected it is the lower-precedence source and is suppressed
  (ADR-0008 D3, :mod:`attribution_platform.sources.precedence`).
- **4624** successful logon → ``logon``, ``target_user``, ``network.source``.
- **4776** credential validation (NTLM) → ``logon`` (package, workstation,
  status), ``target_user``.
- **4656 / 4663 / 4658** object handle requested / object accessed / handle
  closed → ``object_access`` and the requesting ``process``.
- **5140 / 5145** network share accessed / share object checked → ``share``,
  ``object_access`` (type, mask, list) and ``network.source``.

**Exact values.** Every value detection content reads is kept exactly as
logged — including Windows' ``-`` "no value" marker and unrendered ``%%NNNN``
message references (``AccessList``, ``ImpersonationLevel``, …), which Sigma
rules are written against. The only derived values are documented, exact
conversions: hex process ids (``0x1a74``) to integers, ``MandatoryLabel``
integrity SIDs to Sysmon's level names (only the four unambiguous RIDs),
``EventType`` to ``event.outcome``, and bare file names from full paths.
Process identity fields holding ``-`` / ``0x0`` mean "no process" and are
left absent.

**Event classification.** ``event.dataset`` = ``system.security`` (the
Windows Security channel; Elastic's own dataset name), ``event.provider`` =
the logging provider, ``event.code`` = the event ID. ECS categories are set
only where unambiguous (4688 process/start, 4624 and 4776 authentication/
start); object and share events carry none rather than an invented one.

**Record shapes (ADR-0008 D4).** Collector records (``winlog`` envelope,
``@timestamp`` = event time) and flat NXLog/Logstash exports, whose exact UTC
event time is derived by :mod:`attribution_platform.sources.nxlog_time`.
Flat records carrying only ``TimeCreated`` (the round-1 OTRF exports) are
refused: that field has no zone and on the real samples sits exactly 16 h
behind Sysmon's ``UtcTime`` — no real zone — so no trustworthy event time
exists.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    LogonRef,
    NetworkEndpoint,
    NetworkInfo,
    ObjectAccessRef,
    Observation,
    ProcessRef,
    ShareRef,
    SourceRef,
    TimePrecision,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.nxlog_time import nxlog_event_time, parse_timestamp

#: This adapter's stable source identifier.
WINDOWS_SECURITY_SOURCE_TYPE = "windows_security"
SECURITY_CHANNEL = "Security"
#: ``event.dataset`` for the Windows Security channel (Elastic's dataset name).
SECURITY_DATASET = "system.security"

_ADAPTER = "WindowsSecuritySourceAdapter"

#: ``MandatoryLabel`` integrity SIDs -> the level names Sysmon reports.
_INTEGRITY_LEVELS = {
    "S-1-16-4096": "Low",
    "S-1-16-8192": "Medium",
    "S-1-16-12288": "High",
    "S-1-16-16384": "System",
}
_OUTCOMES = {"AUDIT_SUCCESS": "success", "AUDIT_FAILURE": "failure"}


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


def _hex_pid(data: Mapping[str, Any], key: str) -> int | None:
    value = _text(data, key)
    if value is None or value in ("-", "0x0"):
        return None
    if not value.lower().startswith("0x"):
        raise SourceAdapterError(f"{_ADAPTER}: {key} {value!r} is not a hex process id")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise SourceAdapterError(f"{_ADAPTER}: {key} {value!r} is not a hex process id") from exc


def _port(data: Mapping[str, Any], key: str) -> int | None:
    value = _text(data, key)
    if value is None or value == "-":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise SourceAdapterError(f"{_ADAPTER}: {key} {value!r} is not a port") from exc


def _basename(path: str | None) -> str | None:
    if path is None:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1] or None


def _path(data: Mapping[str, Any], key: str) -> str | None:
    value = _text(data, key)
    return None if value == "-" else value


def _user(data: Mapping[str, Any], prefix: str) -> UserRef | None:
    sid, name, domain = (
        _text(data, f"{prefix}UserSid"),
        _text(data, f"{prefix}UserName"),
        _text(data, f"{prefix}DomainName"),
    )
    if sid is None and name is None and domain is None:
        return None
    return UserRef(id=sid, name=name, domain=domain)


def _source_endpoint(data: Mapping[str, Any]) -> NetworkInfo | None:
    ip, port = _text(data, "IpAddress"), _port(data, "IpPort")
    if ip is None and port is None:
        return None
    return NetworkInfo(source=NetworkEndpoint(ip=ip, port=port))


def _acting_process(data: Mapping[str, Any]) -> ProcessRef | None:
    executable = _path(data, "ProcessName")
    pid = _hex_pid(data, "ProcessId")
    if executable is None and pid is None:
        return None
    return ProcessRef(pid=pid, executable=executable, name=_basename(executable))


def _object_access(data: Mapping[str, Any]) -> ObjectAccessRef:
    return ObjectAccessRef(
        server=_text(data, "ObjectServer"),
        type=_text(data, "ObjectType"),
        name=_text(data, "ObjectName"),
        handle_id=_text(data, "HandleId"),
        access_mask=_text(data, "AccessMask"),
        access_list=_text(data, "AccessList"),
        value_name=_text(data, "ObjectValueName"),
        new_value=_text(data, "NewValue"),
    )


# ---------------------------------------------------------------------------
# Per-event mapping: (category, type, action, fields builder)
# ---------------------------------------------------------------------------

_Fields = dict[str, Any]


def _process_creation(data: Mapping[str, Any]) -> _Fields:
    executable = _path(data, "NewProcessName")
    parent = _path(data, "ParentProcessName")
    return {
        "process": ProcessRef(
            pid=_hex_pid(data, "NewProcessId"),
            name=_basename(executable),
            executable=executable,
            command_line=_text(data, "CommandLine"),
            parent_pid=_hex_pid(data, "ProcessId"),
            parent_name=_basename(parent),
            parent_executable=parent,
            integrity_level=_INTEGRITY_LEVELS.get(_text(data, "MandatoryLabel") or ""),
        ),
        "target_user": _user(data, "Target"),
    }


def _logon(data: Mapping[str, Any]) -> _Fields:
    return {
        "logon": LogonRef(
            logon_type=_text(data, "LogonType"),
            logon_process=_text(data, "LogonProcessName"),
            authentication_package=_text(data, "AuthenticationPackageName"),
            lm_package=_text(data, "LmPackageName"),
            key_length=_text(data, "KeyLength"),
            impersonation_level=_text(data, "ImpersonationLevel"),
            elevated_token=_text(data, "ElevatedToken"),
            logon_id=_text(data, "TargetLogonId"),
            workstation_name=_text(data, "WorkstationName"),
            target_outbound_user_name=_text(data, "TargetOutboundUserName"),
        ),
        "target_user": _user(data, "Target"),
        "network": _source_endpoint(data),
        "process": _acting_process(data),
    }


def _credential_validation(data: Mapping[str, Any]) -> _Fields:
    name = _text(data, "TargetUserName")
    return {
        "logon": LogonRef(
            package_name=_text(data, "PackageName"),
            workstation=_text(data, "Workstation"),
            status=_text(data, "Status"),
        ),
        "target_user": UserRef(name=name) if name is not None else None,
    }


def _object_event(data: Mapping[str, Any]) -> _Fields:
    return {"object_access": _object_access(data), "process": _acting_process(data)}


def _share_event(data: Mapping[str, Any]) -> _Fields:
    return {
        "share": ShareRef(
            name=_text(data, "ShareName"),
            local_path=_text(data, "ShareLocalPath"),
            relative_target_name=_text(data, "RelativeTargetName"),
        ),
        "object_access": _object_access(data),
        "network": _source_endpoint(data),
    }


_EVENTS: dict[
    int, tuple[tuple[str, ...], tuple[str, ...], str, Callable[[Mapping[str, Any]], _Fields]]
] = {
    4688: (("process",), ("start",), "process_start", _process_creation),
    4624: (("authentication",), ("start",), "logon", _logon),
    4776: (("authentication",), ("start",), "credential_validation", _credential_validation),
    4656: ((), (), "object_handle_request", _object_event),
    4663: ((), (), "object_access", _object_event),
    4658: ((), (), "object_handle_close", _object_event),
    5140: ((), (), "share_access", _share_event),
    5145: ((), (), "share_object_check", _share_event),
}
SUPPORTED_EVENT_IDS = tuple(sorted(_EVENTS))


class WindowsSecuritySourceAdapter:
    """Windows Security channel events -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return WINDOWS_SECURITY_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping):
            raise SourceAdapterError(
                f"{_ADAPTER} expects a Mapping (a parsed event), got {type(raw_record).__name__}"
            )
        collector = "winlog" in raw_record
        if collector:
            channel = _get(raw_record, "winlog", "channel")
            event_id_raw = _get(raw_record, "winlog", "event_id")
        else:
            channel = raw_record.get("Channel")
            event_id_raw = raw_record.get("EventID")
        if channel != SECURITY_CHANNEL:
            raise SourceAdapterError(f"{_ADAPTER}: channel {channel!r} is not {SECURITY_CHANNEL!r}")
        try:
            event_id = int(event_id_raw)
        except (TypeError, ValueError) as exc:
            raise SourceAdapterError(f"{_ADAPTER}: event id {event_id_raw!r} is invalid") from exc
        if event_id not in _EVENTS:
            raise SourceAdapterError(
                f"{_ADAPTER}: unsupported event id {event_id} (supported: {SUPPORTED_EVENT_IDS})"
            )

        timestamp: datetime
        precision: TimePrecision | None
        if collector:
            record_id_raw = _get(raw_record, "winlog", "record_id")
            computer = _get(raw_record, "winlog", "computer_name") or _get(
                raw_record, "host", "name"
            )
            data: Mapping[str, Any] = _get(raw_record, "winlog", "event_data") or {}
            provider = _get(raw_record, "winlog", "provider_name")
            outcome = _get(raw_record, "event", "outcome")
            timestamp = parse_timestamp(
                raw_record.get("@timestamp"), "@timestamp", adapter=_ADAPTER
            )
            precision = None
        else:
            if "EventTime" not in raw_record:
                raise SourceAdapterError(
                    f"{_ADAPTER}: flat record has no EventTime; TimeCreated alone carries no "
                    f"zone and is not a trustworthy UTC event time"
                )
            record_id_raw = raw_record.get("RecordNumber", raw_record.get("EventRecordID"))
            computer = raw_record.get("Hostname")
            data = raw_record
            provider = raw_record.get("SourceName")
            outcome = _OUTCOMES.get(str(raw_record.get("EventType")))
            timestamp = nxlog_event_time(raw_record, adapter=_ADAPTER)
            precision = TimePrecision.SECOND
        if record_id_raw is None or str(record_id_raw) == "":
            raise SourceAdapterError(f"{_ADAPTER}: missing required event record id")
        record_id = str(record_id_raw)
        if timestamp.tzinfo is None:
            raise SourceAdapterError(f"{_ADAPTER}: event time has no zone")
        if not isinstance(computer, str) or not computer.strip():
            raise SourceAdapterError(f"{_ADAPTER}: missing required host name")

        category, event_type, action, build = _EVENTS[event_id]
        fields = build(data)
        return (
            Observation(
                observation_id=f"{WINDOWS_SECURITY_SOURCE_TYPE}:{computer}:{record_id}",
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(source_type=self.source_type, source_event_id=record_id),
                event=EventMetadata(
                    kind="event",
                    category=category,
                    type=event_type,
                    action=action,
                    outcome=outcome if isinstance(outcome, str) else None,
                    provider=provider if isinstance(provider, str) else None,
                    code=str(event_id),
                    dataset=SECURITY_DATASET,
                ),
                host=HostRef(name=computer),
                user=_user(data, "Subject"),
                **fields,
            ),
        )


__all__ = [
    "SECURITY_CHANNEL",
    "SECURITY_DATASET",
    "SUPPORTED_EVENT_IDS",
    "WINDOWS_SECURITY_SOURCE_TYPE",
    "WindowsSecuritySourceAdapter",
]
