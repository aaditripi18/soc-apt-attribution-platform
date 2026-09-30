"""The Windows Security event log SourceAdapter (ADR-0008 Wave 1, batches A and B).

Converts Windows ``Security`` channel events into Observations. Supported
(each verified on real OTRF samples; any other event ID fails closed).
Batch A:

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

Batch B (the acting session's ``SubjectLogonId`` → ``logon.subject_logon_id``
throughout):

- **4625** failed logon (as 4624, plus status, sub-status, failure reason);
  **4648** logon with explicit credentials (``logon.target_server_name`` /
  ``target_info``); **4611** logon process registered.
- **4768 / 4769 / 4771** Kerberos TGT / service ticket / pre-auth failure →
  ``service`` (``ServiceName`` / ``ServiceSid``), ``kerberos`` (options,
  encryption type, pre-auth type, certificate thumbprint), ``logon.status``,
  the client account as ``target_user``.
- **4672 / 4673 / 4674** privileges assigned / privileged service / privileged
  object operation → ``privilege``.
- **4697** service installed → ``service``; **4698 / 4702** scheduled task
  created / updated → ``scheduled_task``.
- **4657** registry value modified, **4661 / 4662** SAM / directory-service
  handle and operation → ``object_access`` (old value and types, operation
  type, ``Properties`` GUIDs, additional info).
- **4720 / 4722 / 4724 / 4738 / 4728 / 4732** account management →
  ``account_change`` and the account or group acted upon as ``target_user``.
- **5379** Credential Manager read → ``credential_read``; **5441 / 5447** WFP
  filter present / changed → ``wfp_filter`` (acting account = ``UserSid``).

**Exact values.** Every value detection content reads is kept exactly as
logged — including Windows' ``-`` "no value" marker and unrendered ``%%NNNN``
message references (``AccessList``, ``ImpersonationLevel``, …), which Sigma
rules are written against. The only derived values are documented, exact
conversions: hex process ids (``0x1a74``) to integers, ``MandatoryLabel``
integrity SIDs to Sysmon's level names (only the four unambiguous RIDs),
``EventType`` to ``event.outcome``, bare file names from full paths, and the
decimal ``ClientProcessId`` / ``ParentProcessId`` of 4697 / 5379 to integers.
Process identity fields holding ``-`` / ``0x0`` mean "no process" and are
left absent.

**Event classification.** ``event.dataset`` = ``system.security`` (the
Windows Security channel; Elastic's own dataset name), ``event.provider`` =
the logging provider, ``event.code`` = the event ID. ECS categories are set
only where unambiguous (4688 process/start; 4624, 4625, 4648, 4768, 4769,
4771 and 4776 authentication/start); every other event carries none rather
than an invented one, and is identified by ``event.code`` / ``event.action``.

**Record shapes (ADR-0008 D4).** Collector records (``winlog`` envelope,
``@timestamp`` = event time; Winlogbeat 6 records are first normalized to it by
:mod:`attribution_platform.sources.winlogbeat`; the channel name is compared
case-insensitively) and flat NXLog/Logstash exports, whose exact UTC
event time is derived by :mod:`attribution_platform.sources.nxlog_time`.
Flat records carrying only ``TimeCreated`` (the round-1 OTRF exports) are
refused: that field has no zone and on the real samples sits exactly 16 h
behind Sysmon's ``UtcTime`` — no real zone — so no trustworthy event time
exists.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from attribution_platform.domain import (
    AccountChangeRef,
    CredentialReadRef,
    EventMetadata,
    HostRef,
    KerberosRef,
    LogonRef,
    NetworkEndpoint,
    NetworkInfo,
    ObjectAccessRef,
    Observation,
    PrivilegeRef,
    ProcessRef,
    ScheduledTaskRef,
    ServiceRef,
    ShareRef,
    SourceRef,
    TimePrecision,
    UserRef,
    WfpFilterRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.nxlog_time import nxlog_event_time, parse_timestamp
from attribution_platform.sources.winlogbeat import (
    channel_matches,
    is_winlogbeat6,
    normalize_winlogbeat6,
)

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
        old_value=_text(data, "OldValue"),
        new_value_type=_text(data, "NewValueType"),
        old_value_type=_text(data, "OldValueType"),
        operation_type=_text(data, "OperationType"),
        properties=_text(data, "Properties"),
        additional_info=_text(data, "AdditionalInfo"),
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


# --- Security batch B ------------------------------------------------------


def _decimal_pid(data: Mapping[str, Any], key: str) -> int | None:
    """A decimal process id (4697 ``ClientProcessId`` / ``ParentProcessId``,
    5379 ``ClientProcessId``) — unlike the hex ids of the older events."""
    value = _text(data, key)
    if value is None or value == "-":
        return None
    if not value.isdigit():
        raise SourceAdapterError(f"{_ADAPTER}: {key} {value!r} is not a decimal process id")
    return int(value)


def _subject_session(data: Mapping[str, Any], **facts: str | None) -> LogonRef | None:
    """``LogonRef`` holding the acting session's ``SubjectLogonId`` plus any
    event-specific logon facts; ``None`` when there is nothing to hold."""
    values = {"subject_logon_id": _text(data, "SubjectLogonId"), **facts}
    if all(v is None for v in values.values()):
        return None
    return LogonRef(**values)


def _target_account(data: Mapping[str, Any]) -> UserRef | None:
    """The account acted upon. Account-management and Kerberos events log its
    SID as ``TargetSid`` (logon events: ``TargetUserSid``)."""
    sid = _text(data, "TargetSid") or _text(data, "TargetUserSid")
    name, domain = _text(data, "TargetUserName"), _text(data, "TargetDomainName")
    if sid is None and name is None and domain is None:
        return None
    return UserRef(id=sid, name=name, domain=domain)


def _failed_logon(data: Mapping[str, Any]) -> _Fields:
    fields = _logon(data)
    fields["logon"] = dataclasses.replace(
        fields["logon"],
        status=_text(data, "Status"),
        sub_status=_text(data, "SubStatus"),
        failure_reason=_text(data, "FailureReason"),
        subject_logon_id=_text(data, "SubjectLogonId"),
    )
    return fields


def _explicit_credentials(data: Mapping[str, Any]) -> _Fields:
    return {
        "logon": _subject_session(
            data,
            target_server_name=_text(data, "TargetServerName"),
            target_info=_text(data, "TargetInfo"),
        ),
        "target_user": _user(data, "Target"),
        "network": _source_endpoint(data),
        "process": _acting_process(data),
    }


def _logon_process_registered(data: Mapping[str, Any]) -> _Fields:
    return {"logon": _subject_session(data, logon_process=_text(data, "LogonProcessName"))}


def _privileges(data: Mapping[str, Any]) -> _Fields:
    fields: _Fields = {
        "logon": _subject_session(data),
        "privilege": PrivilegeRef(
            privilege_list=_text(data, "PrivilegeList"), service=_text(data, "Service")
        ),
        "process": _acting_process(data),
    }
    if _text(data, "ObjectName") is not None or _text(data, "ObjectServer") is not None:
        fields["object_access"] = _object_access(data)
    return fields


def _service_installed(data: Mapping[str, Any]) -> _Fields:
    client_pid = _decimal_pid(data, "ClientProcessId")
    parent_pid = _decimal_pid(data, "ParentProcessId")
    return {
        "logon": _subject_session(data),
        "service": ServiceRef(
            name=_text(data, "ServiceName"),
            file_name=_text(data, "ServiceFileName"),
            type=_text(data, "ServiceType"),
            start_type=_text(data, "ServiceStartType"),
            account=_text(data, "ServiceAccount"),
        ),
        "process": (
            ProcessRef(pid=client_pid, parent_pid=parent_pid)
            if client_pid is not None or parent_pid is not None
            else None
        ),
    }


def _scheduled_task(data: Mapping[str, Any]) -> _Fields:
    return {
        "logon": _subject_session(data),
        "scheduled_task": ScheduledTaskRef(
            name=_text(data, "TaskName"),
            content=_text(data, "TaskContent"),
            content_new=_text(data, "TaskContentNew"),
        ),
    }


def _object_event_with_session(data: Mapping[str, Any]) -> _Fields:
    return {**_object_event(data), "logon": _subject_session(data)}


def _kerberos(data: Mapping[str, Any]) -> _Fields:
    return {
        "logon": LogonRef(status=_text(data, "Status")),
        "service": ServiceRef(name=_text(data, "ServiceName"), id=_text(data, "ServiceSid")),
        "kerberos": KerberosRef(
            ticket_options=_text(data, "TicketOptions"),
            ticket_encryption_type=_text(data, "TicketEncryptionType"),
            pre_auth_type=_text(data, "PreAuthType"),
            cert_thumbprint=_text(data, "CertThumbprint"),
        ),
        "target_user": _target_account(data),
        "network": _source_endpoint(data),
    }


def _account_change(data: Mapping[str, Any]) -> _Fields:
    return {
        "logon": _subject_session(data),
        "target_user": _target_account(data),
        "account_change": AccountChangeRef(
            sam_account_name=_text(data, "SamAccountName"),
            user_principal_name=_text(data, "UserPrincipalName"),
            display_name=_text(data, "DisplayName"),
            old_uac_value=_text(data, "OldUacValue"),
            new_uac_value=_text(data, "NewUacValue"),
            user_account_control=_text(data, "UserAccountControl"),
            sid_history=_text(data, "SidHistory"),
            primary_group_id=_text(data, "PrimaryGroupId"),
            member_name=_text(data, "MemberName"),
            member_sid=_text(data, "MemberSid"),
        ),
    }


def _credential_read(data: Mapping[str, Any]) -> _Fields:
    pid = _decimal_pid(data, "ClientProcessId")
    return {
        "logon": _subject_session(data),
        "credential_read": CredentialReadRef(
            target_name=_text(data, "TargetName"),
            type=_text(data, "Type"),
            read_operation=_text(data, "ReadOperation"),
            count_returned=_text(data, "CountOfCredentialsReturned"),
            return_code=_text(data, "ReturnCode"),
        ),
        "process": ProcessRef(pid=pid) if pid is not None else None,
    }


def _wfp_filter(data: Mapping[str, Any]) -> _Fields:
    sid = _text(data, "UserSid")
    return {
        "wfp_filter": WfpFilterRef(
            name=_text(data, "FilterName"),
            key=_text(data, "FilterKey"),
            type=_text(data, "FilterType"),
            change_type=_text(data, "ChangeType"),
            provider_name=_text(data, "ProviderName"),
            provider_context_name=_text(data, "ProviderContextName"),
            layer_name=_text(data, "LayerName"),
            callout_name=_text(data, "CalloutName"),
        ),
        # WFP events log the acting account as UserSid / "DOMAIN\\user"
        # UserName; only the SID maps exactly onto UserRef.
        "user": UserRef(id=sid) if sid is not None else None,
    }


_AUTH = (("authentication",), ("start",))
_NONE: tuple[tuple[str, ...], tuple[str, ...]] = ((), ())

_EVENTS: dict[
    int, tuple[tuple[str, ...], tuple[str, ...], str, Callable[[Mapping[str, Any]], _Fields]]
] = {
    4688: (("process",), ("start",), "process_start", _process_creation),
    4624: (*_AUTH, "logon", _logon),
    4776: (*_AUTH, "credential_validation", _credential_validation),
    4656: (*_NONE, "object_handle_request", _object_event),
    4663: (*_NONE, "object_access", _object_event),
    4658: (*_NONE, "object_handle_close", _object_event),
    5140: (*_NONE, "share_access", _share_event),
    5145: (*_NONE, "share_object_check", _share_event),
    # batch B
    4625: (*_AUTH, "logon_failed", _failed_logon),
    4648: (*_AUTH, "explicit_credential_logon", _explicit_credentials),
    4768: (*_AUTH, "kerberos_tgt_request", _kerberos),
    4769: (*_AUTH, "kerberos_service_ticket_request", _kerberos),
    4771: (*_AUTH, "kerberos_preauth_failed", _kerberos),
    4611: (*_NONE, "logon_process_registered", _logon_process_registered),
    4672: (*_NONE, "special_privileges_assigned", _privileges),
    4673: (*_NONE, "privileged_service_called", _privileges),
    4674: (*_NONE, "privileged_object_operation", _privileges),
    4697: (*_NONE, "service_installed", _service_installed),
    4698: (*_NONE, "scheduled_task_created", _scheduled_task),
    4702: (*_NONE, "scheduled_task_updated", _scheduled_task),
    4657: (*_NONE, "registry_value_modified", _object_event_with_session),
    4661: (*_NONE, "object_handle_request_directory", _object_event_with_session),
    4662: (*_NONE, "directory_object_operation", _object_event_with_session),
    4720: (*_NONE, "user_account_created", _account_change),
    4722: (*_NONE, "user_account_enabled", _account_change),
    4724: (*_NONE, "password_reset_attempted", _account_change),
    4738: (*_NONE, "user_account_changed", _account_change),
    4728: (*_NONE, "member_added_to_global_group", _account_change),
    4732: (*_NONE, "member_added_to_local_group", _account_change),
    5379: (*_NONE, "credential_manager_read", _credential_read),
    5441: (*_NONE, "wfp_filter_present", _wfp_filter),
    5447: (*_NONE, "wfp_filter_changed", _wfp_filter),
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
        if is_winlogbeat6(raw_record):
            raw_record = normalize_winlogbeat6(raw_record)
        collector = "winlog" in raw_record
        if collector:
            channel = _get(raw_record, "winlog", "channel")
            event_id_raw = _get(raw_record, "winlog", "event_id")
        else:
            channel = raw_record.get("Channel")
            event_id_raw = raw_record.get("EventID")
        if not channel_matches(channel, SECURITY_CHANNEL):
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
        # The acting account is the Subject* fields unless the event logs it
        # under other names (WFP: UserSid), in which case the builder sets it.
        user = fields.pop("user") if "user" in fields else _user(data, "Subject")
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
                user=user,
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
