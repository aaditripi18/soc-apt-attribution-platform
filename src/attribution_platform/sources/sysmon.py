"""The Windows/Sysmon SourceAdapter: a native-collector event -> Observation
(gate G0.11).

Per docs/architecture/12-deployment-and-endpoint-scope.md (C0.2) §D.1/§D.2/§F:
Sysmon is the **primary v1 Windows telemetry source**, but it is **not** an
Attribution Engine dependency — this module is the *entire* place Sysmon/
Winlogbeat-native field names may appear. Nothing above the
:class:`~attribution_platform.sources.adapter.SourceAdapter` boundary (the
domain layer, extraction, or any future attribution logic) ever sees
``winlog.event_id``, ``winlog.event_data.*``, or any other collector-native
key — those are read *only* in this module and converted into the
source-agnostic G0.3 entity groups.

**Raw record shape:** a parsed JSON event as the native Windows collector
(Elastic Agent's Windows/Sysmon integration, or Winlogbeat's Sysmon module —
collector choice is a Phase-1 operational decision per C0.2 §L, not fixed
here) actually emits: ECS top-level fields it already maps
(``@timestamp``, ``host``, ``user``, ``process``, ``source``/``destination``,
``network``) plus the ``winlog.*`` envelope Windows Event Log-based
collectors always carry (``event_id``, ``record_id``, ``computer_name``,
``channel``). This is a plain ``Mapping`` (a dict from parsed JSON), not a
new dataclass shape — mirroring how a real collector's output naturally
arrives, unlike G0.4's ``SyntheticRecord`` (which invented a fictional
minimal shape because the synthetic source has no real one).

**Scope — a growing, explicit set of Sysmon event types (ADR-0008 Wave 1):**
Event IDs 1 (Process Create), 5 (Process Terminated), 3 (Network Connection), 7 (Image Load), 8
(CreateRemoteThread), 10 (Process Access), 11 (File Create), 12 (Registry
key/value create or delete), 13 (Registry value set), 15 (file stream hash),
17/18 (pipe created/connected), 19/20/21 (WMI filter/consumer/binding), 22
(DNS query) and 23 (file delete).
Three real-world record shapes are accepted: collector records (ECS +
``winlog`` envelope), Winlogbeat 6 records (normalized to the ``winlog`` shape
by :mod:`attribution_platform.sources.winlogbeat`), and flat Windows-EventData
records (e.g. OTRF). A record naming any channel other than Sysmon's (compared
case-insensitively) is refused — other channels reuse Sysmon's small event IDs.

**Event time** is Sysmon's own ``UtcTime`` whenever the event carries it, in
every shape; the collector's ``@timestamp`` is used only when it does not. On
real collector data the two disagree: in OTRF's APT3 CALDERA recording 18,712 of
50,223 Sysmon events are 1–60 s apart, and in the Empire recording 3,409 network
events (ID 3, one host) are 272.8 h apart — the sensor's statement of when the
activity happened is authoritative, the forwarding pipeline's clock is not.
The original G0.11 scope was Event ID 1 (Process Create) and Event ID 3
(Network Connection).
These are chosen because they are the two most fundamental Sysmon events
for endpoint behavioral visibility and because they exercise two different
G0.3 entity groups (``ProcessRef`` and ``NetworkInfo``), proving the mapping
pattern generalizes rather than being a one-off. Extending to more event
types (File Create=11, Registry=12/13/14, ...) is a deliberate, later
addition — never speculative, per the same discipline G0.4's docstring
already established for ``SyntheticRecord``. An unrecognized
``winlog.event_id`` **fails closed** (raises, rather than silently dropping
or guessing) — this module does not stand up continuous live ingestion at
this gate, so refusing the unfamiliar is strictly safer than pretending to
handle it.

**No live collection, no host changes:** this module never installs,
configures, or talks to a real Sysmon/Windows Event Log service — it is a
pure function over already-parsed JSON records, exactly like every other
adapter. :func:`load_ndjson_events` reads a *file* of such records (for
tests and for a human trying this against an exported capture) — it is a
few lines of NDJSON parsing, not a second fixture/replay framework; the
actual replay orchestration (rule context, Evidence derivation, persistence)
is G0.9's ``replay`` package, reused unmodified by feeding this adapter's
output through the same G0.5/G0.6/G0.8 functions any other adapter uses.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attribution_platform.domain import (
    CodeSignature,
    DllRef,
    DnsRef,
    EventMetadata,
    FileRef,
    FileStreamRef,
    HashSet,
    HostRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    PeInfo,
    PipeRef,
    ProcessAccessRef,
    ProcessRef,
    RegistryRef,
    RemoteThreadRef,
    SourceRef,
    UserRef,
    WmiRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.sysmon_xml import is_sysmon_event_xml, parse_sysmon_event_xml
from attribution_platform.sources.winlogbeat import (
    channel_matches,
    is_winlogbeat6,
    normalize_winlogbeat6,
)

#: This adapter's stable source identifier.
SYSMON_SOURCE_TYPE = "sysmon"

#: The Windows event channel Sysmon writes to (checked for flat records).
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
#: Sysmon for Linux's channel (ADR-0010 D1): same schema, written to syslog as XML.
SYSMON_LINUX_CHANNEL = "Linux-Sysmon/Operational"
#: The platform each channel proves (ECS ``host.os.type``, ADR-0010 D2).
_CHANNEL_OS = {SYSMON_CHANNEL.casefold(): "windows", SYSMON_LINUX_CHANNEL.casefold(): "linux"}

PROCESS_CREATE_EVENT_ID = 1
PROCESS_TERMINATE_EVENT_ID = 5
NETWORK_CONNECT_EVENT_ID = 3
IMAGE_LOAD_EVENT_ID = 7
CREATE_REMOTE_THREAD_EVENT_ID = 8
PROCESS_ACCESS_EVENT_ID = 10
FILE_CREATE_EVENT_ID = 11
FILE_STREAM_HASH_EVENT_ID = 15
PIPE_CREATED_EVENT_ID = 17
PIPE_CONNECTED_EVENT_ID = 18
WMI_FILTER_EVENT_ID = 19
WMI_CONSUMER_EVENT_ID = 20
WMI_BINDING_EVENT_ID = 21
REGISTRY_OBJECT_EVENT_ID = 12  # key/value created or deleted
REGISTRY_VALUE_SET_EVENT_ID = 13
DNS_QUERY_EVENT_ID = 22
FILE_DELETE_EVENT_ID = 23

#: The Sysmon event IDs this adapter understands; anything else fails closed.
_SUPPORTED_EVENT_IDS = (
    PROCESS_CREATE_EVENT_ID,
    PROCESS_TERMINATE_EVENT_ID,
    NETWORK_CONNECT_EVENT_ID,
    IMAGE_LOAD_EVENT_ID,
    CREATE_REMOTE_THREAD_EVENT_ID,
    PROCESS_ACCESS_EVENT_ID,
    FILE_CREATE_EVENT_ID,
    REGISTRY_OBJECT_EVENT_ID,
    REGISTRY_VALUE_SET_EVENT_ID,
    FILE_STREAM_HASH_EVENT_ID,
    PIPE_CREATED_EVENT_ID,
    PIPE_CONNECTED_EVENT_ID,
    WMI_FILTER_EVENT_ID,
    WMI_CONSUMER_EVENT_ID,
    WMI_BINDING_EVENT_ID,
    DNS_QUERY_EVENT_ID,
    FILE_DELETE_EVENT_ID,
)

#: Neutral ``event.action`` tokens for event types whose detection scope needs
#: an exact action (the collector's own action text varies by collector).
CREATE_REMOTE_THREAD_ACTION = "create_remote_thread"
PROCESS_ACCESS_ACTION = "process_access"
DNS_QUERY_ACTION = "dns_query"
#: File-family actions: several Sysmon events are "file creation" in ECS terms,
#: so detection scopes need the exact action to tell them apart.
FILE_CREATE_ACTION = "file_create"
FILE_STREAM_CREATE_ACTION = "file_stream_create"
FILE_DELETE_ACTION = "file_delete"
PROCESS_END_ACTION = "process_end"
PIPE_ACTIONS = {PIPE_CREATED_EVENT_ID: "pipe_create", PIPE_CONNECTED_EVENT_ID: "pipe_connect"}
WMI_ACTIONS = {
    WMI_FILTER_EVENT_ID: "wmi_filter",
    WMI_CONSUMER_EVENT_ID: "wmi_consumer",
    WMI_BINDING_EVENT_ID: "wmi_binding",
}
#: Sysmon WMI ``Operation`` -> ECS ``event.type``; anything else fails closed.
_WMI_OPERATION_TYPES = {"Created": "creation", "Deleted": "deletion"}

#: The process-GUID EventData names differ by event type in real Sysmon output:
#: event 8 writes ``SourceProcessGuid``, event 10 ``SourceProcessGUID``.
_GUID_SUFFIX = {CREATE_REMOTE_THREAD_EVENT_ID: "Guid", PROCESS_ACCESS_EVENT_ID: "GUID"}

#: Sysmon registry ``EventType`` -> ECS ``event.type``, per event ID.
_REGISTRY_EVENT_TYPES: Mapping[int, Mapping[str, str]] = {
    REGISTRY_OBJECT_EVENT_ID: {
        "CreateKey": "creation",
        "DeleteKey": "deletion",
        "DeleteValue": "deletion",
    },
    REGISTRY_VALUE_SET_EVENT_ID: {"SetValue": "change"},
}

#: Envelope fields of a flat record (the event's own data is everything else).
_FLAT_ENVELOPE_FIELDS = frozenset(
    {
        "@timestamp",
        "Channel",
        "EventID",
        "EventRecordID",
        "Hostname",
        "Keywords",
        "Level",
        "Message",
        "ProviderGuid",
        "SourceName",
        "Task",
        "TimeCreated",
        # NXLog / Logstash envelope (OTRF 2020 "mordorDataset" exports). These
        # describe the log pipeline and the event-log service account, never the
        # Sysmon event itself; EventTime/EventReceivedTime are collector-local.
        "@version",
        "AccountName",
        "AccountType",
        "Category",
        "Domain",
        "EventReceivedTime",
        "EventTime",
        "EventTypeOrignal",
        "ExecutionProcessID",
        "Opcode",
        "OpcodeValue",
        "RecordNumber",
        "Severity",
        "SeverityValue",
        "SourceModuleName",
        "SourceModuleType",
        "ThreadID",
        "UserID",
        "Version",
        "host",
        "port",
        "tags",
    }
)


def _get(record: Mapping[str, Any], *path: str) -> Any:
    """Safe nested-field lookup; returns ``None`` if any hop is absent or
    not itself a mapping (never raises on a merely-missing optional field)."""
    current: Any = record
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def _as_int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise SourceAdapterError(
            f"SysmonSourceAdapter: {field} {value!r} is not an integer"
        ) from exc


def _is_flat(record: Mapping[str, Any]) -> bool:
    """A flat Windows-EventData record (e.g. OTRF/NXLog JSON): ``EventID`` and
    ``Channel`` at top level and no ``winlog`` envelope."""
    return "winlog" not in record and "EventID" in record and "Channel" in record


def _parse_sysmon_utc(raw: Any) -> datetime:
    """Sysmon's own ``UtcTime`` (``YYYY-MM-DD HH:MM:SS.fff``, always UTC)."""
    if not isinstance(raw, str):
        raise SourceAdapterError(f"SysmonSourceAdapter: UtcTime {raw!r} is not a string")
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise SourceAdapterError(f"SysmonSourceAdapter: UtcTime {raw!r} is not valid") from exc
    if parsed.tzinfo is not None:
        raise SourceAdapterError(f"SysmonSourceAdapter: UtcTime {raw!r} must not carry an offset")
    return parsed.replace(tzinfo=UTC)


#: NXLog's own ``EventType`` values (its event severity/audit type). They are
#: never a Sysmon ``EventType`` (CreateKey, SetValue, ...); on an NXLog record
#: such a value means NXLog's field has taken the name of Sysmon's.
_NXLOG_EVENT_TYPES = frozenset(
    {"INFO", "WARNING", "ERROR", "CRITICAL", "VERBOSE", "AUDIT_SUCCESS", "AUDIT_FAILURE"}
)


def _sysmon_event_type_from_message(message: Any) -> str | None:
    """Sysmon's own ``EventType`` from its rendered message, when exactly one
    ``EventType: <value>`` line is present; otherwise ``None``."""
    if not isinstance(message, str):
        return None
    values = [
        line[len("EventType: ") :].strip()
        for line in message.splitlines()
        if line.startswith("EventType: ")
    ]
    return values[0] if len(values) == 1 and values[0] else None


def _normalize_flat(record: Mapping[str, Any]) -> dict[str, Any]:
    """Re-envelope a flat record so the rest of the adapter reads it exactly
    like a collector record: its event fields become ``winlog.event_data``.

    - **Time:** Sysmon's own ``UtcTime`` — never the collector's
      ``@timestamp``/``TimeCreated``, which in real OTRF samples disagree with
      ``UtcTime`` by hours (a collector time-zone artefact).
    - **Colliding ``EventType``:** on an NXLog record, an ``EventType`` from
      NXLog's own vocabulary (``INFO``, ``AUDIT_SUCCESS``, ...) is NXLog's field,
      not Sysmon's, and is dropped. For registry events 12/13 — whose operation
      *is* Sysmon's ``EventType`` — Sysmon's value is recovered from the
      ``EventType:`` line of Sysmon's rendered message (exactly one such line;
      the value is still checked against the allowed operations). Real OTRF
      APT29 exports: 342,814 registry events recovered this way.
    - **Record id:** the Windows event record number when present
      (``EventRecordID``, or ``RecordNumber`` in NXLog exports); otherwise a
      deterministic content address ``sha256:<hex>`` of the record's canonical
      JSON (the source provides no identifier; derived, never random).
    """
    channel = record.get("Channel")
    if not channel_matches(channel, SYSMON_CHANNEL):
        raise SourceAdapterError(
            f"SysmonSourceAdapter: flat record channel {channel!r} is not {SYSMON_CHANNEL!r}"
        )
    record_id = record.get("EventRecordID", record.get("RecordNumber"))
    if record_id is None:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        record_id = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if "UtcTime" not in record:
        raise SourceAdapterError("SysmonSourceAdapter: flat record missing required field UtcTime")
    event_data = {k: v for k, v in record.items() if k not in _FLAT_ENVELOPE_FIELDS}
    nxlog = "EventReceivedTime" in record or "SourceModuleType" in record
    if nxlog and event_data.get("EventType") in _NXLOG_EVENT_TYPES:
        del event_data["EventType"]
        if _as_int(record["EventID"], "EventID") in _REGISTRY_EVENT_TYPES:
            recovered = _sysmon_event_type_from_message(record.get("Message"))
            if recovered is not None:
                event_data["EventType"] = recovered
    return {
        "@timestamp": _parse_sysmon_utc(record["UtcTime"]).isoformat(),
        "winlog": {
            "event_id": record["EventID"],
            "record_id": record_id,
            "computer_name": record.get("Hostname"),
            "channel": channel,
            "event_data": event_data,
        },
    }


def _require_event_id(record: Mapping[str, Any]) -> int:
    raw = _get(record, "winlog", "event_id")
    if raw is None:
        raw = _get(record, "event", "code")  # some collectors surface it only here
    if raw is None:
        raise SourceAdapterError("SysmonSourceAdapter: missing required field winlog.event_id")
    return _as_int(raw, "winlog.event_id")


def _require_timestamp(record: Mapping[str, Any]) -> datetime:
    utc_time = _get(record, "winlog", "event_data", "UtcTime")
    if utc_time is not None:
        return _parse_sysmon_utc(utc_time)  # the sensor's own event time wins
    raw = record.get("@timestamp")
    if raw is None:
        raise SourceAdapterError("SysmonSourceAdapter: missing required field '@timestamp'")
    if not isinstance(raw, str):
        raise SourceAdapterError(
            f"SysmonSourceAdapter: '@timestamp' must be a string, got {type(raw).__name__}"
        )
    try:
        return datetime.fromisoformat(raw)
    except ValueError as exc:
        raise SourceAdapterError(
            f"SysmonSourceAdapter: '@timestamp' {raw!r} is not a valid ISO-8601 timestamp"
        ) from exc


def _require_record_id(record: Mapping[str, Any]) -> str:
    raw = _get(record, "winlog", "record_id")
    if raw is None:
        raise SourceAdapterError("SysmonSourceAdapter: missing required field winlog.record_id")
    return str(raw)


def _require_computer_name(record: Mapping[str, Any]) -> str:
    name = _get(record, "winlog", "computer_name") or _get(record, "host", "name")
    if not isinstance(name, str) or not name.strip():
        raise SourceAdapterError(
            "SysmonSourceAdapter: missing required field winlog.computer_name (or host.name)"
        )
    return name


def _host_ref(record: Mapping[str, Any], computer_name: str, os_type: str | None) -> HostRef:
    ip_raw = _get(record, "host", "ip")
    ip = tuple(ip_raw) if isinstance(ip_raw, list) else ()
    return HostRef(name=computer_name, ip=ip, os_type=os_type)


def _event_data_or_ecs(record: Mapping[str, Any], event_data_key: str, *ecs_path: str) -> Any:
    """Sysmon's own ``winlog.event_data`` value when present, else the ECS
    field the collector mapped it to. Sysmon's EventData names are exactly the
    field names Windows detection content (Sigma) is written against, so the
    raw value is the faithful one; the ECS path covers collectors that only
    emit ECS. ``ecs_path`` may be empty (no ECS equivalent exists)."""
    value = _get(record, "winlog", "event_data", event_data_key)
    if value is None and ecs_path:
        value = _get(record, *ecs_path)
    return value


def _user_ref(record: Mapping[str, Any]) -> UserRef | None:
    name = _get(record, "user", "name")
    domain = _get(record, "user", "domain")
    if name is None and domain is None:
        # Sysmon's raw ``User`` is ``DOMAIN\name``; split on the first backslash.
        raw = _get(record, "winlog", "event_data", "User")
        if isinstance(raw, str) and raw.strip():
            domain_part, sep, name_part = raw.partition("\\")
            if sep:
                domain, name = domain_part or None, name_part or None
            else:
                name = raw
    if name is None and domain is None:
        return None
    return UserRef(name=name, domain=domain)


def _basename(path: Any) -> Any:
    """The file name of a Windows path (``ntpath`` semantics), else ``None``."""
    if not isinstance(path, str) or not path.strip():
        return None
    return ntpath.basename(path) or None


def _pe_info(record: Mapping[str, Any], ecs_owner: str) -> PeInfo | None:
    """PE version info from Sysmon's EventData (``OriginalFileName``, …) or the
    ECS ``<ecs_owner>.pe.*`` fields. ``ecs_owner`` is ``process`` for process
    creation and ``dll`` for image load — the same EventData names describe
    different binaries in different event types."""
    pe = PeInfo(
        original_file_name=_event_data_or_ecs(
            record, "OriginalFileName", ecs_owner, "pe", "original_file_name"
        ),
        description=_event_data_or_ecs(record, "Description", ecs_owner, "pe", "description"),
        product=_event_data_or_ecs(record, "Product", ecs_owner, "pe", "product"),
        company=_event_data_or_ecs(record, "Company", ecs_owner, "pe", "company"),
    )
    return None if pe == PeInfo() else pe


#: Sysmon's ``HashAlgorithms`` names -> HashSet field and hex length. IMPHASH is a
#: Sysmon-computed import hash, kept out of HashSet (not a file digest).
_HASH_FIELDS = {"MD5": ("md5", 32), "SHA1": ("sha1", 40), "SHA256": ("sha256", 64)}


def _process_hashes(record: Mapping[str, Any]) -> HashSet | None:
    """The image hashes of a Process Create event: Sysmon's ``Hashes`` value
    (``ALGO=HEX[,ALGO=HEX…]``, its documented form) parsed exactly, else the ECS
    ``process.hash.*`` fields. ``-`` is Sysmon's own "no value" (hashing off, as
    Sysmon for Linux writes it) and means absent. Malformed values fail closed;
    nothing is guessed."""
    raw = _event_data_or_ecs(record, "Hashes")
    values: dict[str, str] = {}
    if raw is None:
        for key in ("md5", "sha1", "sha256"):
            ecs_value = _get(record, "process", "hash", key)
            if ecs_value:
                values[key] = str(ecs_value).lower()
        return HashSet(**values) if values else None
    if str(raw).strip() == "-":
        return None
    for part in str(raw).split(","):
        name, sep, value = part.strip().partition("=")
        if not sep or not value:
            raise SourceAdapterError(f"SysmonSourceAdapter: malformed Hashes entry {part!r}")
        if name.upper() == "IMPHASH":
            continue
        if name.upper() not in _HASH_FIELDS:
            raise SourceAdapterError(f"SysmonSourceAdapter: unknown hash algorithm {name!r}")
        field_name, length = _HASH_FIELDS[name.upper()]
        if len(value) != length or any(c not in "0123456789abcdefABCDEF" for c in value):
            raise SourceAdapterError(
                f"SysmonSourceAdapter: {name} value is not {length} hex digits"
            )
        values[field_name] = value.lower()
    return HashSet(**values) if values else None


def _process_ref(record: Mapping[str, Any], *, creation: bool) -> ProcessRef | None:
    """The acting process. ``creation`` (Process Create only) adds the fields
    that event alone carries — parent lineage details, working directory,
    integrity level and the image's PE metadata."""
    pid = _event_data_or_ecs(record, "ProcessId", "process", "pid")
    executable = _event_data_or_ecs(record, "Image", "process", "executable")
    name = _get(record, "process", "name") or _basename(executable)
    entity_id = _event_data_or_ecs(record, "ProcessGuid", "process", "entity_id")

    if pid is None and executable is None and name is None:
        return None
    base: dict[str, Any] = {
        "pid": _as_int(pid, "process.pid") if pid is not None else None,
        "name": name,
        "executable": executable,
        "entity_id": entity_id,
    }
    if not creation:
        return ProcessRef(**base)

    parent_pid = _event_data_or_ecs(record, "ParentProcessId", "process", "parent", "pid")
    parent_executable = _event_data_or_ecs(record, "ParentImage", "process", "parent", "executable")
    return ProcessRef(
        **base,
        command_line=_event_data_or_ecs(record, "CommandLine", "process", "command_line"),
        parent_pid=_as_int(parent_pid, "process.parent.pid") if parent_pid is not None else None,
        # ECS process.parent.name is the bare file name; derive it from the parent
        # executable only when the collector did not supply it (never a full path).
        parent_name=_get(record, "process", "parent", "name") or _basename(parent_executable),
        parent_entity_id=_event_data_or_ecs(
            record, "ParentProcessGuid", "process", "parent", "entity_id"
        ),
        parent_executable=parent_executable,
        parent_command_line=_event_data_or_ecs(
            record, "ParentCommandLine", "process", "parent", "command_line"
        ),
        working_directory=_event_data_or_ecs(
            record, "CurrentDirectory", "process", "working_directory"
        ),
        # No ECS field exists for Sysmon's IntegrityLevel; only the raw value.
        integrity_level=_event_data_or_ecs(record, "IntegrityLevel"),
        pe=_pe_info(record, "process"),
        hashes=_process_hashes(record),
    )


def _network_info(record: Mapping[str, Any]) -> NetworkInfo | None:
    source_ip = _event_data_or_ecs(record, "SourceIp", "source", "ip")
    source_port = _event_data_or_ecs(record, "SourcePort", "source", "port")
    dest_ip = _event_data_or_ecs(record, "DestinationIp", "destination", "ip")
    dest_port = _event_data_or_ecs(record, "DestinationPort", "destination", "port")
    transport = _event_data_or_ecs(record, "Protocol", "network", "transport")
    # Sysmon's ``Initiated`` -> ECS direction is not verified; ECS value only.
    direction = _get(record, "network", "direction")

    if source_ip is None and dest_ip is None:
        return None

    source = (
        NetworkEndpoint(
            ip=source_ip,
            port=_as_int(source_port, "source.port") if source_port is not None else None,
        )
        if source_ip is not None or source_port is not None
        else None
    )
    destination = (
        NetworkEndpoint(
            ip=dest_ip,
            port=_as_int(dest_port, "destination.port") if dest_port is not None else None,
        )
        if dest_ip is not None or dest_port is not None
        else None
    )
    return NetworkInfo(
        source=source,
        destination=destination,
        protocol=transport,
        transport=transport,
        direction=direction,
    )


def _actor_and_target(
    record: Mapping[str, Any], event_id: int
) -> tuple[ProcessRef | None, ProcessRef]:
    """Source (acting) and target processes of a process-access or
    remote-thread event, from Sysmon's ``Source*``/``Target*`` EventData (with
    the event type's own GUID spelling). The acting process falls back to the
    collector's ECS ``process.*``; the target has no ECS equivalent."""
    guid = _GUID_SUFFIX[event_id]

    def process(prefix: str, ecs: bool) -> ProcessRef | None:
        path = ("process",) if ecs else ()
        pid = _event_data_or_ecs(record, f"{prefix}ProcessId", *path, *(("pid",) if ecs else ()))
        executable = _event_data_or_ecs(
            record, f"{prefix}Image", *path, *(("executable",) if ecs else ())
        )
        entity_id = _event_data_or_ecs(
            record, f"{prefix}Process{guid}", *path, *(("entity_id",) if ecs else ())
        )
        if pid is None and executable is None and entity_id is None:
            return None
        return ProcessRef(
            pid=_as_int(pid, f"{prefix}ProcessId") if pid is not None else None,
            name=_basename(executable),
            executable=executable,
            entity_id=entity_id,
        )

    target = process("Target", ecs=False)
    if target is None:
        raise SourceAdapterError(
            f"SysmonSourceAdapter: event {event_id} without any target process field"
        )
    return process("Source", ecs=True), target


def _ed(record: Mapping[str, Any], key: str) -> Any:
    return _get(record, "winlog", "event_data", key)


def _wmi_event(record: Mapping[str, Any], event_id: int) -> tuple[EventMetadata, WmiRef]:
    """Sysmon 19/20/21: the subscription object and whether it was created or
    deleted. ``Operation`` decides ``event.type``; an absent or unknown value
    fails closed. Values are kept exactly as Sysmon reported them."""
    operation = _ed(record, "Operation")
    ecs_type = _WMI_OPERATION_TYPES.get(operation) if isinstance(operation, str) else None
    if ecs_type is None:
        raise SourceAdapterError(
            f"SysmonSourceAdapter: WMI event {event_id} has Operation {operation!r}; "
            f"expected one of {sorted(_WMI_OPERATION_TYPES)}"
        )
    wmi = WmiRef(
        operation=operation,
        name=_ed(record, "Name"),
        namespace=_ed(record, "EventNamespace"),
        query=_ed(record, "Query"),
        consumer_type=_ed(record, "Type"),
        destination=_ed(record, "Destination"),
        filter=_ed(record, "Filter"),
        consumer=_ed(record, "Consumer"),
    )
    event = EventMetadata(
        kind="event", category=("configuration",), type=(ecs_type,), action=WMI_ACTIONS[event_id]
    )
    return event, wmi


def _pipe_ref(record: Mapping[str, Any]) -> PipeRef:
    name = _ed(record, "PipeName")
    if not isinstance(name, str) or not name.strip():
        raise SourceAdapterError("SysmonSourceAdapter: pipe event without PipeName")
    return PipeRef(name=name)


def _dns_ref(record: Mapping[str, Any]) -> DnsRef:
    name = _event_data_or_ecs(record, "QueryName", "dns", "question", "name")
    if not isinstance(name, str) or not name.strip():
        raise SourceAdapterError("SysmonSourceAdapter: DNS query event without QueryName")
    status = _get(record, "winlog", "event_data", "QueryStatus")
    return DnsRef(
        question_name=name,
        query_status=str(status) if status is not None else None,
        results=_get(record, "winlog", "event_data", "QueryResults"),
    )


def _signed(raw: Any) -> bool | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str) and raw.strip().lower() in ("true", "false"):
        return raw.strip().lower() == "true"
    raise SourceAdapterError(f"SysmonSourceAdapter: Signed {raw!r} is not true/false")


def _dll_ref(record: Mapping[str, Any]) -> DllRef:
    path = _event_data_or_ecs(record, "ImageLoaded", "dll", "path")
    if not isinstance(path, str) or not path.strip():
        raise SourceAdapterError("SysmonSourceAdapter: image load event without ImageLoaded")
    signature = CodeSignature(
        signed=_signed(_event_data_or_ecs(record, "Signed", "dll", "code_signature", "exists")),
        subject_name=_event_data_or_ecs(
            record, "Signature", "dll", "code_signature", "subject_name"
        ),
        status=_event_data_or_ecs(record, "SignatureStatus", "dll", "code_signature", "status"),
    )
    return DllRef(
        path=path,
        name=_basename(path),
        pe=_pe_info(record, "dll"),
        code_signature=None if signature == CodeSignature() else signature,
    )


def _file_ref(record: Mapping[str, Any]) -> FileRef:
    path = _event_data_or_ecs(record, "TargetFilename", "file", "path")
    if not isinstance(path, str) or not path.strip():
        raise SourceAdapterError("SysmonSourceAdapter: file event without TargetFilename")
    return FileRef(path=path, name=_basename(path), directory=ntpath.dirname(path) or None)


def _registry_event(record: Mapping[str, Any], event_id: int) -> tuple[EventMetadata, RegistryRef]:
    """Registry events require Sysmon's own ``EventType`` (it decides the
    operation); an unexpected value fails closed — never guessed.

    One exact exception: Sysmon event 13 *is* "registry value set", whose
    ``EventType`` is always ``SetValue``, so when an export pipeline dropped the
    field (real OTRF NXLog exports do) it follows from the event ID. Event 12
    can be CreateKey, DeleteKey or DeleteValue; without ``EventType`` its
    operation is unknown and the record is refused."""
    event_type = _get(record, "winlog", "event_data", "EventType")
    if event_type is None and event_id == REGISTRY_VALUE_SET_EVENT_ID:
        event_type = "SetValue"
    ecs_type = _REGISTRY_EVENT_TYPES[event_id].get(event_type) if event_type else None
    if ecs_type is None:
        raise SourceAdapterError(
            f"SysmonSourceAdapter: registry event {event_id} has EventType {event_type!r}; "
            f"expected one of {sorted(_REGISTRY_EVENT_TYPES[event_id])}"
        )
    path = _event_data_or_ecs(record, "TargetObject", "registry", "path")
    if not isinstance(path, str) or not path.strip():
        raise SourceAdapterError("SysmonSourceAdapter: registry event without TargetObject")
    data = (
        _get(record, "winlog", "event_data", "Details")
        if event_id == REGISTRY_VALUE_SET_EVENT_ID
        else None
    )
    event = EventMetadata(
        kind="event", category=("registry",), type=(ecs_type,), action=str(event_type)
    )
    return event, RegistryRef(path=path, data=data)


class SysmonSourceAdapter:
    """Windows/Sysmon ``SourceAdapter``: one Sysmon event -> one ``Observation``.

    Accepts both real-world record shapes (ADR-0008 D4): a collector record
    (Winlogbeat/Elastic Agent: ECS fields + ``winlog`` envelope) and a flat
    Windows-EventData record (e.g. OTRF/NXLog JSON). Supports the event IDs in
    ``_SUPPORTED_EVENT_IDS``; any other ID, channel, or malformed record fails
    closed with :class:`SourceAdapterError`.
    """

    @property
    def source_type(self) -> str:
        return SYSMON_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if isinstance(raw_record, str) and is_sysmon_event_xml(raw_record):
            raw_record = parse_sysmon_event_xml(raw_record)  # ADR-0010 D1 (Sysmon for Linux)
        if not isinstance(raw_record, Mapping):
            raise SourceAdapterError(
                f"SysmonSourceAdapter expects a Mapping (a parsed Sysmon-module JSON event), "
                f"got {type(raw_record).__name__}"
            )
        record: Mapping[str, Any]
        if is_winlogbeat6(raw_record):
            record = normalize_winlogbeat6(raw_record)
        elif _is_flat(raw_record):
            record = _normalize_flat(raw_record)
        else:
            record = raw_record
        channel = _get(record, "winlog", "channel")
        os_type: str | None = None
        if channel is not None:
            os_type = _CHANNEL_OS.get(channel.casefold()) if isinstance(channel, str) else None
            if os_type is None:
                raise SourceAdapterError(
                    f"SysmonSourceAdapter: channel {channel!r} is neither {SYSMON_CHANNEL!r} "
                    f"nor {SYSMON_LINUX_CHANNEL!r}"
                )

        event_id = _require_event_id(record)
        if event_id not in _SUPPORTED_EVENT_IDS:
            raise SourceAdapterError(
                f"SysmonSourceAdapter: unsupported winlog.event_id {event_id!r} "
                f"(supported: {_SUPPORTED_EVENT_IDS})"
            )
        timestamp = _require_timestamp(record)
        record_id = _require_record_id(record)
        computer_name = _require_computer_name(record)

        supplied_observation_id = raw_record.get("observation_id")
        observation_id = (
            supplied_observation_id
            if isinstance(supplied_observation_id, str) and supplied_observation_id.strip()
            else f"sysmon:{computer_name}:{record_id}"
        )

        default_action = _get(record, "event", "action")
        entities: dict[str, Any] = {
            "host": _host_ref(record, computer_name, os_type),
            "user": _user_ref(record),
            "process": _process_ref(record, creation=event_id == PROCESS_CREATE_EVENT_ID),
        }
        if event_id == PROCESS_CREATE_EVENT_ID:
            event = EventMetadata(
                kind="event",
                category=("process",),
                type=("start",),
                action=default_action or "Process Create (rule: ProcessCreate)",
            )
        elif event_id == NETWORK_CONNECT_EVENT_ID:
            event = EventMetadata(
                kind="event",
                category=("network",),
                type=("connection", "start"),
                action=default_action or "Network connection detected (rule: NetworkConnect)",
            )
            entities["network"] = _network_info(record)
        elif event_id == IMAGE_LOAD_EVENT_ID:
            event = EventMetadata(
                kind="event",
                category=("library",),
                type=("start",),
                action=default_action or "Image loaded (rule: ImageLoad)",
            )
            entities["dll"] = _dll_ref(record)
        elif event_id in (CREATE_REMOTE_THREAD_EVENT_ID, PROCESS_ACCESS_EVENT_ID):
            entities["process"], entities["target_process"] = _actor_and_target(record, event_id)
            if event_id == PROCESS_ACCESS_EVENT_ID:
                event = EventMetadata(
                    kind="event",
                    category=("process",),
                    type=("access",),
                    action=PROCESS_ACCESS_ACTION,
                )
                entities["process_access"] = ProcessAccessRef(
                    granted_access=_get(record, "winlog", "event_data", "GrantedAccess"),
                    call_trace=_get(record, "winlog", "event_data", "CallTrace"),
                )
            else:
                event = EventMetadata(
                    kind="event",
                    category=("process",),
                    type=("change",),
                    action=CREATE_REMOTE_THREAD_ACTION,
                )
                entities["remote_thread"] = RemoteThreadRef(
                    start_address=_get(record, "winlog", "event_data", "StartAddress"),
                    start_module=_get(record, "winlog", "event_data", "StartModule"),
                    start_function=_get(record, "winlog", "event_data", "StartFunction"),
                )
        elif event_id == DNS_QUERY_EVENT_ID:
            # Deliberately no "connection" type: a lookup is not a connection, so
            # network_connection detection content never applies to it.
            event = EventMetadata(
                kind="event",
                category=("network",),
                type=("protocol", "info"),
                action=DNS_QUERY_ACTION,
            )
            entities["dns"] = _dns_ref(record)
        elif event_id == FILE_CREATE_EVENT_ID:
            event = EventMetadata(
                kind="event", category=("file",), type=("creation",), action=FILE_CREATE_ACTION
            )
            entities["file"] = _file_ref(record)
        elif event_id == FILE_STREAM_HASH_EVENT_ID:
            event = EventMetadata(
                kind="event",
                category=("file",),
                type=("creation",),
                action=FILE_STREAM_CREATE_ACTION,
            )
            entities["file"] = _file_ref(record)
            entities["file_stream"] = FileStreamRef(
                contents=_ed(record, "Contents"), hashes=_ed(record, "Hash")
            )
        elif event_id == PROCESS_TERMINATE_EVENT_ID:
            # The end of one process instance's lifetime (ADR-0003 Amendment B:
            # the evidence that a pid no longer belongs to it).
            event = EventMetadata(
                kind="event", category=("process",), type=("end",), action=PROCESS_END_ACTION
            )
        elif event_id == FILE_DELETE_EVENT_ID:
            event = EventMetadata(
                kind="event", category=("file",), type=("deletion",), action=FILE_DELETE_ACTION
            )
            entities["file"] = _file_ref(record)
        elif event_id in PIPE_ACTIONS:
            event = EventMetadata(
                kind="event",
                category=("file",),
                type=("creation",) if event_id == PIPE_CREATED_EVENT_ID else ("access",),
                action=PIPE_ACTIONS[event_id],
            )
            entities["pipe"] = _pipe_ref(record)
        elif event_id in WMI_ACTIONS:
            event, entities["wmi"] = _wmi_event(record, event_id)
        else:  # REGISTRY_OBJECT_EVENT_ID / REGISTRY_VALUE_SET_EVENT_ID
            event, entities["registry"] = _registry_event(record, event_id)

        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                raw_reference=SourceRef(source_type=self.source_type, source_event_id=record_id),
                event=event,
                **entities,
            ),
        )


def load_ndjson_events(path: Path) -> tuple[dict[str, Any], ...]:
    """Read newline-delimited JSON Sysmon-module events from a file.

    Each non-blank line must be one JSON object — the shape a Winlogbeat/
    Filebeat export or an EVTX-to-JSON conversion naturally produces, and the
    shape a hand-authored test fixture uses too. Deliberately minimal (file
    parsing only, no schema beyond "one JSON object per line"): this is
    **not** G0.9's fixture/replay framework — it has no concept of rules,
    Evidence, or ATT&CK references. Feed each returned dict to
    :class:`SysmonSourceAdapter` (via
    :func:`attribution_platform.sources.adapter.convert`) and the resulting
    Observations into the *same* G0.5/G0.6/G0.8 functions any other source's
    Observations flow through.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SourceAdapterError(f"could not read Sysmon event file {path}: {exc}") from exc

    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SourceAdapterError(
                f"{path}: line {line_number} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise SourceAdapterError(f"{path}: line {line_number} is not a JSON object")
        events.append(parsed)

    if not events:
        raise SourceAdapterError(f"{path}: no events found")

    return tuple(events)
