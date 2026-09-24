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

**Deliberately narrow v1 scope — two Sysmon event types, not a full
parser:** Event ID 1 (Process Create) and Event ID 3 (Network Connection).
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

import json
import ntpath
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    PeInfo,
    ProcessRef,
    SourceRef,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError

#: This adapter's stable source identifier.
SYSMON_SOURCE_TYPE = "sysmon"

#: The only two ``winlog.event_id`` values this v1 adapter understands.
PROCESS_CREATE_EVENT_ID = 1
NETWORK_CONNECT_EVENT_ID = 3
_SUPPORTED_EVENT_IDS = (PROCESS_CREATE_EVENT_ID, NETWORK_CONNECT_EVENT_ID)


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


def _require_event_id(record: Mapping[str, Any]) -> int:
    raw = _get(record, "winlog", "event_id")
    if raw is None:
        raw = _get(record, "event", "code")  # some collectors surface it only here
    if raw is None:
        raise SourceAdapterError("SysmonSourceAdapter: missing required field winlog.event_id")
    return _as_int(raw, "winlog.event_id")


def _require_timestamp(record: Mapping[str, Any]) -> datetime:
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


def _host_ref(record: Mapping[str, Any], computer_name: str) -> HostRef:
    ip_raw = _get(record, "host", "ip")
    ip = tuple(ip_raw) if isinstance(ip_raw, list) else ()
    return HostRef(name=computer_name, ip=ip)


def _user_ref(record: Mapping[str, Any]) -> UserRef | None:
    name = _get(record, "user", "name")
    domain = _get(record, "user", "domain")
    if name is None and domain is None:
        return None
    return UserRef(name=name, domain=domain)


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


def _basename(path: Any) -> Any:
    """The file name of a Windows path (``ntpath`` semantics), else ``None``."""
    if not isinstance(path, str) or not path.strip():
        return None
    return ntpath.basename(path) or None


def _pe_info(record: Mapping[str, Any]) -> PeInfo | None:
    pe = PeInfo(
        original_file_name=_event_data_or_ecs(
            record, "OriginalFileName", "process", "pe", "original_file_name"
        ),
        description=_event_data_or_ecs(record, "Description", "process", "pe", "description"),
        product=_event_data_or_ecs(record, "Product", "process", "pe", "product"),
        company=_event_data_or_ecs(record, "Company", "process", "pe", "company"),
    )
    return None if pe == PeInfo() else pe


def _process_ref(record: Mapping[str, Any]) -> ProcessRef | None:
    pid = _get(record, "process", "pid")
    executable = _get(record, "process", "executable")
    name = _get(record, "process", "name")
    command_line = _get(record, "process", "command_line")
    entity_id = _get(record, "process", "entity_id")
    parent_pid = _get(record, "process", "parent", "pid")
    parent_executable = _event_data_or_ecs(record, "ParentImage", "process", "parent", "executable")
    # ECS process.parent.name is the bare file name; derive it from the parent
    # executable only when the collector did not supply it (never a full path).
    parent_name = _get(record, "process", "parent", "name") or _basename(parent_executable)
    parent_entity_id = _get(record, "process", "parent", "entity_id")

    if pid is None and executable is None and name is None:
        return None

    return ProcessRef(
        pid=_as_int(pid, "process.pid") if pid is not None else None,
        name=name,
        executable=executable,
        command_line=command_line,
        entity_id=entity_id,
        parent_pid=_as_int(parent_pid, "process.parent.pid") if parent_pid is not None else None,
        parent_name=parent_name,
        parent_entity_id=parent_entity_id,
        parent_executable=parent_executable,
        parent_command_line=_event_data_or_ecs(
            record, "ParentCommandLine", "process", "parent", "command_line"
        ),
        working_directory=_event_data_or_ecs(
            record, "CurrentDirectory", "process", "working_directory"
        ),
        # No ECS field exists for Sysmon's IntegrityLevel; only the raw value.
        integrity_level=_event_data_or_ecs(record, "IntegrityLevel"),
        pe=_pe_info(record),
    )


def _network_info(record: Mapping[str, Any]) -> NetworkInfo | None:
    source_ip = _get(record, "source", "ip")
    source_port = _get(record, "source", "port")
    dest_ip = _get(record, "destination", "ip")
    dest_port = _get(record, "destination", "port")
    transport = _get(record, "network", "transport")
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


class SysmonSourceAdapter:
    """Reference Windows/Sysmon ``SourceAdapter``: a Winlogbeat/Elastic-Agent
    Sysmon-module JSON event -> ``Observation``.

    Supports exactly two ``winlog.event_id`` values (see module docstring);
    any other value fails closed with :class:`SourceAdapterError`.
    """

    @property
    def source_type(self) -> str:
        return SYSMON_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping):
            raise SourceAdapterError(
                f"SysmonSourceAdapter expects a Mapping (a parsed Sysmon-module JSON event), "
                f"got {type(raw_record).__name__}"
            )

        event_id = _require_event_id(raw_record)
        timestamp = _require_timestamp(raw_record)
        record_id = _require_record_id(raw_record)
        computer_name = _require_computer_name(raw_record)

        supplied_observation_id = raw_record.get("observation_id")
        observation_id = (
            supplied_observation_id
            if isinstance(supplied_observation_id, str) and supplied_observation_id.strip()
            else f"sysmon:{computer_name}:{record_id}"
        )

        host = _host_ref(raw_record, computer_name)
        user = _user_ref(raw_record)
        process = _process_ref(raw_record)
        default_action = _get(raw_record, "event", "action")

        if event_id == PROCESS_CREATE_EVENT_ID:
            event = EventMetadata(
                kind="event",
                category=("process",),
                type=("start",),
                action=default_action or "Process Create (rule: ProcessCreate)",
            )
            network = None
        elif event_id == NETWORK_CONNECT_EVENT_ID:
            event = EventMetadata(
                kind="event",
                category=("network",),
                type=("connection", "start"),
                action=default_action or "Network connection detected (rule: NetworkConnect)",
            )
            network = _network_info(raw_record)
        else:
            raise SourceAdapterError(
                f"SysmonSourceAdapter: unsupported winlog.event_id {event_id!r} "
                f"(this v1 adapter supports only {_SUPPORTED_EVENT_IDS} — "
                "Process Create and Network Connect)"
            )

        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                raw_reference=SourceRef(source_type=self.source_type, source_event_id=record_id),
                event=event,
                host=host,
                user=user,
                process=process,
                network=network,
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
