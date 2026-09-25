"""Loading a raw-telemetry replay fixture for the G1.0 DetectionEngine (gate
G1.2).

**Deliberately a separate type from :mod:`attribution_platform.replay.fixtures`
(G0.9), not an extension of it.** G0.9's ``Fixture``/``ReplayScenario`` format
has each scenario *assert* its own Evidence (``evidence_id``/``claim``/
``attack_ref``) — representing a detection produced externally to this
platform (e.g. a hand-authored "this is what an analyst would have
concluded" scenario). A :class:`DetectionReplayFixture` scenario asserts no
such thing: it carries only raw, source-agnostic telemetry content, and
*which* rule (if any) fires and *which* ATT&CK technique (if any) it maps to
is decided later, by the real :class:`~attribution_platform.detection.DetectionEngine`
evaluating it — never by the fixture itself. Keeping these as two distinct
types (rather than adding an "optional interpretation" field to the existing
one) makes it structurally impossible for a fixture author to accidentally
bypass the detection engine while writing what looks like a "detection
replay" scenario — the format itself has nowhere to put an asserted
``attack_ref``.

One JSON file holds:

    {
      "fixture_id": "<stable name>",
      "scenarios": [
        {
          "scenario_id": "<stable name, unique within the file>",
          "raw_record": {"record_id": "...", "timestamp": "<ISO-8601>", "observation_id": "..."},
          "process": {"name": "...", "command_line": "...", ...},   // optional
          "event": {"action": "...", ...},                          // optional
          "host": {...}, "user": {...}, "network": {...}, "file": {...}  // optional
        },
        ...
      ]
    }

``raw_record`` is exactly the G0.4 :class:`~attribution_platform.sources.synthetic.SyntheticRecord`
shape G0.9 already uses (the unmodified reference adapter is reused
unchanged — see :mod:`attribution_platform.replay.detection_pipeline`).
``process``/``event``/``host``/``user``/``network``/``file`` are the same
G0.3 ECS-aligned entity groups :class:`~attribution_platform.domain.Observation`
and the G1.0 rule engine already use (the exact set
``attribution_platform.detection.rules._ALLOWED_TOP_LEVEL_FIELDS`` covers) —
this is what a rule's ``FieldCondition`` actually evaluates against; without
it, no fixture could ever produce a genuine rule match.

Fail-closed: any structural problem raises
:class:`~attribution_platform.replay.errors.ReplayError` (the same error type
G0.9 fixtures use — this is still "the fixture itself is malformed", not a
new failure category).

Deterministic and repeatable, exactly like G0.9: the fixture's SHA-256
content hash is computed once over the raw file bytes and exposed as
``DetectionReplayFixture.dataset_ref``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
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
    LogonRef,
    NetworkEndpoint,
    NetworkInfo,
    ObjectAccessRef,
    PeInfo,
    PipeRef,
    PowerShellRef,
    ProcessAccessRef,
    ProcessRef,
    RegistryRef,
    RemoteThreadRef,
    ShareRef,
    UserRef,
    WmiRef,
)
from attribution_platform.replay.errors import ReplayError
from attribution_platform.sources.synthetic import SyntheticRecord

_REQUIRED_SCENARIO_FIELDS = ("scenario_id", "raw_record")
_OPTIONAL_ENTITY_FIELDS = (
    "event",
    "host",
    "user",
    "process",
    "network",
    "file",
    "dll",
    "registry",
    "target_process",
    "process_access",
    "remote_thread",
    "dns",
    "file_stream",
    "pipe",
    "wmi",
    "powershell",
    "target_user",
    "logon",
    "object_access",
    "share",
)


@dataclass(frozen=True)
class DetectionReplayScenario:
    """One raw-telemetry fixture scenario: a raw record plus the entity data
    a real source would have normalized onto its ``Observation`` — no rule
    reference, no evidence assertion (see module docstring)."""

    scenario_id: str
    raw_record: SyntheticRecord
    event: EventMetadata | None = None
    host: HostRef | None = None
    user: UserRef | None = None
    process: ProcessRef | None = None
    network: NetworkInfo | None = None
    file: FileRef | None = None
    dll: DllRef | None = None
    registry: RegistryRef | None = None
    target_process: ProcessRef | None = None
    process_access: ProcessAccessRef | None = None
    remote_thread: RemoteThreadRef | None = None
    dns: DnsRef | None = None
    file_stream: FileStreamRef | None = None
    pipe: PipeRef | None = None
    wmi: WmiRef | None = None
    powershell: PowerShellRef | None = None
    target_user: UserRef | None = None
    logon: LogonRef | None = None
    object_access: ObjectAccessRef | None = None
    share: ShareRef | None = None


@dataclass(frozen=True)
class DetectionReplayFixture:
    """A loaded raw-telemetry replay fixture file: its identity, content
    hash, and scenarios."""

    fixture_id: str
    content_hash: str
    scenarios: tuple[DetectionReplayScenario, ...]

    @property
    def dataset_ref(self) -> str:
        """The ``SourceRef.dataset_ref`` value for every Observation replayed
        from this fixture: ``"<fixture_id>@<sha256 of the file bytes>"`` (the
        same convention as
        :attr:`attribution_platform.replay.fixtures.Fixture.dataset_ref`)."""
        return f"{self.fixture_id}@{self.content_hash}"


def load_detection_replay_fixture_file(path: Path) -> DetectionReplayFixture:
    """Read and validate one raw-telemetry replay fixture JSON file from disk."""
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ReplayError(f"could not read fixture file {path}: {exc}") from exc

    content_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReplayError(f"{path}: not valid JSON: {exc}") from exc

    return _fixture_from_dict(data, content_hash=content_hash, source=str(path))


def _fixture_from_dict(data: Any, *, content_hash: str, source: str) -> DetectionReplayFixture:
    if not isinstance(data, dict):
        raise ReplayError(f"{source}: fixture root must be a JSON object")

    fixture_id = data.get("fixture_id")
    if not isinstance(fixture_id, str) or not fixture_id.strip():
        raise ReplayError(f"{source}: 'fixture_id' must be a non-empty string")

    scenarios_raw = data.get("scenarios")
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        raise ReplayError(f"{source}: 'scenarios' must be a non-empty list")

    scenarios = tuple(
        _scenario_from_dict(s, index=i, source=source) for i, s in enumerate(scenarios_raw)
    )

    scenario_ids = [s.scenario_id for s in scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ReplayError(f"{source}: duplicate scenario_id values: {scenario_ids}")

    return DetectionReplayFixture(
        fixture_id=fixture_id, content_hash=content_hash, scenarios=scenarios
    )


def _scenario_from_dict(s: Any, *, index: int, source: str) -> DetectionReplayScenario:
    if not isinstance(s, dict):
        raise ReplayError(f"{source}: scenarios[{index}] must be a JSON object")
    for field_name in _REQUIRED_SCENARIO_FIELDS:
        if field_name not in s:
            raise ReplayError(f"{source}: scenarios[{index}] missing required field {field_name!r}")
    for field_name in s:
        if field_name not in (*_REQUIRED_SCENARIO_FIELDS, *_OPTIONAL_ENTITY_FIELDS):
            raise ReplayError(f"{source}: scenarios[{index}] has unrecognized field {field_name!r}")

    scenario_id = s["scenario_id"]
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise ReplayError(f"{source}: scenarios[{index}].scenario_id must be a non-empty string")

    where = f"{source}: scenarios[{index}]"
    return DetectionReplayScenario(
        scenario_id=scenario_id,
        raw_record=_synthetic_record_from_dict(s["raw_record"], index=index, source=source),
        event=_event_metadata_from_dict(s.get("event"), where=f"{where}.event"),
        host=_host_ref_from_dict(s.get("host"), where=f"{where}.host"),
        user=_user_ref_from_dict(s.get("user"), where=f"{where}.user"),
        process=_process_ref_from_dict(s.get("process"), where=f"{where}.process"),
        network=_network_info_from_dict(s.get("network"), where=f"{where}.network"),
        file=_file_ref_from_dict(s.get("file"), where=f"{where}.file"),
        dll=_dll_ref_from_dict(s.get("dll"), where=f"{where}.dll"),
        registry=_registry_ref_from_dict(s.get("registry"), where=f"{where}.registry"),
        target_process=_process_ref_from_dict(
            s.get("target_process"), where=f"{where}.target_process"
        ),
        process_access=_process_access_from_dict(
            s.get("process_access"), where=f"{where}.process_access"
        ),
        remote_thread=_remote_thread_from_dict(
            s.get("remote_thread"), where=f"{where}.remote_thread"
        ),
        dns=_dns_ref_from_dict(s.get("dns"), where=f"{where}.dns"),
        file_stream=_file_stream_from_dict(s.get("file_stream"), where=f"{where}.file_stream"),
        pipe=_pipe_ref_from_dict(s.get("pipe"), where=f"{where}.pipe"),
        wmi=_wmi_ref_from_dict(s.get("wmi"), where=f"{where}.wmi"),
        powershell=_powershell_ref_from_dict(s.get("powershell"), where=f"{where}.powershell"),
        target_user=_user_ref_from_dict(s.get("target_user"), where=f"{where}.target_user"),
        logon=_flat_ref(LogonRef, _LOGON_FIELDS, s.get("logon"), where=f"{where}.logon"),
        object_access=_flat_ref(
            ObjectAccessRef,
            _OBJECT_ACCESS_FIELDS,
            s.get("object_access"),
            where=f"{where}.object_access",
        ),
        share=_flat_ref(ShareRef, _SHARE_FIELDS, s.get("share"), where=f"{where}.share"),
    )


def _synthetic_record_from_dict(d: Any, *, index: int, source: str) -> SyntheticRecord:
    if not isinstance(d, dict):
        raise ReplayError(f"{source}: scenarios[{index}].raw_record must be a JSON object")
    if "record_id" not in d or "timestamp" not in d:
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record requires 'record_id' and 'timestamp'"
        )
    try:
        timestamp = datetime.fromisoformat(d["timestamp"])
    except (TypeError, ValueError) as exc:
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record.timestamp is not a valid ISO-8601 "
            f"timestamp: {exc}"
        ) from exc
    record_id = d["record_id"]
    if not isinstance(record_id, str) or not record_id.strip():
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record.record_id must be a non-empty string"
        )
    observation_id = d.get("observation_id")
    if observation_id is not None and not isinstance(observation_id, str):
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record.observation_id must be a string if present"
        )
    return SyntheticRecord(record_id=record_id, timestamp=timestamp, observation_id=observation_id)


def _require_dict(d: Any, *, where: str) -> dict[str, Any] | None:
    if d is None:
        return None
    if not isinstance(d, dict):
        raise ReplayError(f"{where} must be a JSON object if present")
    return d


def _event_metadata_from_dict(d: Any, *, where: str) -> EventMetadata | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return EventMetadata(
        kind=parsed.get("kind"),
        category=tuple(parsed.get("category", ())),
        type=tuple(parsed.get("type", ())),
        action=parsed.get("action"),
        outcome=parsed.get("outcome"),
        provider=parsed.get("provider"),
        code=parsed.get("code"),
        dataset=parsed.get("dataset"),
    )


def _host_ref_from_dict(d: Any, *, where: str) -> HostRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return HostRef(id=parsed.get("id"), name=parsed.get("name"), ip=tuple(parsed.get("ip", ())))


def _user_ref_from_dict(d: Any, *, where: str) -> UserRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return UserRef(id=parsed.get("id"), name=parsed.get("name"), domain=parsed.get("domain"))


def _process_ref_from_dict(d: Any, *, where: str) -> ProcessRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return ProcessRef(
        pid=parsed.get("pid"),
        name=parsed.get("name"),
        executable=parsed.get("executable"),
        command_line=parsed.get("command_line"),
        entity_id=parsed.get("entity_id"),
        parent_pid=parsed.get("parent_pid"),
        parent_name=parsed.get("parent_name"),
        parent_entity_id=parsed.get("parent_entity_id"),
        parent_executable=parsed.get("parent_executable"),
        parent_command_line=parsed.get("parent_command_line"),
        working_directory=parsed.get("working_directory"),
        integrity_level=parsed.get("integrity_level"),
        pe=_pe_info_from_dict(parsed.get("pe"), where=f"{where}.pe"),
    )


def _pe_info_from_dict(d: Any, *, where: str) -> PeInfo | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return PeInfo(
        original_file_name=parsed.get("original_file_name"),
        description=parsed.get("description"),
        product=parsed.get("product"),
        company=parsed.get("company"),
    )


def _network_endpoint_from_dict(d: Any, *, where: str) -> NetworkEndpoint | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return NetworkEndpoint(ip=parsed.get("ip"), port=parsed.get("port"))


def _network_info_from_dict(d: Any, *, where: str) -> NetworkInfo | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return NetworkInfo(
        source=_network_endpoint_from_dict(parsed.get("source"), where=f"{where}.source"),
        destination=_network_endpoint_from_dict(
            parsed.get("destination"), where=f"{where}.destination"
        ),
        protocol=parsed.get("protocol"),
        transport=parsed.get("transport"),
        direction=parsed.get("direction"),
    )


def _hash_set_from_dict(d: Any, *, where: str) -> HashSet | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return HashSet(md5=parsed.get("md5"), sha1=parsed.get("sha1"), sha256=parsed.get("sha256"))


def _dll_ref_from_dict(d: Any, *, where: str) -> DllRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    signature = _require_dict(parsed.get("code_signature"), where=f"{where}.code_signature")
    return DllRef(
        path=parsed.get("path"),
        name=parsed.get("name"),
        pe=_pe_info_from_dict(parsed.get("pe"), where=f"{where}.pe"),
        code_signature=(
            CodeSignature(
                signed=signature.get("signed"),
                subject_name=signature.get("subject_name"),
                status=signature.get("status"),
            )
            if signature is not None
            else None
        ),
    )


def _process_access_from_dict(d: Any, *, where: str) -> ProcessAccessRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return ProcessAccessRef(
        granted_access=parsed.get("granted_access"), call_trace=parsed.get("call_trace")
    )


def _remote_thread_from_dict(d: Any, *, where: str) -> RemoteThreadRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return RemoteThreadRef(
        start_address=parsed.get("start_address"),
        start_module=parsed.get("start_module"),
        start_function=parsed.get("start_function"),
    )


def _dns_ref_from_dict(d: Any, *, where: str) -> DnsRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return DnsRef(
        question_name=parsed.get("question_name"),
        query_status=parsed.get("query_status"),
        results=parsed.get("results"),
    )


def _file_stream_from_dict(d: Any, *, where: str) -> FileStreamRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return FileStreamRef(contents=parsed.get("contents"), hashes=parsed.get("hashes"))


def _pipe_ref_from_dict(d: Any, *, where: str) -> PipeRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return PipeRef(name=parsed.get("name"))


def _wmi_ref_from_dict(d: Any, *, where: str) -> WmiRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    fields = (
        "operation",
        "name",
        "namespace",
        "query",
        "consumer_type",
        "destination",
        "filter",
        "consumer",
    )
    return WmiRef(**{f: parsed.get(f) for f in fields})


_LOGON_FIELDS = (
    "logon_type",
    "logon_process",
    "authentication_package",
    "package_name",
    "lm_package",
    "key_length",
    "impersonation_level",
    "elevated_token",
    "logon_id",
    "workstation_name",
    "workstation",
    "status",
    "sub_status",
    "target_outbound_user_name",
)

_OBJECT_ACCESS_FIELDS = (
    "server",
    "type",
    "name",
    "handle_id",
    "access_mask",
    "access_list",
    "value_name",
    "new_value",
)

_SHARE_FIELDS = (
    "name",
    "local_path",
    "relative_target_name",
)


def _flat_ref(cls: Any, fields: tuple[str, ...], d: Any, *, where: str) -> Any:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return cls(**{f: parsed.get(f) for f in fields})


def _powershell_ref_from_dict(d: Any, *, where: str) -> PowerShellRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    fields = (
        "script_block_text",
        "script_block_id",
        "script_path",
        "message_number",
        "message_total",
        "payload",
        "context_info",
    )
    return PowerShellRef(**{f: parsed.get(f) for f in fields})


def _registry_ref_from_dict(d: Any, *, where: str) -> RegistryRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return RegistryRef(path=parsed.get("path"), data=parsed.get("data"))


def _file_ref_from_dict(d: Any, *, where: str) -> FileRef | None:
    parsed = _require_dict(d, where=where)
    if parsed is None:
        return None
    return FileRef(
        path=parsed.get("path"),
        name=parsed.get("name"),
        directory=parsed.get("directory"),
        hashes=_hash_set_from_dict(parsed.get("hashes"), where=f"{where}.hashes"),
    )
