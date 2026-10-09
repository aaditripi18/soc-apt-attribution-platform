"""Where Elastic prebuilt rules meet this platform's telemetry (ADR-0015 D3).

An Elastic rule is written against documents in Elasticsearch indices. It applies
here only where a source this platform reads produces documents *of an index the
rule searches*, and its conditions are then evaluated against what those
documents contain. This module states both, for one source so far: **Windows
Sysmon**, as Elastic's Windows integration indexes it (data stream
``logs-windows.sysmon_operational-*``).

**Event profiles.** For every Sysmon event this platform supports, a profile
records the constant ECS values Elastic's pipeline gives that event
(``event.category`` / ``event.type`` / ``event.action`` from the pipeline's own
table; ``event.dataset``, ``data_stream.dataset`` and ``event.module`` from the
data stream's ``constant_keyword`` fields; ``event.provider`` and ``event.kind``
as Elastic's pipeline test fixtures show them; ``host.os.type`` as Elastic Agent
reports a Windows host) and the conditions that select exactly the platform's
own Observations of that event. A rule condition on a constant field is decided
per profile at import time; every other field must be one of the derived views
in :mod:`attribution_platform.detection.derived_fields` (verified field by field
against Elastic's fixtures) or the branch is a gap.

Pinned references: ``elastic/integrations`` commit
``ff5328128a30c75046130ae58ddba450caa1f2dc`` (pipeline
``packages/windows/_dev/shared/ingest_pipeline/sysmon_operational.yml`` and its
``_dev/test/pipeline`` fixtures; ``fields/base-fields.yml``) and ECS ``v8.17.0``
(``generated/ecs/ecs_flat.yml``, the field types).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from attribution_platform.detection.derived_fields import (
    DERIVED_NAMESPACE,
    ECS_FIELD_TYPES,
    SYSMON_ARRAY_FIELDS,
    SYSMON_DERIVED_FIELDS,
)

ELASTIC_FIELD_MAP_VERSION = "elastic-field-map/1"

INTEGRATIONS_COMMIT = "ff5328128a30c75046130ae58ddba450caa1f2dc"
ECS_VERSION = "8.17.0"

#: The concrete data stream Elastic's Windows integration writes Sysmon events
#: to. A rule applies to Sysmon telemetry iff one of its index patterns matches it.
SYSMON_DATA_STREAM = "logs-windows.sysmon_operational-default"

#: The fields whose value is a constant of the event profile (decided at import).
CONSTANT_FIELDS = frozenset(
    {
        "event.category",
        "event.type",
        "event.action",
        "event.code",
        "event.kind",
        "event.module",
        "event.dataset",
        "event.provider",
        "event.outcome",
        "data_stream.dataset",
        "data_stream.type",
        "host.os.type",
    }
)


#: Field families the pinned Sysmon pipeline never writes (no processor targets
#: them; Elastic Agent adds only agent / host / input / data-stream metadata), so
#: they are absent from every Sysmon document: a positive condition on one never
#: matches. They are Elastic Defend's (``process.Ext.*``, ``process.code_signature.*``
#: ...), which multi-source rules test alongside Sysmon-compatible branches.
KNOWN_ABSENT_PREFIXES: tuple[str, ...] = (
    "process.Ext.",
    "process.parent.Ext.",
    "process.code_signature.",
    "process.parent.code_signature.",
    "process.token.",
    "process.parent.token.",
    "file.Ext.",
    "dll.Ext.",
    "Effective_process.",
)


def known_absent(field: str) -> bool:
    return field.startswith(KNOWN_ABSENT_PREFIXES)


@dataclass(frozen=True)
class EventProfile:
    """One Sysmon event kind: its constant ECS values and our selector."""

    profile_id: str
    logsource: str
    #: ECS constant field -> its values (a 1-tuple for a scalar); a field in
    #: CONSTANT_FIELDS but absent here is known to be absent.
    constants: Mapping[str, tuple[str, ...]]
    #: Conditions (field_path, operator, value, negate) selecting exactly our
    #: Observations of this event kind; the first is the engine's index key.
    selector: tuple[tuple[str, str, str | tuple[str, ...] | None, bool], ...]


_COMMON = {
    "event.kind": ("event",),
    "event.module": ("windows",),
    "event.dataset": ("windows.sysmon_operational",),
    "data_stream.dataset": ("windows.sysmon_operational",),
    "data_stream.type": ("logs",),
    "event.provider": ("Microsoft-Windows-Sysmon",),
    "host.os.type": ("windows",),
}
#: Selector conditions every Sysmon profile shares: a Windows host, and no
#: ``event.dataset`` (the Sysmon adapter sets none; Windows Security / other
#: sources do), so no other Windows source's Observations are selected.
_WINDOWS_SYSMON = (
    ("host.os_type", "equals", "windows", False),
    ("event.dataset", "exists", None, True),
)


def _profile(
    event_id: int,
    logsource: str,
    category: tuple[str, ...],
    types: tuple[str, ...],
    action: tuple[str, ...],
    selector: tuple[tuple[str, str, str | tuple[str, ...] | None, bool], ...],
) -> EventProfile:
    return EventProfile(
        profile_id=f"sysmon:{event_id}",
        logsource=logsource,
        constants=MappingProxyType(
            {
                **_COMMON,
                "event.code": (str(event_id),),
                "event.category": category,
                "event.type": types,
                "event.action": action,
            }
        ),
        selector=selector + _WINDOWS_SYSMON,
    )


def _cat(
    category: str, *rest: tuple[str, str, str | tuple[str, ...] | None, bool]
) -> tuple[tuple[str, str, str | tuple[str, ...] | None, bool], ...]:
    return (("event.category", "has_element", category, False), *rest)


def _type(value: str) -> tuple[str, str, str, bool]:
    return ("event.type", "has_element", value, False)


def _action(value: str | tuple[str, ...]) -> tuple[str, str, str | tuple[str, ...], bool]:
    return ("event.action", "in" if isinstance(value, tuple) else "equals", value, False)


#: Sysmon event profiles, in event-id order. ``event.category`` / ``event.type`` /
#: ``event.action`` are the pipeline's table ("Set event action, category and
#: type for all event types"); selectors use the Sysmon adapter's own values.
SYSMON_PROFILES: tuple[EventProfile, ...] = (
    _profile(
        1,
        "windows/process_creation",
        ("process",),
        ("start",),
        ("Process creation",),
        _cat("process", _type("start")),
    ),
    _profile(
        3,
        "windows/network_connection",
        ("network",),
        ("start", "connection", "protocol"),
        ("Network connection",),
        _cat("network", _type("connection")),
    ),
    _profile(
        5,
        "windows/process_termination",
        ("process",),
        ("end",),
        ("Process terminated",),
        _cat("process", _type("end")),
    ),
    _profile(
        7,
        "windows/image_load",
        ("process", "library"),
        ("change", "start"),
        ("Image loaded", "load"),
        _cat("library", _type("start")),
    ),
    _profile(
        8,
        "windows/create_remote_thread",
        ("process",),
        ("change",),
        ("CreateRemoteThread",),
        _cat("process", _action("create_remote_thread")),
    ),
    _profile(
        10,
        "windows/process_access",
        ("process",),
        ("access",),
        ("ProcessAccess",),
        _cat("process", _action("process_access")),
    ),
    _profile(
        11,
        "windows/file_event",
        ("file",),
        ("creation",),
        ("FileCreate",),
        _cat("file", _action("file_create")),
    ),
    _profile(
        12,
        "windows/registry_add_delete",
        ("configuration", "registry"),
        ("change",),
        ("RegistryEvent (Object create and delete)",),
        _cat("registry", _action(("CreateKey", "DeleteKey", "DeleteValue"))),
    ),
    _profile(
        13,
        "windows/registry_set",
        ("configuration", "registry"),
        ("change",),
        ("RegistryEvent (Value Set)",),
        _cat("registry", _action("SetValue")),
    ),
    _profile(
        15,
        "windows/create_stream_hash",
        ("file",),
        ("access",),
        ("FileCreateStreamHash",),
        _cat("file", _action("file_stream_create")),
    ),
    _profile(
        17,
        "windows/pipe_created",
        ("file",),
        ("creation",),
        ("PipeEvent (Pipe Created)",),
        _cat("file", _action("pipe_create")),
    ),
    _profile(
        18,
        "windows/pipe_connected",
        ("file",),
        ("access",),
        ("PipeEvent (Pipe Connected)",),
        _cat("file", _action("pipe_connect")),
    ),
    _profile(
        19,
        "windows/wmi_filter",
        ("process",),
        ("info",),
        ("WmiEvent (WmiEventFilter activity detected)",),
        _cat("configuration", _action("wmi_filter")),
    ),
    _profile(
        20,
        "windows/wmi_consumer",
        ("process",),
        ("change",),
        ("WmiEvent (WmiEventConsumer activity detected)",),
        _cat("configuration", _action("wmi_consumer")),
    ),
    _profile(
        21,
        "windows/wmi_binding",
        ("process",),
        ("access",),
        ("WmiEvent (WmiEventConsumerToFilter activity detected)",),
        _cat("configuration", _action("wmi_binding")),
    ),
    _profile(
        22,
        "windows/dns_query",
        ("network",),
        ("connection", "protocol", "info"),
        ("DNSEvent (DNS query)",),
        _cat("network", _action("dns_query")),
    ),
    _profile(
        23,
        "windows/file_delete",
        ("file",),
        ("deletion",),
        ("FileDelete (File Delete archived)",),
        _cat("file", _action("file_delete")),
    ),
)


@dataclass(frozen=True)
class FieldTarget:
    """Where a non-constant ECS field is read, and how."""

    field_path: str
    array: bool
    ecs_type: str


#: ECS field -> the derived view rules read it through.
SYSMON_FIELDS: Mapping[str, FieldTarget] = MappingProxyType(
    {
        name: FieldTarget(
            field_path=f"{DERIVED_NAMESPACE}.{name}",
            array=name in SYSMON_ARRAY_FIELDS,
            ecs_type=ECS_FIELD_TYPES[name],
        )
        for name in SYSMON_DERIVED_FIELDS
    }
)


def applies_to_sysmon(index_patterns: tuple[str, ...]) -> bool:
    """Whether a rule searching ``index_patterns`` reads the Sysmon data stream
    (Elasticsearch index patterns: ``*`` wildcards, ``-`` prefix excludes)."""
    included = any(
        not p.startswith("-") and fnmatch.fnmatchcase(SYSMON_DATA_STREAM, p) for p in index_patterns
    )
    excluded = any(
        p.startswith("-") and fnmatch.fnmatchcase(SYSMON_DATA_STREAM, p[1:]) for p in index_patterns
    )
    return included and not excluded


__all__ = [
    "ELASTIC_FIELD_MAP_VERSION",
    "INTEGRATIONS_COMMIT",
    "ECS_VERSION",
    "SYSMON_DATA_STREAM",
    "CONSTANT_FIELDS",
    "KNOWN_ABSENT_PREFIXES",
    "known_absent",
    "EventProfile",
    "SYSMON_PROFILES",
    "FieldTarget",
    "SYSMON_FIELDS",
    "applies_to_sysmon",
]
