"""Where Elastic prebuilt rules meet this platform's telemetry (ADR-0015 D3).

An Elastic rule is written against documents in Elasticsearch indices. It applies
here only where a source this platform reads produces documents *of an index the
rule searches*, and its conditions are then evaluated against what those
documents contain. This module states both, per **data stream**
(:data:`STREAMS`): the concrete data stream Elastic's integration writes to, the
event profiles of the platform's Observations in it, and the derived view set
(:mod:`attribution_platform.detection.derived_registry`) rule conditions read.

**Event profiles.** A profile records the ECS values that are *constant* for one
kind of event in the stream, and the conditions that select exactly the
platform's own Observations of that kind. For Windows Sysmon there is one
profile per Sysmon event (``event.category`` / ``event.type`` / ``event.action``
from the pipeline's own table); a cloud audit stream has a single profile whose
only constants are the stream's own (``event.dataset``, ``data_stream.dataset``,
``event.module`` — the integration's ``constant_keyword`` fields and Elastic's
sample documents). A rule condition on a constant field is decided per profile at
import time; a field a profile lists as ``None`` is known to be absent; every
other field must be one of the stream's derived views (each verified against
Elastic's pipeline test fixtures) or the branch is a gap.

Pinned references: ``elastic/integrations`` commit
``ff5328128a30c75046130ae58ddba450caa1f2dc`` (ingest pipelines, their
``_dev/test/pipeline`` fixtures, ``fields/base-fields.yml``, ``sample_event.json``)
and ECS ``v8.17.0`` (``generated/ecs/ecs_flat.yml``, the field types).
"""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from types import MappingProxyType

from attribution_platform.detection.derived_cloud import (
    AZURE_AUDIT_VIEWS,
    AZURE_SIGNIN_VIEWS,
    CLOUDTRAIL_VIEWS,
    GITHUB_VIEWS,
    KUBERNETES_VIEWS,
    O365_VIEWS,
    OKTA_VIEWS,
)
from attribution_platform.detection.derived_fields import SYSMON_VIEWS
from attribution_platform.detection.derived_security import SECURITY_VIEWS
from attribution_platform.detection.derived_views import ViewSet
from attribution_platform.sources.windows_security import SUPPORTED_EVENT_IDS

ELASTIC_FIELD_MAP_VERSION = "elastic-field-map/2"  # 2: several data streams

INTEGRATIONS_COMMIT = "ff5328128a30c75046130ae58ddba450caa1f2dc"
ECS_VERSION = "8.17.0"

#: The concrete data stream Elastic's Windows integration writes Sysmon events
#: to. A rule applies to Sysmon telemetry iff one of its index patterns matches it.
SYSMON_DATA_STREAM = "logs-windows.sysmon_operational-default"

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


@dataclass(frozen=True)
class EventProfile:
    """One Sysmon event kind: its constant ECS values and our selector."""

    profile_id: str
    logsource: str
    #: ECS field -> its constant values for this event kind (a 1-tuple for a
    #: scalar), or ``None`` when the field is known to be absent.
    constants: Mapping[str, tuple[str, ...] | None]
    #: Conditions (field_path, operator, value, negate) selecting exactly our
    #: Observations of this event kind; the first is the engine's index key.
    selector: tuple[tuple[str, str, str | tuple[str, ...] | None, bool], ...]
    #: Array field -> elements every event of this kind has; its other elements
    #: are not known at import. A condition is decided (true) only when it asks
    #: for one of these; anything else on the field is a gap.
    always_contains: Mapping[str, tuple[str, ...]] = MappingProxyType({})


_COMMON = {
    "event.kind": ("event",),
    "event.module": ("windows",),
    "event.dataset": ("windows.sysmon_operational",),
    "data_stream.dataset": ("windows.sysmon_operational",),
    "data_stream.type": ("logs",),
    "event.provider": ("Microsoft-Windows-Sysmon",),
    "host.os.type": ("windows",),
    # Set by the pipeline only for events 27 and 255, which are not supported.
    "event.outcome": None,
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
class DataStream:
    """One Elastic data stream this platform has telemetry for."""

    stream_id: str
    #: The concrete data stream name; a rule applies iff an index pattern matches it.
    data_stream: str
    views: ViewSet
    profiles: tuple[EventProfile, ...]
    #: Field-name prefixes the stream's pipeline never writes (always absent).
    known_absent: tuple[str, ...] = ()

    def applies_to(self, index_patterns: tuple[str, ...]) -> bool:
        """Whether a rule searching ``index_patterns`` reads this data stream
        (Elasticsearch index patterns: ``*`` wildcards, a ``-`` prefix excludes)."""
        included = any(
            not p.startswith("-") and fnmatch.fnmatchcase(self.data_stream, p)
            for p in index_patterns
        )
        excluded = any(
            p.startswith("-") and fnmatch.fnmatchcase(self.data_stream, p[1:])
            for p in index_patterns
        )
        return included and not excluded

    def absent(self, field: str) -> bool:
        return bool(self.known_absent) and field.startswith(self.known_absent)


def _audit_stream(
    stream_id: str,
    dataset: str,
    module: str | None,
    views: ViewSet,
    logsource: str,
    our_dataset: str,
    always_contains: Mapping[str, tuple[str, ...]] | None = None,
) -> DataStream:
    """A cloud / SaaS audit stream: one profile, selected by the adapter's own
    ``event.dataset``; only the stream's own constants are decided at import."""
    constants: dict[str, tuple[str, ...] | None] = {
        "event.dataset": (dataset,),
        "data_stream.dataset": (dataset,),
        "data_stream.type": ("logs",),
    }
    if module is not None:
        constants["event.module"] = (module,)
    return DataStream(
        stream_id=stream_id,
        data_stream=f"logs-{dataset}-default",
        views=views,
        profiles=(
            EventProfile(
                profile_id=stream_id,
                logsource=logsource,
                constants=MappingProxyType(constants),
                always_contains=MappingProxyType(dict(always_contains or {})),
                selector=(("event.dataset", "equals", our_dataset, False),),
            ),
        ),
    )


SYSMON_STREAM = DataStream(
    stream_id="sysmon",
    data_stream=SYSMON_DATA_STREAM,
    views=SYSMON_VIEWS,
    profiles=SYSMON_PROFILES,
    known_absent=KNOWN_ABSENT_PREFIXES,
)

#: Field families the Security pipeline never writes: the Defend-only ones, and
#: the process details a 4688 event does not carry (it sets only the executable,
#: name, pid, command line and args of the process and the executable, name and
#: pid of its parent).
SECURITY_KNOWN_ABSENT: tuple[str, ...] = (
    *KNOWN_ABSENT_PREFIXES,
    "process.pe.",
    "process.hash.",
    "process.working_directory",
    "process.parent.args",
    "process.parent.command_line",
)
#: Filtering-platform events arrive with their own ``event.action`` text, which
#: the pipeline's table does not replace in Elastic's fixtures.
_SECURITY_ACTION_NOT_CONSTANT = frozenset({5441, 5447})


def _security_profiles() -> tuple[EventProfile, ...]:
    """One profile per Security event the adapter reads; ``event.category`` /
    ``event.type`` / ``event.action`` from the pipeline's own table (an event the
    table lacks gets none of the three)."""
    table = json.loads(
        files("attribution_platform.detection")
        .joinpath("pipeline_tables/security_categorization.json")
        .read_text(encoding="utf-8")
    )
    profiles = []
    for event_id in SUPPORTED_EVENT_IDS:
        entry = table.get(str(event_id), {})
        constants: dict[str, tuple[str, ...] | None] = {
            "event.kind": ("event",),
            "event.module": ("system",),
            "event.dataset": ("system.security",),
            "data_stream.dataset": ("system.security",),
            "data_stream.type": ("logs",),
            "host.os.type": ("windows",),
            "event.code": (str(event_id),),
            "event.category": tuple(entry["category"]) if "category" in entry else None,
            "event.type": tuple(entry["type"]) if "type" in entry else None,
        }
        if event_id not in _SECURITY_ACTION_NOT_CONSTANT:
            constants["event.action"] = (entry["action"],) if "action" in entry else None
        profiles.append(
            EventProfile(
                profile_id=f"security:{event_id}",
                logsource="windows/security",
                constants=MappingProxyType(constants),
                selector=(
                    ("event.dataset", "equals", "system.security", False),
                    ("event.code", "equals", str(event_id), False),
                ),
            )
        )
    return tuple(profiles)


SECURITY_STREAM = DataStream(
    stream_id="security",
    data_stream="logs-system.security-default",
    views=SECURITY_VIEWS,
    profiles=_security_profiles(),
    known_absent=SECURITY_KNOWN_ABSENT,
)

#: Every data stream Elastic rules are translated for, in a fixed order.
STREAMS: tuple[DataStream, ...] = (
    SYSMON_STREAM,
    SECURITY_STREAM,
    _audit_stream(
        "cloudtrail", "aws.cloudtrail", "aws", CLOUDTRAIL_VIEWS, "aws/cloudtrail", "aws.cloudtrail"
    ),
    _audit_stream(
        "o365",
        "o365.audit",
        "o365",
        O365_VIEWS,
        "m365/audit",
        "o365.audit",
        # The pipeline appends "web" to every record's event.category; further
        # categories depend on the audit schema.
        always_contains={"event.category": ("web",)},
    ),
    _audit_stream(
        "entra_audit",
        "azure.auditlogs",
        "azure",
        AZURE_AUDIT_VIEWS,
        "azure/auditlogs",
        "azure.auditlogs",
    ),
    _audit_stream(
        "entra_signin",
        "azure.signinlogs",
        "azure",
        AZURE_SIGNIN_VIEWS,
        "azure/signinlogs",
        "azure.signinlogs",
    ),
    _audit_stream("okta", "okta.system", "okta", OKTA_VIEWS, "okta/okta", "okta.system"),
    _audit_stream("github", "github.audit", "github", GITHUB_VIEWS, "github/audit", "github.audit"),
    # Elastic's Kubernetes sample documents carry no event.module.
    _audit_stream(
        "kubernetes",
        "kubernetes.audit_logs",
        None,
        KUBERNETES_VIEWS,
        "kubernetes/audit",
        "kubernetes.audit_logs",
    ),
)


def applies_to_sysmon(index_patterns: tuple[str, ...]) -> bool:
    return SYSMON_STREAM.applies_to(index_patterns)


__all__ = [
    "ELASTIC_FIELD_MAP_VERSION",
    "INTEGRATIONS_COMMIT",
    "ECS_VERSION",
    "SYSMON_DATA_STREAM",
    "KNOWN_ABSENT_PREFIXES",
    "EventProfile",
    "SYSMON_PROFILES",
    "DataStream",
    "SYSMON_STREAM",
    "SECURITY_STREAM",
    "STREAMS",
    "applies_to_sysmon",
]
