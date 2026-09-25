"""Sigma logsource/field → our ECS-aligned Observation fields (ADR-0007 D5),
versioned as :data:`FIELD_MAP_VERSION`. Pure data; no pySigma import.

A mapping is listed **only** when it is exact for every source adapter that
produces that Observation kind today (``sources/sysmon.py``, ``sources/synthetic.py``).
The Sysmon adapter fills these fields from Sysmon's own ``winlog.event_data``
values — the very names Sigma's Windows fields use — so the mapping is 1:1.

Version history: ``/1`` Image, CommandLine (+ network fields). ``/2`` (ADR-0007
D10 step 1) adds ParentImage, ParentCommandLine, CurrentDirectory,
IntegrityLevel, OriginalFileName, Description, Product, Company. ``/3``
(ADR-0008 Wave 1) adds the ``image_load``, ``file_event`` and ``registry_*``
logsources (Sysmon events 7, 11, 12, 13). Field names are per logsource: in
``image_load`` ``OriginalFileName`` etc. describe the loaded DLL, not the process.
``/4`` adds ``process_access``, ``create_remote_thread`` (Sysmon 10, 8: ``Source*``
is the acting ``process``, ``Target*`` the ``target_process``) and ``dns_query``
(Sysmon 22); scopes may now also require an exact ``event.action``. ``/5``
adds ``create_stream_hash`` (15), ``pipe_created`` (17/18), ``wmi_event``
(19/20/21) and ``file_delete`` (23), and ``file_event`` now also requires the
``file_create`` action (stream-hash events are file creations too).

Anything else is a *telemetry gap*, reported per rule by the importer — never
approximated. ``UNMAPPED_FIELD_REASONS`` records why the most frequent
unmapped Sigma fields are not mapped, so the gap is explained rather than
silent.

Logsources map to ``has_element`` conditions on ECS ``event.category`` /
``event.type`` (never Sysmon event IDs), keeping imported rules
source-agnostic (doc 12 §D.1).
"""

from __future__ import annotations

from types import MappingProxyType

FIELD_MAP_VERSION = "sigma-field-map/5"

#: ``(product, category)`` → the ``(field_path, operator, value)`` scope
#: conditions an Observation must satisfy to be the kind of event the Sigma
#: rule describes. The first is always ``event.category has_element`` (the
#: detection engine indexes on it); ``event.action equals`` is used where a
#: category+type pair alone would be ambiguous.
LOGSOURCE_SCOPES: MappingProxyType[tuple[str, str], tuple[tuple[str, str, str], ...]] = (
    MappingProxyType(
        {
            ("windows", "process_creation"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "start"),
            ),
            ("windows", "network_connection"): (
                ("event.category", "has_element", "network"),
                ("event.type", "has_element", "connection"),
            ),
            ("windows", "image_load"): (
                ("event.category", "has_element", "library"),
                ("event.type", "has_element", "start"),
            ),
            ("windows", "file_event"): (
                ("event.category", "has_element", "file"),
                ("event.type", "has_element", "creation"),
                ("event.action", "equals", "file_create"),
            ),
            ("windows", "create_stream_hash"): (
                ("event.category", "has_element", "file"),
                ("event.type", "has_element", "creation"),
                ("event.action", "equals", "file_stream_create"),
            ),
            ("windows", "file_delete"): (
                ("event.category", "has_element", "file"),
                ("event.type", "has_element", "deletion"),
                ("event.action", "equals", "file_delete"),
            ),
            # Sigma pipe_created covers both Sysmon 17 (created) and 18 (connected).
            ("windows", "pipe_created"): (
                ("event.category", "has_element", "file"),
                ("event.action", "startswith", "pipe_"),
            ),
            # Sigma wmi_event covers Sysmon 19/20/21.
            ("windows", "wmi_event"): (
                ("event.category", "has_element", "configuration"),
                ("event.action", "startswith", "wmi_"),
            ),
            # Sigma's registry_* categories over Sysmon 12/13 (14, rename, is not
            # supported yet): add = CreateKey, delete = DeleteKey/DeleteValue,
            # set = SetValue, event = any registry event.
            ("windows", "registry_add"): (
                ("event.category", "has_element", "registry"),
                ("event.type", "has_element", "creation"),
            ),
            ("windows", "registry_delete"): (
                ("event.category", "has_element", "registry"),
                ("event.type", "has_element", "deletion"),
            ),
            ("windows", "registry_set"): (
                ("event.category", "has_element", "registry"),
                ("event.type", "has_element", "change"),
            ),
            ("windows", "registry_event"): (("event.category", "has_element", "registry"),),
            ("windows", "process_access"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "access"),
            ),
            ("windows", "create_remote_thread"): (
                ("event.category", "has_element", "process"),
                ("event.type", "has_element", "change"),
                ("event.action", "equals", "create_remote_thread"),
            ),
            ("windows", "dns_query"): (
                ("event.category", "has_element", "network"),
                ("event.type", "has_element", "protocol"),
                ("event.action", "equals", "dns_query"),
            ),
        }
    )
)

#: Registry fields shared by every ``registry_*`` logsource. ``EventType`` is
#: Sysmon's own value (CreateKey/DeleteKey/DeleteValue/SetValue), which the
#: adapter records verbatim as ``event.action``.
_REGISTRY_FIELDS: MappingProxyType[str, str] = MappingProxyType(
    {
        "Image": "process.executable",
        "TargetObject": "registry.path",
        "Details": "registry.data",
        "EventType": "event.action",
    }
)

#: ``(product, category)`` → Sigma field name → our dotted ``field_path``.
FIELD_MAPS: MappingProxyType[tuple[str, str], MappingProxyType[str, str]] = MappingProxyType(
    {
        ("windows", "process_creation"): MappingProxyType(
            {
                "Image": "process.executable",
                "CommandLine": "process.command_line",
                "ParentImage": "process.parent_executable",
                "ParentCommandLine": "process.parent_command_line",
                "CurrentDirectory": "process.working_directory",
                "IntegrityLevel": "process.integrity_level",
                "OriginalFileName": "process.pe.original_file_name",
                "Description": "process.pe.description",
                "Product": "process.pe.product",
                "Company": "process.pe.company",
            }
        ),
        ("windows", "network_connection"): MappingProxyType(
            {
                "Image": "process.executable",
                "DestinationIp": "network.destination.ip",
                "DestinationPort": "network.destination.port",
                "SourceIp": "network.source.ip",
                "SourcePort": "network.source.port",
                "Protocol": "network.transport",
            }
        ),
        ("windows", "image_load"): MappingProxyType(
            {
                "Image": "process.executable",
                "ImageLoaded": "dll.path",
                "OriginalFileName": "dll.pe.original_file_name",
                "Description": "dll.pe.description",
                "Product": "dll.pe.product",
                "Company": "dll.pe.company",
                "Signed": "dll.code_signature.signed",
                "Signature": "dll.code_signature.subject_name",
                "SignatureStatus": "dll.code_signature.status",
            }
        ),
        ("windows", "file_event"): MappingProxyType(
            {
                "Image": "process.executable",
                "TargetFilename": "file.path",
            }
        ),
        ("windows", "registry_add"): _REGISTRY_FIELDS,
        ("windows", "registry_delete"): _REGISTRY_FIELDS,
        ("windows", "registry_set"): _REGISTRY_FIELDS,
        ("windows", "registry_event"): _REGISTRY_FIELDS,
        ("windows", "process_access"): MappingProxyType(
            {
                "SourceImage": "process.executable",
                "TargetImage": "target_process.executable",
                "GrantedAccess": "process_access.granted_access",
                "CallTrace": "process_access.call_trace",
            }
        ),
        ("windows", "create_remote_thread"): MappingProxyType(
            {
                "SourceImage": "process.executable",
                "TargetImage": "target_process.executable",
                "StartAddress": "remote_thread.start_address",
                "StartModule": "remote_thread.start_module",
                "StartFunction": "remote_thread.start_function",
            }
        ),
        ("windows", "create_stream_hash"): MappingProxyType(
            {
                "Image": "process.executable",
                "TargetFilename": "file.path",
                "Contents": "file_stream.contents",
                "Hash": "file_stream.hashes",
            }
        ),
        ("windows", "file_delete"): MappingProxyType(
            {
                "Image": "process.executable",
                "TargetFilename": "file.path",
            }
        ),
        ("windows", "pipe_created"): MappingProxyType(
            {
                "Image": "process.executable",
                "PipeName": "pipe.name",
            }
        ),
        ("windows", "wmi_event"): MappingProxyType(
            {
                "Operation": "wmi.operation",
                "Name": "wmi.name",
                "EventNamespace": "wmi.namespace",
                "Query": "wmi.query",
                "Type": "wmi.consumer_type",
                "Destination": "wmi.destination",
                "Filter": "wmi.filter",
                "Consumer": "wmi.consumer",
            }
        ),
        ("windows", "dns_query"): MappingProxyType(
            {
                "Image": "process.executable",
                "QueryName": "dns.question_name",
                "QueryStatus": "dns.query_status",
                "QueryResults": "dns.results",
            }
        ),
    }
)

#: Why notable Sigma fields are deliberately unmapped (report text only).
UNMAPPED_FIELD_REASONS: MappingProxyType[str, str] = MappingProxyType(
    {
        "Hashes": (
            "Sigma matches Sysmon's combined 'SHA1=..,MD5=..,IMPHASH=..' string (often "
            "IMPHASH, which no adapter captures); no exact mapping onto structured hashes"
        ),
        "User": "UserRef splits domain and name; Sigma matches the combined 'DOMAIN\\user' string",
        "ParentUser": "the parent process's user is not captured",
        "DestinationHostname": "destination hostname is not captured on NetworkInfo",
        "SourceUser": "the acting process's user is not captured for process access",
        "SourceParentImage": "Sysmon 8 carries no source-parent image",
        "SourceCommandLine": "Sysmon 8 carries no source command line",
        "Initiated": "Sysmon 'Initiated' → ECS network.direction mapping is not verified",
    }
)

__all__ = [
    "FIELD_MAP_VERSION",
    "LOGSOURCE_SCOPES",
    "FIELD_MAPS",
    "UNMAPPED_FIELD_REASONS",
]
