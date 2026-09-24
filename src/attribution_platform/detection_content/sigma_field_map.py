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

FIELD_MAP_VERSION = "sigma-field-map/3"

#: ``(product, category)`` → the ``(field_path, element)`` scope conditions an
#: Observation must satisfy to be the kind of event the Sigma rule describes.
LOGSOURCE_SCOPES: MappingProxyType[tuple[str, str], tuple[tuple[str, str], ...]] = MappingProxyType(
    {
        ("windows", "process_creation"): (
            ("event.category", "process"),
            ("event.type", "start"),
        ),
        ("windows", "network_connection"): (
            ("event.category", "network"),
            ("event.type", "connection"),
        ),
        ("windows", "image_load"): (
            ("event.category", "library"),
            ("event.type", "start"),
        ),
        ("windows", "file_event"): (
            ("event.category", "file"),
            ("event.type", "creation"),
        ),
        # Sigma's registry_* categories over Sysmon 12/13 (14, rename, is not
        # supported yet): add = CreateKey, delete = DeleteKey/DeleteValue,
        # set = SetValue, event = any registry event.
        ("windows", "registry_add"): (
            ("event.category", "registry"),
            ("event.type", "creation"),
        ),
        ("windows", "registry_delete"): (
            ("event.category", "registry"),
            ("event.type", "deletion"),
        ),
        ("windows", "registry_set"): (
            ("event.category", "registry"),
            ("event.type", "change"),
        ),
        ("windows", "registry_event"): (("event.category", "registry"),),
    }
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
        "Initiated": "Sysmon 'Initiated' → ECS network.direction mapping is not verified",
    }
)

__all__ = [
    "FIELD_MAP_VERSION",
    "LOGSOURCE_SCOPES",
    "FIELD_MAPS",
    "UNMAPPED_FIELD_REASONS",
]
