"""``sigma-field-map/1`` — Sigma logsource/field → our ECS-aligned Observation
fields (ADR-0007 D5). Pure data; no pySigma import.

A mapping is listed **only** when it is exact for every source adapter that
produces that Observation kind today (``sources/sysmon.py``, ``sources/synthetic.py``).
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

FIELD_MAP_VERSION = "sigma-field-map/1"

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
    }
)

#: ``(product, category)`` → Sigma field name → our dotted ``field_path``.
FIELD_MAPS: MappingProxyType[tuple[str, str], MappingProxyType[str, str]] = MappingProxyType(
    {
        ("windows", "process_creation"): MappingProxyType(
            {
                "Image": "process.executable",
                "CommandLine": "process.command_line",
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
    }
)

#: Why notable Sigma fields are deliberately unmapped (report text only).
UNMAPPED_FIELD_REASONS: MappingProxyType[str, str] = MappingProxyType(
    {
        "ParentImage": (
            "ProcessRef.parent_name holds a basename or a full path depending on the source "
            "record, so no single predicate reproduces Sigma's full-path semantics exactly"
        ),
        "OriginalFileName": "PE version-info metadata is not captured by any adapter",
        "Description": "PE version-info metadata is not captured by any adapter",
        "Product": "PE version-info metadata is not captured by any adapter",
        "Company": "PE version-info metadata is not captured by any adapter",
        "Hashes": "file hashes are not captured on ProcessRef",
        "ParentCommandLine": "parent command line is not captured on ProcessRef",
        "User": "UserRef splits domain and name; Sigma matches the combined 'DOMAIN\\user' string",
        "IntegrityLevel": "process integrity level is not captured",
        "CurrentDirectory": "process working directory is not captured",
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
