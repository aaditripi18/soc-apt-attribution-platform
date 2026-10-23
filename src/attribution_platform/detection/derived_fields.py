"""Derived ECS views: fields Elastic's Sysmon pipeline computes (ADR-0015 D2).

Elastic's prebuilt rules read ECS fields that Elastic's *ingest pipeline* computes
from raw Sysmon values — ``process.args`` (a Windows argv split of the command
line), ``process.name`` (the image's file name), ``file.extension``,
``registry.value``, ``registry.data.strings`` (a ``DWORD`` rendered as decimal) and
more. A rule is exact on our Observations only if those fields mean what the
pipeline makes them mean. This module reproduces each derivation from the pinned
pipeline — ``elastic/integrations`` commit ``ff5328128a30``,
``packages/windows/_dev/shared/ingest_pipeline/sysmon_operational.yml`` — and
exposes it to the rule engine under the ``elastic_sysmon.`` namespace, e.g.
``elastic_sysmon.process.args``. Nothing here guesses: a value the pipeline would
not produce is ``None``.

Two pipeline behaviours apply to every field: event data values ``""``, ``"-"``
and the all-zero GUID are removed before anything else (so they are absent), and
derived fields are computed only from the value the pipeline itself reads. The
views are meaningful only for Observations made by the Sysmon adapter from
Windows Sysmon events; generated Elastic rules scope every condition to those
(``detection_content/elastic_field_map.py``). ``tests/test_elastic_sysmon_conformance.py``
checks every view against Elastic's own pipeline test fixtures.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any

from attribution_platform.detection.derived_views import (
    KEYWORD_IGNORE_ABOVE,
    ViewSet,
    build_view_set,
)
from attribution_platform.domain import Observation

#: The pipeline's first processor removes these event-data values.
_REMOVED_VALUES = frozenset({"", "-", "{00000000-0000-0000-0000-000000000000}"})


def _ed(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str) and value in _REMOVED_VALUES:
        return None
    return value


def _attr(obj: Any, *path: str) -> Any:
    for name in path:
        if obj is None:
            return None
        obj = getattr(obj, name, None)
    return obj


# ---------------------------------------------------------------------------
# Windows argv split ("Implements Windows-like SplitCommandLine")
# ---------------------------------------------------------------------------


def _read_next_arg(cmd: str) -> tuple[str, str]:
    """The pipeline's ``readNextArg`` (Go's pre-2008 rule): ``(arg, rest)``."""
    b: list[str] = []
    inquote = False
    nslash = 0
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if c in (" ", "\t"):
            if not inquote:
                b.append("\\" * nslash)
                return "".join(b), cmd[i + 1 :]
        elif c == '"':
            b.append("\\" * (nslash // 2))
            if nslash % 2 == 0:
                if inquote and i + 1 < len(cmd) and cmd[i + 1] == '"':
                    b.append(c)
                    i += 1
                inquote = not inquote
            else:
                b.append(c)
            nslash = 0
            i += 1
            continue
        elif c == "\\":
            nslash += 1
            i += 1
            continue
        b.append("\\" * nslash)
        nslash = 0
        b.append(c)
        i += 1
    b.append("\\" * nslash)
    return "".join(b), ""


@functools.lru_cache(maxsize=8192)  # pure; many rule conditions read one command line
def windows_argv(cmd: str) -> tuple[str, ...]:
    """The pipeline's ``commandLineToArgv``: skip spaces/tabs, then read one arg."""
    args: list[str] = []
    while cmd:
        if cmd[0] in (" ", "\t"):
            cmd = cmd[1:]
            continue
        arg, cmd = _read_next_arg(cmd)
        args.append(arg)
    return tuple(args)


def _args(command_line: Any) -> tuple[str, ...] | None:
    """An empty argv (a blank command line) indexes as no value at all."""
    cmd = _ed(command_line)
    if not isinstance(cmd, str):
        return None
    return windows_argv(cmd) or None


# ---------------------------------------------------------------------------
# Names and paths
# ---------------------------------------------------------------------------


def _process_name(executable: Any) -> str | None:
    """ "Adds process name information": the text after the last backslash, set
    only when non-empty and the path is longer than one character."""
    path = _ed(executable)
    if not isinstance(path, str) or len(path) <= 1:
        return None
    idx = path.rfind("\\")
    if idx < 0:
        return None
    return path[idx + 1 :] or None


def _process_executable(obs: Observation) -> str | None:
    """``process.executable``: Image (or SourceImage, events 8 / 10, which the
    adapter already makes the acting process); for a WMI consumer event (20),
    which has neither, the pipeline renames the consumer's ``Destination``."""
    value = _ed(_attr(obs, "process", "executable"))
    if value is None:
        value = _ed(_attr(obs, "wmi", "destination"))
    return value if isinstance(value, str) else None


def _file_path(obs: Observation) -> str | None:
    """``file.path``: TargetFilename (file events) or ImageLoaded (image load)."""
    value = _ed(_attr(obs, "file", "path"))
    if value is None:
        value = _ed(_attr(obs, "dll", "path"))
    return value if isinstance(value, str) else None


def _split_path(path: str | None) -> tuple[str, str, str | None] | None:
    """ "Adds file information": ``(name, directory, extension)`` when the path is
    longer than one character and contains a backslash."""
    if path is None or len(path) <= 1:
        return None
    idx = path.rfind("\\")
    if idx < 0:
        return None
    ext_idx = path.rfind(".")
    return path[idx + 1 :], path[:idx], path[ext_idx + 1 :] if ext_idx > -1 else None


def _file_name(obs: Observation) -> str | None:
    pipe = _ed(_attr(obs, "pipe", "name"))
    if isinstance(pipe, str) and _file_path(obs) is None:
        return pipe  # PipeName -> file.name; no path, so nothing overwrites it
    parts = _split_path(_file_path(obs))
    return parts[0] if parts else None


def _file_directory(obs: Observation) -> str | None:
    parts = _split_path(_file_path(obs))
    return parts[1] if parts else None


def _file_extension(obs: Observation) -> str | None:
    parts = _split_path(_file_path(obs))
    return parts[2] if parts else None


def _dll_name(obs: Observation) -> str | None:
    if _attr(obs, "dll") is None:
        return None
    parts = _split_path(_file_path(obs))
    return parts[0] if parts else None


# ---------------------------------------------------------------------------
# Registry ("Set registry fields")
# ---------------------------------------------------------------------------

_HIVES = MappingProxyType(
    {
        "HKEY_CLASSES_ROOT": "HKCR",
        "HKCR": "HKCR",
        "HKEY_CURRENT_CONFIG": "HKCC",
        "HKCC": "HKCC",
        "HKEY_CURRENT_USER": "HKCU",
        "HKCU": "HKCU",
        "HKEY_DYN_DATA": "HKDD",
        "HKDD": "HKDD",
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKLM": "HKLM",
        "HKEY_PERFORMANCE_DATA": "HKPD",
        "HKPD": "HKPD",
        "HKEY_USERS": "HKU",
        "HKU": "HKU",
    }
)
_QWORD = re.compile(r"QWORD \(((0x[0-9A-F]{8})-(0x[0-9A-F]{8}))\)", re.IGNORECASE)
_DWORD = re.compile(r"DWORD \((0x[0-9A-F]{8})\)", re.IGNORECASE)


def _registry_tokens(obs: Observation) -> list[str] | None:
    path = _ed(_attr(obs, "registry", "path"))
    if not isinstance(path, str):
        return None
    tokens = path.split("\\")
    while tokens and tokens[-1] == "":  # Java String.split drops trailing empties
        tokens.pop()
    return tokens or None


def _registry_hive(obs: Observation) -> str | None:
    tokens = _registry_tokens(obs)
    return _HIVES.get(tokens[0]) if tokens else None


def _registry_key(obs: Observation) -> str | None:
    tokens = _registry_tokens(obs)
    if not tokens or tokens[0] not in _HIVES or len(tokens) <= 1:
        return None
    return "\\".join(tokens[1:])


def _registry_value(obs: Observation) -> str | None:
    tokens = _registry_tokens(obs)
    return tokens[-1] if tokens else None


def _registry_data(obs: Observation) -> tuple[tuple[str, ...], str] | None:
    data = _ed(_attr(obs, "registry", "data"))
    if not isinstance(data, str) or _registry_tokens(obs) is None:
        return None
    qword = _QWORD.fullmatch(data)
    if qword:
        high, low = int(qword.group(2)[2:], 16), int(qword.group(3)[2:], 16)
        return (str((high << 8) + low),), "SZ_QWORD"  # the pipeline's own arithmetic
    dword = _DWORD.fullmatch(data)
    if dword:
        return (str(int(dword.group(1)[2:], 16)),), "SZ_DWORD"
    if data == "Binary Data":
        return (data,), "REG_BINARY"
    return (data,), "REG_SZ"


def _registry_data_strings(obs: Observation) -> tuple[str, ...] | None:
    parsed = _registry_data(obs)
    return parsed[0] if parsed else None


def _registry_data_type(obs: Observation) -> str | None:
    parsed = _registry_data(obs)
    return parsed[1] if parsed else None


def _port(value: Any) -> str | None:
    return None if value is None else str(value)


def _ip(value: Any) -> str | None:
    """An ``ip`` field as Elasticsearch holds it: the address in canonical form (the
    pipeline's ``convert … type: ip`` leaves a value that is not an address unset)."""
    if value is None or _ed(value) is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


#: The pipeline-level derivations, before the index mapping is applied.
_PIPELINE_FIELDS: Mapping[str, Callable[[Observation], Any]] = MappingProxyType(
    {
        "process.executable": _process_executable,
        "process.name": lambda o: _process_name(_process_executable(o)),
        "process.command_line": lambda o: _ed(_attr(o, "process", "command_line")),
        "process.args": lambda o: _args(_attr(o, "process", "command_line")),
        "process.working_directory": lambda o: _ed(_attr(o, "process", "working_directory")),
        "process.parent.executable": lambda o: _ed(_attr(o, "process", "parent_executable")),
        "process.parent.name": lambda o: _process_name(_attr(o, "process", "parent_executable")),
        "process.parent.command_line": lambda o: _ed(_attr(o, "process", "parent_command_line")),
        "process.parent.args": lambda o: _args(_attr(o, "process", "parent_command_line")),
        "process.pe.original_file_name": lambda o: _ed(
            _attr(o, "process", "pe", "original_file_name")
        ),
        "process.pe.company": lambda o: _ed(_attr(o, "process", "pe", "company")),
        "process.pe.description": lambda o: _ed(_attr(o, "process", "pe", "description")),
        "process.pe.product": lambda o: _ed(_attr(o, "process", "pe", "product")),
        "file.path": _file_path,
        "file.name": _file_name,
        "file.directory": _file_directory,
        "file.extension": _file_extension,
        "dll.path": lambda o: _ed(_attr(o, "dll", "path")),
        "dll.name": _dll_name,
        "dll.pe.original_file_name": lambda o: _ed(_attr(o, "dll", "pe", "original_file_name")),
        "dll.code_signature.subject_name": lambda o: _ed(
            _attr(o, "dll", "code_signature", "subject_name")
        ),
        "registry.path": lambda o: _ed(_attr(o, "registry", "path")),
        "registry.hive": _registry_hive,
        "registry.key": _registry_key,
        "registry.value": _registry_value,
        "registry.data.strings": _registry_data_strings,
        "registry.data.type": _registry_data_type,
        "dns.question.name": lambda o: _ed(_attr(o, "dns", "question_name")),
        "network.transport": lambda o: _ed(_attr(o, "network", "transport")),
        "network.direction": lambda o: _ed(_attr(o, "network", "direction")),
        "source.port": lambda o: _port(_attr(o, "network", "source", "port")),
        "destination.port": lambda o: _port(_attr(o, "network", "destination", "port")),
        "source.ip": lambda o: _ip(_attr(o, "network", "source", "ip")),
        "destination.ip": lambda o: _ip(_attr(o, "network", "destination", "ip")),
        # sequence join keys (ADR-0015 Amendment E): the GUIDs as written
        "process.entity_id": lambda o: _ed(_attr(o, "process", "entity_id")),
        "process.parent.entity_id": lambda o: _ed(_attr(o, "process", "parent_entity_id")),
        # Event data the pipeline neither renames nor removes stays in the
        # document as winlog.event_data.<Name>, verbatim (after the "-" removal).
        "winlog.event_data.IntegrityLevel": lambda o: _ed(_attr(o, "process", "integrity_level")),
        "winlog.event_data.GrantedAccess": lambda o: _ed(
            _attr(o, "process_access", "granted_access")
        ),
        "winlog.event_data.CallTrace": lambda o: _ed(_attr(o, "process_access", "call_trace")),
        "winlog.event_data.TargetImage": lambda o: _ed(_attr(o, "target_process", "executable")),
        "winlog.event_data.StartAddress": lambda o: _ed(_attr(o, "remote_thread", "start_address")),
        "winlog.event_data.StartModule": lambda o: _ed(_attr(o, "remote_thread", "start_module")),
        "winlog.event_data.StartFunction": lambda o: _ed(
            _attr(o, "remote_thread", "start_function")
        ),
        "winlog.event_data.SignatureStatus": lambda o: _ed(
            _attr(o, "dll", "code_signature", "status")
        ),
        "winlog.event_data.Signature": lambda o: _ed(
            _attr(o, "dll", "code_signature", "subject_name")
        ),
        "winlog.event_data.Operation": lambda o: _ed(_attr(o, "wmi", "operation")),
        "winlog.event_data.Name": lambda o: _ed(_attr(o, "wmi", "name")),
        "winlog.event_data.EventNamespace": lambda o: _ed(_attr(o, "wmi", "namespace")),
        "winlog.event_data.Query": lambda o: _ed(_attr(o, "wmi", "query")),
        "winlog.event_data.Type": lambda o: _ed(_attr(o, "wmi", "consumer_type")),
        "winlog.event_data.Consumer": lambda o: _ed(_attr(o, "wmi", "consumer")),
        "winlog.event_data.Filter": lambda o: _ed(_attr(o, "wmi", "filter")),
    }
)

#: ECS fields whose derived value is an array (``element_*`` operators only).
SYSMON_ARRAY_FIELDS = frozenset({"process.args", "process.parent.args", "registry.data.strings"})

#: ECS 8.17 (``ecs_flat.yml``) types of the fields that are not ``keyword``:
#: ``wildcard`` fields have no ``ignore_above``; ``long`` fields compare as integers.
_NON_KEYWORD = {
    "process.command_line": "wildcard",
    "process.parent.command_line": "wildcard",
    "registry.data.strings": "wildcard",
    "source.port": "long",
    "destination.port": "long",
    "source.ip": "ip",
    "destination.ip": "ip",
}

SYSMON_VIEWS: ViewSet = build_view_set(
    "elastic_sysmon", _PIPELINE_FIELDS, non_keyword=_NON_KEYWORD, arrays=SYSMON_ARRAY_FIELDS
)

#: ``elastic_sysmon.<ECS field>`` -> its queryable value for a Sysmon Observation.
SYSMON_DERIVED_FIELDS: Mapping[str, Callable[[Observation], Any]] = SYSMON_VIEWS.views
ECS_FIELD_TYPES: Mapping[str, str] = SYSMON_VIEWS.types
DERIVED_NAMESPACE = SYSMON_VIEWS.namespace

__all__ = [
    "DERIVED_NAMESPACE",
    "SYSMON_DERIVED_FIELDS",
    "SYSMON_ARRAY_FIELDS",
    "SYSMON_VIEWS",
    "ECS_FIELD_TYPES",
    "KEYWORD_IGNORE_ABOVE",
    "windows_argv",
]
