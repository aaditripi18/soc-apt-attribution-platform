"""Source-agnostic entity value objects used inside Observations/Evidence.

Gate G0.3. These are the *curated normalized field groups* (host, user,
process, network, file, event metadata, time span) that a legitimate
telemetry source may populate — ECS-aligned generic concepts, never
Sysmon- or collector-specific. Every field is optional: a source populates
what it has and leaves the rest absent (``None`` / empty tuple). Nothing
here is mandatory, and there is no generic ``dict[str, Any]`` bag — raw,
source-native fields that have no normalized home are preserved by
*reference* to the raw record via :class:`~attribution_platform.domain.provenance.SourceRef`,
not copied into these structures (docs/architecture/13, G0.3 §6).

All classes are ``@dataclass(frozen=True)`` with only scalar or ``tuple``
fields, so they are deeply immutable and value-equal by construction — no
mutable container is ever exposed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from attribution_platform.domain.errors import DomainContractError, ensure_aware_datetime


@dataclass(frozen=True)
class HashSet:
    """Cryptographic hashes of a file/artifact (all optional)."""

    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class FileRef:
    """A file/path artifact referenced by an observation (all optional)."""

    path: str | None = None
    name: str | None = None
    directory: str | None = None
    hashes: HashSet | None = None


@dataclass(frozen=True)
class PeInfo:
    """Portable-Executable version-info metadata of a process image (all
    optional) — ECS ``process.pe.*``. Values are the image's own embedded
    resource strings as the source reported them, never inferred."""

    original_file_name: str | None = None
    description: str | None = None
    product: str | None = None
    company: str | None = None


@dataclass(frozen=True)
class CodeSignature:
    """Code-signing facts about a binary as the source reported them (all
    optional) — ECS ``*.code_signature.*``. ``signed`` is whether a signature
    was present; ``status`` is the source's verification result (e.g.
    ``Valid``); ``subject_name`` is the signer."""

    signed: bool | None = None
    subject_name: str | None = None
    status: str | None = None


@dataclass(frozen=True)
class DllRef:
    """A library loaded into a process (all optional) — ECS ``dll.*``.

    ``pe``/``code_signature`` describe the **loaded library**, not the
    loading process (which is the Observation's ``process``)."""

    path: str | None = None
    name: str | None = None
    pe: PeInfo | None = None
    code_signature: CodeSignature | None = None


@dataclass(frozen=True)
class RegistryRef:
    """A Windows registry key or value touched by an event (all optional) —
    ECS ``registry.*``. ``path`` is the full path as the source reported it
    (a key path, or key path plus value name); ``data`` is the value data as
    the source rendered it as a string (e.g. Sysmon's ``Details``). The kind of
    operation lives on the Observation's ``event`` (``type``/``action``)."""

    path: str | None = None
    data: str | None = None


@dataclass(frozen=True)
class ProcessAccessRef:
    """One process opening a handle to another (all optional). The acting
    process is the Observation's ``process``; the accessed one is its
    ``target_process``. ``granted_access`` is the access mask as the source
    rendered it (e.g. ``0x1010``); ``call_trace`` is the source's stack
    string."""

    granted_access: str | None = None
    call_trace: str | None = None


@dataclass(frozen=True)
class RemoteThreadRef:
    """A thread created by one process inside another (all optional). The
    creating process is the Observation's ``process``; the one receiving the
    thread is its ``target_process``."""

    start_address: str | None = None
    start_module: str | None = None
    start_function: str | None = None


@dataclass(frozen=True)
class DnsRef:
    """A DNS lookup made by a process (all optional). ``question_name`` is the
    queried name (ECS ``dns.question.name``); ``query_status`` is the source's
    status code as a string (Sysmon ``QueryStatus``, a Win32 status, ``0`` =
    success); ``results`` is the source's raw answer string."""

    question_name: str | None = None
    query_status: str | None = None
    results: str | None = None


@dataclass(frozen=True)
class FileStreamRef:
    """An alternate data stream written to a file (all optional); the file is
    the Observation's ``file``. ``contents`` is the stream content as the source
    reported it (e.g. a ``Zone.Identifier`` body; Sysmon writes ``-`` when it
    does not capture it); ``hashes`` is the source's combined hash string
    (e.g. ``SHA1=…,MD5=…``) exactly as rendered."""

    contents: str | None = None
    hashes: str | None = None


@dataclass(frozen=True)
class PipeRef:
    """A named pipe created or connected to (all optional). Whether it was
    created or connected is on the Observation's ``event``."""

    name: str | None = None


@dataclass(frozen=True)
class WmiRef:
    """A WMI event-subscription object (filter, consumer or filter-to-consumer
    binding) as the source reported it (all optional); which of the three it is
    lives on the Observation's ``event.action``. Values are kept exactly as
    reported (Sysmon quotes names and escapes paths)."""

    operation: str | None = None
    name: str | None = None
    namespace: str | None = None
    query: str | None = None
    consumer_type: str | None = None
    destination: str | None = None
    filter: str | None = None
    consumer: str | None = None


@dataclass(frozen=True)
class PowerShellRef:
    """PowerShell engine logging (all optional) — ECS ``powershell.*``.

    Script-block logging: ``script_block_text`` (one logged part of a script
    block), ``script_block_id``, ``script_path``, and ``message_number`` /
    ``message_total`` (a long script block is logged in several parts, each
    its own event). Module/pipeline logging: ``payload`` (the logged
    invocation details) and ``context_info`` (the host context block). All
    text is kept exactly as the source logged it."""

    script_block_text: str | None = None
    script_block_id: str | None = None
    script_path: str | None = None
    message_number: int | None = None
    message_total: int | None = None
    payload: str | None = None
    context_info: str | None = None


@dataclass(frozen=True)
class LogonRef:
    """Windows logon and credential-validation facts (all optional; ADR-0008
    Security log). Values are kept exactly as the source logged them —
    including Windows' ``-`` "no value" marker and unrendered ``%%NNNN``
    message references, which detection content is written against.

    ``workstation_name`` is the logon events' ``WorkstationName``;
    ``workstation`` is credential validation's ``Workstation`` (distinct source
    fields, kept distinct). ``authentication_package`` is the logon events'
    ``AuthenticationPackageName``; ``package_name`` is credential validation's
    ``PackageName``. ``logon_id`` is the new session's id (``TargetLogonId``)."""

    logon_type: str | None = None
    logon_process: str | None = None
    authentication_package: str | None = None
    package_name: str | None = None
    lm_package: str | None = None
    key_length: str | None = None
    impersonation_level: str | None = None
    elevated_token: str | None = None
    logon_id: str | None = None
    workstation_name: str | None = None
    workstation: str | None = None
    status: str | None = None
    sub_status: str | None = None
    target_outbound_user_name: str | None = None


@dataclass(frozen=True)
class ObjectAccessRef:
    """A Windows audited object handle request/access (all optional; ADR-0008
    Security log): object manager server, type and name, the handle, the
    access mask and the access list (unrendered ``%%NNNN`` references, as
    logged), and for registry values the value name and new value."""

    server: str | None = None
    type: str | None = None
    name: str | None = None
    handle_id: str | None = None
    access_mask: str | None = None
    access_list: str | None = None
    value_name: str | None = None
    new_value: str | None = None


@dataclass(frozen=True)
class ShareRef:
    """A network share access (all optional; ADR-0008 Security log): share name,
    its local path, and for detailed share auditing the relative target
    name (the file or directory accessed inside the share)."""

    name: str | None = None
    local_path: str | None = None
    relative_target_name: str | None = None


@dataclass(frozen=True)
class ProcessRef:
    """A process and its immediate parent lineage (all optional).

    ``entity_id``/``parent_entity_id`` are stable per-process identifiers
    where a source provides them (e.g. an ECS ``process.entity_id``); they
    are the source's identifiers, not values this layer invents.

    ``name``/``parent_name`` are **bare file names** (ECS ``process.name`` /
    ``process.parent.name``); full paths belong in ``executable`` /
    ``parent_executable``. Fields added by ADR-0007 D10 step 1 (parent
    executable and command line, working directory, integrity level, PE
    metadata) let detection content match the process-creation fields
    endpoint sources actually report.
    """

    pid: int | None = None
    name: str | None = None
    executable: str | None = None
    command_line: str | None = None
    entity_id: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    parent_entity_id: str | None = None
    parent_executable: str | None = None
    parent_command_line: str | None = None
    working_directory: str | None = None
    integrity_level: str | None = None
    pe: PeInfo | None = None


@dataclass(frozen=True)
class HostRef:
    """A host/asset identity (all optional). ``ip`` is a tuple (a host may
    have several addresses); order is preserved as supplied."""

    id: str | None = None
    name: str | None = None
    ip: tuple[str, ...] = ()


@dataclass(frozen=True)
class UserRef:
    """A user/account identity (all optional)."""

    id: str | None = None
    name: str | None = None
    domain: str | None = None


@dataclass(frozen=True)
class NetworkEndpoint:
    """One end of a network connection (all optional)."""

    ip: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class NetworkInfo:
    """Network source/destination information for an observation (all optional)."""

    source: NetworkEndpoint | None = None
    destination: NetworkEndpoint | None = None
    protocol: str | None = None
    transport: str | None = None
    direction: str | None = None


@dataclass(frozen=True)
class EventMetadata:
    """ECS-style event classification (all optional).

    ``category`` and ``type`` are tuples because ECS models them as arrays
    (a single event may carry several categories/types). Order is preserved
    as supplied by the source. ``provider`` / ``code`` are ECS
    ``event.provider`` (the logging provider, e.g.
    ``Microsoft-Windows-Security-Auditing``) and ``event.code`` (the source's
    own event identifier, e.g. ``"4624"``), and ``dataset`` is ECS
    ``event.dataset`` (the log the event belongs to, e.g. ``system.security``
    for the Windows Security channel — Elastic's own dataset name), added for
    the Windows event logs (ADR-0008), whose detection content selects on
    them.
    """

    kind: str | None = None
    category: tuple[str, ...] = ()
    type: tuple[str, ...] = ()
    action: str | None = None
    outcome: str | None = None
    provider: str | None = None
    code: str | None = None
    dataset: str | None = None


@dataclass(frozen=True)
class TimeSpan:
    """A closed time interval [start, end], both timezone-aware.

    Used for derived Evidence that may span multiple observations. Validates
    that both bounds are tz-aware and that ``start <= end`` (fail closed).
    """

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        start = ensure_aware_datetime(self.start, "TimeSpan.start")
        end = ensure_aware_datetime(self.end, "TimeSpan.end")
        if start > end:
            raise DomainContractError(
                f"TimeSpan.start ({start.isoformat()}) must not be after end ({end.isoformat()})"
            )
