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
    as supplied by the source.
    """

    kind: str | None = None
    category: tuple[str, ...] = ()
    type: tuple[str, ...] = ()
    action: str | None = None
    outcome: str | None = None


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
