"""The Observation contract: source-agnostic normalized telemetry (gate G0.3).

An :class:`Observation` is **normalized telemetry that came from a source** —
the output of the normalization/ECS-mapping step, sitting between the raw
source record and any derived :class:`~attribution_platform.domain.evidence.Evidence`
(docs/architecture/13, G0.3; docs/architecture/12 §D.2).

Reconciliation with docs/architecture/06 (recorded per CLAUDE.md principle 12):
doc 06 — written before this gate — used "Observation" for a *detection-rule
match* atop a separate "RawEvent". This G0.3 gate (authoritative for open
question Q1) uses "Observation" for the *normalized telemetry event* itself,
and defers the "detection match / interpreted claim" concept to
:class:`Evidence`. The raw record is **not** a stored domain object here; it is
referenced via :class:`~attribution_platform.domain.provenance.SourceRef`
(``raw_reference``). So the three levels the gate requires to stay distinct —
raw telemetry, normalized Observation, derived Evidence — are: raw = referenced
(not copied), Observation = this class, Evidence = the derived layer.

Source-agnostic by construction: every telemetry field is optional and
expressed as an ECS-aligned generic entity group
(:mod:`attribution_platform.domain.entities`); none is Sysmon-/collector-
specific, and none is mandatory. Source-native fields with no normalized home
are preserved by reference through ``raw_reference`` — there is deliberately no
generic ``dict[str, Any]`` field. Adding a new *normalized* concept is a
deliberate contract extension (bump ``schema_version``), not an open-ended bag.

Deeply immutable and value-equal by construction: a ``@dataclass(frozen=True)``
whose fields are only scalars, ``tuple``, or other frozen dataclasses — there
is no exposed mutable mapping or list at any depth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from attribution_platform.domain.entities import (
    DllRef,
    DnsRef,
    EventMetadata,
    FileRef,
    FileStreamRef,
    HostRef,
    NetworkInfo,
    PipeRef,
    ProcessAccessRef,
    ProcessRef,
    RegistryRef,
    RemoteThreadRef,
    UserRef,
    WmiRef,
)
from attribution_platform.domain.enums import TimePrecision
from attribution_platform.domain.errors import ensure_aware_datetime, ensure_nonempty_str
from attribution_platform.domain.provenance import SourceRef

#: Version of THIS Observation normalization contract (our schema, distinct
#: from ``attack_kb_version``). Bumped only on a deliberate contract change.
OBSERVATION_SCHEMA_VERSION = "observation/1"


@dataclass(frozen=True)
class Observation:
    """One normalized telemetry event from a source.

    Required:
    - ``observation_id``: stable, opaque identifier **supplied upstream** by
      the source/adapter (never generated here — G0.3 §5). It is the
      Observation's identity key; adapters are responsible for assigning
      stable, de-duplicated ids.
    - ``timestamp``: the event time, **timezone-aware** (naive rejected).
    - ``raw_reference``: provenance back to the raw source record.

    Optional (populate what the source has; leave the rest absent):
    - ``timestamp_precision`` — declared precision of ``timestamp``.
    - ``event`` — ECS-style event category/type/action metadata.
    - ``host`` / ``user`` / ``process`` / ``network`` / ``file`` / ``dll`` /
      ``registry`` / ``target_process`` / ``process_access`` / ``remote_thread``
      / ``dns`` / ``file_stream`` / ``pipe`` / ``wmi`` — entity groups (added
      by ADR-0008 Wave 1 for image-load, registry, process-access,
      remote-thread, DNS, stream, pipe and WMI events;
      ``target_process`` is the process *acted upon*, ``process`` the actor).

    ``schema_version`` defaults to the current contract version (a static
    fact about this code, not fabricated data).
    """

    observation_id: str
    timestamp: datetime
    raw_reference: SourceRef
    timestamp_precision: TimePrecision | None = None
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
    schema_version: str = field(default=OBSERVATION_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        ensure_nonempty_str(self.observation_id, "Observation.observation_id")
        ensure_aware_datetime(self.timestamp, "Observation.timestamp")
        ensure_nonempty_str(self.schema_version, "Observation.schema_version")
        # raw_reference / entity groups are typed frozen dataclasses; their own
        # __post_init__ already validated them at their construction time.
