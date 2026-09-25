"""The detection-match record contract (gate G0.5).

This is the `E -> L2` boundary contract from
docs/architecture/04-component-boundaries.md: the structured hand-off from
the detection layer (a detection rule / analytic that fired over telemetry)
into the domain layer. It is the input the extractor
(:mod:`attribution_platform.extraction.extractor`) consumes to produce
normalized :class:`~attribution_platform.domain.Observation` objects.

Scope reconciliation (recorded per CLAUDE.md principle 12): this contract was
originally sketched under G0.4 but was scoped there to *only* the source-
adapter interface; it lands here in G0.5, alongside the extractor that
consumes it, which is its natural home (doc 13 G0.5 objective:
"detection-match record -> Observation ... rule ref, entities, time span").

A ``DetectionMatchRecord`` represents: *rule R matched, referencing these
matched event(s), keying on these field(s)*. Each :class:`MatchedEvent`
carries the normalized field data + source provenance for one matched raw
event; the extractor turns each into exactly one ``Observation``.

Source-agnostic by construction: matched events carry the generic G0.3
entity value objects and a G0.3 :class:`~attribution_platform.domain.SourceRef`
— never any source-native (Sysmon/Elastic/collector) schema. Raw-record
provenance flows entirely through the existing ``SourceRef`` boundary; no new
raw-data mechanism is introduced.

These are input contracts, so they validate their own *structural* invariants
at construction (fail-closed, raising :class:`ExtractionError`); per-event
telemetry validation (e.g. timezone-aware timestamps) is enforced when the
extractor constructs the ``Observation`` (docs/architecture/13, G0.5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from attribution_platform.domain import (
    DllRef,
    DnsRef,
    EventMetadata,
    FileRef,
    FileStreamRef,
    HostRef,
    NetworkInfo,
    PipeRef,
    PowerShellRef,
    ProcessAccessRef,
    ProcessRef,
    RegistryRef,
    RemoteThreadRef,
    SourceRef,
    TimePrecision,
    UserRef,
    WmiRef,
)
from attribution_platform.extraction.errors import ExtractionError


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Extraction-layer non-empty-string check (raises ``ExtractionError``)."""
    if not isinstance(value, str) or not value.strip():
        raise ExtractionError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


@dataclass(frozen=True)
class RuleRef:
    """Identity of the detection rule/analytic that produced a match.

    ``rule_id`` + ``rule_version`` together identify *which* logic fired and
    at *what version* — the seed a later gate (G0.6) uses as
    ``DerivationProvenance.method``/``method_version`` when it derives
    Evidence. Not consumed into Observations here (Observations are pure
    normalized telemetry); carried as detection-match context.
    """

    rule_id: str
    rule_version: str

    def __post_init__(self) -> None:
        _require_nonempty_str(self.rule_id, "RuleRef.rule_id")
        _require_nonempty_str(self.rule_version, "RuleRef.rule_version")


@dataclass(frozen=True)
class MatchedEvent:
    """One matched event's normalized field data + source provenance.

    Carries exactly the inputs needed to construct one ``Observation``:
    a supplied ``observation_id``, the ``source_ref`` provenance back to the
    raw record, the event ``timestamp``, and the optional G0.3 entity groups.
    A plain input DTO — semantic validation of ``timestamp`` and the entity
    groups happens when the extractor builds the ``Observation``.
    """

    observation_id: str
    source_ref: SourceRef
    timestamp: datetime
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
    powershell: PowerShellRef | None = None

    def __post_init__(self) -> None:
        _require_nonempty_str(self.observation_id, "MatchedEvent.observation_id")
        if not isinstance(self.source_ref, SourceRef):
            raise ExtractionError(
                f"MatchedEvent.source_ref must be a domain SourceRef, "
                f"got {type(self.source_ref).__name__}"
            )


@dataclass(frozen=True)
class DetectionMatchRecord:
    """A detection rule/analytic match over one or more telemetry events.

    - ``rule_ref``: the analytic that fired.
    - ``matched_events``: the matched event(s) — **non-empty** (a match with
      no events is meaningless). The extractor produces one ``Observation``
      per matched event, in order.
    - ``matched_fields``: optional names of the fields the rule keyed on
      (context faithfully representing the match; not consumed into
      Observations at this gate).
    """

    rule_ref: RuleRef
    matched_events: tuple[MatchedEvent, ...]
    matched_fields: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.rule_ref, RuleRef):
            raise ExtractionError(
                f"DetectionMatchRecord.rule_ref must be a RuleRef, "
                f"got {type(self.rule_ref).__name__}"
            )
        if not isinstance(self.matched_events, tuple) or not self.matched_events:
            raise ExtractionError(
                "DetectionMatchRecord.matched_events must be a non-empty tuple of MatchedEvent"
            )
        for i, me in enumerate(self.matched_events):
            if not isinstance(me, MatchedEvent):
                raise ExtractionError(
                    f"DetectionMatchRecord.matched_events[{i}] must be a MatchedEvent, "
                    f"got {type(me).__name__}"
                )
        for mf in self.matched_fields:
            _require_nonempty_str(mf, "DetectionMatchRecord.matched_fields[]")
