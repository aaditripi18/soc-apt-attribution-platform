"""ADR-0008 D3 — one authoritative source per observation kind per host.

When two sources record the same activity (Sysmon 1 and Security 4688 both
record a process start), the platform never merges the two afterwards —
merging without a shared identifier would be a guess. Instead each
observation kind has an ordered source precedence, and a deployment declares
which sources it collects on each host. On a host where a higher-precedence
source is declared, a lower-precedence source's observations *of that kind*
are **suppressed**: removed from ingestion, and recorded (id, kind, source,
and the source that took precedence) so the suppression is visible and
counted, never silent. Observations of other kinds from the same source are
kept (4624 logons are not suppressed by Sysmon — Sysmon has no logon event).

The observation kind is read from neutral fields only (``event.category`` /
``event.type``), so the policy is source-agnostic. Fail closed: an
observation of a precedence-governed kind whose host has no declaration, or
whose own source is not declared for its host, is an error — the declaration
is the deployment's coverage statement, and guessing it would re-open the
double-counting D3 exists to prevent.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from attribution_platform.domain import Observation
from attribution_platform.sources.errors import SourceAdapterError

#: Observation kind -> source types, highest precedence first. Sysmon is
#: preferred for process starts: it carries process GUIDs (structural
#: correlation, ADR-0003) where Security 4688 has only pids.
DEFAULT_SOURCE_PRECEDENCE: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {"process_start": ("sysmon", "windows_security")}
)


def observation_kind(observation: Observation) -> str | None:
    """The precedence-governed kind of ``observation``, or ``None``."""
    event = observation.event
    if event is not None and "process" in event.category and "start" in event.type:
        return "process_start"
    return None


def _host_key(observation: Observation) -> str | None:
    host = observation.host
    if host is None:
        return None
    for value in (host.id, host.name):
        if value is not None and value.strip():
            return value
    return None


@dataclass(frozen=True)
class SuppressedObservation:
    """One observation removed by precedence, and why."""

    observation_id: str
    kind: str
    source_type: str
    host: str
    suppressed_by: str


@dataclass(frozen=True)
class PrecedenceResult:
    """Observations kept (input order preserved) and those suppressed."""

    kept: tuple[Observation, ...]
    suppressed: tuple[SuppressedObservation, ...]

    def suppressed_counts(self) -> dict[tuple[str, str, str], int]:
        """``(host, kind, source_type)`` -> number suppressed."""
        counts: dict[tuple[str, str, str], int] = {}
        for item in self.suppressed:
            key = (item.host, item.kind, item.source_type)
            counts[key] = counts.get(key, 0) + 1
        return counts


def apply_source_precedence(
    observations: Sequence[Observation],
    declared_sources: Mapping[str, Iterable[str]],
    precedence: Mapping[str, Sequence[str]] = DEFAULT_SOURCE_PRECEDENCE,
) -> PrecedenceResult:
    """Apply D3 to ``observations`` given the deployment's
    ``declared_sources`` (host id or name -> source types collected there)."""
    declared = {host: frozenset(sources) for host, sources in declared_sources.items()}
    kept: list[Observation] = []
    suppressed: list[SuppressedObservation] = []
    for observation in observations:
        kind = observation_kind(observation)
        order = tuple(precedence.get(kind, ())) if kind is not None else ()
        source = observation.raw_reference.source_type
        if kind is None or source not in order:
            kept.append(observation)
            continue
        host = _host_key(observation)
        if host is None or host not in declared:
            raise SourceAdapterError(
                f"source precedence: observation {observation.observation_id!r} ({kind} from "
                f"{source!r}) is on host {host!r}, which has no source declaration"
            )
        if source not in declared[host]:
            raise SourceAdapterError(
                f"source precedence: observation {observation.observation_id!r} comes from "
                f"{source!r}, which is not declared for host {host!r}"
            )
        preferred = next(s for s in order if s in declared[host])
        if preferred == source:
            kept.append(observation)
        else:
            suppressed.append(
                SuppressedObservation(
                    observation_id=observation.observation_id,
                    kind=kind,
                    source_type=source,
                    host=host,
                    suppressed_by=preferred,
                )
            )
    return PrecedenceResult(kept=tuple(kept), suppressed=tuple(suppressed))


__all__ = [
    "DEFAULT_SOURCE_PRECEDENCE",
    "PrecedenceResult",
    "SuppressedObservation",
    "apply_source_precedence",
    "observation_kind",
]
