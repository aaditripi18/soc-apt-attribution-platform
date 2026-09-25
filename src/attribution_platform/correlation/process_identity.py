"""Process identity for pid-only telemetry (ADR-0003 Amendment B).

Some sources identify the acting process by **pid only** — PowerShell 4103/4104
logging, Security 4624/4688. Pids are reused, so ADR-0003 never *matches*
Observations on a pid. Amendment B instead **resolves** a pid-only Observation
to one process-instance id, and only when the telemetry itself proves which
instance owned that pid at that time (B1). A resolution records exactly which
Observations proved it (B2) and is never presented as a collector-asserted
identity: this module returns resolutions beside the Observations and never
rewrites an Observation.

**Proof rule (B1).** For a pid-only Observation *O* on host *h* with pid *p* at
time *t*:

1. *Start.* Among process-start Observations (``event.category`` ∋ ``process``,
   ``event.type`` ∋ ``start``, with ``process.entity_id`` and ``process.pid``) on
   *h* with pid *p* that are not confidently after *t*, the latest must be
   **confidently later than every other one** (else ``AMBIGUOUS_START``); none
   → ``NO_START``.
2. *Still alive at t.* If that instance has a process-end Observation
   (``event.type`` ∋ ``end``, same ``entity_id``, same host): the end must not be
   confidently before *t* (else ``ENDED_BEFORE`` — the pid may have been reused
   by a process the telemetry never showed) → basis ``START_AND_END``. If it has
   none: resolved (``START_NOT_ENDED``) only when the host's telemetry records
   process ends at all (at least one end Observation on *h*); otherwise absence
   proves nothing → ``NO_END_COVERAGE``.

A pid is unique among *live* processes, so a start at or before *t* with no end
before *t*, and no later start of the same pid before *t*, identifies the owner
exactly. Timestamps are compared at their common declared precision
(:func:`~attribution_platform.correlation.structural.is_confidently_before`,
ADR-0004 D6); ties are never resolved by guessing.

Pure and deterministic; reads only the ``process`` / ``host`` / ``event``
entity groups (source-agnostic — no source type is consulted).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from attribution_platform.correlation.structural import is_confidently_before
from attribution_platform.domain import Observation

PROCESS_IDENTITY_METHOD = "process-identity-resolution"
PROCESS_IDENTITY_METHOD_VERSION = "1.0"


class ResolutionBasis(Enum):
    """How a resolution was proved (B1 step 2)."""

    START_AND_END = "start_and_end"
    START_NOT_ENDED = "start_not_ended"


class UnresolvedReason(Enum):
    """Why a pid-only Observation stayed unresolved (fail closed)."""

    NO_HOST = "no_host"
    NO_START = "no_start"
    AMBIGUOUS_START = "ambiguous_start"
    ENDED_BEFORE = "ended_before"
    NO_END_COVERAGE = "no_end_coverage"


@dataclass(frozen=True)
class ResolvedProcessIdentity:
    """One pid-only Observation bound to a process instance, with its proof."""

    observation_id: str
    host_scope: tuple[str, str]
    entity_id: str
    basis: ResolutionBasis
    start_observation_id: str
    end_observation_id: str | None

    @property
    def proof_observation_ids(self) -> tuple[str, ...]:
        """The Observations that prove the binding (B2)."""
        ids = [self.start_observation_id]
        if self.end_observation_id is not None:
            ids.append(self.end_observation_id)
        return tuple(ids)


@dataclass(frozen=True)
class ProcessIdentityResolution:
    """Every resolution and every refusal, both sorted by Observation id."""

    resolved: tuple[ResolvedProcessIdentity, ...]
    unresolved: tuple[tuple[str, UnresolvedReason], ...]

    def by_observation_id(self) -> dict[str, ResolvedProcessIdentity]:
        return {r.observation_id: r for r in self.resolved}

    def unresolved_counts(self) -> dict[UnresolvedReason, int]:
        counts: dict[UnresolvedReason, int] = {}
        for _, reason in self.unresolved:
            counts[reason] = counts.get(reason, 0) + 1
        return counts


def _host_scope(observation: Observation) -> tuple[str, str] | None:
    """The same host scoping rule as structural correlation: ``host.id``,
    else ``host.name``."""
    host = observation.host
    if host is None:
        return None
    if host.id is not None and host.id.strip():
        return ("id", host.id)
    if host.name is not None and host.name.strip():
        return ("name", host.name)
    return None


def _has(values: tuple[str, ...], wanted: str) -> bool:
    return wanted in values


def _is_lifecycle(observation: Observation, kind: str) -> bool:
    event, process = observation.event, observation.process
    return (
        event is not None
        and _has(event.category, "process")
        and _has(event.type, kind)
        and process is not None
        and bool((process.entity_id or "").strip())
    )


def _needs_resolution(observation: Observation) -> bool:
    process = observation.process
    return process is not None and process.pid is not None and not (process.entity_id or "").strip()


def resolve_process_identities(observations: Iterable[Observation]) -> ProcessIdentityResolution:
    """Resolve every pid-only Observation in ``observations`` by the B1 proof
    rule (module docstring). ``observations`` must include the process-start and
    process-end telemetry of the same hosts — the proof comes only from it."""
    unique: dict[str, Observation] = {}
    for observation in observations:
        unique.setdefault(observation.observation_id, observation)
    ordered = sorted(unique.values(), key=lambda o: o.observation_id)

    starts: dict[tuple[tuple[str, str], int], list[Observation]] = {}
    ends: dict[tuple[tuple[str, str], str], list[Observation]] = {}
    hosts_with_ends: set[tuple[str, str]] = set()
    for observation in ordered:
        scope = _host_scope(observation)
        if scope is None or observation.process is None:
            continue
        if _is_lifecycle(observation, "start") and observation.process.pid is not None:
            starts.setdefault((scope, observation.process.pid), []).append(observation)
        elif _is_lifecycle(observation, "end"):
            assert observation.process.entity_id is not None
            ends.setdefault((scope, observation.process.entity_id), []).append(observation)
            hosts_with_ends.add(scope)

    resolved: list[ResolvedProcessIdentity] = []
    unresolved: list[tuple[str, UnresolvedReason]] = []
    for observation in ordered:
        if not _needs_resolution(observation):
            continue
        assert observation.process is not None and observation.process.pid is not None
        scope = _host_scope(observation)
        if scope is None:
            unresolved.append((observation.observation_id, UnresolvedReason.NO_HOST))
            continue
        candidates = [
            s
            for s in starts.get((scope, observation.process.pid), ())
            if not is_confidently_before(observation, s)
        ]
        if not candidates:
            unresolved.append((observation.observation_id, UnresolvedReason.NO_START))
            continue
        latest = max(candidates, key=lambda s: (s.timestamp, s.observation_id))
        if any(
            other is not latest and not is_confidently_before(other, latest) for other in candidates
        ):
            unresolved.append((observation.observation_id, UnresolvedReason.AMBIGUOUS_START))
            continue
        assert latest.process is not None and latest.process.entity_id is not None
        entity_id = latest.process.entity_id
        instance_ends = ends.get((scope, entity_id), [])
        if instance_ends:
            end = min(instance_ends, key=lambda e: (e.timestamp, e.observation_id))
            if is_confidently_before(end, observation):
                unresolved.append((observation.observation_id, UnresolvedReason.ENDED_BEFORE))
                continue
            basis, end_id = ResolutionBasis.START_AND_END, end.observation_id
        elif scope in hosts_with_ends:
            basis, end_id = ResolutionBasis.START_NOT_ENDED, None
        else:
            unresolved.append((observation.observation_id, UnresolvedReason.NO_END_COVERAGE))
            continue
        resolved.append(
            ResolvedProcessIdentity(
                observation_id=observation.observation_id,
                host_scope=scope,
                entity_id=entity_id,
                basis=basis,
                start_observation_id=latest.observation_id,
                end_observation_id=end_id,
            )
        )
    return ProcessIdentityResolution(resolved=tuple(resolved), unresolved=tuple(unresolved))


__all__ = [
    "PROCESS_IDENTITY_METHOD",
    "PROCESS_IDENTITY_METHOD_VERSION",
    "ProcessIdentityResolution",
    "ResolutionBasis",
    "ResolvedProcessIdentity",
    "UnresolvedReason",
    "resolve_process_identities",
]
