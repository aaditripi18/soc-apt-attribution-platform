"""Deterministic detection-match -> Observation extraction (gate G0.5).

The extraction boundary: a pure function from a
:class:`~attribution_platform.extraction.detection_match.DetectionMatchRecord`
to a tuple of normalized :class:`~attribution_platform.domain.Observation`
objects — one per matched event, in the record's order.

Guarantees:

- **Deterministic:** a pure function of its input; no wall-clock time, no
  generated ids, no randomness. Equal records yield equal Observation tuples.
- **Provenance-preserving:** each produced ``Observation.raw_reference`` *is*
  the matched event's ``SourceRef`` (the existing G0.3 provenance boundary —
  no new raw-data mechanism).
- **Fail-closed with a typed error:** record-level problems are rejected at
  ``DetectionMatchRecord`` construction (``ExtractionError``); a matched event
  that cannot be normalized into a valid ``Observation`` (e.g. a naive
  timestamp) raises ``ExtractionError`` wrapping the underlying
  ``DomainContractError`` with which-event context.
- **Source-agnostic:** operates only on the generic detection-match contract
  and G0.3 domain types; no Sysmon/Elastic/collector-specific logic.

Deliberately NOT here (later gates): technique mapping / ATT&CK matching,
Evidence creation, correlation, any real detection engine, Elastic.
"""

from __future__ import annotations

from attribution_platform.domain import Observation
from attribution_platform.domain.errors import DomainContractError
from attribution_platform.extraction.detection_match import DetectionMatchRecord
from attribution_platform.extraction.errors import ExtractionError


def extract_observations(record: DetectionMatchRecord) -> tuple[Observation, ...]:
    """Extract one normalized ``Observation`` per matched event, in order."""
    observations: list[Observation] = []
    for i, matched in enumerate(record.matched_events):
        try:
            observation = Observation(
                observation_id=matched.observation_id,
                timestamp=matched.timestamp,
                raw_reference=matched.source_ref,
                timestamp_precision=matched.timestamp_precision,
                event=matched.event,
                host=matched.host,
                user=matched.user,
                process=matched.process,
                network=matched.network,
                file=matched.file,
                dll=matched.dll,
                registry=matched.registry,
                target_process=matched.target_process,
                process_access=matched.process_access,
                remote_thread=matched.remote_thread,
                dns=matched.dns,
                file_stream=matched.file_stream,
                pipe=matched.pipe,
                wmi=matched.wmi,
                powershell=matched.powershell,
            )
        except DomainContractError as exc:
            rule = record.rule_ref
            raise ExtractionError(
                f"detection match (rule={rule.rule_id!r}@{rule.rule_version!r}): "
                f"matched_events[{i}] (observation_id={matched.observation_id!r}) could not be "
                f"normalized into a valid Observation: {exc}"
            ) from exc
        observations.append(observation)
    return tuple(observations)
