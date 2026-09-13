"""The synthetic/replay reference SourceAdapter (gate G0.4).

Not a real telemetry source. A minimal, deterministic reference
implementation of :class:`~attribution_platform.sources.adapter.SourceAdapter`
that exists to:

1. prove the interface is genuinely implementable by something other than
   the abstraction's own author;
2. serve as the fixture-producing adapter for later offline/replay testing
   and validation (docs/architecture/13, CL-3 — the golden/scenario corpus
   is hand-authored synthetic data, not a real collector);
3. be the pattern a later real adapter (Sysmon, Windows Event Log, etc. —
   gate G0.9) follows.

Deliberately trivial: the "raw record" here already carries normalized
values (a hand-authored fixture), so there is no parsing/normalization logic
worth writing — this adapter's only job is packaging that record into an
``Observation`` with correctly-stamped ``SourceRef`` provenance, which is
exactly what a reference implementation should exercise.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from attribution_platform.domain import Observation, SourceRef
from attribution_platform.sources.errors import SourceAdapterError

#: This adapter's stable source identifier.
SYNTHETIC_SOURCE_TYPE = "synthetic"


@dataclass(frozen=True)
class SyntheticRecord:
    """One hand-authored synthetic raw record.

    This *is* the source-native shape for the synthetic source — analogous
    to a Sysmon XML event or a Winlogbeat JSON document for their own
    sources. It is deliberately sparse; extend only when a real fixture
    needs a field, never speculatively.
    """

    record_id: str
    timestamp: datetime
    observation_id: str | None = None


class SyntheticSourceAdapter:
    """Reference ``SourceAdapter``: :class:`SyntheticRecord` -> ``Observation``."""

    @property
    def source_type(self) -> str:
        return SYNTHETIC_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, SyntheticRecord):
            raise SourceAdapterError(
                f"SyntheticSourceAdapter expects a SyntheticRecord, "
                f"got {type(raw_record).__name__}"
            )

        observation_id = raw_record.observation_id or raw_record.record_id

        return (
            Observation(
                observation_id=observation_id,
                timestamp=raw_record.timestamp,
                raw_reference=SourceRef(
                    source_type=self.source_type,
                    source_event_id=raw_record.record_id,
                ),
            ),
        )
