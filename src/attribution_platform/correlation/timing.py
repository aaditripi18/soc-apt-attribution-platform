"""Precision-aware timestamp comparison shared by the correlation modules
(ADR-0004 D6's rule: compare at the two timestamps' common, coarser declared
precision; compare raw values when a precision is undeclared or unknown)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from attribution_platform.domain import Observation, TimePrecision

#: Truncation granularity per declared precision (ADR-0004 D6's table).
PRECISION_GRANULARITY: dict[TimePrecision, timedelta] = {
    TimePrecision.SECOND: timedelta(seconds=1),
    TimePrecision.MILLISECOND: timedelta(milliseconds=1),
    TimePrecision.MICROSECOND: timedelta(microseconds=1),
    TimePrecision.NANOSECOND: timedelta(microseconds=1),
}
#: The coarsest granularity above: two timestamps further apart than this can
#: never compare as tied.
MAX_GRANULARITY = max(PRECISION_GRANULARITY.values())
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def comparable_timestamps(a: Observation, b: Observation) -> tuple[datetime, datetime]:
    """The two timestamps as ADR-0004 D6 compares them."""
    ts_a, ts_b = a.timestamp, b.timestamp
    prec_a, prec_b = a.timestamp_precision, b.timestamp_precision
    if prec_a is not None and prec_b is not None:
        gran_a, gran_b = PRECISION_GRANULARITY.get(prec_a), PRECISION_GRANULARITY.get(prec_b)
        if gran_a is not None and gran_b is not None:
            granularity = max(gran_a, gran_b)
            ts_a = _EPOCH + ((ts_a - _EPOCH) // granularity) * granularity
            ts_b = _EPOCH + ((ts_b - _EPOCH) // granularity) * granularity
    return ts_a, ts_b


def is_confidently_before(candidate: Observation, reference: Observation) -> bool:
    """``True`` only when ``candidate`` certainly happened before ``reference``.
    A tie at the common precision is *not* "before"."""
    ts_a, ts_b = comparable_timestamps(candidate, reference)
    return ts_a < ts_b


__all__ = [
    "MAX_GRANULARITY",
    "PRECISION_GRANULARITY",
    "comparable_timestamps",
    "is_confidently_before",
]
