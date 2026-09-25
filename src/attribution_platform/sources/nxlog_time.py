"""Exact UTC event time for flat NXLog/Logstash Windows event exports.

Shared by the Windows event-log adapters (ADR-0008 D4). In these exports a
Windows event carries no UTC event time: ``EventTime`` is the host's local
time with no zone, and ``@timestamp`` is when the pipeline *received* the
event. ``EventReceivedTime`` (host-local) and ``@timestamp`` (UTC) mark the
same reception instant, so their difference is the host's UTC offset. Real
UTC offsets are multiples of 15 minutes and pipeline delay is seconds, so
rounding to 15 minutes recovers the offset exactly; a residual over 5 minutes
cannot be a zone and the record is refused, as it is when any of the three
fields is missing or carries an unexpected zone. ``EventTime`` has one-second
resolution. Validated on every record of the OTRF Empire samples (offset −4 h
throughout; pipeline delays ≤ 16 s).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from attribution_platform.sources.errors import SourceAdapterError

_ZONE_STEP = timedelta(minutes=15)
_MAX_PIPELINE_DELAY = timedelta(minutes=5)


def parse_timestamp(value: Any, field: str, *, adapter: str) -> datetime:
    """Parse an ISO-8601 timestamp field; refuse a missing or invalid one."""
    if not isinstance(value, str) or not value.strip():
        raise SourceAdapterError(f"{adapter}: missing required field {field}")
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceAdapterError(f"{adapter}: {field} {value!r} is not a valid timestamp") from exc


def nxlog_event_time(record: Mapping[str, Any], *, adapter: str) -> datetime:
    """The exact UTC event time of a flat NXLog record (see module docstring)."""
    event_local = parse_timestamp(record.get("EventTime"), "EventTime", adapter=adapter)
    received_local = parse_timestamp(
        record.get("EventReceivedTime"), "EventReceivedTime", adapter=adapter
    )
    received_utc = parse_timestamp(record.get("@timestamp"), "@timestamp", adapter=adapter)
    if event_local.tzinfo is not None or received_local.tzinfo is not None:
        raise SourceAdapterError(
            f"{adapter}: EventTime/EventReceivedTime unexpectedly carry a zone"
        )
    if received_utc.tzinfo is None:
        raise SourceAdapterError(f"{adapter}: @timestamp must carry a UTC zone")
    raw_offset = received_local - received_utc.astimezone(UTC).replace(tzinfo=None)
    offset = round(raw_offset / _ZONE_STEP) * _ZONE_STEP
    if abs(raw_offset - offset) > _MAX_PIPELINE_DELAY:
        raise SourceAdapterError(
            f"{adapter}: cannot derive the host UTC offset exactly "
            f"(receive-time difference {raw_offset} is not a 15-minute zone step)"
        )
    return (event_local - offset).replace(tzinfo=UTC)


__all__ = ["nxlog_event_time", "parse_timestamp"]
