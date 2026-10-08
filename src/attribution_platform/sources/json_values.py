"""Exact value readers shared by the JSON (cloud / SaaS) source adapters (ADR-0011).

Each helper reads a value *as logged* or fails closed with a
:class:`~attribution_platform.sources.errors.SourceAdapterError` naming the
adapter — nothing here guesses, normalises or fills in.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from attribution_platform.domain import TimePrecision
from attribution_platform.sources.errors import SourceAdapterError

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def scalar_text(value: Any, adapter: str) -> str | None:
    """A logged scalar as text: JSON booleans as ``true`` / ``false``; ``None``
    and blank strings are absent; an object or array is not a scalar and fails
    closed."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float | str):
        text = str(value)
        return text if text.strip() else None
    raise SourceAdapterError(f"{adapter}: expected a scalar, got {type(value).__name__}")


def at_path(record: Mapping[str, Any], path: tuple[str, ...], adapter: str) -> str | None:
    """The scalar at ``path`` (``None`` when a step is absent or not an object)."""
    node: Any = record
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return scalar_text(node, adapter)


def _precision(fraction_digits: int) -> TimePrecision:
    if fraction_digits == 0:
        return TimePrecision.SECOND
    if fraction_digits <= 3:
        return TimePrecision.MILLISECOND
    return TimePrecision.MICROSECOND  # finer digits are truncated by datetime


def zoned_iso_time(value: Any, field: str, adapter: str) -> tuple[datetime, TimePrecision]:
    """An ISO 8601 event time that states its zone (ADR-0011 D5), with the
    precision its fraction declares. A value without a zone is refused."""
    if not isinstance(value, str):
        raise SourceAdapterError(f"{adapter}: {field} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceAdapterError(f"{adapter}: {field}={value!r} is not ISO 8601") from exc
    if parsed.tzinfo is None:
        raise SourceAdapterError(f"{adapter}: {field}={value!r} has no zone")
    _, _, rest = value.partition(".")
    return parsed, _precision(len(rest) - len(rest.lstrip("0123456789")))


def epoch_millis_time(value: Any, field: str, adapter: str) -> datetime:
    """Integer milliseconds since the Unix epoch (UTC by definition)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SourceAdapterError(f"{adapter}: {field}={value!r} is not epoch milliseconds")
    return _EPOCH + timedelta(milliseconds=value)  # exact: no float division


def ip_or_none(value: str | None) -> str | None:
    """``value`` when it is an IP address (canonical form), else ``None`` — a
    host name or service name is never put where an IP belongs."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


__all__ = ["at_path", "epoch_millis_time", "ip_or_none", "scalar_text", "zoned_iso_time"]
