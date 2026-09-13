"""Domain-contract errors and shared fail-closed validation helpers.

Gate G0.3. Constructors validate at build time and raise
:class:`DomainContractError` on any architectural-invariant violation
(fail closed) — a caller can never obtain a partially-valid domain object.
"""

from __future__ import annotations

from datetime import datetime


class DomainContractError(ValueError):
    """Raised when a domain contract's architectural invariant is violated.

    Subclasses ``ValueError`` because these are all "bad input to a
    constructor" conditions. Callers must treat this as fatal — do not
    construct a domain object with fabricated/placeholder values to get
    past it (docs/architecture/13-phase-0-implementation-plan.md, G0.3).
    """


def ensure_nonempty_str(value: object, field: str) -> str:
    """Return ``value`` if it is a non-empty, non-whitespace ``str``; else raise.

    Identifiers and other required string fields must be genuinely present.
    Whitespace-only strings are treated as absent (a common
    normalization/serialization artifact) and rejected rather than silently
    accepted.
    """
    if not isinstance(value, str):
        raise DomainContractError(f"{field} must be a str, got {type(value).__name__}")
    if not value.strip():
        raise DomainContractError(f"{field} must be a non-empty, non-whitespace string")
    return value


def ensure_aware_datetime(value: object, field: str) -> datetime:
    """Return ``value`` if it is a timezone-aware ``datetime``; else raise.

    Naive datetimes are rejected: a domain timestamp with no timezone is
    ambiguous and would make cross-source temporal reasoning (a later gate)
    silently wrong. Absence must be represented explicitly (``None`` on an
    optional field), never as a naive/placeholder datetime.
    """
    if not isinstance(value, datetime):
        raise DomainContractError(f"{field} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise DomainContractError(f"{field} must be timezone-aware (got a naive datetime)")
    return value
