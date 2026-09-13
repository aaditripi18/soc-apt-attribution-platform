"""Closed vocabularies for the domain contracts (gate G0.3).

These are small, fixed enumerations, not scoring scales. In particular
:class:`EvidenceQuality` describes how trustworthy an *evidence item itself*
is (source reliability / observational quality) — it is **not** attribution
likelihood or attribution confidence (ADR-0002), carries no numeric score,
and no combination/derivation logic operates on it at this gate. Confusing
it with attribution likelihood/confidence is explicitly forbidden by the
G0.3 gate instructions.
"""

from __future__ import annotations

from enum import Enum


class EvidenceType(Enum):
    """The category of a derived Evidence claim (from docs/architecture/06).

    Membership is a closed set; constructing ``EvidenceType(x)`` with an
    unknown ``x`` raises ``ValueError`` (fail-closed enum validation).
    """

    BEHAVIORAL = "behavioral"  # a TTP / behavior observed
    EVIDENTIARY = "evidentiary"  # an IOC / infrastructure artifact (corroborating only)
    PROCEDURAL = "procedural"  # a specific procedure-level detail
    CONTEXTUAL = "contextual"  # victimology / targeting context


class EvidenceQuality(Enum):
    """Qualitative trustworthiness of an evidence item itself (optional).

    NOT attribution likelihood/confidence, NOT a numeric score — see the
    module docstring. Left off an Evidence object entirely (``None``) when
    not assessed; ``UNKNOWN`` is available for "assessed and indeterminate".
    """

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class TimePrecision(Enum):
    """Precision of a telemetry timestamp, where a source declares it.

    Optional metadata: different sources timestamp at different resolutions
    (e.g. second-precision event logs vs. sub-millisecond endpoint sensors).
    Absence (``None``) means the precision was not declared — it is never
    guessed.
    """

    SECOND = "second"
    MILLISECOND = "millisecond"
    MICROSECOND = "microsecond"
    NANOSECOND = "nanosecond"
    UNKNOWN = "unknown"
