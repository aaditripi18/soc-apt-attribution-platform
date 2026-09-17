"""Calibration-layer errors (gate B1.1, ADR-0006).

Continues the per-layer fail-closed error pattern already used by
:class:`attribution_platform.attribution.errors.AttributionError`,
:class:`attribution_platform.correlation.errors.CorrelationError`,
:class:`attribution_platform.detection.errors.DetectionError`, and every
other domain-adjacent layer in this project — each layer raises its own
typed error rather than a shared/generic one, so a caller can tell which
layer rejected the input from the exception type alone.

Scope note (ADR-0006): the ``calibration`` package is the corpus / schema /
versioning layer. It performs **no** attribution scoring, likelihood,
confidence, ranking, or abstention, computes no ``g(x)``/``D(x)``, never
alters ATT&CK relationships, and fits no calibration parameter — those are
later, separately-gated pieces (B1.2+ and the fitting sub-gate). B1.1 adds
only this error type and the importable package foundation.
"""

from __future__ import annotations


class CalibrationError(ValueError):
    """Raised when a calibration-layer contract's or corpus invariant is violated.

    Subclasses ``ValueError`` because these are all "bad input to a
    constructor / corpus check" conditions (fail closed) — a caller can never
    obtain a partially-valid or semantically-inconsistent calibration object.
    Matching the accepted ADR-0006 discipline, this is fatal: callers must not
    fabricate placeholder values to get past it (e.g. a silent negative label,
    or an ATT&CK-derived ground-truth label).
    """
