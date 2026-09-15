"""Correlation-domain errors (gate G2.0).

Continues the per-layer fail-closed error pattern already used by
:class:`attribution_platform.detection.errors.DetectionError`,
:class:`attribution_platform.extraction.errors.ExtractionError`,
:class:`attribution_platform.replay.errors.ReplayError`, and every other
domain-adjacent layer in this project — each layer raises its own typed
error rather than a shared/generic one, so a caller can tell which layer
rejected the input from the exception type alone.
"""

from __future__ import annotations


class CorrelationError(ValueError):
    """Raised when a correlation-domain contract's invariant is violated.

    Subclasses ``ValueError`` because these are all "bad input to a
    constructor" conditions (fail closed) — a caller can never obtain a
    partially-valid or semantically-inconsistent correlation object (e.g. a
    ``CorrelationGroup`` whose ``structural_link_ids`` actually contains a
    contextual link).
    """
