"""Attribution-domain errors (gate G3.2).

Continues the per-layer fail-closed error pattern already used by
:class:`attribution_platform.correlation.errors.CorrelationError`,
:class:`attribution_platform.detection.errors.DetectionError`,
:class:`attribution_platform.extraction.errors.ExtractionError`, and every
other domain-adjacent layer in this project — each layer raises its own
typed error rather than a shared/generic one, so a caller can tell which
layer rejected the input from the exception type alone.
"""

from __future__ import annotations


class AttributionError(ValueError):
    """Raised when an attribution-domain contract's invariant is violated.

    Subclasses ``ValueError`` because these are all "bad input to a
    constructor" conditions (fail closed) — a caller can never obtain a
    partially-valid or semantically-inconsistent attribution object (e.g. an
    ``AttributionResult`` whose ``leading_hypothesis_id`` is not even a
    member of its own ``candidate_hypothesis_ids``).
    """
