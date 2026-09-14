"""Detection-layer errors (gate G1.0).

Continues the per-layer fail-closed error pattern already used throughout
(:class:`attribution_platform.domain.errors.DomainContractError`,
:class:`attribution_platform.extraction.errors.ExtractionError`,
:class:`attribution_platform.attack_knowledge.resolution.AttackReferenceError`,
...): each layer owns its own typed error, raised instead of silently
accepting malformed input or fabricating a value.
"""

from __future__ import annotations


class DetectionError(ValueError):
    """Raised when a detection rule, rule pack, or detection result is
    malformed, or when detection-layer evaluation cannot proceed safely.

    Fail-closed: raised for a malformed rule-pack file (bad JSON, missing
    fields, an unknown predicate operator, a value of the wrong shape for its
    operator, a duplicate rule id+version, an unrecognized top-level field
    path), for an ATT&CK technique mapping that does not resolve against the
    pinned KB (wrapping
    :class:`~attribution_platform.attack_knowledge.resolution.AttackReferenceError`),
    and for a caller passing something other than the expected typed object
    (a non-``Observation``, a non-``DetectionResult``) into this layer's
    functions.
    """
