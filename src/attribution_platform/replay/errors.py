"""Replay/fixture-loading errors (gate G0.9).

Continues the per-layer fail-closed error pattern already used by
:class:`attribution_platform.attack_knowledge.verification.ArtifactIntegrityError`,
:class:`attribution_platform.domain.errors.DomainContractError`,
:class:`attribution_platform.sources.errors.SourceAdapterError`,
:class:`attribution_platform.extraction.errors.ExtractionError`, and
:class:`attribution_platform.dataplane.errors.ElasticIntegrationError`.
"""

from __future__ import annotations


class ReplayError(ValueError):
    """Raised when a fixture file cannot be parsed into replayable scenarios.

    Fail-closed: raised for anything wrong with the *fixture itself* — invalid
    JSON, a missing required field, a wrong-shaped value, an unrecognized
    ``evidence_type``, a malformed timestamp, or a duplicate ``scenario_id``.

    Deliberately NOT raised for a well-formed fixture that a downstream
    pipeline stage rejects on its own terms (e.g. an ``attack_ref`` that does
    not resolve in the loaded ATT&CK KB, or an Elastic write failure) — those
    surface as the existing typed error from the layer that caught them
    (:class:`~attribution_platform.sources.errors.SourceAdapterError`,
    :class:`~attribution_platform.extraction.errors.ExtractionError`,
    :class:`~attribution_platform.extraction.evidence_derivation.EvidenceDerivationError`,
    :class:`~attribution_platform.attack_knowledge.resolution.AttackReferenceError`,
    :class:`~attribution_platform.dataplane.errors.ElasticIntegrationError`),
    not re-wrapped here. This keeps "the fixture is malformed" cleanly
    distinguishable from "the fixture is well-formed but the pipeline
    correctly refused it."
    """
