"""Extraction-layer errors (gate G0.5).

Continues the per-layer fail-closed error pattern already used by
:class:`attribution_platform.attack_knowledge.verification.ArtifactIntegrityError`,
:class:`attribution_platform.domain.errors.DomainContractError`, and
:class:`attribution_platform.sources.errors.SourceAdapterError`.
"""

from __future__ import annotations


class ExtractionError(ValueError):
    """Raised when a detection-match record cannot be extracted into Observations.

    Fail-closed: raised for malformed detection-match input (missing rule
    identity, no matched events, wrong element types) and — wrapping the
    underlying :class:`~attribution_platform.domain.errors.DomainContractError`
    with which-event context — when a matched event cannot be normalized into
    a valid :class:`~attribution_platform.domain.Observation`. Every failure
    in the extraction layer surfaces as this one typed error.
    """
