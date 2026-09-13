"""Source-adapter errors (gate G0.4).

Mirrors the pattern already established by
:class:`attribution_platform.attack_knowledge.verification.ArtifactIntegrityError`
and :class:`attribution_platform.domain.errors.DomainContractError`: each
layer owns its own fail-closed error type.
"""

from __future__ import annotations


class SourceAdapterError(ValueError):
    """Raised when a source adapter violates the ``SourceAdapter`` contract.

    Fail-closed: raised instead of silently accepting a malformed adapter,
    a malformed raw record, or a result that doesn't match what the adapter
    itself declared (e.g. an Observation whose ``raw_reference.source_type``
    disagrees with ``adapter.source_type``).
    """
