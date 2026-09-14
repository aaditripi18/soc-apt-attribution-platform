"""Dataplane (Elastic integration) errors (gate G0.8).

Continues the per-layer fail-closed error pattern already used by
:class:`attribution_platform.attack_knowledge.verification.ArtifactIntegrityError`,
:class:`attribution_platform.domain.errors.DomainContractError`,
:class:`attribution_platform.sources.errors.SourceAdapterError`, and
:class:`attribution_platform.extraction.errors.ExtractionError`.
"""

from __future__ import annotations


class ElasticIntegrationError(ValueError):
    """Raised when a domain object cannot be persisted to or loaded from Elastic.

    Fail-closed: raised for a non-domain-object input, a stored document that
    cannot be reconstructed into a valid domain object (missing/malformed
    fields, a ``schema_version`` this gate does not know how to read), and
    any underlying Elasticsearch/transport failure (connection, TLS, auth,
    non-2xx response). Every failure in this layer surfaces as this one typed
    error — callers never see a raw ``urllib`` / JSON / Elasticsearch
    exception, and never receive a partially-persisted or partially-built
    domain object.
    """
