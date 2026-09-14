"""Elasticsearch client and persistence (the telemetry/data plane).

Per ADR-0001 (D2) and docs/architecture/04-component-boundaries.md: Elastic
is the data plane only — ingest, ECS normalization, storage, search, and
detection execution. This package is a thin client around that boundary; it
holds no attribution, correlation, or evidence-graph reasoning.

Gate status:

- **G0.7 (implemented, ``docker-compose.yml`` at the repo root):** the
  platform stack (Elasticsearch + Kibana) bring-up. Not code in this
  package.
- **G0.8 (implemented):** ``client`` — the ``ElasticClient`` structural
  Protocol (the one abstraction the Attribution Engine and every future
  caller depend on, never a concrete client); ``http_client`` — a thin,
  stdlib-only REST client implementing it against a real cluster;
  ``fake_client`` — an in-memory implementation for tests (no live
  Elasticsearch required); ``mappings`` — pinned, schema-version-derived
  index names and explicit field mappings for the Observation/Evidence
  indices; ``persistence`` — ``persist_observation``/``load_observation``/
  ``persist_evidence``/``load_evidence``, the typed, idempotent,
  fail-closed round trip between G0.3 domain objects and Elastic documents
  (no second schema — documents are exactly
  ``attribution_platform.domain.to_serializable(obj)``).
- **Not yet implemented:** replay/bulk ingestion (G0.9); the read-model API
  (G0.10); detection rules, EQL/ES|QL correlation, attack-chain logic, or
  attribution scoring (none of which belong in this package regardless of
  gate).
"""

from __future__ import annotations

from attribution_platform.dataplane.client import ElasticClient
from attribution_platform.dataplane.errors import ElasticIntegrationError
from attribution_platform.dataplane.fake_client import FakeElasticClient
from attribution_platform.dataplane.http_client import ElasticsearchHttpClient
from attribution_platform.dataplane.mappings import (
    EVIDENCE_INDEX,
    EVIDENCE_MAPPING,
    OBSERVATIONS_INDEX,
    OBSERVATIONS_MAPPING,
)
from attribution_platform.dataplane.persistence import (
    PersistResult,
    load_evidence,
    load_observation,
    persist_evidence,
    persist_observation,
)

__all__ = [
    "ElasticClient",
    "ElasticIntegrationError",
    "ElasticsearchHttpClient",
    "FakeElasticClient",
    "OBSERVATIONS_INDEX",
    "OBSERVATIONS_MAPPING",
    "EVIDENCE_INDEX",
    "EVIDENCE_MAPPING",
    "PersistResult",
    "persist_observation",
    "load_observation",
    "persist_evidence",
    "load_evidence",
]
