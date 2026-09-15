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
- **G1.1 (implemented):** ``client``/``http_client``/``fake_client`` gain one
  additive method, ``search(index, query, *, size)`` — a bounded, read-only
  query (no scroll/pagination, ``size`` required and capped), added because
  reading Elastic Detection Engine alerts
  (:mod:`attribution_platform.elastic_detections`) needs more than a
  known-id lookup. No mutation surface added; ``ensure_index``/
  ``index_document``/``get_document`` are unchanged.
- **G2.3 (implemented):** ``correlation_persistence`` —
  ``persist_correlation_link``/``load_correlation_link``/
  ``persist_correlation_group``/``load_correlation_group``, the same typed,
  idempotent, fail-closed round trip ``persistence`` already established,
  additively extended to the two G2.0 correlation contracts
  (:mod:`attribution_platform.correlation`); ``mappings`` gains
  ``CORRELATION_LINKS_INDEX``/``CORRELATION_LINKS_MAPPING``/
  ``CORRELATION_GROUPS_INDEX``/``CORRELATION_GROUPS_MAPPING``, the same
  schema-version-derived-index-name convention as the Observation/Evidence
  entries. This is the first gate this package imports
  :mod:`attribution_platform.correlation` — a new but one-directional,
  non-cyclic, ADR-0003-anticipated dependency (see
  ``correlation_persistence``'s own docstring).
- **Not yet implemented:** replay/bulk ingestion orchestration (that
  cross-cutting logic lives in :mod:`attribution_platform.replay`, not
  here); the read-model API (G0.10); detection rules, EQL/ES|QL
  correlation, attack-chain logic, or attribution scoring (none of which
  belong in this package regardless of gate).
"""

from __future__ import annotations

from attribution_platform.dataplane.client import ElasticClient
from attribution_platform.dataplane.correlation_persistence import (
    load_correlation_group,
    load_correlation_link,
    persist_correlation_group,
    persist_correlation_link,
)
from attribution_platform.dataplane.errors import ElasticIntegrationError
from attribution_platform.dataplane.fake_client import FakeElasticClient
from attribution_platform.dataplane.http_client import ElasticsearchHttpClient
from attribution_platform.dataplane.mappings import (
    CORRELATION_GROUPS_INDEX,
    CORRELATION_GROUPS_MAPPING,
    CORRELATION_LINKS_INDEX,
    CORRELATION_LINKS_MAPPING,
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
    "CORRELATION_LINKS_INDEX",
    "CORRELATION_LINKS_MAPPING",
    "CORRELATION_GROUPS_INDEX",
    "CORRELATION_GROUPS_MAPPING",
    "PersistResult",
    "persist_observation",
    "load_observation",
    "persist_evidence",
    "load_evidence",
    "persist_correlation_link",
    "load_correlation_link",
    "persist_correlation_group",
    "load_correlation_group",
]
