"""Elasticsearch client and persistence (the telemetry/data plane).

Per ADR-0001 (D2) and docs/architecture/04-component-boundaries.md: Elastic
is the data plane only — ingest, ECS normalization, storage, search, and
detection execution. This package is a thin client around that boundary; it
holds no attribution, correlation, or evidence-graph reasoning.

Scaffolding only at this gate (G0.0) — no Elasticsearch client, indexes, or
configuration exist yet. Deployment is implemented in G0.7; the client and
persistence round-trip in G0.8.
"""
