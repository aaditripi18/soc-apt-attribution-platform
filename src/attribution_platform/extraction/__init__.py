"""Detection-match record -> Observation extraction boundary.

Per docs/architecture/04-component-boundaries.md and
docs/architecture/06-evidence-model.md: turns a detection match (rule id,
matched fields, entities, source event references) into a provenance-carrying
``Observation``. This is deterministic, source-agnostic logic — it consumes
the normalized contract produced by ``attribution_platform.sources`` and
knows nothing about where the telemetry originated.

Scaffolding only at this gate (G0.0) — no extraction logic exists yet.
Implemented in G0.5.
"""
