"""Read-model API boundary.

Per ADR-0001 (D11) and docs/architecture/04-component-boundaries.md: serves
stored investigations/evidence/results as read-model JSON. This layer
performs NO computation — no attribution, no scoring, no correlation. The
(future) analyst frontend renders what this API returns; it never computes
anything itself either.

Scaffolding only at this gate (G0.0) — no endpoints exist yet, and no API
framework has been chosen. Implemented in G0.10.
"""
