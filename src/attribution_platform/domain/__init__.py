"""Core domain contracts: Observation, Evidence, TechniqueAssertion, provenance.

This is the source-agnostic boundary described in
docs/architecture/12-deployment-and-endpoint-scope.md (§D.1/§D.2) and
docs/architecture/06-evidence-model.md: everything in and above this package
is defined purely in normalized (ECS/domain) and ATT&CK terms.

Hard rule (enforced by later gates' guard tests, not yet by code at this
gate): this package MUST NOT import from ``attribution_platform.sources`` or
``attribution_platform.dataplane`` and MUST NOT reference any source-native
field name (e.g. ``sysmon.*``, ``winlog.*``, a specific collector's schema).

Scaffolding only at this gate (G0.0) — no models are defined yet.
Implemented in G0.3 per docs/architecture/13-phase-0-implementation-plan.md.
"""
