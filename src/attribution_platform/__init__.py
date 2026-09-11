"""SOC APT Attribution Platform.

An explainable, evidence-based APT attribution engine. See
docs/architecture/ for the accepted architecture (ADR-0001, ADR-0002) and
docs/architecture/13-phase-0-implementation-plan.md for the implementation
roadmap this package structure follows.

Package layout (each submodule states which Phase-0 gate implements it):

- ``domain``          — core contracts (Observation, Evidence, TechniqueAssertion,
                         provenance). Source-agnostic; no other submodule's types
                         may leak into it. Implemented in G0.3.
- ``attack_knowledge`` — pinned MITRE ATT&CK STIX loading and knowledge access.
                         Implemented in G0.1 (acquisition) / G0.2 (loading).
- ``sources``          — telemetry-source adapters (SourceAdapter interface +
                         synthetic reference adapter). Source-native specifics
                         (e.g. Sysmon event IDs, Elastic field names) live only
                         here, never in ``domain`` or above. Implemented in G0.4.
- ``extraction``       — detection-match record -> Observation boundary.
                         Implemented in G0.5.
- ``dataplane``        — Elasticsearch client and persistence. Implemented in
                         G0.7 (deployment) / G0.8 (integration).
- ``api``              — read-model API (serves stored data; performs no
                         attribution logic). Implemented in G0.10.

This package intentionally contains no attribution, correlation, or
attack-chain logic yet — see ADR-0001/ADR-0002 and the Phase-0 plan for why.
"""

__version__ = "0.0.0"
