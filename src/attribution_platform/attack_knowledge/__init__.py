"""Pinned MITRE ATT&CK knowledge: acquisition, verification, and access.

Per docs/architecture/11-attack-knowledge-versioning.md (C0.1, ACCEPTED):
loads only a vendored, hash-verified, immutable ATT&CK Enterprise v19.0 STIX
2.1 bundle. No live MITRE service dependency at runtime; no floating/latest
data. All ATT&CK vocabulary (tactics, techniques, sub-techniques, groups,
software, campaigns, relationships, aliases) is derived from the pinned
bundle — nothing is hard-coded here or anywhere downstream.

Scaffolding only at this gate (G0.0) — no bundle has been acquired and no
loader exists yet. Acquisition is implemented in G0.1; loading in G0.2.
"""
