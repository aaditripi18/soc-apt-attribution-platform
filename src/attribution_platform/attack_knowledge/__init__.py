"""Pinned MITRE ATT&CK knowledge: acquisition, verification, and access.

Per docs/architecture/11-attack-knowledge-versioning.md (C0.1, ACCEPTED):
loads only a vendored, hash-verified, immutable ATT&CK Enterprise v19.0 STIX
2.1 bundle (vendored under data/attack/enterprise/v19.0/, outside this
package). No live MITRE service dependency at runtime; no floating/latest
data. All ATT&CK vocabulary (tactics, techniques, sub-techniques, groups,
software, campaigns, relationships, aliases) is derived from the pinned
bundle — nothing is hard-coded here or anywhere downstream.

Gate status:

- **G0.1 (implemented):** ``verification`` — offline, fail-closed artifact
  integrity verification (SHA-256, STIX collection metadata, object
  fingerprint) against the vendored bundle's recorded manifest. No
  technique/group/software query API exists yet.
- **G0.2 (not started):** the knowledge-access loader (technique/tactic/
  group/software/campaign lookups, alias resolution, relationship
  traversal) that will be built on top of a verified artifact.
"""
