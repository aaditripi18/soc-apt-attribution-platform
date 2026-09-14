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
  fingerprint) against the vendored bundle's recorded manifest.
- **G0.2 (implemented):** ``loader`` — the deterministic runtime loader
  (``load_attack_knowledge()``) that verifies the artifact via G0.1's
  contract, then exposes the raw, verified STIX objects indexed by id and
  by type (tactics/techniques/sub-techniques/groups/software/campaigns/
  mitigations/relationships). Deliberately narrow: no alias resolution, no
  relationship traversal, no re-typed domain model — see ``loader``'s
  module docstring for the exact scope decisions.
- **G0.6 (implemented):** ``resolution`` — ``resolve_attack_ref()``, a
  bounded KB lookup validating a domain ``AttackRef`` against the loaded KB
  (exists + STIX type match + KB-version match). No alias resolution, no
  relationship traversal.
- **Not yet implemented:** candidate generation / alias resolution /
  relationship traversal, attribution.
"""
