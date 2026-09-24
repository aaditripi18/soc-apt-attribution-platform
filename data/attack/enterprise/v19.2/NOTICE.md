# NOTICE — MITRE ATT&CK® Attribution

This directory contains a vendored, immutable copy of official MITRE ATT&CK®
data, used under the MITRE ATT&CK Terms of Use.

## Attribution statement

> MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.
> This project uses MITRE ATT&CK® data. © 2018–2026 The MITRE Corporation.
> This work is reproduced and distributed under the MITRE ATT&CK Terms of Use:
> <https://attack.mitre.org/resources/terms-of-use/>.

No claim of ownership is made over MITRE ATT&CK content. The SOC APT
Attribution Platform's own code, evidence model, and attribution methodology
are original work that **consumes** ATT&CK as structured knowledge; they do
not modify or represent ATT&CK content as this project's own.

## What is vendored here

| Field | Value |
|---|---|
| Release | MITRE ATT&CK Enterprise **v19.2** |
| Format | Official **STIX 2.1** collection bundle |
| Source repository | [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data) |
| Release tag | [`v19.2`](https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2) |
| Artifact filename | `enterprise-attack-19.2.json` |
| Retrieved | 2026-09-24 (UTC) |
| Integrity | SHA-256-verified; see [`manifest.json`](manifest.json) in this directory for the full acquisition record (hash, STIX collection metadata, object fingerprint, source references) |

This is the exact, immutable, official bundle for release `v19.2` — not the
floating unversioned "latest" bundle and not fetched from a live MITRE
service at runtime. See
[docs/architecture/11-attack-knowledge-versioning.md](../../../../docs/architecture/11-attack-knowledge-versioning.md)
for the full versioning strategy (accepted decision C0.1; v19.0 → v19.2 upgrade recorded in §0).

## Terms of Use

Full terms: <https://attack.mitre.org/resources/terms-of-use/>. This project
does not redistribute ATT&CK data as a standalone product; it is used
internally as the pinned knowledge base for evidence-based APT attribution
analysis, with this attribution preserved wherever ATT&CK-derived content is
surfaced (analyst-facing output carries the `attack_kb_version` alongside its
conclusions — see [ADR-0002](../../../../docs/architecture/adr/0002-attribution-scoring-and-evidence-methodology.md)).
