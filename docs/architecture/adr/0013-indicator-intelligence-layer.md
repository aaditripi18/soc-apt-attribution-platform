# ADR-0013 — Indicator (IOC) intelligence layer

- **Status:** PROPOSED (2026-10-08) — research complete; **owner decision required** on D3 before any
  implementation. The recommended path (D1–D2) is stated so the decision is a yes / no, not an open question.
- **Builds on:** ADR-0002 / 0005 (attribution methodology: evidence-driven, ACH over ATT&CK features),
  ADR-0003 (contextual vs structural links), ADR-0012 (network telemetry — the infrastructure facts an IOC
  would match).

## Context — measured, not assumed

**What an indicator match is.** An IOC match says: *a value observed here (IP, domain, hash, certificate) was
reported by a third party in connection with an actor or malware family*. It is not an observation of behaviour;
it is a **label claim** made elsewhere, at another time. CLAUDE.md's attribution philosophy is "evidence-driven
rather than label-driven" — so how such a claim may enter attribution is a methodology decision, not plumbing.

**The corpus cannot validate it.** Every recording in calibration corpus v2 (APT29 days 1–2, APT3 CALDERA /
Empire, the seven LSASS campaigns) and every network log of ADR-0012 uses **private lab infrastructure**
(`10.0.0.0/8`, `192.168.0.0/16`, lab domains such as `dmevals.local`, lab-built payloads). No public indicator
feed can match them. An IOC layer built now would have **zero measurable effect** on the corpus and could only
be tested on records with an inserted indicator value.

**Candidate sources (checked 2026-10-08):**

| Source | Licence / access | Attribution in the data | Reproducible pin | Fit |
|---|---|---|---|---|
| abuse.ch ThreatFox | fair use; every export needs an account **Auth-Key**; IOCs **expire after 6 months** | malware family (+ tags) | no — rolling, expiring | ✗ for a pinned, reproducible pipeline |
| CISA / partner advisories (STIX) | US-government work (public domain); per-advisory files | **actor stated by the advisory** | yes — one file per advisory | ✓, but only some advisories publish STIX (e.g. AA24-057A on APT29 publishes **no** indicators) |
| MISP galaxies | CC0 / BSD | actor and malware **metadata, no IOCs** | yes | context only |
| ATT&CK (pinned v19.2) | Apache-2.0 | **no IOCs** by design | yes | — |

**How the engine could use it.** ATT&CK Software ↔ Group relationships are already in the knowledge base
(the importer accepts software tags after review, e.g. PsExec S0029). An indicator attributed to a *malware
family* maps cleanly onto that path (family → ATT&CK Software → Groups that use it). An indicator attributed
directly to an *actor* has no ATT&CK feature to attach to; scoring it would need a new evidence class in the ACH
matrix (an ADR-0005 amendment) with its own diagnosticity — and indicator diagnosticity is not one number:
hashes of bespoke tooling are near-unique, IPs are reused, rented and reassigned within weeks.

## Decisions (proposed)

**D1 — Recommended: contextual only.** An indicator match is recorded as a **contextual annotation** on the
Observation / unit (which value, which source document, which actor or family it names, the report date, the
indicator type) — shown to the analyst, **never** a structural link and **never** an ACH feature. It explains;
it does not score. This is consistent with ADR-0003's rule for shared infrastructure.

**D2 — Recommended source and form.** Per-advisory STIX 2.1 bundles from government advisories that publish
them, pinned by URL and SHA-256 like every other dataset; exact matching only (IP, domain, URL, file hash,
certificate fingerprint); indicator validity windows kept and shown (a 2023 indicator matched in 2026 is
labelled stale, not dropped silently). No rolling feeds.

**D3 — Owner decision.** Whether indicator matches may ever contribute to attribution **scores** (an ADR-0005
amendment: a separate, typed evidence class with stated diagnosticity per indicator type), or stay contextual
(D1) permanently. Recommendation: contextual now; revisit only with validation data that contains real public
infrastructure (none exists in the corpus).

## Consequences

- If D1–D2 are accepted: a small, testable component (STIX ingestion → exact match → contextual annotation),
  validated by golden tests on real advisory bundles with one inserted value; no change to any attribution result.
- Until decided, nothing is built: building an unvalidatable scoring path would contradict CLAUDE.md principles
  1–4 and 14.

## Alternatives rejected

- **Rolling commercial / community feeds** — not reproducible, licence-restricted, expiring.
- **Scoring indicators as ATT&CK-technique-like features now** — label-driven, unvalidated, and an IP's
  diagnosticity is not knowable from the feed alone.
