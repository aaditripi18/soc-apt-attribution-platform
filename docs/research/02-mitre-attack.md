# 02 — MITRE ATT&CK Data & Tooling

Covers requested areas 7–8 and part of 12: ATT&CK official data & STIX, ATT&CK libraries/tooling, and the
ATT&CK-native threat-actor (Groups/Software/Campaigns) knowledge that anchors attribution.

> All verdicts are candidates for architectural review, not decisions.

---

## Summary opinion (design opinion)

ATT&CK should be treated as **versioned, structured knowledge loaded from official STIX**, not as
copied-out technique names (the previous version's failure). Use the official STIX 2.1 data + the official
Python library as the source of truth, model the relationships ourselves in our evidence/graph layer, and
**pin an ATT&CK version** so every attribution result is traceable to the knowledge version used.

---

## Official ATT&CK data

### `mitre-attack/attack-stix-data` — current canonical source
- **What it is (fact):** ATT&CK Enterprise/Mobile/ICS domains as **STIX 2.1** JSON "collections,"
  versioned by ATT&CK release (e.g., `enterprise-attack-<version>.json`). Includes the data-model docs and
  query examples. Has quality-of-life improvements over the legacy repo.
- **Maturity/Maintenance:** Official, current, maintained per ATT&CK release.
- **License (VERIFIED 2026-09):** MITRE copyright ("Copyright 2020-2025 The MITRE Corporation") + the
  **ATT&CK Terms of Use** (https://attack.mitre.org/resources/terms-of-use/) — permissive, attribution
  required. Note: each domain also ships an unversioned bundle that always matches the latest release; for
  reproducibility we must pin a **versioned** bundle, not the floating one.
- **Verdict:** **Integrate** as the source of truth (candidate). Pin a specific version in-repo for
  reproducibility.

### `mitre/cti` — legacy STIX 2.0
- **What it is (fact):** ATT&CK (and CAPEC) in **STIX 2.0**. Still maintained "for the foreseeable future"
  but the data model is older than attack-stix-data.
- **Verdict:** **Study/avoid for new work** — prefer STIX 2.1 (attack-stix-data) unless a dependency
  needs 2.0.

## ATT&CK relationships we must model (fact, from ATT&CK data model)

Tactics ↔ Techniques ↔ Sub-techniques; Techniques ↔ Mitigations; Techniques ↔ Data
Sources/Components/Detections; **Groups → (uses) → Techniques/Software**; **Campaigns → (attributed-to) →
Groups** and **Campaigns → (uses) → Techniques/Software**; Software → Techniques. In STIX these are
`attack-pattern`, `intrusion-set` (Groups), `malware`/`tool` (Software), `campaign`, `course-of-action`,
`x-mitre-tactic`/`data-source`/`data-component`, joined by `relationship` objects. **This relationship
graph is the literal backbone of evidence-based attribution** and maps cleanly onto a property graph
([05](05-correlation-graph-attack-chain.md)).

## ATT&CK libraries & tooling

### `mitre-attack/mitreattack-python` (incl. `MitreAttackData`)
- **What it does:** Official Python library to load and query ATT&CK STIX 2.0/2.1 — get techniques,
  groups, software, and their related objects; also includes Navigator-layer and other utilities.
- **Maturity/Maintenance:** Official, actively maintained.
- **License (VERIFIED 2026-09):** **Apache-2.0** (repo shows 815+ commits, active issues/PRs).
- **Dependencies:** `stix2`, `taxii2-client` ([04](04-threat-intel-and-ioc.md)).
- **Reuse:** Loading, querying, and traversing ATT&CK relationships without hand-rolling STIX parsing.
- **Verdict:** **Integrate** (candidate) — strongest option for programmatic ATT&CK access.

### `attackcti` (OTRF ATTACK-Python-Client)
- **What it does:** Thin wrapper over `stix2` + `taxii2-client` to pull ATT&CK from the public **TAXII**
  server with convenience functions.
- **Maturity/Maintenance (VERIFIED 2026-09):** Mature, community (OTRF); self-described "Production/Stable"
  with **low recent activity** (~207 commits, no visible recent cadence) — treat as **stable but not
  actively developed**.
- **License (VERIFIED 2026-09):** **BSD-3-Clause** (permissive).
- **Verdict:** **Study / optional Integrate.** Convenient, but pulling from a **remote TAXII** server hurts
  **reproducibility**; prefer loading a **pinned local STIX file** via `mitreattack-python`. Use attackcti
  only for ad-hoc exploration.

### ATT&CK Navigator
- **What it does:** Web UI to annotate/visualize technique coverage as "layers" (JSON).
- **License:** Apache-2.0.
- **Verdict:** **Integrate/Study** for coverage visualization (candidate). Both Elastic detection-rules and
  our own evidence engine can emit Navigator layers — a cheap, standards-based way to show technique
  coverage in the eventual frontend.

### ATT&CK Workbench (Center for Threat-Informed Defense)
- **What it does:** App to explore/create/annotate/**extend** the ATT&CK knowledge base (host your own
  extended ATT&CK).
- **License:** Apache-2.0.
- **Verdict:** **Study** now. Potentially useful later if we maintain local ATT&CK extensions/annotations,
  but it is heavier infra than we need in early phases.

## ATT&CK-native threat-actor knowledge (Groups/Software/Campaigns)

- **What it is (fact):** ATT&CK tracks ~170+ **Groups** with attributed techniques, software, linked
  campaigns, targeted sectors/geographies, and references. This is a **curated, citable, behavioral**
  actor knowledge base — exactly the reference set to match observed TTPs against.
- **Verdict:** **Integrate** as the primary actor/technique ground truth (candidate). Enrich later with
  external TI ([04](04-threat-intel-and-ioc.md)).
- **Caveats (important for attribution correctness):**
  - Group→technique links are **presence, not frequency/specificity** — many groups "use" common
    techniques (e.g., T1059). Naive matching over-attributes. Our scoring must weight **discriminating**
    techniques (rare/actor-characteristic) far above common ones (see [08](08-attribution-methodology-foundations.md)).
  - **Naming overlap / aliasing:** vendors name the same actor differently (APT29 vs Cozy Bear vs
    Midnight Blizzard). ATT&CK records aliases; we must normalize actor identity and never imply
    false precision.
  - ATT&CK Groups are **not exhaustive** and lag public reporting; absence is not evidence of absence.

---

## Open questions for architectural review

1. **Version pinning strategy:** vendor a specific `attack-stix-data` release into the repo and expose the
   version in every attribution result? (Strongly recommended — supports reproducibility principle.)
2. Do we load ATT&CK into our **graph store** ([05](05-correlation-graph-attack-chain.md)) as first-class
   nodes/edges, or query it via `mitreattack-python` at runtime and only materialize what we need?
3. How do we represent **procedure-level** evidence (the "P" in TTP), which ATT&CK captures only as free
   text on Group→technique relationships? This granularity matters for discriminating attribution.

## Sources

- [attack-stix-data (STIX 2.1)](https://github.com/mitre-attack/attack-stix-data) ·
  [mitre/cti (STIX 2.0, legacy)](https://github.com/mitre/cti) ·
  [ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) ·
  [attackcti (ATTACK-Python-Client)](https://attackcti.com/intro.html)
- [ATT&CK Groups](https://attack.mitre.org/groups/) · [ATT&CK Campaigns](https://attack.mitre.org/campaigns/)
- [ATT&CK Workbench (CTID)](https://github.com/center-for-threat-informed-defense)
