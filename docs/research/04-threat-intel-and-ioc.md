# 04 — Threat Intelligence Platforms & IOC Enrichment

Covers requested areas 10–12: TI platforms/frameworks, IOC enrichment, APT/threat-actor knowledge bases.

> All verdicts are candidates for architectural review, not decisions.

---

## Summary opinion (design opinion)

For a research/portfolio project, a **full TI platform (MISP/OpenCTI) is likely more infrastructure than we
need early**, and both partly duplicate what we should build natively (a STIX-aware knowledge graph). The
higher-value, lower-cost move is to **consume STIX 2.1 directly** (OASIS libraries) into our own evidence
graph, treat ATT&CK Groups ([02](02-mitre-attack.md)) as the actor baseline, and pull **free IOC feeds**
for enrichment. Study OpenCTI's data model closely — it is essentially the graph we are trying to build.

---

## Threat-intelligence platforms

### OpenCTI (Filigran)
- **What it does:** Open-source CTI knowledge platform built natively on **STIX 2.1**, representing threat
  actors, intrusion sets, campaigns, malware, tools, techniques, and indicators as a **connected graph**;
  large connector ecosystem (incl. ATT&CK, MISP).
- **Maturity/Maintenance:** High; actively developed by Filigran; mature connector ecosystem.
- **License (VERIFIED 2026-09):** **Community Edition = Apache-2.0**; **Enterprise Edition = separate
  commercial "Enterprise Edition license"** (extra features toggled in platform settings). CE is genuinely
  open source; just avoid depending on EE-only features.
- **Dependencies (heavy):** Elasticsearch/OpenSearch, Redis, RabbitMQ, MinIO, plus workers/connectors.
- **Reuse / fit:** Its **STIX-2.1 graph data model is almost exactly our target model** for evidence and
  actor knowledge; ATT&CK-native; integrates with Elastic as its own store.
- **Duplicates our project?** Substantially, on the *knowledge-graph* side — which is precisely why it is
  most valuable as a **model to study/borrow** rather than a black box to depend on (our differentiator is
  the *attribution reasoning*, which OpenCTI does not do for us).
- **Verdict:** **Study now; consider Integrate later** as an enrichment/knowledge backend if our own graph
  proves insufficient (candidate). Adopting it early would add large infra and risk making us "a thin UI on
  OpenCTI" — the previous-version trap.
- **Risks:** Operational weight; scope creep; enterprise-feature boundaries.

### MISP (CIRCL)
- **What it does:** Operational IOC **sharing** platform: events, attributes, tags (incl. ATT&CK galaxies),
  correlation between indicators, feeds, STIX/TAXII import-export, and a rich **enrichment module**
  ecosystem.
- **Maturity/Maintenance:** Very high; long-established; actively maintained.
- **License (fact):** **AGPLv3** (core). Widely integrated (incl. with Elastic, Cortex, OpenCTI).
- **Reuse:** Excellent **IOC store + enrichment modules + feed ingestion**; easier to stand up than
  OpenCTI; can export STIX for our graph.
- **Duplicates?** IOC-centric; complements (does not replace) our behavioral/TTP attribution.
- **Verdict:** **Study; optional Integrate** as an IOC/enrichment backend if we want managed feeds without
  building feed plumbing (candidate).
- **Risks:** AGPL (network-copyleft if we modify+serve it); IOC-centricity means it is **weak on
  behavioral attribution** — do not mistake IOC correlation for TTP attribution.

### Framework note
OpenCTI ≈ *knowledge/graph* orientation (STIX 2.1, TTP-rich); MISP ≈ *operational IOC sharing*
orientation. They interoperate (converters exist both directions). Neither performs **explainable
evidence-based attribution** — that gap is our project.

## IOC enrichment sources (free / API-accessible)

Design opinion: enrichment should be a **pluggable, cached, side-channel** layer that adds *corroborating*
evidence to a hypothesis — never the primary attribution signal (IOCs are the **most easily manipulated**
artifact; see [08](08-attribution-methodology-foundations.md)).

| Source | What it provides | License/access | Verdict |
|---|---|---|---|
| **abuse.ch** (MalwareBazaar, URLhaus, ThreatFox) | Malware samples/hashes, malicious URLs, IOCs w/ actor tags | Free, API; generally permissive **(verify per feed)** | **Integrate** (candidate) — high-quality, free, API-friendly |
| **AlienVault OTX** | Community "pulses," 20M+ indicators, API | Free API (account) | **Integrate/Study** — broad but variable quality |
| **VirusTotal** | File/URL/domain reputation, multi-engine | Free tier rate-limited; ToS restricts redistribution | **Integrate w/ care** — mind rate limits + ToS |
| **CISA KEV** | Known-exploited vulns | Public | **Integrate** — cheap, authoritative context |
| **Shadowserver / PhishTank** | Infra + phishing telemetry | Free/community | **Study/optional** |

Enrichment plumbing options: **Cortex analyzers** ([06](06-soc-and-attribution-tools.md)) or **MISP
modules** provide ready-made connectors to many of the above — worth reusing rather than hand-writing each
API client. **(verify Cortex/MISP-module licenses: Cortex is AGPL.)**

## APT / threat-actor knowledge bases

- **Primary (Integrate):** **ATT&CK Groups/Software/Campaigns** ([02](02-mitre-attack.md)) — curated,
  behavioral, citable, versioned.
- **Secondary (Study/Enrich):** OpenCTI/MISP-imported reporting; abuse.ch/OTX actor tags; public vendor
  reporting referenced by ATT&CK. Use to *corroborate* and to surface **contradicting** evidence, not as
  ground truth.
- **Correctness caveats (carry into scoring):** actor **aliasing/overlap**; **shared/sold tooling** breaks
  malware-based attribution; reporting **bias and lag**; and the ever-present risk of **false-flag**
  operations. Our engine must be able to represent *contradicting* and *uncertain* evidence, not only
  supporting evidence.

---

## Open questions for architectural review

1. Build our **own STIX-2.1 evidence/knowledge graph** ([05](05-correlation-graph-attack-chain.md)) and
   consume feeds into it, **or** adopt OpenCTI/MISP as the backend and layer attribution on top? (Leaning:
   build our own graph early to own the differentiator; study OpenCTI's model closely; revisit adopting it
   once our reasoning layer is proven.)
2. Which enrichment sources are in the **minimum viable** set (leaning abuse.ch + OTX + CISA KEV), and do
   we reuse **Cortex/MISP modules** for connectors vs. writing thin clients?
3. How is enrichment **cached and versioned** so results stay reproducible and offline-testable?

## Sources

- [MISP project](https://www.misp-project.org/) ·
  [MISP vs OpenCTI (2025 guide)](https://www.cosive.com/misp-vs-opencti)
- [Open-source threat-intel feeds (Anomali)](https://www.anomali.com/blog/open-source-threat-intelligence-feeds) ·
  [Top free IOC enrichment platforms (SOCRadar)](https://socradar.io/blog/top-10-free-ioc-search-enrichment-platforms/)
