# Ecosystem Reconnaissance — SOC APT Attribution Platform

**Status:** Research phase. Nothing here is an architecture decision. Every recommendation is a
**candidate requiring architectural review** before adoption.

**Date of research:** 2026-09-11
**Method:** Authoritative vendor/standards documentation and primary GitHub repositories, cross-checked
against recent (2024–2026) secondary sources. Facts, assumptions, and design opinions are labelled
throughout. Where a license or maintenance claim could not be confirmed from a primary source in this
pass, it is marked **(verify)** and must be confirmed before it influences a decision.

## Why this document set exists

The previous version of this project failed on cybersecurity substance: unreliable ATT&CK mapping,
hard-coded/simulated attribution, weak data modeling, and a frontend not backed by real functionality.
The purpose of this reconnaissance is to find **mature components we can stand on** so our own effort
concentrates on the genuinely hard, differentiating parts — **explainable, evidence-based correlation and
attribution** — rather than re-implementing telemetry storage, schemas, detection content, or the ATT&CK
knowledge base that mature projects already provide well.

## How to read the verdicts

Each candidate technology is assessed on: what it does, maturity, maintenance, license, major
dependencies, reusable functionality, Elastic fit, ATT&CK fit, whether it duplicates Elastic, a verdict,
and limitations/risks. Verdicts use a fixed vocabulary:

- **Integrate** — strong candidate to use directly as a dependency or deployed component.
- **Adapt** — borrow the logic/data, but expect to fork or wrap it.
- **Study** — learn from it; do not take a runtime dependency.
- **Avoid** — a likely trap (license, maintenance, or duplication risk).

## Documents

| # | Document | Covers (of the 18 requested areas) |
|---|----------|-------------------------------------|
| 01 | [Elastic Stack](01-elastic-stack.md) | Elastic Security, Elasticsearch, Kibana, ECS, Elastic detection content, integrations & data sources |
| 02 | [MITRE ATT&CK Data & Tooling](02-mitre-attack.md) | ATT&CK official data & STIX, ATT&CK libraries/tooling, ATT&CK-based threat-actor knowledge |
| 03 | [Detection Engineering](03-detection-engineering.md) | Sigma & the detection-engineering ecosystem |
| 04 | [Threat Intelligence & IOC Enrichment](04-threat-intel-and-ioc.md) | TI platforms/frameworks, IOC enrichment, APT/threat-actor knowledge bases |
| 05 | [Correlation, Graph & Attack-Chain Reconstruction](05-correlation-graph-attack-chain.md) | Security event correlation, attack-chain reconstruction, graph/network analysis |
| 06 | [SOC & Attribution Tools/Research](06-soc-and-attribution-tools.md) | Open-source SOC investigation platforms, open-source APT attribution tools & research |
| 07 | [Datasets & Synthetic Telemetry](07-datasets-and-synthetic-telemetry.md) | Security telemetry datasets and synthetic-data projects |
| 08 | [Attribution Methodology Foundations](08-attribution-methodology-foundations.md) | Diamond Model, kill chains, analytic-confidence standards (grounds our scoring) |
| 09 | [Technology Decision Matrix](09-technology-decision-matrix.md) | Consolidated candidate matrix + recommendations for architectural review |
| 10 | [Research Audit](10-research-audit.md) | Critical audit of docs 01–09: verified facts, corrections, and what must not be relied on |

## Cross-cutting findings (read these first)

1. **Elastic already provides a large amount of what a naive build would re-implement** — storage,
   ECS normalization, EQL/ES|QL correlation, prebuilt ATT&CK-mapped detection rules, entity risk scoring,
   and even an LLM-driven "Attack Discovery" that maps alert clusters to ATT&CK and *suggests* a threat
   actor. Our value cannot be "another SIEM." See [01](01-elastic-stack.md) and
   [05](05-correlation-graph-attack-chain.md).

2. **The differentiator is explainability and determinism.** Elastic's Attack Discovery reaches an
   attribution-flavored answer via an opaque LLM. The strongest recent research
   ([06](06-soc-and-attribution-tools.md)) says **TTP/behavioral evidence is the most robust attribution
   basis** and that **explainability** (e.g., LIME) is a known gap. A deterministic, evidence-graph-backed,
   hypothesis-based attribution engine with a documented confidence methodology
   ([08](08-attribution-methodology-foundations.md)) is a genuinely exceptional and defensible niche.

3. **License hazards are real and specific.** ATT&CK data and most MITRE tooling are permissive; Sigma
   *rules* (DRL 1.1) and the Sigma *library* (LGPL) differ; Elastic's `detection-rules` are **Elastic
   License v2** (not OSI-open); **TheHive 5 is commercially licensed** (read-only without a paid key).
   Licenses gate architecture — see each document and the matrix in [09](09-technology-decision-matrix.md).

4. **Do not confuse popularity with fitness.** Several high-star projects are either unmaintained,
   duplicate Elastic, or carry licenses hostile to our goals. Each entry states the specific risk.
