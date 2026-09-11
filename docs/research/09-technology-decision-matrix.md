# 09 — Technology Decision Matrix (Candidates for Architectural Review)

**These are recommendations, not decisions.** Nothing here is adopted until it passes architectural
review. Verdict vocabulary: **Integrate** (use directly) · **Adapt** (fork/borrow) · **Study** (learn,
no runtime dependency) · **Avoid** (likely trap). Items marked **(verify)** have a license or maintenance
claim not confirmed from a primary source in this pass and must be checked before they influence a
decision.

---

## Master matrix

| Technology | Role | Maturity | Maintenance | License | Elastic fit | ATT&CK fit | Duplicates Elastic? | Verdict |
|---|---|---|---|---|---|---|---|---|
| **Elasticsearch + Kibana** | Telemetry store / search / viz | Very high | Active (vendor) | AGPLv3 / SSPL / ELv2 (clients Apache-2.0) | Core | via Security | Is the backbone | **Integrate** |
| **Elastic Security app** | Detection, correlation, risk, Attack Discovery | High | Active | ELv2/AGPL. **VERIFIED tiers:** detection engine + prebuilt rules **free/Basic**; entity analytics, Attack Discovery, ML **Platinum+** (Platinum not sold to new self-managed) | Core | First-class | Overlaps attribution (opaque) | **Integrate** (Basic evidence) / **Study** (Attack Discovery baseline) |
| **ECS** | Event normalization schema | High | Merging into OTel SemConv | Apache-2.0 | Core | `threat.*` fields | n/a | **Integrate** (watch OTel merge) |
| **elastic/detection-rules** | ATT&CK-tagged detection content | High | Active | **ELv2 (not OSI-open)** | Native | Explicit + Navigator | Complements | **Integrate/Adapt** (ELv2 review) |
| **Elastic integrations / Agent / Fleet** | Telemetry acquisition | High | Active | Mixed **(verify)** | Native | via content | n/a | **Integrate** (lab) |
| **attack-stix-data** | ATT&CK knowledge (STIX 2.1) | Official/current | Per release | **ATT&CK Terms of Use** (verified) | via our graph | Is ATT&CK | n/a | **Integrate** (pin a *versioned* bundle) |
| **mitreattack-python** | ATT&CK access library | Official | Active | **Apache-2.0** (verified) | n/a | Native | n/a | **Integrate** |
| **attackcti** | ATT&CK via TAXII | Mature (community) | **Stable, low activity** (verified) | **BSD-3-Clause** (verified) | n/a | Native | n/a | **Study** (repro risk) |
| **ATT&CK Navigator** | Technique coverage viz | High | Active | Apache-2.0 | export layers | Native | n/a | **Integrate/Study** |
| **ATT&CK Workbench** | Extend ATT&CK KB | Medium | Active (CTID) | Apache-2.0 | n/a | Native | n/a | **Study** (later) |
| **Sigma rules (SigmaHQ)** | Vendor-neutral detection content | High | Active | **DRL 1.1** | via backend | Technique tags | Complements detection-rules | **Integrate/Adapt** |
| **pySigma (+ ES backend)** | Sigma→query conversion | Mature core | Core active; **ES backend last release v2.1.1 (Aug 2024), slow cadence** (verified) | **LGPL-2.1** | Lucene/ES\|QL/EQL/NDJSON | preserves tags | n/a | **Integrate** (behind boundary) |
| **OpenCTI** | STIX-2.1 CTI knowledge graph | High | Active (Filigran) | **CE Apache-2.0 / EE commercial** (verified) | uses ES | Native | Overlaps our graph | **Study** now / Integrate later |
| **MISP** | IOC sharing + enrichment | Very high | Active | **AGPLv3** | integrates | ATT&CK galaxies | IOC-centric | **Study / optional Integrate** |
| **abuse.ch (MalwareBazaar/URLhaus/ThreatFox)** | Free IOC feeds | High | Active | Free/permissive **(verify per feed)** | ingest | actor tags | n/a | **Integrate** |
| **AlienVault OTX** | Community IOC feed | High | Active | Free API | ingest | pulses | n/a | **Integrate/Study** |
| **VirusTotal** | Reputation enrichment | Very high | Active | Free tier + ToS limits | API | n/a | n/a | **Integrate w/ care** |
| **CISA KEV** | Known-exploited vulns | High | Active | Public | ingest | n/a | n/a | **Integrate** |
| **Graph lib (NetworkX/igraph)** | Embedded evidence graph | High | Active | BSD/LGPL | complements | models ATT&CK | n/a | **Integrate** (phase 1) |
| **Neo4j / Memgraph** | Graph DB (scale) | Very high | Active | **GPLv3 / commercial** (Neo4j) | complements | models STIX | n/a | **Study/Adapt** (later) |
| **STIG (idaholab)** | STIX graph viz | Medium | **(verify)** | **(verify)** | n/a | STIX | n/a | **Study** |
| **Cortex** | Observable enrichment engine | High | Active | **AGPLv3** | integrates | n/a | n/a | **Study / optional Integrate** |
| **TheHive 5** | SOC case management | High | Active | **Commercial (read-only w/o key)** | integrates | n/a | n/a | **Avoid** (study model only) |
| **Wazuh** | Open XDR/SIEM | Very high | Active | **GPLv2** (indexer Apache-2.0) | duplicates Elastic | ruleset | **Yes** | **Study** (or lab agent) |
| **Velociraptor** | Endpoint DFIR/hunting | High | Active (frequent releases) | **AGPL-3.0** (verified; `Velocidex`) | feeds evidence | via artifacts | no | **Study / optional Integrate** |
| **Shuffle** | SOAR orchestration | Medium-high | Active | **backend AGPL-3.0 / apps+SDK MIT** (verified) | integrates | n/a | no | **Study** (later) |
| **MITRE CALDERA** | Adversary emulation / data gen | High | Active | **Apache-2.0** | generates telemetry | Native | no | **Integrate** (lab data gen) |
| **Atomic Red Team** | Per-technique test/data gen | Very high | Active | **MIT** | generates telemetry | Native | no | **Integrate** (lab data gen) |
| **OTRF Security-Datasets (Mordor)** | Replayable labeled telemetry | Established | **Stable, slowed cadence** (verified) | **MIT** (verified) | replay into ES | Labeled | no | **Integrate** (validation corpus) |
| **EVTX-ATTACK-SAMPLES / EVTX-to-MITRE** | Labeled EVTX fixtures | Established | Varies | **sbousseaden = GPL-3.0** (verified); mdecrevoisier **(verify)** | replay | Labeled | no | **Study / local fixtures** (mind GPL for redistribution) |
| **Splunk attack_data / BOTS; DARPA TC; CIC** | Larger/academic datasets | High | Varies | **(verify)** | partial | partial | no | **Study** |

### Candidates added during the audit ([10](10-research-audit.md))

| Technology | Role | Maturity | License | Why it matters here | Verdict |
|---|---|---|---|---|---|
| **STIX 2.1 `confidence` scales + `stix2.confidence.scales`** | Standard confidence representation | Standard/official | BSD-3 (lib) | Normative 0–100 ↔ None/Low/Med/High, Admiralty, WEP, DNI mappings; lets our score serialize to a standard | **Integrate** (serialization boundary) |
| **OCSF (Open Cybersecurity Schema Framework)** | Vendor-neutral event schema | High; LF-backed (AWS/Splunk/IBM/CrowdStrike…) v1.4.0 | Apache-2.0 | Real alternative to ECS → schema decision is 3-way | **Study** (don't preclude) |
| **DeTT&CT (Rabobank)** | ATT&CK data-source/visibility/detection **coverage scoring** | Mature | GPL-3.0 **(verify)** | Directly powers "what evidence would raise confidence" + telemetry→technique visibility | **Study / Adapt** (model, not runtime dep) |
| **MITRE CAR (Cyber Analytics Repository)** | ATT&CK-mapped analytics | Mature (MITRE) | Apache-2.0 **(verify)** | Complement/alternative to Sigma for analytic content | **Study** |
| **STIX-shifter (IBM/OCA)** | Federated query translation across data sources incl. Elastic | Mature | Apache-2.0 **(verify)** | Alternative/complement to pySigma for query translation; reduces Elastic lock-in | **Study** |
| **Kùzu / Memgraph (embedded/fast graph)** | Middle ground between NetworkX and Neo4j server | Growing | MIT (Kùzu) **(verify)** | Embedded graph DB with Cypher — scale path without a heavy server | **Study** |
| **DARPA OpTC / TC (OpTC subset)** | APT-style host provenance dataset | Research | Open (research) **(verify)** | Named, well-known APT-scenario provenance data for chain-reconstruction validation | **Study** |

---

## Recommended candidate stack (for review — not adopted)

A coherent "stand on mature substrate, build the differentiator" shape:

- **Telemetry & search:** Elasticsearch + Kibana; **ECS** as the normalized contract (design for the
  ECS→OTel merge behind a mapping boundary).
- **Detection/evidence producers:** Elastic `detection-rules` (internal use, pending ELv2 review) **and**
  **Sigma** (redistribution-safe) converted via **pySigma**; each rule match becomes a provenance-carrying
  **observation → technique** edge.
- **ATT&CK knowledge:** **pinned `attack-stix-data` (STIX 2.1)** loaded via **mitreattack-python**; ATT&CK
  Groups/Software/Campaigns as the actor baseline; emit **Navigator** layers for coverage.
- **Evidence/knowledge graph:** start **embedded (NetworkX/igraph)** over ATT&CK + observations + IOCs;
  graduate to **Neo4j/Memgraph** only if scale demands. Study **OpenCTI's** STIX-2.1 model as the schema
  reference.
- **Enrichment:** pluggable, cached — **abuse.ch + AlienVault OTX + CISA KEV** first; consider reusing
  **Cortex analyzers / MISP modules** for connectors; VirusTotal with rate-limit/ToS care.
- **Validation data:** **OTRF Security-Datasets** (replay) + **Atomic Red Team / CALDERA** (generate) as a
  pinned golden + scenario corpus.
- **The build-it-ourselves core (the point of the project):** the **explainable, deterministic attribution
  engine** — ACH-style competing hypotheses, discriminating-technique weighting, IOC as corroboration,
  **two-axis output (likelihood + confidence per ICD-203)**, full provenance, uncertainty + next-evidence
  ([08](08-attribution-methodology-foundations.md)).

## Things to explicitly NOT do (design opinions)

- **Do not reinvent** storage, ECS normalization, event correlation (EQL/ES|QL), the ATT&CK KB, or
  detection content — mature options exist.
- **Do not build on TheHive 5** (commercial read-only trap); study its model instead.
- **Do not run Wazuh *and* Elastic** as parallel backbones — redundant.
- **Do not put nondeterministic LLM output on the attribution correctness path.** Elastic's Attack
  Discovery is the opaque baseline we differentiate *against*, not a dependency.
- **Do not treat IOC matches as attribution** — behavioral/TTP evidence leads; IOCs corroborate.

## Top risks to resolve before implementation

1. **Licensing:** ELv2 scope for `detection-rules`; AGPL implications for anything we modify+serve
   (Elastic source, MISP, Cortex, OpenCTI); Sigma DRL attribution; dataset/sample-repo licenses. **(verify
   all before redistribution.)**
2. **Elastic paid-tier dependence:** confirm which security features we rely on are Basic-tier vs paid.
3. **Maintenance fragility:** pySigma Elasticsearch backend maintainer signal; some OTRF/sample repos'
   cadence. **(verify.)**
4. **Duplication creep:** the constant temptation to reproduce Elastic/OpenCTI instead of building the
   attribution differentiator — the exact failure mode to avoid.
5. **Scientific validity:** no capability counted as done without passing the versioned labeled corpus;
   confidence must be **calibrated**, not just plausible-looking.

## Immediate next steps (still research/planning — no application code)

1. Architectural review of this matrix; record decisions as ADRs under `docs/decisions/` (or similar).
2. Resolve every **(verify)** item (licenses, maintenance) against primary sources.
3. Draft the **attribution scoring spec** (likelihood + confidence methodology) from
   [08](08-attribution-methodology-foundations.md), with worked examples — before any engine code.
4. Define the **minimum viable golden corpus** and the first milestone: deterministic
   telemetry → observation → ATT&CK-technique mapping, validated against known-labeled data.
