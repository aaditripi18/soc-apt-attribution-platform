# 01 — Elastic Stack

Covers requested areas 1–6: Elastic Security, Elasticsearch, Kibana, Elastic Common Schema (ECS),
Elastic detection rules/content, Elastic integrations & security data sources.

> All verdicts are candidates for architectural review, not decisions.

---

## Summary opinion (design opinion, not a decision)

Elastic is the strongest candidate for the **telemetry backbone**: ingestion, ECS normalization, storage,
search, and a large body of prebuilt ATT&CK-mapped detection content. Building our own SIEM would repeat
the previous version's core mistake (effort spent on plumbing instead of substance). The open question for
review is **how much of Elastic's higher-order security logic** (correlation, risk scoring, Attack
Discovery) we lean on versus build ourselves — because our differentiator lives exactly there.

---

## Elasticsearch + Kibana (storage, search, visualization)

- **What it does:** Distributed search/analytics engine (Elasticsearch) and its visualization/app layer
  (Kibana). Together they are the data plane and UI substrate for Elastic Security.
- **Maturity:** Very high; industry-standard.
- **Maintenance:** Very active, vendor-backed (Elastic N.V.).
- **License (fact):** Since **2024-08-29**, source is available under **AGPLv3** *in addition to* the
  existing **SSPL 1.0** and **Elastic License 2.0 (ELv2)** — i.e., officially open source again (AGPL is
  OSI-approved). **Elastic client libraries remain Apache 2.0.** Binary distributions unchanged.
- **Dependencies:** JVM (Elasticsearch); Node.js (Kibana).
- **Reuse:** Storage, indexing, KQL/Lucene/EQL/ES|QL query, dashboards, alerting framework.
- **ATT&CK fit:** Strong via Elastic Security content (below).
- **Duplicates?** It *is* the thing we would otherwise reinvent — do not reinvent it.
- **Verdict:** **Integrate** as the telemetry/search backbone (candidate).
- **Risks:** (a) AGPL is copyleft — if we *modify Elasticsearch/Kibana source* and convey it over a
  network, AGPL obligations attach. Using the binaries and *client libraries* (Apache 2.0) for an app that
  talks to Elastic does **not** trigger this. Confirm our usage pattern stays on the client side.
  (b) Operational weight (JVM heap, cluster ops) is non-trivial for a personal project — plan a modest
  single-node/dev footprint. (c) **Tier split — VERIFIED (2026-09):** the **detection engine and prebuilt
  detection rules are free (Basic)**, but **entity risk scoring / entity analytics, Attack Discovery, and
  ML anomaly detection require Platinum or Enterprise** — and **Platinum is no longer sold to new
  self-managed customers** (Elastic steers new buyers to Elastic Cloud). Practical consequence: for this
  project the paid, opaque higher-order features are effectively out of reach on a self-managed free stack,
  which *reinforces* building our own explainable engine on Basic-tier primitives + raw queries.

## Elastic Security (SIEM/detection app)

- **What it does:** Security app on top of ES/Kibana: detection rules engine, alerts, Timeline
  investigation, cases, entity analytics/risk scoring, and an LLM-based **Attack Discovery** that clusters
  alerts, maps them to the ATT&CK matrix, identifies involved users/hosts, and *suggests a possible threat
  actor*. (VERIFIED: Attack Discovery, entity analytics, and ML are **Platinum+**; it also requires a
  configured LLM connector.)
- **Correlation (fact):** Supports **EQL sequence** queries for ordered multi-stage patterns and **ES|QL**
  for pipe-based analysis; multiple correlation rule types; behavior-based rules that feed risk scoring.
- **Maturity/Maintenance:** High; actively developed.
- **License:** App code under ELv2/AGPL per the tri-license; **advanced Security features are gated to
  paid subscription tiers.**
- **ATT&CK fit:** First-class — rules carry ATT&CK metadata; coverage overview exists in-product.
- **Duplicates our project?** **Partially, and this is the central strategic question.** Attack Discovery
  overlaps with "attribution," but it is **LLM-driven and opaque** — the opposite of our explainable,
  deterministic, evidence-graph goal. Treat Elastic's detection/correlation as **upstream evidence
  producers**; treat its Attack Discovery as **a baseline/comparison and a source of alert clusters**, not
  as our attribution engine.
- **Verdict:** **Integrate** as evidence source; **Study** Attack Discovery as a baseline to beat on
  explainability (candidate).
- **Risks:** Feature-tier gating; opaque scoring in Attack Discovery is exactly what our project must not
  imitate.

## Elastic Common Schema (ECS)

- **What it does:** Open, field-normalization schema for events/logs (host, network, user, process,
  event.category/type, `threat.*` for ATT&CK, etc.). Gives telemetry a consistent, queryable shape — the
  "traceable path" the project principles require.
- **Maturity:** High; the de-facto normalization schema in the Elastic ecosystem and beyond.
- **Maintenance / direction (fact):** ECS was **donated to OpenTelemetry (2023)**; ECS and OTel Semantic
  Conventions are **converging into one schema maintained by OTel**. As of 2025 the convergence is
  **partial/incomplete**; the classic ECS format is effectively **"frozen" but still supported**, with a
  migration path to the merged schema.
- **License:** Apache 2.0.
- **ATT&CK fit:** ECS has a dedicated `threat.*` field set for ATT&CK tactic/technique tagging — directly
  useful for our evidence model.
- **Alternative schema — OCSF (added in audit):** the **Open Cybersecurity Schema Framework** (Linux
  Foundation; backed by AWS, Splunk, IBM, CrowdStrike, Palo Alto; v1.4.0, Jan 2025) is a **vendor-neutral**
  normalization schema and a real alternative to ECS, with a threat-intelligence-enrichment event class.
  The schema decision is therefore **three-way (ECS vs. OTel SemConv vs. OCSF)**, not two-way. For an
  Elastic-centric build, ECS remains the path of least resistance, but the internal mapping boundary should
  not assume ECS is the only possible contract.
- **Verdict:** **Integrate** ECS as our normalized event contract (candidate). **Design note:** track the
  ECS→OTel SemConv convergence so our field contract doesn't bind to a schema that is being superseded;
  isolate schema mapping behind an internal boundary so we can follow the merge later (and remain open to
  OCSF).
- **Risks:** Schema-in-transition; avoid deep coupling to ECS-only field names where an OTel/OCSF
  equivalent is emerging.

## Elastic detection content (`elastic/detection-rules`)

- **What it does:** Public repo of Elastic Security detection rules (KQL/EQL/ES|QL), each carrying
  metadata including **ATT&CK mappings**; the repo can auto-generate an **ATT&CK Navigator layer**.
- **Maturity/Maintenance:** High; actively maintained by Elastic.
- **License (fact — important):** **Elastic License v2 (ELv2)**, *not* an OSI-open license. Contributions
  require Elastic's CLA.
- **Reuse:** Ready-made, ATT&CK-tagged detections → a rich source of **observations → technique** evidence
  edges for our model, and a coverage map.
- **ATT&CK fit:** Excellent (explicit mappings, Navigator layer).
- **Duplicates?** Complements, not duplicates, our attribution layer.
- **Verdict:** **Integrate / Adapt** the rules as an evidence source (candidate), **subject to ELv2
  review.** ELv2 forbids providing the software as a hosted/managed service to third parties and forbid
  circumventing license keys — likely *fine* for a personal, non-hosted research project, but **must be
  reviewed** before we redistribute anything derived from it. Consider Sigma ([03](03-detection-engineering.md))
  as a **DRL/permissively-licensed alternative or complement** for content we intend to redistribute.
- **Risks:** License is the main one; also rules assume ECS + Elastic query languages (fine if we're on
  Elastic, coupling if not).

## Elastic integrations & security data sources

- **What it does:** Elastic Agent + **Fleet** + hundreds of **integration packages** (Windows/Sysmon,
  Linux/auditd, cloud, network, endpoint) that ship ECS-aligned ingest pipelines. Elastic Defend provides
  endpoint telemetry.
- **Maturity/Maintenance:** High; actively maintained.
- **License:** Mixed (packages/agent vary; much is ELv2/Apache). **(verify per integration we actually
  use.)**
- **Reuse:** Turnkey, ECS-normalized ingestion for exactly the telemetry types an APT investigation needs
  — removes a huge amount of undifferentiated work.
- **Verdict:** **Integrate** for telemetry acquisition/normalization in dev/lab (candidate). For
  reproducible research we will more often **replay curated datasets** ([07](07-datasets-and-synthetic-telemetry.md))
  than run live agents.
- **Risks:** Per-package license variance; version-coupling between Agent, Fleet, and stack version.

---

## Open questions for architectural review

1. **(Largely resolved by audit)** Elastic's higher-order security features (entity analytics, Attack
   Discovery, ML) are **Platinum+ and not sold to new self-managed customers** — so the working assumption
   is we **reproduce** these in our own explainable engine on **Basic-tier primitives + raw ES queries**,
   not depend on them. Confirm nothing in our minimum design secretly needs a paid feature.
2. Do we ever **redistribute** anything derived from `detection-rules` (ELv2) or ship a hosted instance
   (AGPL/ELv2/SSPL implications)? If yes, tighten the licensing analysis now.
3. Do we bind our normalized event contract to **classic ECS** or design for the **ECS→OTel** merged
   schema from the start (with a mapping boundary)?
4. Elastic vs. **OpenSearch** (Apache 2.0 fork) — does staying strictly OSI-open matter enough to trade
   away Elastic Security's ATT&CK-native content? (Leaning Elastic for the security content, but flag it.)

## Sources

- [Elastic licensing FAQ](https://www.elastic.co/pricing/faq/licensing) ·
  [Elasticsearch is open source again (AGPL)](https://www.elastic.co/blog/elasticsearch-is-open-source-again)
- [ECS ↔ OpenTelemetry convergence (OTel blog)](https://opentelemetry.io/blog/2023/ecs-otel-semconv-convergence/) ·
  [ECS & OpenTelemetry (Elastic docs)](https://www.elastic.co/docs/reference/ecs/ecs-opentelemetry)
- [Elastic opens public detection rules repo](https://www.elastic.co/security-labs/blog/elastic-security-opens-public-detection-rules-repo) ·
  [elastic/detection-rules](https://github.com/elastic/detection-rules)
- [Attack Discovery (Elastic docs)](https://www.elastic.co/docs/solutions/security/ai/attack-discovery) ·
  [Elastic Security detection engineering capabilities](https://www.elastic.co/blog/elastic-security-detection-engineering)
