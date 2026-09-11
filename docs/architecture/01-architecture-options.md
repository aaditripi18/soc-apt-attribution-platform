# 01 — Architecture Options

**Status:** Architecture-design phase. Nothing here is decided. This document defines **three genuinely
viable architectures**, describes each across the required dimensions, then compares them against the 14
review criteria. The recommendation lives in [02-recommended-architecture.md](02-recommended-architecture.md);
the decisions requiring your sign-off live in [05-architecture-open-questions.md](05-architecture-open-questions.md)
and the [ADR](adr/0001-evidence-graph-core-architecture.md) (all marked PROPOSED).

Grounded in: [CLAUDE.md](../../CLAUDE.md) and `docs/research/` (esp.
[09 decision matrix](../research/09-technology-decision-matrix.md),
[10 audit](../research/10-research-audit.md),
[08 attribution methodology](../research/08-attribution-methodology-foundations.md),
[05 correlation/graph](../research/05-correlation-graph-attack-chain.md)).

## The design tension

The research fixes several boundaries already: **do not reinvent** storage/search/detection (Elastic on the
free tier does this well), **do not treat IOCs or an opaque LLM as attribution**, and **do build** the
explainable evidence→attribution reasoning ourselves. The three options therefore differ mainly on **where
the reasoning lives** and **how heavy the substrate is**:

- **Option A — Elastic-Centric Thin App:** push as much as possible into Elastic; our code is a thin
  attribution/enrichment layer. Lightest.
- **Option B — Evidence-Graph Core:** Elastic is the data plane; a dedicated service owns an
  explainable evidence graph + correlation + attribution. Balanced.
- **Option C — Provenance-Graph / Research-Grade:** a full provenance graph in a graph DB with
  ML-assisted reconstruction/attribution. Heaviest.

They are deliberately spread across the effort/complexity axis so the comparison is real, not a rigged
"middle wins." Where A or C would actually be the right call is stated honestly in each section and in
[02](02-recommended-architecture.md).

---

## Option A — Elastic-Centric Thin App

**One-liner:** Elastic does telemetry + detection + correlation + most of the UI (Kibana); our app is a
thin Python service that reads alerts, scores attribution, and writes results back.

| Dimension | Option A |
|---|---|
| **Overall structure** | Elastic (single node) + a thin Python "attribution" service + Kibana as primary UI, with a small custom panel/app for attribution output. |
| **Major components** | Elastic ingest/detection; Python service (alert reader → scorer → result writer); Kibana dashboards. |
| **Data flow** | Telemetry → Elastic → detection rules → alerts index → our service reads alerts → scores → writes an `attribution-*` index → Kibana renders. |
| **Telemetry ingestion** | Elastic Agent/Fleet + integrations (live) or `_bulk` replay of datasets. |
| **Elastic's role** | Maximal: store, search, normalize (ECS), detect, correlate (EQL/ES\|QL), and visualize. |
| **ECS / normalization** | ECS as-is; rely entirely on Elastic integration pipelines. No internal contract. |
| **ATT&CK knowledge layer** | Mostly implicit via rule `threat.*` tags; light use of `mitreattack-python` for lookups. No owned ATT&CK graph. |
| **Detection layer** | Elastic prebuilt rules (free) + optional Sigma→Elastic. Runs inside Elastic. |
| **Evidence extraction** | Thin: an alert ≈ an observation; technique = the rule's tag. Little independent extraction. |
| **Correlation layer** | Elastic EQL sequences + correlation rules; our service does minimal grouping. |
| **Attack-chain representation** | Elastic alert timelines / EQL sequence output; no owned chain model. |
| **Attribution engine** | Thin scorer over alert ATT&CK tags → group match; limited ACH; risk of shallow logic. |
| **Hypothesis representation** | Flat ranked list stored as index docs; competing-hypothesis structure is minimal. |
| **Confidence representation** | Single score per candidate in an index field; two-axis is bolted on, easy to degrade to "arbitrary number." |
| **TI / enrichment** | Call feeds (abuse.ch/OTX) inline; store enrichment on alert docs. |
| **Persistence** | Elastic indices only. |
| **API / backend** | Thin; may lean on Kibana's APIs + a small FastAPI. |
| **Frontend boundary** | Mostly Kibana; minimal custom UI. |
| **Graph / visualization** | Kibana viz + (paid) Graph; no first-class evidence graph. |
| **Testing** | Hard — logic partly lives in Elastic rules/queries; fewer pure units. |
| **Reproducibility** | Weak — depends on live stack + rule versions + index state. |
| **Deployment complexity** | Low (one Elastic + one small service). |
| **Development complexity** | Low. |
| **Major risks** | **Re-creates the previous version's failure mode: a thin UI over someone else's engine.** Attribution is shallow; explainability constrained; reproducibility poor. |
| **Unnecessarily reinvented** | Almost nothing — which is precisely the problem: it also builds almost none of the differentiator. |

**When A is actually the right call:** if the top priority were the fastest possible demo, or if the
project's thesis were "operate Elastic well" rather than "explainable attribution." Neither matches
[CLAUDE.md](../../CLAUDE.md).

---

## Option B — Evidence-Graph Core  *(carried forward as the recommendation)*

**One-liner:** Elastic is the telemetry/detection **data plane**; a dedicated **Attribution Engine**
service owns an explainable, provenance-first **evidence graph** that fuses pinned ATT&CK knowledge with
extracted observations, then runs deterministic correlation, attack-chain reconstruction, and ACH-based
attribution with a two-axis confidence methodology.

| Dimension | Option B |
|---|---|
| **Overall structure** | Four clean layers: (1) Elastic data plane, (2) Evidence/Extraction pipeline, (3) Attribution Engine (graph + reasoning), (4) API + purpose-built analyst frontend. Kibana kept for raw telemetry drill-down. |
| **Major components** | Elastic; ATT&CK Knowledge loader (pinned STIX); Observation Extractor; Evidence Graph; Correlation & Attack-Chain builder; Attribution (ACH) engine; Enrichment adapters; API; React frontend. |
| **Data flow** | Telemetry → Elastic → detections → **Observation Extractor** pulls matches as structured Observations → Evidence Graph → Correlation/Chain → Attribution → results (with provenance) → API → frontend. |
| **Telemetry ingestion** | Elastic Agent/integrations (live lab) **and** dataset replay (`_bulk`) — same downstream path, which is what makes it reproducible. |
| **Elastic's role** | Data plane only: ingest, ECS normalization, search, and detection (free tier). **Not** our attribution engine. |
| **ECS / normalization** | ECS is the external contract; an **internal thin mapping boundary** converts ECS→our domain objects, leaving room for OTel/OCSF later. |
| **ATT&CK knowledge layer** | **Owned**: pinned `attack-stix-data` (versioned) loaded via `mitreattack-python` into the evidence graph as first-class nodes/edges (tactics, techniques, sub-techniques, software, groups, campaigns, relationships). |
| **Detection layer** | Elastic prebuilt rules + Sigma (license split); each rule match becomes a provenance-carrying Observation→Technique assertion. Detection stays in Elastic; **interpretation** is ours. |
| **Evidence extraction** | First-class: Observations with source event IDs, matched fields, rule id, and a weighted `supports`/`contradicts` link to an ATT&CK technique. |
| **Correlation layer** | Deterministic: link observations by shared entity (host/user/process) + time window; consume Elastic EQL sequence output as *input signal*, not as the final chain. |
| **Attack-chain representation** | Owned graph object: observations ordered by ATT&CK **tactic / kill-chain phase**, edges annotated with *why* (shared entity/time), rendered as a timeline + subgraph. |
| **Attribution engine** | **The differentiator**: behavioral feature vector over techniques → candidate groups via **discriminating-technique weighting** → **ACH** matrix of supporting/contradicting evidence → ranked competing hypotheses. Deterministic; ML optional and interpretable later. |
| **Hypothesis representation** | Explicit `Hypothesis` objects (one per candidate actor/campaign) each holding supporting evidence, contradicting evidence, coverage/visibility notes, and provenance. |
| **Confidence representation** | **Two axes** (ICD-203): *likelihood* (WEP scale) + *confidence* (basis strength), computed from documented inputs, serialized to STIX 2.1 `confidence` only at the boundary. Never a lone number. |
| **TI / enrichment** | Pluggable, cached adapters (abuse.ch/OTX/CISA KEV; optionally Cortex/MISP later). Enrichment is *corroborating/contradicting* evidence, never decisive. |
| **Persistence** | Elastic (telemetry/alerts) + an **Attribution Store** holding the evidence graph and results as **reproducible, version-stamped artifacts** (start: on-disk JSON/JSONL + SQLite/DuckDB index + in-memory graph; port left for a graph DB). |
| **API / backend** | FastAPI (or similar) exposing investigations, evidence graph, chains, and attribution results — read models the frontend renders. |
| **Frontend boundary** | Purpose-built analyst UI renders results + provenance; **never computes attribution**. Deep-links to Kibana for raw telemetry. |
| **Graph / visualization** | Evidence graph view, ACH matrix, tactic-ordered attack-chain timeline, two-axis confidence panel, "next-evidence" suggestions. |
| **Testing** | Strong: pure-logic units for scoring/chain; golden-corpus integration tests (labeled datasets → expected techniques); scenario tests (CALDERA/Atomic → expected chain + ranking); determinism + calibration harness. |
| **Reproducibility** | Strong: pinned ATT&CK version + content-hashed input datasets + a per-result **provenance manifest**; offline replay path independent of live-stack state. |
| **Deployment complexity** | Moderate: Elastic (Docker) + our service + frontend; graph DB deferred. |
| **Development complexity** | Moderate but **bounded and modular** (build only layers 2–4; layer 1 is off-the-shelf). |
| **Major risks** | Scope creep into a full SIEM; edge/dependency explosion in the graph; getting discriminating-weight scoring calibrated. All are manageable and called out in [05](05-architecture-open-questions.md). |
| **Unnecessarily reinvented** | None if disciplined: storage/search/detection = Elastic; ATT&CK KB = MITRE; conversion = pySigma. We build **only** extraction + graph reasoning + attribution — exactly the differentiator. |

**When B is the right call:** when the goal is a technically credible, explainable attribution system that a
reviewer can trust and reproduce — i.e., this project.

---

## Option C — Provenance-Graph / Research-Grade

**One-liner:** Ingest raw host/network **provenance**, build a full provenance graph in a dedicated graph
database, reconstruct attack chains with research techniques (tactic-transition probabilities / graph
learning), and attribute with ML plus post-hoc explanation.

| Dimension | Option C |
|---|---|
| **Overall structure** | Graph DB (Neo4j/Memgraph) as center of gravity; Elastic is one store among several; provenance ingestion + ML pipelines around the graph. |
| **Major components** | Provenance collectors (Sysmon/eBPF/DARPA-style data); graph DB; provenance-graph builder; ML chain-reconstruction; ML attribution + LIME/SHAP; Elastic; custom UI. |
| **Data flow** | Raw provenance → graph DB → graph construction/pruning → ML detection/reconstruction → ML attribution → explanations → UI. |
| **Telemetry ingestion** | High-volume provenance (process/file/network lineage); much larger than B. |
| **Elastic's role** | Peripheral: maybe search/log store; not central. Weakens the "Elastic is core" principle. |
| **ECS / normalization** | Provenance schema-centric; ECS secondary. |
| **ATT&CK knowledge layer** | Owned graph, as in B, but embedded in a larger provenance graph. |
| **Detection layer** | Graph/ML anomaly + TTP tagging over provenance; less reliance on Sigma/Elastic rules. |
| **Evidence extraction** | Rich (provenance lineage) but noisy; heavy pruning needed. |
| **Correlation layer** | Best-in-class: native provenance causality. |
| **Attack-chain representation** | Strongest: causal provenance paths, tactic-transition scoring. |
| **Attribution engine** | ML classifiers over TTP/graph features + LIME/SHAP explanations. |
| **Hypothesis representation** | Possible, but ML ranking is less naturally hypothesis-structured than ACH. |
| **Confidence representation** | Model probabilities + post-hoc explanation — **explainability is weaker/derivative** than B's deterministic ACH. |
| **TI / enrichment** | As B, plus graph-native infrastructure pivoting. |
| **Persistence** | Graph DB (server) + Elastic + model artifacts. |
| **API / backend** | Heavier; must serve graph + model outputs. |
| **Frontend boundary** | Custom UI, but energy is consumed by backend/ML. |
| **Graph / visualization** | Excellent graph views; the graph DB shines here. |
| **Testing** | Harder: ML is non-deterministic; provenance datasets are large; calibration is a research task. |
| **Reproducibility** | Weak-moderate: model training/data drift; large data; harder to pin. |
| **Deployment complexity** | High: graph DB cluster + provenance pipeline + ML runtime. |
| **Development complexity** | High: closest to a research thesis; real risk of never finishing the differentiator. |
| **Major risks** | Over-scope for a personal project; **ML opacity conflicts with the explainability principle**; multi-host provenance is an open research problem. |
| **Unnecessarily reinvented** | Risks reinventing provenance capture (Sysmon/eBPF exist), a graph DB, and Elastic-side correlation; heavy ML infra. |

**When C is the right call:** if this were a funded research thesis with compute, time, and a tolerance for
ML opacity. It is the highest-ceiling option but the poorest fit for a *disciplined, explainable, finishable*
personal portfolio project.

---

## Comparison against the 14 review criteria

Ratings: **●●● Strong · ●●○ Moderate · ●○○ Weak.** Justifications are per-cell-brief; fuller reasoning is
in each option above.

| # | Criterion | A (Elastic-Centric) | B (Evidence-Graph Core) | C (Provenance/ML) |
|---|---|:--:|:--:|:--:|
| 1 | Cybersecurity correctness | ●●○ leans on Elastic; own logic thin | **●●●** deterministic, tested, authoritative sources | ●●○ strong but ML harder to guarantee |
| 2 | Evidence traceability | ●●○ alert-level only | **●●●** provenance-first graph, every link inspectable | ●●○ provenance rich, ML step less traceable |
| 3 | Attribution explainability | ●○○ constrained/opaque risk | **●●●** ACH + two-axis, first-class | ●●○ post-hoc (LIME/SHAP), derivative |
| 4 | Elastic integration | **●●●** maximal | ●●● data plane (clean) | ●●○ peripheral |
| 5 | MITRE ATT&CK integration | ●●○ via tags | **●●●** owned pinned STIX graph | ●●● owned graph |
| 6 | Handle realistic telemetry | ●●● Elastic-native | ●●● Elastic + replay | ●●● (even overkill volumes) |
| 7 | Correlation & attack-chain | ●●○ EQL only | ●●● owned deterministic chains | **●●●** provenance-best |
| 8 | APT attribution capability | ●○○ shallow | **●●●** the differentiator | ●●○ high ceiling, risky to land |
| 9 | Reproducibility | ●○○ live-stack dependent | **●●●** pinned versions + replay + manifests | ●○○ ML/data drift |
| 10 | Testability | ●●○ logic in Elastic | **●●●** pure logic + golden corpus | ●●○ ML non-determinism |
| 11 | Maintainability | ●●● least code | ●●○ modular, bounded | ●○○ most code + infra + ML |
| 12 | Demonstrates technical depth | ●○○ looks like a SIEM UI | ●●● genuine engine | **●●●** highest ceiling |
| 13 | Reasonable complexity (personal) | **●●●** lowest | ●●○ bounded | ●○○ over-scoped |
| 14 | Exceptional analyst frontend | ●●○ Kibana-bound | ●●● purpose-built + Kibana drill-down | ●●○ energy goes to backend |

**Reading the table honestly:** A wins **complexity/maintainability/Elastic-integration**; C wins **raw
depth and attack-chain**. **B wins the criteria that encode this project's actual thesis** — correctness,
traceability, explainability, MITRE integration, attribution, reproducibility, testability, and the
depth-vs-complexity balance — while remaining finishable and producing a strong analyst frontend. That is
why B is carried forward in [02](02-recommended-architecture.md).

## What all three must not reinvent (from the research)

Regardless of choice: **storage, search, ECS normalization, and detection execution belong to Elastic**;
**the ATT&CK knowledge base belongs to MITRE (pinned STIX)**; **Sigma→query conversion belongs to
pySigma**; **confidence-scale conversion belongs to `stix2.confidence.scales`**. Our build effort must
concentrate on evidence extraction, the evidence graph, correlation/attack-chain reconstruction, and the
attribution engine — the parts no mature tool provides.
