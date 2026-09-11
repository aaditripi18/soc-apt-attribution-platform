# 05 — Architecture Open Questions (Decisions for Review)

**Status: PROPOSED leanings — none decided.** These are the decisions to settle before implementation.
Each has: the question, the realistic options, a **proposed lean**, and **what would resolve it**. Ordered
by how much they gate Phase 1.

---

### Q1 — Normalized-event contract & mapping thickness  *(gates Phase 1)*
**Question:** Do we bind to ECS directly, or define our own thin internal event contract mapped from ECS?
**Options:** (a) use ECS field names throughout; (b) thin internal contract with an ECS→domain mapper
(OTel/OCSF-ready).
**Proposed lean:** **(b)** — a *thin* mapping boundary. Keeps us Elastic-native today without hard-coding
ECS everywhere, per audit finding B-2 (schema is a 3-way future).
**Resolves when:** we list the exact fields Phase 1 needs (host/user/process/cmdline/hashes/network) and
confirm the mapper stays ≤ a small, obvious translation, not a second schema.

### Q2 — Attribution scoring specification  *(gates Phase 3; spec must exist before code)*
**Question:** The exact, versioned formula for discriminating-technique weight, and how inputs feed
**likelihood** vs **confidence** separately.
**Options:** (a) TF-IDF-style weight over Group×Technique + rule-based confidence; (b) probabilistic model;
(c) ML (deferred — opacity risk).
**Proposed lean:** **(a)**, deterministic and explainable, ML explicitly deferred.
**Resolves when:** a written `attribution-scoring-spec` with worked examples exists and passes review — a
prerequisite deliverable of Phase 3, not an implementation detail.

### Q3 — Graph substrate  *(gates Phase 2, reversible)*
**Question:** Embedded graph (NetworkX/igraph) now, or a graph DB (Neo4j/Kùzu/Memgraph) from the start?
**Options:** (a) embedded + `GraphStore` port; (b) embedded graph DB (Kùzu); (c) Neo4j/Memgraph server.
**Proposed lean:** **(a)** now; revisit when real query patterns (pathfinding, actor-similarity at scale)
demand a DB. Avoids premature infra (research doc 05).
**Resolves when:** Phase 2's actual traversal/query needs are written down and measured against embedded
performance.

### Q4 — Detection-content strategy & conversion  *(gates Phase 1)*
**Question:** Sigma (permissive) vs Elastic prebuilt rules (ELv2, internal) vs both; and pySigma vs
STIX-shifter vs native execution.
**Proposed lean:** **both under a license split** — Elastic prebuilt rules for internal coverage, Sigma via
pySigma for anything redistributable — with conversion behind a boundary and Elastic rules as fallback if
the pySigma ES backend stalls (audit B-4).
**Resolves when:** we confirm Phase-1 golden-corpus techniques are covered by a small rule set and that
conversion fidelity holds on labeled data.

### Q5 — First-milestone telemetry scope  *(gates Phase 1)*
**Question:** Which telemetry domain first?
**Options:** (a) Windows/endpoint (Sysmon/EVTX) — richest labeled data; (b) multi-source from day one;
(c) include network/cloud early.
**Proposed lean:** **(a) Windows/endpoint-first**, scope stated explicitly; broaden only after the
technique-mapping foundation is proven (audit E-7).
**Resolves when:** you confirm endpoint-first is acceptable for the portfolio narrative.

### Q6 — Validation & calibration corpus  *(gates every "done")*
**Question:** Which labeled datasets form the minimum golden + scenario corpus, and how is calibration
measured?
**Proposed lean:** Security-Datasets (MIT) + a few EVTX fixtures (GPL — local only) for technique mapping;
CALDERA/Atomic scenarios for chains + attribution; calibration measured on the scenario set (not just
top-1). 
**Resolves when:** the concrete dataset list + metrics are written into a `corpus/README` before Phase 1
exit.

### Q7 — Actor aliasing & false-flag modeling  *(gates Phase 3)*
**Question:** How do we represent actor aliases (APT29 = Cozy Bear = …) and deliberate deception?
**Proposed lean:** normalize identity via ATT&CK Group aliases; represent false-flag as an explicit
*hypothesis* + *contradicting evidence*, never a silent mis-attribution.
**Resolves when:** the scoring spec (Q2) defines alias handling and a deception hypothesis type.

### Q8 — Attribution store technology  *(gates Phase 1, reversible)*
**Question:** How to persist the evidence graph + results reproducibly?
**Options:** (a) on-disk JSON/JSONL + SQLite/DuckDB index; (b) Postgres; (c) the graph DB from Q3.
**Proposed lean:** **(a)** — the artifact *is* the reproducible record; DB indices are conveniences.
**Resolves when:** result size/query needs are known after Phase 1.

### Q9 — Enrichment scope for v1  *(gates Phase 4)*
**Question:** Which TI sources ship first, and do we reuse Cortex/MISP modules or write thin adapters?
**Proposed lean:** thin cached adapters for abuse.ch + OTX + CISA KEV; Cortex/MISP considered later; all
strictly *corroborating/contradicting*, never decisive.
**Resolves when:** Phase 4 is planned.

### Q10 — Deployment shape  *(gates Phase 0)*
**Question:** Docker Compose single-node Elastic + our service + frontend — confirm scale and OS assumptions.
**Proposed lean:** yes; Windows-friendly Compose; graph DB deferred; no paid Elastic tier.
**Resolves when:** you confirm the local footprint is acceptable.

---

## Still-open `(verify)` items inherited from research (non-blocking, track them)

- `mdecrevoisier/EVTX-to-MITRE-Attack` license; DeTT&CT / CAR / STIX-shifter / Kùzu exact licenses; Splunk
  `attack_data`/BOTS and DARPA TC/OpTC usage terms; per-Elastic-integration license for anything deployed.
  (From [research audit E-6](../research/10-research-audit.md).) Resolve before any redistribution.

## Cross-cutting principle checks (must stay true as decisions land)

- No decision may put an opaque/LLM step on the attribution correctness path.
- No decision may break the provenance chain from result back to raw observation.
- No capability is "done" without passing the corpus (Q6) deterministically.
- No frontend feature may exist without real backend functionality behind it.
