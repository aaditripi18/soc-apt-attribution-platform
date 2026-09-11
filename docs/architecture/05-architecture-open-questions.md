# 05 — Architecture Open Questions (Decisions for Review)

**Status: PROPOSED leanings — none decided.** These are the decisions to settle before implementation.
Each has: the question, the realistic options, a **proposed lean**, and **what would resolve it**. Ordered
by how much they gate Phase 1.

> **Update (2026-09-11):** [ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md) and its
> companion specs ([06 evidence model](06-evidence-model.md), [07 scoring spec](07-attribution-scoring-spec.md),
> [08 validation & calibration](08-validation-and-calibration.md)) now **resolve Q2 and Q7** (methodology
> level) and **sharpen Q6**. See the per-question notes below. What ADR-0002 leaves open is the *fitted*
> calibration values (need the corpus) and the concrete corpus contents — tracked under Q6.

---

### Q1 — Normalized-event contract & mapping thickness  *(gates Phase 1)*
**Question:** Do we bind to ECS directly, or define our own thin internal event contract mapped from ECS?
**Options:** (a) use ECS field names throughout; (b) thin internal contract with an ECS→domain mapper
(OTel/OCSF-ready).
**Proposed lean:** **(b)** — a *thin* mapping boundary. Keeps us Elastic-native today without hard-coding
ECS everywhere, per audit finding B-2 (schema is a 3-way future).
**Resolves when:** we list the exact fields Phase 1 needs (host/user/process/cmdline/hashes/network) and
confirm the mapper stays ≤ a small, obvious translation, not a second schema.

### Q2 — Attribution scoring specification  *(RESOLVED at methodology level by ADR-0002; PROPOSED)*
**Question:** The exact, versioned formula for discriminating-technique weight, and how inputs feed
**likelihood** vs **confidence** separately.
**Resolution (PROPOSED):** [ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md) +
[07 scoring spec](07-attribution-scoring-spec.md) define: ACH comparison; a single derived weighting
(discriminating power `D` from the pinned Group×Technique matrix, with all seven required properties
specified); two independent axes (likelihood via relative, WEP-banded support separation; confidence via
coverage/quality/corroboration/consistency/contradiction/calibration, bounded by the weakest link); an
"Unattributed" null hypothesis; and an explicit insufficient-evidence decision rule. ML deferred.
**Still open (→ Q6):** the *fitted* `D` shape and decision-rule constants (`τ_separation`, `min_confidence`,
`τ_margin`) require the calibration corpus; they are `calibration_version` parameters, not magic numbers.
**Approve when:** you accept the methodology in ADR-0002/06/07 (worked examples included).

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

### Q6 — Validation & calibration corpus  *(SHARPENED by ADR-0002; gates every "done")*
**Question:** Which labeled datasets form the minimum golden + scenario corpus, and how is calibration
measured?
**Sharpened (PROPOSED):** [08 validation & calibration](08-validation-and-calibration.md) now specifies the
**case types** (positive, negative, common-technique-only, ambiguous, competing-group, incomplete-telemetry,
expected-but-missing, false-flag, alias), the **metrics** (ranking, **abstention**, competing-case,
**calibration reliability diagrams for both axes**, discriminating-evidence, contradiction, explanation
faithfulness, determinism), the **calibration procedure** (fit on a split, freeze a `calibration_version`,
validate held-out, bias toward abstention when thin), and headless testability.
**Still open:** the concrete dataset/case *contents* (which exact Security-Datasets/CALDERA/Atomic scenarios)
— to be written into a `corpus/README` before Phase 1 exit; the fitted calibration values then feed Q2.
**Resolves when:** the concrete case list exists and the first calibration is fit + validated.

### Q7 — Actor aliasing & false-flag modeling  *(RESOLVED at methodology level by ADR-0002 D10; PROPOSED)*
**Question:** How do we represent actor aliases (APT29 = Cozy Bear = …) and deliberate deception?
**Resolution (PROPOSED):** aliases are collapsed to one `Candidate` via the KB alias set during candidate
generation ([07](07-attribution-scoring-spec.md) §3); residual identity ambiguity is carried as
`uncertainty`. Deception is surfaced as an explicit **alternative explanation** with **capped confidence**
whenever easily-planted *evidentiary* artifacts point one way while hard-to-fake *behavioral* evidence points
another ([07](07-attribution-scoring-spec.md) §10; worked Example D). Never a silent mis-attribution.
**Approve when:** you accept ADR-0002 D10.

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
