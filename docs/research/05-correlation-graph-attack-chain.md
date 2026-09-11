# 05 — Correlation, Graph & Attack-Chain Reconstruction

Covers requested areas 13–15: security event correlation, attack-chain reconstruction, graph/network
analysis.

> All verdicts are candidates for architectural review, not decisions.

---

## Summary opinion (design opinion)

This is the **heart of the differentiator** and where most of *our* code should live. Split the problem
into layers, and be deliberate about the Elastic boundary:

1. **Event-level correlation** (which raw events relate): **use Elastic** (EQL sequences, ES|QL,
   correlation rules). Do not reinvent.
2. **Evidence/knowledge graph** (observations ↔ techniques ↔ software ↔ groups ↔ campaigns ↔ IOCs): **build
   our own**, ATT&CK/STIX-shaped, in a property graph. This is our asset.
3. **Attack-chain reconstruction** (ordering observations into kill-chain/tactic-sequenced narratives):
   **build our own**, grounded in the research below and the methodology in [08](08-attribution-methodology-foundations.md).

The recurring research pattern is consistent and reassuring: build a graph over events, tag nodes/edges
with **ATT&CK TTPs**, then reconstruct chains by **tactic/kill-chain ordering** — exactly the shape we want.

---

## What Elastic already gives us (do not rebuild)

- **EQL `sequence`** — ordered, multi-stage patterns across event categories (native attack-chain
  detection at the query level).
- **ES|QL** — pipe-based correlation/aggregation.
- **Correlation rule types + entity risk scoring** — alerts elevate host/user risk; behavior-based rules
  feed scoring.
- **Attack Discovery** — LLM clusters alerts, maps to ATT&CK, suggests an actor.

**Implication:** our correlation layer should **consume Elastic's event correlation output as evidence**
and focus on the *graph reasoning and explainable ordering/attribution* that Elastic does **not** do
deterministically. (Attack Discovery is the opaque baseline we aim to beat on explainability.)

## Graph technology

### Property-graph databases (Neo4j and alternatives)
- **What it does:** Stores nodes/edges with properties; native traversal, pattern-matching (Cypher),
  and graph algorithms (centrality, community detection, pathfinding) — a natural fit for STIX/ATT&CK,
  which MITRE itself designed on **graph principles**.
- **Maturity:** Very high (Neo4j).
- **License (fact):** Neo4j **Community = GPLv3**, **Enterprise = commercial**. Alternatives worth a look:
  **Memgraph**, **ArangoDB**, or a lighter embedded/in-memory graph (e.g., Python **NetworkX** /
  **igraph**) for early phases.
- **Reuse:** Store the ATT&CK relationship graph + our evidence graph; run pathfinding for attack-chain
  candidates and similarity for actor matching.
- **Elastic fit:** Complementary — Elastic for event search/correlation, graph DB for
  relationship reasoning. (Elastic also has a Kibana **Graph** feature, but it is paid-tier and
  aggregation-based, not a full graph store. **(verify tier.)**)
- **Verdict:** **Study/Adapt.** **Design opinion:** start with an **embedded graph library (NetworkX/
  igraph)** over pinned ATT&CK STIX + our evidence, to prove the model with zero infra; graduate to
  **Neo4j/Memgraph** only when scale/queries demand it. Avoid committing to a heavy graph server before the
  reasoning model is validated.
- **Risks:** Neo4j Community GPLv3 (copyleft) and Enterprise cost; premature infra weight.

### STIX-graph tooling
- **STIG (Structured Threat Intelligence Graph, `idaholab/STIG`)** — Neo4j-backed STIX visualization/
  editing. **Study** for how to project STIX into a graph + visualize relationships; not a runtime
  dependency. **(verify license/maintenance.)**
- **OpenCTI** ([04](04-threat-intel-and-ioc.md)) — effectively a productized STIX-2.1 graph; **study its
  schema** as a reference for our own.

## Attack-chain reconstruction — what the research says (Study)

Recent, directly relevant academic work (treat as **method inspiration**, not dependencies):

- **Provenance-graph APT detection/reconstruction** (e.g., *MGDA*, *SLOT*, *T-Trace*, *TGL-APT*, *TPPR*):
  build graphs from logs, tag with ATT&CK TTPs, and reconstruct chains by **tactic/technique ordering and
  transition probabilities**. *SLOT* explicitly stitches scattered nodes into a chain using ATT&CK
  **tactic-phase tags** — the pattern we want.
- **Common challenges to design around:** filtering signal from millions of provenance events;
  correlating across **multiple hosts** (many academic schemes are single-host); avoiding
  over-connection/“dependency explosion.”

**Design opinion:** we do **not** need bleeding-edge provenance ML to be exceptional. A **deterministic,
explainable** reconstruction — order observations by ATT&CK tactic/kill-chain phase, link by shared
entities (host/user/process/time), and expose *why* each edge exists — is more valuable to this project
(and more defensible) than an opaque model. ML ranking can be an *optional, explainable* enhancement later.

## Our correlation/attribution data model (proposed, for review)

```
Event (ECS/OTel)
  └─(matched by rule)→ Observation ──supports(weight,provenance)──▶ Technique (ATT&CK)
Observations ──share entity/time──▶ linked into Attack-Chain (ordered by tactic/kill-chain phase)
Techniques + Software + IOCs ──consistent-with / contradicts──▶ Candidate (Group/Campaign)
Candidate ──scored──▶ Attribution Hypothesis (confidence + explanation, doc 08)
```

Every edge carries **provenance** (source events, rule, matched fields) and a **weight**; contradiction is
a first-class edge type. This is the concrete antidote to the previous version's disconnected/hard-coded
results.

---

## Open questions for architectural review

1. **Embedded graph (NetworkX/igraph) first, or Neo4j/Memgraph from the start?** (Leaning embedded-first.)
2. Where is the **Elastic ↔ graph** boundary drawn — what exactly do we pull out of Elastic as
   "observations," and in what shape?
3. Is attack-chain ordering **purely deterministic** (tactic/kill-chain + entity/time linking) initially,
   with ML ranking deferred and kept explainable?
4. How do we prevent **dependency/edge explosion** so chains stay legible to an analyst?

## Sources

- [Investigate security events — EQL/ES|QL (Elastic docs)](https://www.elastic.co/docs/solutions/security/investigate) ·
  [Attack Discovery (Elastic docs)](https://www.elastic.co/docs/solutions/security/ai/attack-discovery)
- [Neo4j for cybersecurity](https://neo4j.com/blog/cybersecurity-graph-technology-excellent-fit/) ·
  [STIG — Structured Threat Intelligence Graph](https://github.com/idaholab/STIG)
- [MGDA: provenance-graph threat detection & scenario reconstruction](https://www.sciencedirect.com/science/article/pii/S1389128625007728) ·
  [TPPR: TTP-pattern-guided attack-path reasoning](https://arxiv.org/html/2510.22191)
