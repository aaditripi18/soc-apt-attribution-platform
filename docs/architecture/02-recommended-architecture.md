# 02 — Recommended Architecture: Evidence-Graph Core (Option B)

**Status: PROPOSED — requires your review before any implementation.** This expands Option B from
[01-architecture-options.md](01-architecture-options.md) into a concrete (still code-free) design. Companion
docs: [03 data flow](03-system-data-flow.md), [04 component boundaries](04-component-boundaries.md),
[05 open questions](05-architecture-open-questions.md), [ADR-0001](adr/0001-evidence-graph-core-architecture.md).

## Why this one wins (summary)

It is the only option that puts *our* effort exactly where the differentiator is — **explainable,
evidence-driven, reproducible attribution** — while reusing mature substrate for everything else. It
directly satisfies the [CLAUDE.md](../../CLAUDE.md) principles: evidence-based (not label-based),
explainable, ATT&CK-modeled, traceable telemetry path, Elastic-as-core, deterministic/testable, and "never
a thin UI on someone else's engine." A and C each violate at least one core principle (A: shallow/opaque
attribution + poor reproducibility; C: ML opacity + over-scope).

## Layered structure

```
┌─────────────────────────────────────────────────────────────────────┐
│ L4  Analyst Frontend (React)  ── renders results + provenance only    │
│     + deep-links to Kibana for raw telemetry                          │
├─────────────────────────────────────────────────────────────────────┤
│ L3  Attribution Engine (our core)                                     │
│     Evidence Graph · Correlation · Attack-Chain · ACH Attribution     │
│     · Confidence (2-axis) · Explanation/Provenance                    │
├─────────────────────────────────────────────────────────────────────┤
│ L2  Evidence Pipeline                                                 │
│     Observation Extractor · ATT&CK Knowledge Loader · Enrichment      │
├─────────────────────────────────────────────────────────────────────┤
│ L1  Data Plane = Elastic (Basic tier)                                 │
│     Ingest · ECS · Search · Detection (Elastic rules + Sigma)         │
└─────────────────────────────────────────────────────────────────────┘
       ▲ authoritative knowledge: pinned MITRE ATT&CK STIX (versioned)
```

Each layer talks only to the one below through a defined contract, so any layer can be tested in isolation
and Elastic can be swapped for replayed data without touching L2–L4.

## The domain model (the heart of the system)

A single **evidence graph** holds both authoritative knowledge and case-specific evidence. Every derived
node stores the IDs of the inputs it was derived from — that back-reference chain is how *every* conclusion
retains provenance to raw observations.

**Knowledge nodes (from pinned ATT&CK STIX — immutable per version):**
`Tactic, Technique, SubTechnique, Software, Group, Campaign`, joined by ATT&CK `relationship` edges
(`group uses technique`, `group uses software`, `campaign attributed-to group`, …).

**Case nodes (produced during an investigation):**

| Node | Holds | Provenance back-reference |
|---|---|---|
| `Event` | a normalized ECS event (or its id in Elastic) | Elastic `_index/_id` |
| `Observation` | a detection match: rule id, matched fields, entities (host/user/process), timestamp | → `Event` ids |
| `TechniqueAssertion` | edge `Observation --supports(weight)--> Technique` + *why* (rule + fields) | → `Observation`, → `Technique` |
| `BehavioralFeature` | the case's technique/tactic feature vector (with weights) | → `TechniqueAssertion` set |
| `AttackChain` | observations ordered by tactic/kill-chain phase; edges = shared entity/time | → `Observation` ids + link reasons |
| `Candidate` | a Group/Campaign under consideration | → `Group`/`Campaign` |
| `EvidenceLink` | `Candidate <--supports / contradicts(weight, source-grade)--> Evidence` | → `TechniqueAssertion`/IOC/enrichment |
| `Hypothesis` | one candidate's case: supporting + contradicting evidence, coverage note | → `EvidenceLink` set |
| `AttributionResult` | ranked hypotheses + two-axis confidence + next-evidence + manifest | → everything above |

Contradiction is a **first-class edge type**, not an absence of support — this is what makes ACH possible
and prevents "points for the favorite" scoring.

## The attribution pipeline (exactly the flow you asked for)

Each arrow is a pure, testable transform; each output object references its inputs (provenance preserved
end-to-end):

```
observable evidence        L1/L2  Elastic detection match → Observation (event ids, fields, entities)
   → ATT&CK techniques     L2/L3  Observation --supports(weight)--> Technique   (TechniqueAssertion)
   → behavioral features   L3     technique/tactic vector, weighted by discriminating power
   → candidate groups      L3     features → Groups via ATT&CK "uses" + discriminating-technique weighting
   → supporting/contra.    L3     per candidate, gather EvidenceLinks (supports AND contradicts)
   → competing hypotheses  L3     ACH matrix: evidence × hypotheses; disconfirming evidence emphasized
   → likelihood/confidence L3     two-axis: WEP likelihood + basis-strength confidence (ICD-203)
   → explainable result    L3/L4  ranked hypotheses, each fully traceable to source observations
```

**Discriminating-technique weighting (proposed method, to be spec'd + validated):** weight each technique
by how *actor-characteristic* it is across the ATT&CK Group×Technique matrix (a TF-IDF-style score:
techniques used by few groups discriminate strongly; ubiquitous ones barely count). Deterministic,
explainable, and computed from the pinned ATT&CK version. This is the concrete antidote to over-attribution
on common techniques (audit finding B-5).

## Confidence representation (never a single number)

Every `AttributionResult` carries, **per hypothesis**:

- **Likelihood** — Words-of-Estimative-Probability band (e.g., "likely, 55–80%"), derived from
  discriminating-weight overlap between case features and the candidate.
- **Confidence** — separate basis-strength grade (high/moderate/low), derived from *how much and how good*
  the evidence is: number of discriminating techniques, telemetry **visibility/coverage** (DeTT&CT-style),
  source grades (Admiralty) of any enrichment, and the weight of *contradicting* evidence.
- **Supporting evidence** and **contradicting evidence** lists (each item links to its observations).
- **Residual uncertainty** + **next-evidence suggestion** (which observation would most change the ranking).
- **STIX serialization** at the boundary via `stix2.confidence.scales`, documented so likelihood/confidence
  are not silently collapsed into one integer.

## Proposed module layout (names illustrative; not code yet)

A modular monorepo — each module independently testable, matching principle 13:

- `dataplane/` — Elastic client + `_bulk` replay loader (thin; no reasoning).
- `attack_knowledge/` — pinned STIX loader (`mitreattack-python`), Group×Technique matrix,
  discriminating-weight computation.
- `extraction/` — detection-match → `Observation` → `TechniqueAssertion` (ECS→domain mapping boundary).
- `graph/` — evidence graph store + traversal (embedded first; a `GraphStore` port so a graph DB can drop
  in later).
- `correlation/` — entity/time linking + attack-chain (tactic-ordered) reconstruction.
- `attribution/` — feature vectors, candidate generation, ACH engine, two-axis confidence, explanations.
- `enrichment/` — pluggable cached IOC/TI adapters (evidence only, never decisive).
- `api/` — read-model endpoints (investigations, graph, chains, results).
- `frontend/` — React analyst UI (renders; never computes attribution).
- `corpus/` + `tests/` — labeled datasets, golden/scenario tests, determinism + calibration harness.

## Persistence & reproducibility

- **Elastic** owns telemetry + alerts (the data plane / source of observations).
- **Attribution Store** owns evidence graph + results as **version-stamped, content-addressed artifacts**:
  start with on-disk JSON/JSONL (the reproducible record) + a SQLite/DuckDB index for queries + in-memory
  graph at runtime. A `GraphStore` port keeps Neo4j/Kùzu as a later option, decided by real query needs.
- **Provenance manifest** on every result: pinned ATT&CK version, input dataset content-hash, rule-set
  version, engine version. Re-running the same inputs must produce identical results (determinism test).
- **Offline replay** path (dataset → `_bulk` → same L2–L4 pipeline) makes results reproducible without
  depending on live-stack state — the core guard against the previous version's "hard-coded/simulated"
  failure.

## Testing strategy (a capability is "done" only when it passes)

1. **Unit** — pure functions: discriminating weights, feature vectors, chain ordering, ACH scoring,
   confidence mapping.
2. **Golden corpus** — labeled datasets (Security-Datasets/EVTX) → assert expected `TechniqueAssertion`s.
3. **Scenario** — CALDERA/Atomic multi-step runs → assert expected attack-chain ordering and that the true
   actor ranks appropriately *with a correct explanation*.
4. **Determinism** — same inputs + pinned ATT&CK ⇒ byte-identical results.
5. **Calibration** — over the scenario corpus, "likely/high-confidence" claims are right at the expected
   rate (calibration, not just top-1 accuracy).

## Deployment (personal-scale)

Docker Compose: single-node Elasticsearch + Kibana; our Python service; the React frontend (Vite dev / static
build). Graph DB intentionally **deferred**. Windows-friendly. No paid Elastic tier required (all needed
features are Basic).

## Frontend boundary (principle 10, enforced)

The frontend consumes read-model JSON from our API and **renders**: attack-chain timeline (tactic-ordered),
evidence graph, ACH matrix (hypotheses × evidence, showing contradiction), two-axis confidence panel, and
next-evidence prompts — each element click-through to the underlying observations and out to Kibana for the
raw events. It performs **no** attribution logic; if the backend can't explain it, the UI can't show it.

## Proposed phased implementation (post-approval; still no code yet)

- **Phase 0 — Skeleton & corpus:** repo/module scaffolding, Elastic-in-Docker, pinned ATT&CK load,
  a minimal labeled golden corpus, CI running empty test suites. *Exit:* ATT&CK graph loads reproducibly;
  a dataset replays into Elastic.
- **Phase 1 — Telemetry → Observation → Technique (the foundation the old version lacked):** extraction +
  `TechniqueAssertion` with provenance, validated against the golden corpus. *Exit:* deterministic,
  tested technique mapping on Windows/endpoint data.
- **Phase 2 — Correlation & attack-chain:** entity/time linking + tactic-ordered chains, validated on
  CALDERA/Atomic scenarios. *Exit:* correct chains with inspectable edge reasons.
- **Phase 3 — Attribution (ACH + two-axis confidence):** feature vectors, discriminating weights, competing
  hypotheses, explanations, STIX serialization. *Exit:* ranked, explained, calibrated attribution on the
  scenario corpus.
- **Phase 4 — Enrichment + next-evidence + frontend:** cached TI adapters, coverage/next-evidence, and the
  analyst UI over the now-proven backend.

Each phase follows the CLAUDE.md loop (understand → smallest sound version → test → validate → expand) and
ends at a reviewable checkpoint.

## Primary risks & mitigations (see [05](05-architecture-open-questions.md) for the decisions)

| Risk | Mitigation |
|---|---|
| Scope creep into a full SIEM | Hard boundary: detection/search stays in Elastic; we only interpret. |
| Graph edge/dependency explosion | Entity/time windowing + phase ordering; cap fan-out; keep chains analyst-legible. |
| Over-attribution on common techniques | Discriminating-technique weighting, validated on labeled scenarios before trust. |
| Confidence looking arbitrary | Documented two-axis methodology + calibration harness + STIX serialization. |
| pySigma ES backend stalling | Keep conversion behind a boundary; Elastic prebuilt rules as fallback content. |
| Graph substrate lock-in | `GraphStore` port; embedded first; DB deferred until queries demand it. |
