# 04 — Component Boundaries: Who Provides What

**Status: PROPOSED.** This document answers the boundary question CLAUDE.md and the research emphasize:
for each capability, **who is responsible** — Elastic, MITRE/authoritative sources, a reused OSS component,
or **our own code**. The rule of thumb: *reuse everything that is undifferentiated; build only the
evidence→attribution reasoning that no mature tool provides.*

## The four responsibility zones

- **E = Elastic (data plane).** Ingest, normalize, store, search, run detections.
- **M = MITRE / authoritative external.** ATT&CK knowledge, STIX schema, confidence-scale definitions,
  detection content, TI feeds.
- **R = Reused OSS library.** Thin, well-scoped dependencies we call (not fork).
- **U = Us (the differentiator).** Evidence extraction, evidence graph, correlation/attack-chain,
  attribution reasoning, explanation/provenance, analyst UI.

## Capability → owner matrix

| Capability | Owner | Notes / specific component |
|---|:--:|---|
| Telemetry ingestion (live) | **E** | Elastic Agent + integrations |
| Telemetry ingestion (replay) | **E**+**U** | Elastic `_bulk`; our thin loader picks/pins datasets |
| ECS normalization | **E** | integration pipelines; we consume ECS |
| Normalized-event → domain contract | **U** | thin mapping boundary (keeps OTel/OCSF open) |
| Storage & search of telemetry | **E** | Elasticsearch |
| Detection execution | **E** | Elastic detection engine |
| Detection content (rules) | **M**/**R** | Elastic prebuilt rules (ELv2, internal) + Sigma (DRL) |
| Sigma → Elastic query conversion | **R** | pySigma + ES backend (behind a boundary) |
| ATT&CK knowledge (tactics/techniques/groups/software/campaigns/relationships) | **M** | pinned `attack-stix-data` (versioned) |
| ATT&CK access library | **R** | `mitreattack-python` |
| Discriminating-technique weighting | **U** | computed from the pinned Group×Technique matrix |
| Observation extraction | **U** | detection match → `Observation` (+ provenance) |
| Observation → Technique assertion | **U** | weighted `supports`/`contradicts` with *why* |
| Evidence graph store + traversal | **U** (on **R**) | our model; embedded graph lib now, `GraphStore` port for a DB later |
| Event-level correlation signal | **E** | EQL `sequence` / ES\|QL consumed as input |
| Attack-chain reconstruction (ordering + explanation) | **U** | tactic/kill-chain ordering, entity/time edges |
| Behavioral feature construction | **U** | technique/tactic vectors, weighted |
| Candidate generation | **U** (on **M**) | via ATT&CK `uses` relationships |
| Competing-hypothesis reasoning (ACH) | **U** | supporting + contradicting evidence per candidate |
| Two-axis confidence (likelihood + basis) | **U** | ICD-203-style methodology |
| Confidence-scale serialization | **R** | `stix2.confidence.scales` (STIX 2.1) |
| Coverage / visibility scoring | **U** (model from **M**) | DeTT&CT-style, adapted; not a runtime dep |
| IOC / TI enrichment data | **M** | abuse.ch / OTX / CISA KEV (cached) |
| Enrichment connectors | **U**/**R** | thin adapters now; optionally Cortex/MISP modules later |
| Provenance manifest + determinism | **U** | version stamping, content hashing |
| Read-model API | **U** | FastAPI serving investigations/graph/chains/results |
| Analyst frontend | **U** | React; renders results + provenance only |
| Raw-telemetry investigation UI | **E** | Kibana (deep-linked from our UI) |
| Attribution baseline for comparison | **E** | Elastic Attack Discovery — offline baseline only, never in-path |

## The bright line (what we will NOT build)

- **Not another SIEM.** No custom ingestion pipeline, no custom log store, no custom detection engine —
  Elastic does these on the free tier.
- **Not a re-typed ATT&CK.** ATT&CK is loaded from pinned STIX, never hand-copied (the previous version's
  failure). We *model relationships over* it; we don't recreate it.
- **Not an opaque scorer.** No single black-box number and no LLM on the attribution correctness path.
- **Not a TI platform.** We consume feeds; we don't rebuild MISP/OpenCTI (may *study* their models).

## The bright line (what we MUST build — because nothing mature does it)

The evidence→attribution reasoning as one explainable, deterministic, provenance-preserving pipeline:
**Observation extraction → evidence graph → correlation/attack-chain → ACH competing hypotheses → two-axis
confidence → explained result.** This is the entire justification for the project; everything else exists
to feed it.

## Interface contracts between layers (so each is testable in isolation)

| Boundary | Contract (proposed) | Why it matters |
|---|---|---|
| E → L2 | "detection match" record (rule id, event ids, entities, fields) | lets replay and live look identical downstream |
| M → L2 | pinned ATT&CK STIX bundle (version-stamped) | reproducibility; ground truth for weights |
| L2 → L3 | `Observation` + `TechniqueAssertion` objects with provenance | pure-function testing of reasoning |
| L3 → L4 | read-model JSON (results, graph, chains) — no logic | enforces "frontend renders, never computes" |
| L3 ↔ graph | `GraphStore` port (get/put nodes+edges, traverse) | swap embedded ↔ DB without touching reasoning |

Keeping these contracts explicit is what allows the CLAUDE.md incremental loop: build the smallest sound
version of one layer, test it against the contract, then expand.
