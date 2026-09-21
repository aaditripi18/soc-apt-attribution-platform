# ADR-0004 — Behavioral Sequence Reconstruction (Phase 2, Gate G2.4)

- **Status:** ACCEPTED (2026-09-15)
- **Date:** 2026-09-15 (proposed) · 2026-09-15 (accepted)
- **Deciders:** project owner (accepted after two rounds of pre-acceptance architecture audit)
- **Supersedes / superseded by:** —
- **Related:** [ADR-0001](0001-evidence-graph-core-architecture.md) ·
  [ADR-0002](0002-attribution-scoring-and-evidence-methodology.md) ·
  [ADR-0003](0003-correlation-and-behavioral-chain-layer.md) ·
  [13 Phase-0 implementation plan](../13-phase-0-implementation-plan.md)

> The decisions below (D1–D21) are **ACCEPTED** as of 2026-09-15. This ADR does not reopen, modify, or
> reinterpret any ADR-0003 decision — it **elaborates** the design commitment ADR-0003 already made in its
> own §"BehavioralSequence (deferred to G2.4)" ("recorded here as a design commitment, not implemented by
> this ADR's own gates") into concrete, field-level, implementable contracts and semantics. Everywhere
> ADR-0003 already binds a choice — timestamp-as-primary-ordering-key with `timestamp_precision` carried
> through, a DAG (never a forced flat line), explicit gap markers instead of fabricated bridging across
> missing telemetry, explicit parallel/unordered representation for undeterminable order, no maliciousness
> assertion, `TEMPORAL_PROXIMITY` as a contextual-only dimension within G2.4's own scope (sequenced as G2.4's
> final sub-gate, G2.4.3 — see D20), no ATT&CK-driven reordering — this ADR states that choice as
> **inherited**, not re-decided. Acceptance does **not** start implementation: no G2.4 code may be written
> until gate G2.4.0 formally begins (see §Implementation gates), mirroring exactly how ADR-0003 itself gated
> G2.0's start.
>
> **Acceptance rationale:** this design went through two rounds of pre-acceptance architecture audit before
> acceptance, and both findings are incorporated into the design below, not merely noted alongside it. The
> first audit found that an intermediate draft of D20 silently narrowed `TEMPORAL_PROXIMITY` out of G2.4,
> contradicting ADR-0003's own G2.4 gate text ("introduces `TEMPORAL_PROXIMITY` as a contextual... dimension
> behind a versioned, content-hashed window parameter"); D20 was corrected to keep it within G2.4 as its own
> final sub-gate, G2.4.3, bound by explicit contextual-only, never-edge, never-gap, never-causal invariants —
> narrowing nothing ADR-0003 already decided. The second audit found that the resulting `SequenceParallelGroup`
> (D9), then scoped to immediate PROCESS_LINEAGE siblings only, under-covered ADR-0003's own unqualified
> "nodes whose relative order is not determinable... remain explicitly parallel/unordered" requirement for
> deeper cross-branch pairs (e.g. `A` vs `C` in `P→A, P→B→C`); D9 was widened to a compact branch-partition
> representation — still one object per branch point, never `O(n²)` — with an explicit convergence-safety
> exclusion so a step reachable from more than one branch is never falsely claimed parallel to either. The
> corrected design — never either intermediate draft — is what this acceptance covers: it modifies no
> ADR-0003 decision, introduces no scoring/attribution/ACH/calibration anywhere in this layer (D15/D17),
> keeps `TEMPORAL_PROXIMITY` and the five existing contextual dimensions strictly annotation-only (D10/D20),
> and remains fully provenance-navigable to raw telemetry through the existing G2.0–G2.3 chain (D12). No
> decision is rejected and none is modified by this acceptance beyond the two corrections already made during
> pre-acceptance review.

## Context

Gates G2.0–G2.3 (all checkpointed — `ec07894`, `79e7644`, `14033f1`, `a0583f9`) established a complete,
deterministic, provenance-first correlation layer per ADR-0003:

```
Evidence + Observation → correlate_structurally (G2.1) → StructuralCorrelationResult
                        → contextualize (G2.2)          → ContextualCorrelationResult
                        → replay + persistence (G2.3)   → validated, replayed, persisted CorrelationGroups
```

Every `CorrelationGroup` is a connected component of Evidence joined only through structural links
(`SHARED_OBSERVATION`, `SAME_PROCESS_ENTITY`, `PROCESS_LINEAGE`) — a correct, provenance-complete
de-duplication unit (ADR-0002 D16/CR-1), but an **unordered set**. ADR-0003 itself already named the next
requirement and deliberately deferred it:

> "an ordered view over one `CorrelationGroup`'s members, built only after G2.0–G2.3 land. It must preserve:
> timestamp ordering... branches... gaps... parallel/uncertain ordering... no maliciousness assertion."

**The problem this ADR resolves.** A group's members may legitimately: branch (one parent process, several
children); tie or conflict on timestamp (clock skew, coarse precision, replay/ingestion reordering); and
originate from one single `Observation` interpreted through several `Evidence`/technique mappings at once
(`SHARED_OBSERVATION`). **A flat, timestamp-sorted list is insufficient for all three cases** — it cannot
represent branching without inventing an order between siblings, it cannot represent a tie without inventing
a winner, and if applied naively to `SHARED_OBSERVATION` evidence it would silently create multiple
"sequential" steps out of one single interpreted moment, double-counting exactly what CR-1 already forbids
one layer down. Worse, a flat list built from timestamps alone would routinely present *temporal
precedence* as if it were *causal precedence* — the single most dangerous failure mode this ADR exists to
make structurally impossible, mirroring exactly why ADR-0003 itself had to correct its own first draft's
host/user misclassification: **an available, reliable signal is not automatically the right semantic
category for it.**

This ADR's job is narrow and specific: define `BehavioralStep`/`BehavioralSequence` and the rules that
build them from an *already-existing, already-validated* `CorrelationGroup`, without adding one bit of new
correlation logic, without touching G2.0–G2.3, and without making any claim beyond what the underlying
structural facts and observed timestamps actually support.

## Decision

Adopt a deterministic, provenance-first, categorically-uncertain behavioral-sequence layer with the
following properties, each elaborated below (D1–D21).

### D1 — Sequence ownership: strictly 1:1 with one CorrelationGroup

A `BehavioralSequence` is built from, and only from, the member evidence/links of **exactly one**
`CorrelationGroup`. This is a permanent invariant, not a default a future gate may loosen without a new ADR:

- **MUST NOT** span multiple `CorrelationGroup`s.
- **MUST NOT** merge two independent groups into one sequence, under any condition.
- **MUST NOT** use any contextual relationship (`SAME_HOST_ID`/`SAME_HOST_NAME`/`SAME_USER_ID`/
  `SAME_USER_NAME`/`SAME_DESTINATION_IP`, or a future `TEMPORAL_PROXIMITY`) to create sequence membership.
- **MUST NOT** bridge two groups because they share a host, user, or destination.
- **MUST NOT** infer a missing cross-group relationship to "complete" a plausible-looking chain.

*Reversibility: low (foundational, directly extends ADR-0003's CorrelationGroup boundary).* A group with no
structural link has no `CorrelationGroup` at all (G2.1's own invariant); by direct consequence, activity
that never formed a group has **no `BehavioralSequence` either** — G2.4 does not retroactively group
anything G2.1/G2.2 did not already group.

### D2 — BehavioralStep: a new, reference-only derived object

A `BehavioralStep` is **not** an `Observation`, **not** an `Evidence`, **not** a `DetectionResult`, and
copies no raw telemetry. It is the smallest new object this ADR introduces, and it exists for exactly one
reason: `SHARED_OBSERVATION` evidence (D4) must collapse to one addressable unit that the sequence's edges
and gaps can reference, which no existing contract can represent alone.

```
BehavioralStep (frozen, value-equal, deterministic identity):
  step_id: str                              # D13
  group_id: str                             # the one CorrelationGroup this step belongs to (D1)
  evidence_ids: tuple[str, ...]              # non-empty, canonicalized sorted-unique
  observation_id: str                        # the single Observation every evidence_id is grounded in
  technique_stix_ids: tuple[str, ...] = ()   # mechanically derived, see below — may be empty
  contextual_annotations: tuple[str, ...] = ()  # see D10 — informational only
  schema_version: str = BEHAVIORAL_STEP_SCHEMA_VERSION   # "behavioral-step/1"
```

**Invariants:**

1. `evidence_ids` is non-empty and canonicalized (sorted-unique) — exactly one entry for every step except a
   `SHARED_OBSERVATION`-collapsed step (D4), which holds every Evidence id sharing that step's Observation.
2. Every id in `evidence_ids` **must** be a member of the originating `CorrelationGroup.member_evidence_ids`
   — a step can never reference Evidence outside the group that owns it.
3. Every id in `evidence_ids` **must** be grounded in exactly `observation_id` — i.e. the real
   `Evidence.provenance.source_observation_ids == (observation_id,)` — reusing G2.1's own fail-closed
   single-Observation check (`_validate_nodes`), not a new or relaxed rule.
4. `technique_stix_ids`, when non-empty, is a **deterministic projection** of the real `attack_ref.stix_id`
   values already present on this step's own Evidence items (sorted-unique) — **never an independent source
   of truth, never asserted, never populated from anything other than the referenced Evidence itself**
   (resolves open question 2: the field is retained, on exactly this condition).
5. `contextual_annotations` is informational only (D10) and **never** consulted by the ordering engine
   (D5–D9) for any purpose — enforced the same way G2.1 never reads `Evidence.attack_ref` (source
   isolation by construction, not merely convention).

### D3 — Representation: an explicit-edge-list DAG

The authoritative structure is:

```
steps:           tuple[BehavioralStep, ...]        # sorted by step_id
edges:           tuple[SequenceEdge, ...]           # directed, sorted by edge_id  (D5–D9)
gaps:            tuple[SequenceGap, ...]            # undirected, sorted by gap_id (D11)
parallel_groups: tuple[SequenceParallelGroup, ...]  # sorted by parallel_group_id (D9)
```

**Rejected representations, explicitly:**

- **A flat, timestamp-ordered list** — cannot represent branching (D9) without inventing an order between
  siblings that no evidence supports, and is exactly the fabrication this ADR exists to forbid.
- **A nested tree object** — process lineage is a tree/DAG only in the *common* case; a data-quality
  anomaly (two differently-sourced Evidence both claiming the same `parent_entity_id`) can legitimately
  produce a step with more than one incoming edge (D9's convergence note) — a strict tree cannot represent
  that without either rejecting valid G2.1 output or silently dropping an edge. A tree also does not
  serialize/persist as cleanly as a flat, id-referencing structure and would require recursive
  construction/traversal logic this project has consistently avoided (G2.0's own `CorrelationGroup` already
  chose ids-not-objects for exactly this reason).
- **A graph-library-specific representation** (e.g. a third-party graph type as the stored shape) — mirrors
  G2.1's own explicit rejection of "a graph framework" in favor of "the minimum correct algorithm"; nothing
  about branching requires more than a flat edge list plus a small acyclicity check (D14).

**Why branching requires an explicit graph, not a list:** a parent with two children is two independent
facts (`Parent→A`, `Parent→B`), not one fact with an implied continuation (`Parent→A→B`). Only a
representation that can hold "A and B are both reachable from Parent, and neither is reachable from the
other" — i.e. a DAG — can state this honestly. A flat list has no way to express "these two are unordered
relative to each other" except by picking an arbitrary position for each, which is precisely a fabricated
claim.

### D4 — SHARED_OBSERVATION collapse (the G2.4 extension of CR-1)

Every Evidence item sharing one literal `Observation` (one `observation_id` — i.e. every Evidence anchored
by a `SHARED_OBSERVATION` structural link) **collapses into exactly one `BehavioralStep`**, holding all of
those Evidence ids in `evidence_ids`. This collapse happens **before** any ordering computation (D5–D9) is
run — it is a step-*construction* rule, not an edge-elimination rule applied afterward.

**Reason:** one telemetry Observation interpreted through several detections/technique mappings is still one
observed event, not several sequential ones (ADR-0003's own words: "not even a relationship between two
events — it is one piece of telemetry interpreted twice"). Treating each mapping as an independent step
would double-count a single observed moment as multiple behaviors — exactly the volume-inflation CR-1 exists
to prevent, now recurring one layer up in the sequence view. Mechanically: step construction first partitions
a group's member Evidence via a `SHARED_OBSERVATION`-only union-find (a narrow, deliberate reuse of G2.1's
union-find *pattern*, scoped to this one link class only — not a general graph algorithm); the resulting
connected components are the steps. No `SequenceEdge`/`SequenceGap` is ever needed *within* one collapsed
step — there is no ordering question between two facts about the same instant.

### D5 — Ordering bases: exactly two, no third "inferred" tier

```
OrderingBasisKind (closed, two values):
  PROCESS_LINEAGE        # directed, from a real PROCESS_LINEAGE CorrelationLink
  TEMPORAL_SAME_ENTITY    # directed, from strict Observation.timestamp comparison within one process entity
```

No other basis exists. In particular there is **no** "inferred ordering" category — anything beyond a direct
`PROCESS_LINEAGE` fact or a direct, strict timestamp comparison within a `SAME_PROCESS_ENTITY` cluster is out
of scope, by design, permanently (not merely "not yet implemented").

**`PROCESS_LINEAGE`:** a real G2.1 `PROCESS_LINEAGE` `CorrelationLink` establishes directed parent→child
ordering. This direction is **authoritative** — it holds even when timestamps disagree (D7). It is never
downgraded to a `SequenceGap`.

**`TEMPORAL_SAME_ENTITY`:** Evidence belonging to the same process entity (`SAME_PROCESS_ENTITY`-linked) may
be ordered using strict `Observation.timestamp` comparison only. This basis means **"observed later within
the same process entity instance,"** not **"caused by the previous action."** Every edge built on this basis
is labeled with this distinction explicitly (via `basis_kind = TEMPORAL_SAME_ENTITY`) so no consumer can
mistake it for a proven causal claim. `SAME_PROCESS_ENTITY`'s own `CorrelationBasis.observation_id_a`/`_b`
fields carry **no** temporal or causal meaning at all (G2.1's own docstring: they are an artifact of
`sorted(..., key=evidence_id)`, never chronology) — ordering here is derived **only** by independently
comparing the real `Observation.timestamp` values, never by reading link-basis field order.

### D6 — Timestamp semantics (deterministic, no arbitrary tie-break)

| Case | Rule |
|---|---|
| Strictly earlier timestamp | Edge `earlier → later`, `basis_kind = TEMPORAL_SAME_ENTITY` |
| Strictly later timestamp | (symmetric — same rule, opposite endpoints) |
| Equal timestamps | **No edge.** `SequenceGap(reason=GapReason.EQUAL_TIMESTAMPS)` |
| Coarse precision (one/both `TimePrecision` coarser than the other) | Compare after truncating both timestamps to the **less precise** side's granularity; if equal after truncation → `SequenceGap(reason=COARSE_PRECISION_TIE)` |
| Unknown precision (`timestamp_precision is None`) on one side, values genuinely differ | Edge is still asserted (real inequality exists), but `precision_uncertain=True` on the edge — surfaced as a caveat, never silently treated as equally strong as a precisely-timed pair |
| Missing timestamp | `Observation.timestamp` is a **required**, tz-validated field in the current domain contract (`domain/observation.py`) — this case is **currently unreachable**, documented as such. `GapReason.MISSING_TIMESTAMP` is defined for forward-compatibility only; **implementation must not fabricate a fixture that violates the domain contract to exercise it** — it is explicitly out of the G2.4.2 golden corpus for this reason, and its absence there is deliberate, not an oversight |
| Timestamps conflicting with `PROCESS_LINEAGE` | See D7 — lineage wins; disagreement is surfaced, never used to reverse the edge |
| Out-of-order ingestion/replay | Irrelevant by construction: ordering is computed purely from `Observation.timestamp` **values**, never from array/ingestion/replay position (mirrors G2.1's `sorted(nodes, key=...)` discipline exactly) |

**Input array order must never affect the result.** All relations are built into an id-keyed structure and
sorted by id before being returned; group members are processed in canonical (evidence-id-sorted) order.
Two independent replays of the same fixture must therefore always produce byte-identical edges/gaps (D13).

### D7 — PROCESS_LINEAGE vs. timestamp conflict

**`PROCESS_LINEAGE` wins over timestamp disagreement, unconditionally.** Example: parent timestamp `10:05`,
child timestamp `10:04` (clock skew, coarse precision, or an ingestion artifact). The sequence still contains
`Parent → Child`, because the OS-asserted causal-creation fact is stronger evidence of order than any
timestamp, which can be skewed, coarse, or (hypothetically, per D6) absent. The disagreement is recorded as
`timestamp_agreement = false` (or the exact equivalent field name chosen at implementation time) on the
edge's `OrderingBasis` — **it is documented as a disagreement between two evidence properties, never
described as "resolved."** No edge is ever reversed or dropped because of a timestamp conflict.

### D8 — SAME_PROCESS_ENTITY ordering: minimal (Hasse-reduced) edges only

For three or more `TEMPORAL_SAME_ENTITY`-ordered steps of one process entity, e.g. `A < B < C` by strict
timestamp, G2.4 emits only the **consecutive** edges:

```
A → B
B → C
```

and **not** the transitively-implied `A → C`, unless `A → C` is independently grounded by its own direct
structural relation (which, for `SAME_PROCESS_ENTITY`, cannot happen — every pair already has its own
pairwise `CorrelationLink`, but the *edge* emitted between non-adjacent steps in the resolved order is still
withheld). **Reason:** emitting the full transitive closure would (a) bloat the representation
proportionally to `O(n²)` instead of `O(n)`, (b) force every consumer to de-duplicate redundant edges before
computing reachability, and (c) risk implying that the *direct* A→C relationship is itself a proven fact of
the same strength as A→B, when it is only a *derived* consequence of two weaker facts chained together. A
consumer needing "did A happen before C" computes DAG reachability; it is not pre-materialized here.

### D9 — Branching: no arbitrary linearization

```
Parent
 ├── Child A
 └── Child B
```

becomes exactly:

```
Parent → Child A
Parent → Child B
```

**There must not be** `Parent → Child A → Child B` unless an independent structural/ordering basis
genuinely supports `A → B` (e.g. — hypothetically — A and B also happen to be `SAME_PROCESS_ENTITY`-linked
to each other with distinct timestamps, an entirely separate fact from their shared parentage). Absent such
a fact, no `SequenceEdge` and no `SequenceGap` exists between A and B — and their relative order is **not**
left to be inferred from silence.

**`SequenceParallelGroup` — the explicit representation of cross-branch parallelism.** Auditing this decision
against ADR-0003's literal, **unqualified** requirement that undeterminable order "remain explicitly
parallel/unordered rather than an invented sequence" — tested against concrete multi-level DAGs, not only the
single-level `Parent→A`/`Parent→B` example — found that an *immediate-children-only* group under-covers the
requirement: in `P→A, P→B→C`, A and C are just as order-undeterminable as A and B (neither reachable from the
other), yet only the `{A,B}` pair was materialized. That is an arbitrary line ADR-0003's text does not draw.
G2.4 therefore represents an entire divergence — not just its first level — as **one compact object per
branch point**, a **branch partition**, still **not a per-pair marker** (which would be `O(n²)` over all
mutually-unreachable step pairs, exactly the kind of unnecessary new abstraction this ADR avoids):

```
SequenceParallelGroup (frozen, deterministic identity):
  parallel_group_id: str                    # D13 — compute_sequence_parallel_group_id(source_step_id, branches)
  source_step_id: str                        # the shared PROCESS_LINEAGE branch point (e.g. "Parent")
  branches: tuple[tuple[str, ...], ...]      # >=2 branches; each inner tuple = one branch's exclusive
                                               # descendant step_ids, root-first, sorted-unique within the tuple
  schema_version: str = SEQUENCE_PARALLEL_GROUP_SCHEMA_VERSION   # "sequence-parallel-group/1"
```

**Scope:** a `SequenceParallelGroup` exists for every step `P` with **two or more** direct `PROCESS_LINEAGE`
children `c1, c2, ..., ck`. `branches` has exactly `k` inner tuples, one per `ci`. Branch `i`'s tuple is `ci`
itself plus every step reachable from `ci` via `edges` that is **not** also reachable from any other `cj`
(`j != i`) — i.e. each branch's *exclusive* descendant set. **Semantics:** any two steps drawn from
*different* inner tuples are explicitly parallel/unordered; two steps in the *same* tuple are not asserted
parallel by this object — their order, if any, is whatever `SequenceEdge`/`SequenceGap` already connects
them elsewhere in the sequence (unchanged).

**Convergence safety, not a convergence feature.** A step reachable from **more than one** of `P`'s children
(the same data-quality anomaly D9's Convergence note already discusses — two differently-sourced Evidence
items both declaring the same `parent_entity_id`) is **excluded from every branch's tuple**. It is therefore
never falsely claimed parallel to either branch's members. This is a safety exclusion, not new convergence
*handling*: `SequenceParallelGroup` still asserts nothing about how a converging step relates to the
branches that feed it — that remains exactly as out of scope as before (resolves open question 4,
unchanged).

**Grounding — a chain, not always a single hop.** `SequenceParallelGroup` needs **no separate
`grounding_link_id` of its own**: it asserts no order and no causal relationship, only that no order was
found, so it has nothing that a `CorrelationLink` could ground the way `SequenceEdge`/`SequenceGap` are
grounded. Each branch's own members remain individually, transitively traceable through the *existing* edge
chain that put them in this sequence at all: a branch root `ci` is grounded directly through its own
`SequenceEdge.basis.grounding_link_id` (one hop, `P → ci`); a deeper branch member (e.g. `C` in `P→B→C`) is
grounded through the **chain** of `SequenceEdge`s connecting it back to its branch root (`B → C`, then
`P → B`), each link in that chain independently grounded in its own `basis.grounding_link_id` — not one
direct edge from `P`. A second, redundant grounding reference on `SequenceParallelGroup` itself would
duplicate provenance already fully present, one or more hops down, in `edges`.

**Invariants:** at least two branches; each branch tuple non-empty, sorted-unique; a step appears in **at
most one** branch tuple of a given `SequenceParallelGroup` (never zero-or-more of *the same* group's several
branches — the convergence exclusion above is what keeps a multi-reachable step out of all of them); no two
steps drawn from the *same* branch tuple may be asserted parallel by this object (their relation, if any,
already exists as an edge/gap elsewhere); no step named in any branch tuple may also be directly connected,
by a `SequenceEdge` or `SequenceGap`, to a step in a *different* tuple of the same group (if it were, the two
would not be "unordered" — checked at construction, mirroring `CorrelationGroup`'s own structural/contextual
disjointness check).

**How `SequenceParallelGroup` differs from `SequenceEdge`, `SequenceGap`, and the absence of any relation —
made unambiguous, with no overlap:**

| | Requires a direct structural link between the pair? | Represents |
|---|---|---|
| `SequenceEdge` | yes | an **established order** between two specific steps |
| `SequenceGap` | yes | a **direct** structural relationship whose order **cannot be resolved** |
| `SequenceParallelGroup` | no (members of different branches share only an indirect, common branch-point ancestor) | steps in **distinct branches** of one divergence have **no determinable relative order**, explicitly represented as parallel/unordered |
| no relation object | n/a | **no structural or epistemic relationship has been established at all** — e.g. two steps in entirely different `BehavioralSequence`s (different `CorrelationGroup`s), or a converging step relative to the branches that feed it (excluded above, by design, not by omission) |

These four categories are exhaustive and mutually exclusive for any two steps within one `BehavioralSequence`
(a converging step's relation to its own feeding branches is the one deliberate, explicitly-scoped exception
in the fourth row — not an ambiguity, a named non-goal, per D9's Convergence paragraph below).

**Convergence** (a step with more than one incoming edge — e.g. two differently-sourced Evidence items both
declaring the same `parent_entity_id` for one child, a data-quality edge case G2.1 does not forbid) is
**structurally supported** by this representation for free — a flat directed edge list is already a general
DAG, not restricted to a single-parent tree — but **G2.4 introduces no special "convergence" inference
feature** (no merge-point detection, no dedicated UI/consumer affordance, and no `SequenceParallelGroup`
entry for converging *parents* relative to each other — that is a distinct concept from diverging *children*
and is not addressed by this object; the convergence-safety exclusion above only prevents a *false* parallel
claim, it does not assert anything new). If the underlying G2.1 links happen to produce a multi-parent step,
the DAG already represents it correctly; making that legible to a future consumer is explicitly out of scope
for this gate (resolves open question 4).

### D10 — Contextual boundary (permanent invariant)

`SAME_HOST_ID`, `SAME_HOST_NAME`, `SAME_USER_ID`, `SAME_USER_NAME`, and `SAME_DESTINATION_IP` **can never
create a `SequenceEdge` or a `SequenceGap`, under any condition.** They may only populate a step's
`contextual_annotations` (D2) — the subset of the originating group's own `contextual_link_ids` that touch
that step's `evidence_ids`, exactly mirroring how G2.2 attaches contextual links to a `CorrelationGroup`
without ever letting them form or merge one.

**This invariant is explicitly reserved, in advance, for the `TEMPORAL_PROXIMITY` dimension G2.4.3 will
add.** `TEMPORAL_PROXIMITY` is in scope for G2.4 overall (D20) but **not implemented until its own sub-gate,
G2.4.3** — from the moment it exists it is bound by this exact same rule: despite its name, it describes
closeness in time (a contextual, environment/coincidence-shaped fact), not instance-identity or causation,
so it is annotation only, never an ordering input, exactly like the five contextual dimensions already in
scope. Recording this now, before the dimension is implemented, is deliberate — it closes off the failure
mode ADR-0003 itself had to correct once already (a reliable-looking signal being promoted to a
group/order-forming role it does not semantically earn).

### D11 — SequenceGap

A `SequenceGap` represents **two steps that have an existing, direct structural relationship, but whose
relative order cannot be honestly resolved** from the available evidence.

```
SequenceGap (frozen, deterministic identity, undirected):
  gap_id: str                # D13 — canonicalized over the sorted (step_id_a, step_id_b) pair
  step_id_a: str              # canonicalized sorted order (mirrors CorrelationLink.anchor_a/b)
  step_id_b: str
  grounding_link_id: str      # the real, structural CorrelationLink this gap is built from
  reason: GapReason           # EQUAL_TIMESTAMPS | COARSE_PRECISION_TIE | MISSING_TIMESTAMP
  schema_version: str = SEQUENCE_GAP_SCHEMA_VERSION   # "sequence-gap/1"
```

**Formal rule (resolves open question 3):** a `SequenceGap` exists **if and only if** two steps' evidence is
connected by a real structural `CorrelationLink` (necessarily `SAME_PROCESS_ENTITY`, since `PROCESS_LINEAGE`
always resolves to an edge per D7, and `SHARED_OBSERVATION`-linked evidence never reaches this stage at all,
having already collapsed into one step per D4) **and** the timestamp comparison for that pair falls into one
of D6's gap-producing cases. Every `SequenceGap` **must** cite `grounding_link_id` — it is never constructed
without a specific, real, structural link backing it.

**If no direct structural link exists between two steps, there is no G2.4 relationship to represent at
all** — not an edge, not a gap. **Silence is preferable to fabricated bridging.** This is the same rule
that keeps two structurally-unrelated `CorrelationGroup`s from ever being merged (D1) applied one level down,
inside a single group, between two steps that merely "look related" without a direct structural fact
connecting them.

### D12 — Provenance

`BehavioralSequence.provenance` reuses G2.0's existing `CorrelationProvenance` contract **unchanged** — no
new provenance hierarchy is invented (the same reuse discipline G2.1 and G2.2 already followed for their own
links/groups). Every `SequenceEdge`/`SequenceGap` additionally carries `grounding_link_id`, extending the
existing chain exactly one hop further and keeping it fully navigable end to end:

```
raw telemetry
  → Observation
    → Evidence
      → CorrelationLink (structural)
        → CorrelationGroup
          → BehavioralSequence (group_id)
            → BehavioralStep (evidence_ids, observation_id)
            → SequenceEdge / SequenceGap (basis.grounding_link_id → back to the exact CorrelationLink)
```

No edge or gap is ever free-floating: `grounding_link_id` **must** be present in the originating
`CorrelationGroup.structural_link_ids` (checked at construction — defense in depth, mirroring
`build_correlation_group`'s own re-verification that a claimed structural link really is one).

### D13 — Deterministic identity

All ids are composed using the **existing G2.0 SHA-256/collision-safe convention**
(`compute_link_id`/`compute_group_id`'s own `_sha256_hex` + `"::"`-join-of-hashed-components pattern) —
**never** a naive free-text delimiter concatenation, which is exactly the defect class G2.0 already found
and fixed once (real ids routinely contain `"::"` themselves) and must not be reintroduced here.

- `step_id = compute_step_id(group_id, sorted(evidence_ids))`
- `sequence_id = compute_sequence_id(group_id, sorted(step_id, ...), method_content_hash)`
- `edge_id = compute_sequence_edge_id(from_step_id, to_step_id, basis_kind, grounding_link_id)` — **not**
  canonicalized/sorted, because direction *is* the fact being identified: a hypothetical `A→B` and `B→A`
  must never collide or be treated as the same relation, unlike `CorrelationLink.anchor_a/b`'s deliberate
  symmetry.
- `gap_id = compute_sequence_gap_id(sorted(step_id_a, step_id_b), reason, grounding_link_id)` —
  canonicalized sorted (undirected, mirrors `CorrelationLink.anchor_a/b` exactly, since a gap asserts no
  direction).

### D14 — DAG invariant (acyclicity)

The graph formed by a `BehavioralSequence`'s `edges` **must** be acyclic. The construction engine **must
validate this constructively** (e.g. a cycle-detection pass over the built edge set) rather than assuming it
follows automatically from the ordering rules above. **A detected cycle fails closed** — the engine raises
rather than silently persisting an inconsistent sequence. (A cycle should be topologically impossible given
D5–D9's rules — a `PROCESS_LINEAGE` edge only ever points from an established parent to its child, and
`TEMPORAL_SAME_ENTITY` edges only ever point from a strictly earlier timestamp to a strictly later one, so
no construction path can produce a back-edge — but the check is retained anyway as defense-in-depth against
future rule changes or an unanticipated data anomaly, mirroring this project's consistent "validate, don't
assume" discipline, e.g. `CorrelationGroup.__post_init__`'s own re-verification of invariants a caller could
in principle have already guaranteed.)

### D15 — Uncertainty: categorical only, no numbers

G2.4 uses **categorical epistemic semantics exclusively.** No field anywhere in this layer is a numeric
confidence, likelihood, score, or weight — carried forward unchanged from ADR-0003 D3/D10 and directly from
ADR-0001 D7/ADR-0002 D2, which reserve the two-axis likelihood/confidence model for the future attribution
layer alone. The distinctions this ADR requires are fully captured by existing or newly-introduced closed
enums, never a float:

| Requested distinction | G2.4 representation |
|---|---|
| directly observed | the raw `Observation.timestamp` / `ProcessRef.parent_entity_id` facts (already-existing G0.3/G1.0 provenance, unchanged) |
| lineage-supported | `SequenceEdge` with `basis_kind = PROCESS_LINEAGE` |
| temporally ordered | `SequenceEdge` with `basis_kind = TEMPORAL_SAME_ENTITY` |
| ambiguous ordering | `SequenceGap` (with its `GapReason`) |
| incomplete sequence | absence of any relation between two non-directly-linked steps — no separate flag needed, the DAG shape represents it natively |

### D16 — ATT&CK boundary

`BehavioralStep.technique_stix_ids` may expose mechanically-derived technique identifiers **only** when
backed by real `Evidence.attack_ref` values already present on that step's own evidence (D2, invariant 4).
ATT&CK data **may annotate** a step this way. ATT&CK **must not**: reorder steps; create a `SequenceEdge` or
`SequenceGap`; establish or imply causality; introduce an actor, group, campaign, or software reference;
create an attribution candidate of any kind; or trigger technique-relationship/`uses`-graph traversal of any
kind. No tactic-based ordering exists anywhere in this layer (a direct carry-forward of ADR-0003's own ATT&CK
boundary: annotation happens strictly after structure exists and never reorders or forms it).

### D17 — Attribution boundary

G2.4 produces **behavioral structure only.** It performs no candidate generation, no actor/campaign
identification, no likelihood, no confidence, no ACH reasoning, no calibration, no attribution conclusion of
any kind, and no abstention decision (abstention is itself an attribution-layer concept — "insufficient
evidence for attribution," ADR-0002 D5 — and has no meaning at this layer, which asserts nothing to abstain
*from*). Its output — a `BehavioralSequence` per `CorrelationGroup` — is **input evidence** for the future
attribution layer, exactly as `CorrelationGroup` already is for G2.4 itself: each layer consumes the one
below it and adds structure, never a conclusion.

### D18 — Persistence (design only — not implemented by this ADR)

Future G2.4.2 persistence must **extend G2.3's existing pattern**, not invent a new one: one new index
(schema-version-derived via the existing `_index_name` helper), holding **one document per
`BehavioralSequence`**, with its `steps`/`edges`/`gaps`/`parallel_groups` all embedded within that one
document. No independent top-level index or id space is needed for individual steps/edges/gaps/parallel
groups — none of them has a lifecycle outside their owning sequence (mirroring how `CorrelationBasis` is already "a value object, no independent identity" per
ADR-0003's own domain model). `persist_behavioral_sequence`/`load_behavioral_sequence` would mirror
`persist_correlation_group`/`load_correlation_group` exactly: the existing, fully generic `to_serializable`
for writes (zero changes needed), one hand-written inverse deserializer for reads, idempotent upsert keyed by
`sequence_id`. **This ADR does not implement persistence** — it fixes the shape a later gate (G2.4.2) must
follow.

### D19 — Long-lived processes: no threshold

G2.4 introduces **no process-lifetime threshold, no max-span threshold, and no temporal window of any
kind.** `SAME_PROCESS_ENTITY` remains unconditionally structural per G2.1's own explicit, already-accepted
decision — a long-lived process's `TEMPORAL_SAME_ENTITY` chain is sequenced exactly as any other, however far
apart in time its steps fall, with no synthetic splitting or truncation. This is a direct carry-forward of
ADR-0003's own "Known limitations" position: *"introducing a max-span or gap threshold now, without corpus
evidence that this is a practical problem, would repeat the exact 'invent a threshold with no
justification' mistake this project's review process already rejected once."* If real corpus evidence later
shows this materially degrades sequence quality, the fix is future, versioned, content-hashed configuration
(D4-style, mirroring the rule-pack/correlation-config content-hash precedent) — never a code literal, and
never introduced without its own separately reviewed architectural decision.

### D20 — TEMPORAL_PROXIMITY: within G2.4 scope, sequenced as G2.4's own final sub-gate

ADR-0003's own §Implementation gates text for G2.4 is explicit: G2.4 *"introduces `TEMPORAL_PROXIMITY` as a
contextual (never structural) dimension behind a versioned, content-hashed window parameter."* **This ADR
does not narrow that out of G2.4.** `TEMPORAL_PROXIMITY` remains part of G2.4's overall scope, consistent
with ADR-0003, exactly as written there. What this revision fixes is *sequencing within* G2.4, not
*exclusion from* G2.4: `TEMPORAL_PROXIMITY` is implemented as **G2.4.3**, G2.4's own final sub-gate, built
only after the core DAG mechanics (G2.4.0–G2.4.2) are contracted, engineered, and validated — never framed
as a separate future phase, and never described as outside G2.4.

**Binding invariants for G2.4.3 (fixed now, in advance, so its later implementation cannot drift):**

- `TEMPORAL_PROXIMITY` is **permanently contextual, annotation-only** — added as a ninth `LinkClass` value
  with `is_structural == False`, alongside the existing five contextual dimensions, **never** joining
  `SHARED_OBSERVATION`/`SAME_PROCESS_ENTITY`/`PROCESS_LINEAGE` as a sixth structural class.
- It **must never** create a `SequenceEdge`.
- It **must never** create a `SequenceGap`.
- It **must never** affect `CorrelationGroup` formation or membership — D1's non-merge invariant and G2.1's
  own structural/contextual boundary apply to it identically to the other five contextual dimensions.
- It **must never** establish, or contribute to, causal ordering of any kind — closeness in time is a
  contextual/coincidental fact, not instance-identity or causation. D5's exactly-two-ordering-bases rule is
  unaffected; `TEMPORAL_PROXIMITY` adds no third basis.
- It **must not** participate in attribution or scoring in any form (D15/D17, unaffected).
- Its window parameter **must** be delivered as external, versioned, content-hashed configuration — never a
  code literal — per ADR-0003 D4's existing, already-accepted commitment: *"any temporal window is external,
  versioned configuration, hashed exactly like a G1.0 rule pack."*

**Why G2.4.3 is still sequenced last within G2.4, not folded into G2.4.0:** extending G2.0's `LinkClass`
enum from eight values to nine is a real, distinguishable kind of change from reconstructing a DAG over
links that already exist — it touches a different, already-accepted contract (`correlation/contracts.py`)
and its own existing contract-drift regression tests. Building the core sequence mechanics first
(G2.4.0–G2.4.2, over the eight existing `LinkClass` values) and adding `TEMPORAL_PROXIMITY` only once that
foundation is proven keeps each sub-gate small and independently reviewable — the same discipline that
produced G2.0→G2.1→G2.2→G2.3 as separate, small gates rather than one large one. This is a **sequencing**
decision, not a scope exclusion: `TEMPORAL_PROXIMITY` is accepted as in-scope, G2.4's own last sub-gate, by
this ADR now.

### D21 — Validation strategy

The G2.4.2 golden corpus must, at minimum, cover:

| # | Scenario | Expected sequence | Expected edges/gaps | Expected uncertainty | Forbidden inference |
|---|---|---|---|---|---|
| 1 | simple lineage chain | 1 sequence, 2 steps | 1 edge (`PROCESS_LINEAGE`) | none | no timestamp-based reordering even if timestamps were reversed |
| 2 | multiple actions in one process | 1 sequence, N steps | minimal chain of `TEMPORAL_SAME_ENTITY` edges (D8) | each edge labeled temporal-not-causal | no transitive/redundant edges |
| 3 | shared Observation, multiple Evidence | 1 sequence, **1 step** (not N) | 0 edges, 0 gaps | none | must not double-count as separate steps (D4/CR-1) |
| 4 | equal timestamps | 2 steps | 0 edges, 1 gap (`EQUAL_TIMESTAMPS`) | ambiguous | no arbitrary tie-break |
| 5 | coarse/unknown precision | 2 steps | 0 edges, 1 gap (`COARSE_PRECISION_TIE`) **or** 1 edge with `precision_uncertain=True`, per D6's exact case | ambiguous / caveated | no false precision |
| 6 | branching process tree (`P→A`, `P→B`) | 1 sequence, 3 steps | 2 edges (`P→A`, `P→B`); 1 `SequenceParallelGroup{source=P, branches=({A},{B})}` | A∥B explicit via the parallel group | must not linearize into `P→A→B` |
| 7 | independent groups (two separate chains) | 2 separate `BehavioralSequence`s | no cross-sequence relation | n/a | must not merge into one sequence (D1) |
| 8 | same host, unrelated groups | no group → **no sequence** | n/a | n/a | must not retroactively group by host |
| 9 | same user, unrelated groups | no group → no sequence | n/a | n/a | must not retroactively group by user |
| 10 | same destination, unrelated groups | no group → no sequence | n/a | n/a | must not retroactively group by destination |
| 11 | structurally-linked, unresolved ordering | 1 sequence, mixed structure | at least 1 gap, citing its grounding link | ambiguous | gap must not be silently omitted or replaced with a guessed edge |
| 12 | timestamp conflicts with lineage | 1 sequence | 1 edge, direction from lineage, `timestamp_agreement=False` | surfaced, not resolved | must not flip or drop the lineage-asserted direction |

**Multi-host non-merge validation (the "multi-host sequences" item in ADR-0003's own G2.4 test list).**
G2.1's already-accepted host-scoping collision safeguard (§"Host-scoped process-entity collision safeguard,"
ADR-0003 — **unchanged by this ADR**) means every structural dimension that can connect two nodes into one
`CorrelationGroup` is either confined to one `Observation` (`SHARED_OBSERVATION`, trivially one host) or
explicitly host-scoped (`SAME_PROCESS_ENTITY`/`PROCESS_LINEAGE`). Consequently **a single `CorrelationGroup`
— and therefore a single `BehavioralSequence` (D1) — cannot structurally span independent host scopes** under
the current, unchanged G2.1 rules. This fact is not treated as "irrelevant because unreachable" — it is
restated here as an explicit, tested **negative/non-merge invariant**, item 13 of this corpus:

| # | Scenario | Expected sequence | Expected edges/gaps | Expected uncertainty | Forbidden inference |
|---|---|---|---|---|---|
| 13 | multi-host input, no cross-host merging | one `BehavioralSequence` **per** host-scoped `CorrelationGroup` — never fewer | none between islands | n/a | must not merge, link, or sequence steps across the two islands merely because they coexist in one replay run; any `SAME_HOST_ID`/`SAME_HOST_NAME` contextual annotation stays annotation-only (D10) |
| 14 | deeper cross-branch parallelism (`P→A`, `P→B→C`) | 1 sequence, 3 steps | 3 edges (`P→A`, `P→B`, `B→C`); 1 `SequenceParallelGroup{source=P, branches=({A},{B,C})}` | A∥B **and** A∥C both explicit via the same parallel group; B→C's own order is unaffected | must not create any relation between A and C other than through the parallel group; must not omit A∥C merely because A and C are not immediate siblings of P |

Concretely: feed the G2.4 engine telemetry describing two (or more) independent structural islands, each
internally linked (e.g. its own `PROCESS_LINEAGE` chain) but scoped to a *different* `host.id` — mirroring
G2.3's own `g12`-style two-chains fixture, replicated across distinct hosts. **Expected:** G2.1 (unchanged)
forms one `CorrelationGroup` per host-scoped island; G2.4 forms exactly one `BehavioralSequence` per group —
directly exercising D1's general non-merge invariant with host-scope as the specific triggering condition.
This scenario is genuinely constructible (unlike a single group literally spanning two hosts, which G2.1's
own rules make impossible to produce) — it validates that **G2.4 itself introduces no new cross-host merging
bug at the sequence-construction layer**, as defense-in-depth alongside D1's general invariant, exactly as
G2.3's golden corpus already re-tests "two independent groups, no merge" from multiple angles (`g7`, `g12`)
rather than relying on a single instance of the rule. `GapReason.MISSING_TIMESTAMP` (D6) remains the one
item in this ADR that is genuinely unreachable and untestable given the current domain contract — multi-host
non-merge, by contrast, *is* testable, and is now specified as such.

## Domain model (proposed contracts — design only, not implemented by this ADR)

```
OrderingBasisKind (closed enum):
  PROCESS_LINEAGE
  TEMPORAL_SAME_ENTITY

GapReason (closed enum):
  EQUAL_TIMESTAMPS
  COARSE_PRECISION_TIE
  MISSING_TIMESTAMP        # defined for forward-compatibility; unreachable under the current domain contract

OrderingBasis (frozen value object, no independent identity — mirrors CorrelationBasis's role):
  basis_kind: OrderingBasisKind
  grounding_link_id: str
  timestamp_agreement: bool | None     # None only where a comparison is not applicable
  precision_uncertain: bool = False

BehavioralStep — see D2.

SequenceEdge (frozen, deterministic identity, directed):
  edge_id: str                    # D13
  from_step_id: str
  to_step_id: str
  basis: OrderingBasis
  schema_version: str = SEQUENCE_EDGE_SCHEMA_VERSION   # "sequence-edge/1"

SequenceGap — see D11.

SequenceParallelGroup — see D9.

BehavioralSequence (frozen, deterministic identity, 1:1 with one CorrelationGroup):
  sequence_id: str                          # D13
  group_id: str                             # D1
  steps: tuple[BehavioralStep, ...]         # sorted by step_id
  edges: tuple[SequenceEdge, ...]           # sorted by edge_id
  gaps: tuple[SequenceGap, ...]             # sorted by gap_id
  parallel_groups: tuple[SequenceParallelGroup, ...]   # sorted by parallel_group_id -- D9
  provenance: CorrelationProvenance         # D12 — reused unchanged
  schema_version: str = BEHAVIORAL_SEQUENCE_SCHEMA_VERSION   # "behavioral-sequence/1"
```

**Sequence-level invariants:** at least one step; step ids unique; every edge/gap endpoint, and every
`SequenceParallelGroup.source_step_id` and every step id named in any of its `branches` tuples, references a
step present in `steps`; every edge's/gap's `grounding_link_id` is present in the originating
`CorrelationGroup.structural_link_ids`; no step pair has both an edge and a gap between it (mirrors
`CorrelationGroup`'s own structural/contextual disjointness rule); a step named in one branch tuple of a
`SequenceParallelGroup` is never also directly connected, by an edge or a gap, to a step named in a
*different* branch tuple of that same group; a step appears in at most one branch tuple per
`SequenceParallelGroup` (D9's convergence-safety exclusion); the `edges` graph is acyclic (D14).

## Non-goals

G2.4 explicitly does **not** introduce: attribution of any kind; actor or campaign fields; candidate
generation; ACH reasoning; likelihood; confidence; calibration; numeric scoring or weighting of any kind;
`TEMPORAL_PROXIMITY` as an ordering, structural, or scoring input of any kind — it is in scope for G2.4
*only* as a contextual annotation, added in its own final sub-gate, G2.4.3 (D20); cross-group bridging (D1);
contextual-link-derived sequence edges (D10); tactic-based ordering (D16); ATT&CK relationship/`uses`
traversal (D16); a process-lifetime threshold (D19); a new telemetry source; a frontend; or any UI
graph-rendering concern.

## Implementation gates

Mirroring the G2.0–G2.3 small-gate discipline exactly — **four sub-gates, all within G2.4**, per ADR-0003's
own G2.4 scope (D20):

- **G2.4.0 — Contracts only.** `BehavioralStep`, `BehavioralSequence`, `SequenceEdge`, `SequenceGap`,
  `SequenceParallelGroup`, `OrderingBasis`, `OrderingBasisKind`, `GapReason`, and the deterministic-id
  helpers (`compute_step_id`/`compute_sequence_id`/`compute_sequence_edge_id`/`compute_sequence_gap_id`/
  `compute_sequence_parallel_group_id`). No engine, no ordering computation, no persistence, no
  `TEMPORAL_PROXIMITY`.
- **G2.4.1 — Pure sequence-construction/ordering engine.** Consumes one `CorrelationGroup` plus its
  member `(Evidence, Observation)` pairs and structural `CorrelationLink`s; produces one
  `BehavioralSequence` per D1–D9/D14, over the eight existing `LinkClass` values. No I/O, no persistence,
  no replay integration, no `TEMPORAL_PROXIMITY`.
- **G2.4.2 — Golden corpus + replay + persistence.** Extends `fixtures/`, adds a replay-pipeline hop
  mirroring G2.3's own `replay_fixture_through_correlation` pattern, and adds `dataplane` persistence per
  D18 (including `parallel_groups`, embedded alongside `steps`/`edges`/`gaps`). No attribution logic
  anywhere; still no `TEMPORAL_PROXIMITY`.
- **G2.4.3 — `TEMPORAL_PROXIMITY`.** Adds the ninth, contextual-only `LinkClass` value (extending
  `correlation/contracts.py`) and its versioned, content-hashed window-parameter configuration, bound by
  D20's invariants throughout. Built last, over an already-proven G2.4.0–G2.4.2 foundation, per ADR-0003's
  own G2.4 gate text — **within G2.4, not outside it.**

## Relationship to ADR-0001, ADR-0002, and ADR-0003

This ADR implements the "BehavioralSequence (deferred to G2.4)" design commitment ADR-0003 already made,
changing **nothing** in that ADR's own decisions (D1–D10 of ADR-0003, its structural/contextual dimension
sets, or its CorrelationGroup semantics). It changes nothing in ADR-0002's scoring methodology, decision
rule, or candidate generation — those remain Phase 3's concern, entirely untouched, and this ADR adds a
second explicit assurance (D17) alongside ADR-0003's own (D10) that the correlation/sequencing layers
collectively hand attribution structure and nothing it forbids. It is consistent with ADR-0001 D5 (ML/
non-deterministic reasoning stays off the correctness path — this layer is fully deterministic) and D11
(the frontend renders, never computes — this ADR defines no UI rendering concern, D3/D9 notwithstanding).

## Consequences

**Positive:** the future attribution layer gains an explicit, DAG-shaped, fully provenance-backed view of
how a group's evidence is temporally/causally organized, without the sequencing layer ever asserting what
that organization *means*; every edge and gap is individually explainable and traceable to one specific raw
fact; branching, convergence, and genuine ambiguity are all representable without fabrication.

**Negative / costs:** a `SAME_PROCESS_ENTITY` chain spanning a long-lived process will, correctly and by
design (D19), be presented as one long temporally-ordered (not causally-proven) chain rather than split into
smaller, more "meaningful" segments — a real, named limitation, not solved here. The `SequenceEdge`/
`SequenceGap`/`SequenceParallelGroup` three-way distinction adds concepts an eventual UI must render legibly;
this ADR does not specify that rendering (explicitly out of scope, ADR-0001 D11). `SequenceParallelGroup`'s
branch-partition shape (D9) is not a strict `O(n)` structure the way `SequenceEdge`/`SequenceGap` are — a
step can appear in one branch tuple per branching ancestor on its path from its sequence's root, so total
membership is bounded by steps × branching depth, not steps alone; for the shallow process trees real
telemetry produces this is not expected to matter in practice, but it is a real, named trade-off against the
strict-linear-size alternative (immediate-children-only) this revision replaced.

**Neutral:** `TEMPORAL_PROXIMITY`'s window-configuration content hash (G2.4.3) is, like G1.0's rule-pack hash
and G2.1–G2.3's correlation-config hash, an intentionally tunable/reversible parameter once it exists — not
a G2.4.0–G2.4.2 concern.

## Alternatives considered (and rejected)

- **Flat timestamp-sorted list.** Rejected: cannot represent branching or ties without fabricating an order
  (see D3, D9).
- **Nested tree object.** Rejected: cannot represent convergence without either rejecting valid G2.1 output
  or dropping an edge; recursive persistence/traversal logic this project has consistently avoided (see D3).
- **A third "inferred ordering" basis** (e.g. process-name heuristics, command-line similarity, or any
  signal beyond direct lineage/timestamp). Rejected: exactly the fabricated-causality pattern this ADR
  exists to forbid, and it would reopen the same category of mistake ADR-0003's own re-audit already caught
  once for host/user identity.
- **Treating `SAME_PROCESS_ENTITY` basis-field order as temporal.** Rejected: that field order is a sort
  artifact, not chronology (D5) — using it would silently fabricate order from a non-ordering fact.
- **A numeric "ordering confidence" score** for gaps/uncertain edges. Rejected: reintroduces exactly the
  arbitrary-points pattern ADR-0002 exists to forbid, one layer earlier and with none of its safeguards
  (D15).
- **Materializing every mutually-unreachable step pair as an explicit parallel marker.** Rejected: `O(n²)`
  in the number of steps, forces every consumer to wade through redundant markers, and is exactly the kind
  of unnecessary new abstraction this ADR avoids. A `SequenceParallelGroup` per branch point, partitioned by
  branch (D9), covers every genuinely cross-branch pair — not only immediate siblings — in one compact object
  per divergence.
- **Scoping `SequenceParallelGroup` to immediate siblings only, leaving deeper cross-branch pairs
  (e.g. `A` vs `C` in `P→A, P→B→C`) covered only by an unmaterialized reachability definition.** This was
  this ADR's own prior revision. Rejected on final pre-acceptance audit: tested against concrete multi-level
  DAGs, it left genuinely order-undeterminable pairs with no representation in the persisted document at
  all, an arbitrary line ADR-0003's unqualified "nodes whose relative order is not determinable" wording does
  not draw. Resolved by widening `SequenceParallelGroup` to a branch partition (D9) — still one compact
  object per branch point, not per pair.
- **Excluding `TEMPORAL_PROXIMITY` from G2.4 entirely** (this ADR's own first draft). Rejected on review:
  ADR-0003's own G2.4 gate text explicitly bundles it into G2.4; narrowing it out — even for a defensible
  sequencing reason — would have silently contradicted an already-accepted ADR rather than elaborating it.
  Resolved instead by keeping it in G2.4's scope and sequencing it as G2.4.3 (D20).

## Open questions resolved by this ADR

1. **Package placement** — `correlation/` is confirmed as the implementation location (same
   source-agnostic/ATT&CK-annotation-only/no-attribution boundary ADR-0003 already established; its own
   title already spans "Correlation *and* Behavioral-Chain").
2. **`technique_stix_ids`** — retained, on the explicit condition (D2, invariant 4) that it is a
   deterministic projection of real `Evidence.attack_ref` values and never an independent source of truth.
3. **`SequenceGap` formal rule** — resolved in D11: a gap exists if and only if a direct structural link
   connects two steps and the timestamp comparison is one of D6's gap-producing cases; no direct link means
   no relationship object at all (not a gap).
4. **Convergence** — resolved in D9: structurally supported by the DAG representation for free (a step may
   have multiple incoming edges); no special inference feature, and no `SequenceParallelGroup`, is added for
   converging parents — that is a distinct concept from diverging children.
5. **Coarse timestamp semantics** — resolved in D6: comparison is truncated to the *less precise* side's
   granularity before comparing; a genuine difference under unknown precision is still asserted but flagged
   `precision_uncertain=True`, never silently treated as full-precision evidence.
6. **Explicit parallel/unordered representation** (raised during design review, not in the original five) —
   resolved in D9: `SequenceParallelGroup` is a branch partition, one compact object per branch point, whose
   `branches` tuple names every step exclusively reachable from each child — not only the immediate
   children. Any two steps drawn from different branches are explicitly, persistently represented as
   parallel/unordered, covering deeper cross-branch pairs (e.g. `A` vs `C` in `P→A, P→B→C`) as well as direct
   siblings, without `O(n²)` per-pair materialization. A step reachable from more than one branch (a
   convergence anomaly) is excluded from every branch tuple rather than falsely claimed parallel to any of
   them (final pre-acceptance audit, superseding this ADR's own prior immediate-children-only revision).

## Follow-up

**Accepted 2026-09-15**, as recorded above — no decision was modified at acceptance itself (unlike ADR-0001
D8/M1 or ADR-0002 D22/M2, this ADR required no in-flight correction *at acceptance*; both substantive
corrections — D20's `TEMPORAL_PROXIMITY` sequencing and D9's branch-partition `SequenceParallelGroup` — were
already incorporated into the design before this final acceptance review, during the two pre-acceptance
audits recorded in the acceptance rationale above, exactly as ADR-0003's own D2 correction was incorporated
before *its* acceptance). [docs/architecture/README.md](../README.md)'s ADR table has been updated to
ACCEPTED accordingly. G2.4 code may still not be written yet: gate G2.4.0 is now a separate, later step from
this ADR's acceptance (§Implementation gates), not a re-statement of pre-acceptance pending status.

## Post-acceptance clarifications

These clarifications resolve two open-text/implementation questions identified during the Phase 2 completion
audit (2026-09-16), after G2.4.0–G2.4.3 were all implemented and checkpointed. **Neither changes, reopens, or
reinterprets any decision D1–D21 above.** Each documents how an already-accepted decision was in fact
satisfied, or records a deliberate, bounded implementation choice made during the later G2.4 sub-gates. Dated
and appended here, never merged into the original decision text above, matching this project's own
established practice of never silently rewriting an accepted ADR (the same discipline this ADR's own
pre-acceptance corrections and ADR-0003's D2 correction already followed).

### Clarification 1 (2026-09-16) — ATT&CK tactic annotation

ADR-0003's own §Implementation gates text for G2.4 states that G2.4 *"adds ATT&CK tactic annotation (never
reordering)."* This is satisfied by the accepted design exactly as built — **no persisted tactic-phase field
is required, and none is added:**

- `BehavioralStep.technique_stix_ids` (D2, invariant 4, above) is already the authoritative,
  mechanically-derived ATT&CK reference for each step: a deterministic projection of the real
  `Evidence.attack_ref.stix_id` values already present on that step's own evidence, itself tied to a specific,
  pinned ATT&CK KB version through that evidence's own provenance.
- Tactic phase is a pure, deterministic function of `(technique_stix_id, pinned ATT&CK KB version)` — already
  fully recoverable by any downstream consumer from `technique_stix_ids` alone, via a lookup against the
  pinned knowledge bundle. It is **derived on read**, never persisted on `BehavioralStep` or any other
  contract this ADR defines.
- A separate, persisted `tactic_phase` field would duplicate information already recoverable from
  `technique_stix_ids` and would itself become "an independent source of truth" for derived data — precisely
  what D2 invariant 4 already forbids for `technique_stix_ids` itself. `BehavioralStep`'s field set is
  therefore unchanged by this clarification.
- Tactic annotation, wherever it is eventually computed (a future presentation/read-model layer, and/or
  Phase 3's own diagnosticity computation), remains strictly presentation/diagnostic context — consistent
  with ADR-0003's own §ATT&CK boundary framing ("the one permitted use... is annotating a resulting
  behavioral structure... **for presentation**") and this ADR's own D16 invariants, unchanged: it **must
  not** reorder steps, **must not** create a `SequenceEdge` or `SequenceGap`, **must not** establish or imply
  causality, and **must not** participate in any Phase 2 attribution or scoring vocabulary — none of which
  exists anywhere in this layer, with or without this clarification.
- **No Phase 2 implementation or contract change is required.** `correlation/sequence.py`,
  `correlation/sequence_engine.py`, and every G2.4.x gate's own acceptance stand exactly as already
  checkpointed.

### Clarification 2 (2026-09-16) — G2.4.2 golden-corpus coverage

This ADR's §Implementation gates text for G2.4.2 states it *"Extends `fixtures/`..."* The accepted G2.4.2
implementation intentionally retained `fixtures/phase2_correlation_scenarios.json` unchanged from its G2.3
state, for a concrete, bounded reason recorded here:

- That file is load-bearing for G2.3's own already-checkpointed regression tests
  (`tests/test_replay_correlation.py`), which pin exact corpus-wide counts (scenario count, evidence count,
  and per-group structural/contextual link counts). Extending it would have required also editing that
  already-accepted G2.3 test file to keep those pinned counts true — reopening a frozen, already-checkpointed
  gate to satisfy a later one, which this project's own gate-to-gate discipline has consistently avoided
  (mirrored by G2.4.1 never touching G2.0–G2.3, and G2.4.2/G2.4.3 never touching G2.4.0/G2.4.1).
- The five scenarios G2.4.2 needed beyond what the existing corpus already exercised — equal timestamps,
  coarse precision tie, lineage/timestamp disagreement, genuine multi-parent convergence, and deeper
  cross-branch parallelism — are internal ordering-engine edge cases (G2.4.1's own timestamp-comparison and
  branch-partition semantics, D6–D9 above), not detection-rule-matching or ATT&CK-mapping-resolution
  scenarios, which is what the raw-telemetry `DetectionReplayFixture` format exists to exercise.
- All five are instead covered by deterministic, in-Python-constructed integration scenarios in
  `tests/test_replay_behavioral_sequence.py`, each executing the real, unmodified G2.1/G2.2 structural/
  contextual engines, the real G2.4.1 `construct_behavioral_sequence`, and the real G2.4.2 persistence path —
  the identical production code path a JSON-fixture-driven scenario would exercise, differing only in
  authoring surface (a Python literal rather than a JSON file), never in engine realism or rigor.
- This approach preserves G2.3's existing fixture-count regression contract exactly, and alters neither the
  `BehavioralSequence` contract nor the golden-corpus semantics established elsewhere in this ADR.
- **No implementation change is required.** This clarification records the deviation and its rationale;
  `fixtures/phase2_correlation_scenarios.json` remains exactly as committed at G2.3.

### Clarification 3 (2026-09-21) — B4 `evidence_type` carry-forward on `BehavioralStep`

Records the accepted carrier for the Phase-3 prerequisite **B4** (`evidence_type` plumbing, ADR-0005 Amendment B
"Preconditions for G3.6" item 4; methodology locked in P4-M, 2026-09-21). This is an **additive** clarification: it
records how an existing fact is carried forward and does **not** rewrite any accepted D1–D21 decision or the
`BehavioralStep`/`BehavioralSequence` contracts above.

**B4 `evidence_type` carry-forward.**

- `Evidence.evidence_type` (a Phase-0 fact, the existing closed `EvidenceType` vocabulary) is the **authoritative
  source**. It is never inferred or re-derived — not from `event_type`, `source_type`, ATT&CK technique, IOC,
  alert severity, correlation patterns, candidate generation, or any attribution output.
- The canonical carrier is a new **additive** field **`BehavioralStep.evidence_types`**, populated by the
  sequence engine (G2.4.1) as it constructs each step — the identical "read a value off the step's own member
  `Evidence`" carry-forward the existing `BehavioralStep.technique_stix_ids` field already uses (it is mechanically
  read off each step's Evidence's `attack_ref`). **No new correlation logic** is introduced.
- Granularity is **per `BehavioralStep`**: the sorted, de-duplicated set of the `evidence_type` values across the
  step's member `Evidence`, represented as a `tuple[str, ...]` over the existing closed `EvidenceType` vocabulary.
  No new taxonomy is introduced. Provenance is preserved because the step already pairs this with its
  `evidence_ids`.
- `evidence_types` is **carry-forward provenance only** and is **not part of step identity**:
  `compute_step_id(group_id, evidence_ids)` and `compute_sequence_id(group_id, step_ids)` (D13) are unchanged, so
  every existing `step_id`/`sequence_id` remains identical. The DAG invariant (D14) is preserved — the value flows
  strictly forward from a Phase-0 fact and depends on no Phase-3/attribution output.
- The **Phase-2 → Phase-3 boundary is unchanged**: Phase 3 continues to receive only `CorrelationGroup` +
  `BehavioralSequence`; no raw `Evidence` is introduced into candidate generation or ACH.

**Schema / persistence implications (recorded, not implemented here).**

- `BEHAVIORAL_STEP_SCHEMA_VERSION` becomes `behavioral-step/2` (a deliberate additive contract-shape change).
- `BEHAVIORAL_SEQUENCE_SCHEMA_VERSION` remains **unchanged**: the `BehavioralSequence` field set is unchanged,
  `sequence_id` is unaffected, and holding it fixed avoids renaming the derived persistence index and rejecting
  previously-stored sequences.
- Persistence will serialize `evidence_types`; older persisted `BehavioralStep` records lacking the field load
  with `evidence_types=()` via the existing tolerant deserialization (default-on-absent). No migration is required
  solely for this additive field.

**Scope boundary.** B4 only makes the already-existing `EvidenceType` fact **available** at the future G3.6 input
boundary (reachable from an ACH cell via the existing `EvidenceAssessment.step_id`). B4 does **not** implement any
G3.6 behaviour — no confidence, evidence-diversity/independence scoring, imitation defense (ADR-0005 §D12), WEP,
likelihood, or abstention. Those remain later, separately-gated work.
