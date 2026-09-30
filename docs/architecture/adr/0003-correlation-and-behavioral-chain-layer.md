# ADR-0003 — Correlation and Behavioral-Chain Layer (Phase 2)

- **Status:** ACCEPTED (2026-09-15)
- **Date:** 2026-09-15 (proposed) · 2026-09-15 (accepted)
- **Deciders:** project owner (accepted after architecture review, critical re-audit, and repository-organization review)
- **Supersedes / superseded by:** —
- **Related:** [ADR-0001](0001-evidence-graph-core-architecture.md) ·
  [ADR-0002](0002-attribution-scoring-and-evidence-methodology.md) ·
  [03 data flow](../03-system-data-flow.md) · [06 evidence model](../06-evidence-model.md) ·
  [07 scoring spec](../07-attribution-scoring-spec.md) ·
  [13 Phase-0 implementation plan](../13-phase-0-implementation-plan.md)

> The decisions below (D1–D10) are **ACCEPTED** as of 2026-09-15. Reversibility is noted per decision.
> Acceptance does **not** start implementation: no `correlation/` package code may be written until gate G2.0
> formally begins (see §Implementation gates), and the docs/03 · docs/06 "AttackChain" terminology
> synchronization remains a separate, not-yet-performed follow-up (§Alternatives considered for a Phase-2
> name).
>
> **Acceptance rationale:** the first draft of this design misclassified `SAME_HOST_ID`/`SAME_USER_ID` as
> structural, group-forming dimensions. A critical re-audit — performed before this document was drafted —
> identified that as a genuine defect (a shared host or user identity does not establish that two
> observations belong to the same underlying behavior; see §Problem statement) and produced the corrected
> causal/instance-identity vs. shared-environment/actor-scope test recorded as D2 below. The corrected design
> — never the flawed first draft — is what was reviewed and is what this acceptance covers: it is fact-based
> rather than knowledge-based (D1), introduces no scoring (D3), keeps ATT&CK to annotation only (§ATT&CK
> boundary), remains fully provenance-navigable to raw telemetry (D5, §Provenance), and performs no
> attribution (D10). No decision was rejected and none is modified by this acceptance.

## Context

Phase 0 and Phase 1 (gates G0.0–G1.3, all checkpointed) established a complete, provenance-first pipeline:

```
raw telemetry → SourceAdapter → Observation → DetectionEngine → DetectionResult → derive_evidence_from_detection → Evidence
```

Every `Evidence` object is **independent**: it is derived from exactly one `DetectionResult`, which is derived
from exactly one `Observation` (Phase 1 is strictly single-Observation scope by design — see the G1.0
`DetectionRule`/`DetectionEngine` docstrings). Nothing in the pipeline today relates two different
`Observation`s to each other. This was a deliberate, explicit Phase-1 boundary, not an oversight — Phase 1's
job was to prove the deterministic detection engine and its ATT&CK-validated mapping worked end to end before
any multi-event reasoning was added.

[ADR-0002](0002-attribution-scoring-and-evidence-methodology.md) **D16 (CR-1)** requires that the future
attribution layer's `support(h)` computation **de-duplicate correlated evidence**: *"multiple detections
arising from the same underlying behavior (causally-related observations that assert the same technique)
count once."* [07 §4](../07-attribution-scoring-spec.md) states this as a hard property of `support(h)`:
*"dominance by discriminating evidence, not volume."* Nothing in the pipeline built so far can identify *which*
evidence items are causally related to which others — that grouping does not exist. Without it, the
attribution layer either has no way to satisfy CR-1, or would have to invent its own ad hoc grouping logic
inside the scoring layer itself, which ADR-0002 does not want and this project's layering discipline
(ADR-0001 D1/D2) does not permit.

[03 — system data flow](../03-system-data-flow.md) already reserves a stage for this: stage 6, "Correlation," sits
between the evidence graph and attribution, and states the requirement precisely: an object whose "provenance
recorded" is *"observation ids + each edge's link reason (shared entity/time)."* This ADR is the accepted-shape
resolution of that already-reserved stage, adapted to the domain contracts actually built in Phase 0/1 (which
did not exist when doc 03 was written) and to the corrected structural/contextual distinction produced by this
ADR's own review process (see Problem Statement).

## Problem statement

**Why a flat bag of detections/evidence is insufficient.** A real intrusion produces multiple, causally
related telemetry events (a phishing document spawns a shell, the shell downloads a payload, the payload
creates a scheduled task). Phase 1's engine correctly detects each event independently, but without an
explicit layer that identifies *which* Evidence items are part of one connected execution thread, the
attribution layer has two bad options: treat every Evidence item as independent (violating CR-1 — one behavior
that trips three rules would count three times) or invent its own correlation logic ad hoc inside the scoring
layer (violating the layering that keeps attribution auditable and testable in isolation).

**Why correlation must not become hidden attribution.** The most dangerous failure mode for this layer is not
"it groups too little" — it is **"it groups by the wrong thing and calls the result a behavior."** A first
draft of this design classified `SAME_HOST_ID`/`SAME_USER_ID` as link types that could form a correlation
group. Architecture review rejected that: a host runs many unrelated processes, and a shared (especially
administrator/service) user identity performs an unbounded set of unrelated actions, so grouping by either
would silently mean **"these events share an environment or an identity," not "these events are one
behavior."** That is not a minor imprecision — it is the CR-1 de-duplication unit *lying about what it
represents*, and it is exactly the kind of business-heuristic drift into attribution-adjacent judgment that
[ADR-0001 D5](0001-evidence-graph-core-architecture.md) and this project's CLAUDE.md forbid happening
outside the deliberately-specified attribution methodology. The corrected design in this ADR exists
specifically to make that failure structurally impossible rather than merely discouraged.

The same discipline applies to ATT&CK: technique/tactic relationships, procedure examples, and
group/software/campaign `uses` edges are exactly the kind of knowledge-base reasoning ADR-0002 reserves for
the attribution layer. If correlation used them to form or strengthen a link, two unrelated intrusions that
both happen to use a common technique would be "correlated" — attribution by another name, arrived at one
layer too early and without any of ADR-0002's safeguards (discriminating power, the `Unattributed` floor,
CR-1 itself).

## Decision

Adopt a deterministic, source-agnostic, provenance-first correlation layer with the following properties,
each elaborated in its own section below:

- **D1 — Fact-based, not knowledge-based.** Correlation links derive solely from observed telemetry
  identifiers and observed causal relationships already present on `Observation`/`Evidence`. No ATT&CK
  actor/software/campaign knowledge, and no technique-rarity signal, is ever an input to link formation.
  *Reversibility: low (foundational to this ADR).*
- **D2 — Structural vs. contextual is a causal/instance-identity vs. shared-environment/actor-scope test,
  never an identifier-stability test.** A relationship is **structural** only if it asserts that two
  observations describe the *same instance of execution* or a *direct causal creation relationship*. A
  relationship that asserts only *shared environment, shared identity, or shared infrastructure* is
  **contextual**, regardless of how reliable the underlying identifier is. Only structural links may form a
  `CorrelationGroup`. *Reversibility: low.* (This is the corrected decision — see Problem Statement and §6–8.)
- **D3 — No scoring, no weighting.** Every relationship is a typed, explained relation (`LinkClass` +
  `CorrelationDimension` + `CorrelationBasis`), never a numeric edge weight, point value, or probability.
  *Reversibility: medium.*
- **D4 — Correlation configuration is versioned and content-hashed.** Which dimensions are enabled (and, when
  introduced later, any temporal window) is external, versioned configuration, hashed exactly like a G1.0 rule
  pack — never a literal threshold in engine code. *Reversibility: high (tunable).*
- **D5 — Provenance-complete.** Every correlation object carries a provenance record mirroring
  `DerivationProvenance`, navigable back to the raw telemetry that produced it, with no exceptions.
  *Reversibility: low.*
- **D6 — Machine-readable explanation on every link**, distinguishing observed fact, derived relationship, and
  uncertainty as separate structured fields — never frontend-generated prose. *Reversibility: medium.*
- **D7 — Ordered/branching behavioral views (`BehavioralSequence`) are a later, separate gate (G2.4)** and
  must retain uncertainty (gaps, branches, parallel/unordered nodes) rather than forcing a neat line; they
  assert no maliciousness or actor identity. *Reversibility: medium.*
- **D8 — Source-agnostic core**, enforced by an import guard: the correlation engine depends only on
  `domain` (and reads `attack_knowledge` for annotation only, per D12 below) — never `sources`, `dataplane`,
  or any collector-specific field. *Reversibility: low.*
- **D9 — Deterministic and idempotent**, so replaying the same telemetry twice produces identical link/group
  ids and no duplicate edges — the mechanism that actually satisfies ADR-0002 D16/CR-1: evidence arising from
  one connected execution thread is identified once, deterministically, so the attribution layer can
  de-duplicate it without inventing its own grouping logic. *Reversibility: low.*
- **D10 — Phase 2 performs no attribution.** No candidate/actor/campaign object, no likelihood, no confidence,
  no maliciousness verdict, and no scoring vocabulary exists anywhere in this layer. Phase 2 hands the
  attribution layer exactly two things: a de-duplication grouping and a structured, provenance-complete view
  of related activity — nothing it forbids. *Reversibility: low.*

### Domain model

The minimum coherent set of new contracts — deliberately **not** the full menu of names evaluated during
design (`EvidenceCluster` and `BehavioralFeature` were considered and rejected: the former is redundant with
`CorrelationGroup`; the latter carries per-technique discriminating power, which is attribution machinery and
belongs to Phase 3, not here).

**`CorrelationDimension`** (closed enum) — the specific field-level relationship a link asserts: the three
structural values (§6) and the five contextual values (§7). A closed vocabulary, exactly like `EvidenceType`
in [domain/enums.py](../../../src/attribution_platform/domain/enums.py) — membership is fixed; an unrecognized
value fails closed.

**`LinkClass`** (closed enum, two values) — `STRUCTURAL` or `CONTEXTUAL`. This is a **type**, not a scale: it
is the only "strength" signal Phase 2 emits, and it is categorical rather than numeric by design (§4/D3).

**`CorrelationBasis`** (value object, no independent identity) — the machine-readable explanation for one
link: `dimension` (a `CorrelationDimension`), `link_class` (derived from `dimension`, never set
independently), `field_path` (e.g. `"process.entity_id"`), `observed_value`, `observation_id_a`,
`observation_id_b`, and `uncertainty_note` (populated only for contextual links — structural links have
nothing to hedge). A pure function of the two Observations' already-extracted field values; no randomness, no
inference beyond field equality.

**`CorrelationLink`** (frozen contract) — the atomic relation between two Evidence items: `link_id` (composed
deterministically from `dimension` + `observed_value` + the two sorted anchor evidence ids + the correlation
config's content hash — never a generated id), `anchor_a`/`anchor_b` (`evidence_id`s), `basis`
(`CorrelationBasis`), `link_class`, `provenance` (`CorrelationProvenance`), `schema_version`. Symmetric except
where the underlying relationship is inherently directional (`PROCESS_LINEAGE` records parent→child
directionally in its basis even though the link itself connects two evidence anchors).

**`CorrelationGroup`** (frozen contract) — a connected component under structural links only (§8–9):
`group_id` (composed deterministically from the sorted set of member evidence ids + config hash),
`member_evidence_ids` (sorted-unique tuple), `member_observation_ids` (sorted-unique tuple, for direct raw
navigation without walking through evidence), `structural_link_ids` (the edges that actually formed this
component), `contextual_link_ids` (links that touch a member but did **not** and could **not** form the
component — see §8's non-exclusivity rule), `provenance`, `schema_version`.

**`CorrelationProvenance`** (frozen contract, deliberately parallel to
[`DerivationProvenance`](../../../src/attribution_platform/domain/provenance.py)) — `method`, `method_version`,
`method_content_hash` (the correlation-config content hash, optional/additive exactly like G1.0's rule-pack
hash), `source_evidence_ids` (non-empty, sorted-unique), `source_observation_ids` (non-empty, sorted-unique).
Non-emptiness of both id sets is a construction-time invariant, exactly like `DerivationProvenance`'s existing
enforcement of `source_observation_ids` — no correlation object may exist without a populated path to at
least one Observation.

## Structural dimensions (exactly three — the group-forming set)

A dimension is structural **if and only if** equality of the field(s) it tests means the two Observations
describe the same instance of execution, or a direct, collector-asserted causal creation relationship —
**never** merely that they share a scope, environment, or actor.

- **`SHARED_OBSERVATION`** — two `Evidence` items were derived from the exact same `Observation` (e.g. one
  `DetectionResult` with multiple `technique_mappings`, fanned out by the existing, unmodified
  `derive_evidence_from_detection`). This is not even a relationship between two events — it is one piece of
  telemetry interpreted twice. There is no weaker case than this; it is the tightest possible structural fact.
- **`SAME_PROCESS_ENTITY`** — two Observations both populate a stable `process.entity_id` with the same value.
  `entity_id` (as distinct from `pid`, which can be reused) identifies one specific running process instance
  for the bounded duration of its lifetime. Two facts about the same process instance are two facts about one
  continuous, non-branching thread of execution — identity-of-instance, not shared scope.
- **`PROCESS_LINEAGE`** — one Observation's `process.parent_entity_id` equals another's `process.entity_id`.
  This is a direct, collector-asserted causal fact (the operating system recorded that this process created
  that process) — not an inference this layer makes. It is the one directional structural dimension.

No other dimension is structural. This set was evaluated as sufficient during the re-audit specifically
because each member satisfies the same-instance-or-direct-causation test and none of them requires any
judgment about environment, identity, or infrastructure.

## Contextual dimensions (attach-only — never group-forming)

A dimension is contextual if equality of the field(s) it tests means only that two Observations occurred in
the same environment, under the same identity, or against the same infrastructure endpoint — a *container* or
an *unbounded-action actor*, not a participant in a causal chain.

- **`SAME_HOST_ID`** / **`SAME_HOST_NAME`** — a host is a container: many unrelated processes execute on it
  concurrently and sequentially. Sharing a host, however reliably identified, says nothing about whether two
  specific observations are related.
- **`SAME_USER_ID`** / **`SAME_USER_NAME`** — a user (especially an administrator or service account) performs
  an unbounded set of unrelated actions by design. This risk is *stronger* than the host case, because shared
  service/admin identities are common and their action sets are large and heterogeneous by construction.
- **`SAME_DESTINATION_IP`** — shared network infrastructure (CDNs, NAT, common egress points, cloud shared
  tenancy) routinely produces identical destination endpoints for causally unrelated traffic.

**A stable identifier does not become structural merely because it is reliable.** `host.id`/`user.id` are more
reliable *facts* than `host.name`/`user.name` (less subject to rename/reuse), and that reliability is recorded
in `CorrelationBasis.field_path`/`observed_value` and reflected in a lighter `uncertainty_note` — but
reliability of the fact and behavioral meaning of the fact are different questions. All five dimensions above
answer "same environment/identity/infrastructure," never "same instance or direct causation," so all five are
`CONTEXTUAL` regardless of identifier stability. This correction — replacing an identifier-stability test with
a causal/instance-identity test — is the substantive fix this ADR makes over the design's first draft.

## CorrelationGroup semantics

**A `CorrelationGroup` is a connected component of the graph whose nodes are `Evidence` items and whose edges
are structural `CorrelationLink`s only** (§9). Nothing else may create or merge a group. Explicitly prohibited,
as a permanent invariant of this layer, not a default that a future gate may loosen without a new ADR:

- **same host ⇒ same group** — prohibited (host identity is contextual-only, §7);
- **same user ⇒ same group** — prohibited (user identity is contextual-only, §7);
- **same destination IP ⇒ same group** — prohibited (shared infrastructure is contextual-only, §7);
- **same technique ⇒ same group** — prohibited (technique sameness is not a telemetry-identifier relationship
  at all; two unrelated intrusions using the same technique are not "one behavior," and grouping by it would
  be indistinguishable from attribution-by-technique-overlap, exactly the pattern ADR-0002 exists to prevent);
- **same ATT&CK actor/software (or any other KB relationship) ⇒ same group** — prohibited absolutely (§12);
  this is not merely undesirable, it is a hard boundary violation between this layer and Phase 3.

**A contextual link touching two different groups must never be interpreted as relating those groups.** If two
independent, structurally-unrelated `CorrelationGroup`s both happen to have a member on `HOST-01`, the
resulting `SAME_HOST_ID` contextual link is stored once and may be surfaced as "also observed on this host:
[other group]" — it must never be rendered, stored, or reasoned about as "these two groups are related." This
applies to every future consumer of this data (the read-model API, a future UI, and the attribution layer
itself): a contextual link is descriptive metadata about members, never a merge signal between the groups
those members belong to.

**Revised CR-1 semantics (the operational meaning a `CorrelationGroup` actually carries):** a group means *"these
Evidence items arose from a chain of observations that are provably the same process instance or in a direct
parent→child creation relationship, and should not be independently counted as separate corroborating
behaviors for attribution's `support(h)` computation."* It does **not** mean "one technique," "one simple
action," or "malicious" — a legitimate process-lineage tree can span multiple tactics/techniques (execution →
discovery → exfiltration, say) and still be exactly one group, because it is one causally-connected thread of
execution. And it never means "same machine" or "same user" — those facts, when true, live in
`contextual_link_ids`, never in the reason the group exists.

## Connected-component algorithm

Build a graph whose nodes are `Evidence` items and whose edges are exactly the `CorrelationLink`s with
`link_class == STRUCTURAL`. A `CorrelationGroup` is one connected component of that graph (standard
union-find/BFS over structural edges; deterministic given a deterministic edge ordering — edges are processed
in a fixed, reproducible order, e.g. sorted by `link_id`, so the resulting group membership and `group_id` are
stable across runs). Contextual links are computed independently over the same node set, are **never** edges
in this graph, and are attached to a group post-hoc as `contextual_link_ids` for every group that has at least
one member touched by that contextual link — the same contextual link id may legitimately appear on multiple
groups' `contextual_link_ids`, which is expected (§8), not a defect.

**Host-scoped process-entity collision safeguard.** `process.entity_id` values (e.g. a Sysmon-style
`ProcessGuid`) are meaningful only within the scope of the host that generated them; if two different sources
or hosts ever produced colliding raw entity-id strings (a data-quality edge case, not expected of well-formed
collectors, but not provable-impossible from the domain contract alone), a naive global string-equality join
on `entity_id` could create a false structural link across two genuinely unrelated hosts. The computation of
`SAME_PROCESS_ENTITY` and `PROCESS_LINEAGE` must therefore scope its join key by host (conceptually
`(host_id_or_name, entity_id)`, not `entity_id` alone) as an **implementation-level collision safeguard**, not
as a new correlation dimension. Host participates here only as scoping plumbing inside the structural
computation — it is never the reported `dimension`, never appears in `CorrelationBasis.field_path` for these
two dimensions, and using it this way does not make host a structural signal (§6 is unaffected; this is a
correctness safeguard on what "same entity id" is allowed to mean, not an exception to §7).

## Explainability

`CorrelationBasis` is the entire explanation mechanism — no frontend-generated prose. Every basis distinguishes
three kinds of statement, matching the same discipline [06 §Uncertainty](../06-evidence-model.md) already applies
to `observation_confidence`/`reliability` grades one layer down:

- **Observed fact** — `field_path` + `observed_value` + `observation_id_a`/`observation_id_b`: a verifiable
  claim about the raw data, checkable against the referenced Observations directly.
- **Derived relationship** — `dimension` + `link_class`: this project's interpretation of that fact (structural
  or contextual, and which specific kind).
- **Uncertainty** — `uncertainty_note`: populated only on contextual links, naming the specific reason the
  match does not imply behavioral relatedness (e.g. *"shared/service accounts are common and do not imply a
  causal relationship"* for a `SAME_USER_ID` link, or *"shared infrastructure/CDN routinely produces identical
  destination endpoints for unrelated traffic"* for `SAME_DESTINATION_IP`). Structural links carry `None` —
  the fact itself is the certainty; there is nothing to hedge.

`LinkClass` is the only categorical certainty signal ever shown; no numeric confidence appears anywhere in
this layer (§Decision D3).

## Provenance

The complete backward-navigable chain, every hop already built in Phase 0/1 except the last two, which this
ADR adds:

```
raw telemetry
  → Observation (raw_reference: SourceRef — source_type, source_event_id, dataset_ref, raw_payload_ref)
    → DetectionResult (rule_ref, rule_pack_content_hash, supporting_observation_ids)
      → Evidence (provenance: DerivationProvenance — method, method_version, method_content_hash,
                  source_observation_ids)
        → CorrelationLink (basis: CorrelationBasis — the two observation_ids + the matched field/value;
                            provenance: CorrelationProvenance — source_evidence_ids, source_observation_ids,
                            method_content_hash)
          → CorrelationGroup (member_evidence_ids, member_observation_ids, structural_link_ids,
                               provenance: CorrelationProvenance)
```

No correlation object may be constructed without a non-empty path to at least one `Observation`
(`CorrelationProvenance.__post_init__` enforces this exactly as `DerivationProvenance` already does).
An analyst navigating backward from any `CorrelationGroup` reaches its member `CorrelationLink`s, each
link's `CorrelationBasis` names the exact two `observation_id`s and field/value that justified it, each
Observation's `raw_reference` names the exact raw record (and, in replay, the exact dataset content hash) —
so "why does this group exist" is always answerable down to a specific field on a specific raw event, never a
trust-me summary.

## ATT&CK boundary

ATT&CK is reference/annotation data only. The one permitted use in this layer is annotating a resulting
behavioral structure (a future `BehavioralSequence` node, G2.4) with the **tactic phase** of its technique, for
presentation (e.g. showing "execution → credential access → …" alongside an already-formed, already-explained
chain). This annotation happens strictly *after* structure exists and **never reorders or forms it** —
disagreements between timestamp-derived order and tactic-kill-chain order are surfaced as-is, not resolved by
preferring one over the other, because real intrusions do not reliably obey tactic order and this layer does
not adjudicate that.

**No `intrusion-set`, `campaign`, `malware`, or `tool` object — and no technique-to-technique/procedure/`uses`
relationship — may be used as a correlation input, at any point, for any dimension.** This is a hard boundary,
not a style preference: using any of them to create or strengthen a link would mean "these are correlated
because ATT&CK says similar actors use similar things," which is attribution reasoning performed one layer
too early, without any of ADR-0002's safeguards (D3 diagnosticity, D17 the `Unattributed` floor, D20 no
single-technique attribution). Every correlation link in this layer must remain fully justifiable with zero
reference to any ATT&CK object.

## Source-agnostic boundary

The correlation core depends only on the `domain` package's entity groups (`host`/`user`/`process`/`network`/
`event`/`file` + `SourceRef`) and, for annotation only, `attack_knowledge` — never `sources`, `dataplane`, or
any collector-specific field name. This mirrors the existing `detection/` package's own boundary (which
already forbids importing `sources`/`dataplane`/`replay`/`api` — see the guard tests in `test_detection.py`)
and will be enforced the same way: an AST-based guard test scanning the correlation package's source for
forbidden imports. Consequence: the identical engine correlates Sysmon, Windows Event Log, Linux, network,
EDR, identity/authentication, or cloud telemetry the moment an adapter emits Observations with the relevant
identifiers populated (`process.entity_id`, `process.parent_entity_id`) — because the join is on ECS-generic
domain fields, not a Sysmon-specific shape. No Sysmon-specific (or any other source-specific) logic exists
anywhere in the correlation core.

## Determinism and idempotency

Every id in this layer (`link_id`, `group_id`) is composed deterministically from stable inputs — the
dimension, the matched value, the sorted anchor ids, and the correlation configuration's own content hash —
never a generated (`uuid4`-style) id, and never wall-clock-derived, exactly as G1.0's `RulePack.content_hash`
and deterministic `detection_id` construction already established. Replaying the same telemetry through the
same correlation configuration twice therefore produces byte-for-byte identical links and groups, and
persisting them twice is a no-op upsert (the same `persist_observation`/`persist_evidence` idempotency
pattern from G0.8/G1.2 applies unchanged). This determinism is not incidental — it is the mechanism that
actually delivers ADR-0002 D16 (CR-1): the attribution layer can safely treat "same `group_id`" as "count once"
without inventing its own de-duplication logic, because the same underlying behavior always produces the same
group across replays.

## Known limitations

**Deferred, not solved here — long-lived-process accumulation.** A single very long-lived process (a
persistent service host, a long-running interactive shell) could, over its real lifetime, accumulate a large
`SAME_PROCESS_ENTITY` structural group spanning hours or days of genuinely unrelated actions taken *through*
that one process. This is materially different from — and smaller than — the host/user risk this ADR
corrects: the causal-actor identity is real (it genuinely is one process), not an arbitrary container, so it
does not violate the structural test in §6. It is nonetheless a real limitation worth naming honestly. No fix
is proposed in this ADR: introducing a max-span or gap threshold now, without corpus evidence that this is a
practical problem, would repeat the exact "invent a threshold with no justification" mistake this project's
review process already rejected once (for temporal-proximity correlation, §Decision D4). If evidence from the
Phase 2 golden corpus or later real telemetry shows this materially degrades group quality, the fix belongs in
a future, evidence-justified gate, expressed as versioned, content-hashed configuration — never a code
literal.

**Telemetry sparsity, not a schema gap.** `process.entity_id`/`parent_entity_id` already exist on
`ProcessRef` (G0.3) and are already consumed by the G0.11 Sysmon adapter when the source provides them, but
today's synthetic fixtures and the reference `SyntheticSourceAdapter` under-populate them, and `host.id`/
`user.id` (as opposed to `host.name`/`user.name`) are not populated by the current Sysmon adapter at all. No
`Observation`-schema extension is required for G2.0–G2.4: this is a fixture/golden-corpus authoring
prerequisite (populate the fields that already exist), not a contract change, and is the explicit
responsibility of the G2.3 golden corpus (§Implementation gates).

## BehavioralSequence (deferred to G2.4)

Recorded here as a design commitment, not implemented by this ADR's own gates: an ordered view over one
`CorrelationGroup`'s members, built only after G2.0–G2.3 land. It must preserve:

- **timestamp ordering** as the primary key, with `timestamp_precision` carried through so skew is visible;
- **branches** — process lineage is a tree/DAG (one parent, many children), so the sequence is a DAG, never
  forced into a single line;
- **gaps** — missing telemetry between two structurally-linked nodes is an explicit gap marker; structural
  links are pairwise-observed only, so no link (and no ordering claim) is ever fabricated across a gap;
- **parallel/uncertain ordering** — ties, or nodes whose relative order is not determinable from the available
  timestamps/precision, remain explicitly parallel/unordered rather than an invented sequence;
- **no maliciousness assertion** — a `BehavioralSequence` presents structure, never a verdict; it carries no
  actor field, no "attack" label, and no confidence/likelihood value anywhere on it.

## Implementation gates

Small, independently testable gates, mirroring the G1.0–G1.3 discipline:

- **G2.0 — Correlation domain contracts.** New `correlation/` package: `errors`, `contracts`
  (`CorrelationLink`, `CorrelationGroup`, `CorrelationBasis`, `CorrelationProvenance`, `LinkClass`,
  `CorrelationDimension`). No engine, no link computation. **Tests:** construction/validation, non-empty
  provenance enforcement, deterministic id/serialization round-trip. **Must NOT:** compute any link; import
  `sources`/`dataplane`; reference any ATT&CK actor/software/campaign object.
- **G2.1 — Structural correlation.** The engine that computes **exactly the three structural dimensions —
  `SHARED_OBSERVATION`, `SAME_PROCESS_ENTITY`, `PROCESS_LINEAGE` — and only those three** — plus
  connected-component group formation over structural edges. **Tests:** positive grouping (lineage chain,
  shared observation); a **required negative test** asserting that observations sharing only `host.id`/
  `user.id` and no structural relationship produce zero merged groups; determinism; idempotent replay;
  provenance; explanation content. **Must NOT:** compute any contextual dimension; introduce temporal
  correlation; reference ATT&CK; emit any score/weight.
- **G2.2 — Contextual associations.** Adds all five contextual dimensions (`SAME_HOST_ID`, `SAME_HOST_NAME`,
  `SAME_USER_ID`, `SAME_USER_NAME`, `SAME_DESTINATION_IP`) as attach-only `CorrelationLink`s carrying
  `uncertainty_note`. **Tests:** contextual links never form or merge groups; a contextual link touching two
  distinct structural groups is stored once and is never interpreted as relating those groups; name-collision
  ambiguity case (same `host.name`, different `host.id`) surfaces both facts without merging. **Must NOT:**
  promote any contextual dimension to structural under any condition; add scoring.
- **G2.3 — Replay integration + golden corpus.** A new fixture (`fixtures/phase2_correlation_scenarios.json`)
  and a replay path mirroring G1.2's pattern (`replay_fixture_through_detection_engine` → feed the resulting
  Evidence/Observations into the G2.1/G2.2 engine); persistence of links/groups through the existing G0.8
  pattern (new indices, idempotent upsert by deterministic id) — no new persistence architecture. **Tests:**
  full end-to-end provenance to raw telemetry; determinism across independent runs; idempotent replay; the
  full positive/negative/contextual-without-merge scenario matrix (§Security/adversarial considerations).
  **Must NOT:** perform attribution; invent persistence beyond the established G0.8 shape.
- **G2.4 — `BehavioralSequence` + temporal configuration.** Derives the ordered DAG view (§BehavioralSequence)
  over an existing group; introduces `TEMPORAL_PROXIMITY` as a contextual (never structural) dimension behind
  a versioned, content-hashed window parameter; adds ATT&CK tactic annotation (never reordering).
  **Tests:** ordering, branching, gaps, parallel/unordered cases, multi-host sequences, tactic annotation
  does not reorder, timestamp/tactic-order disagreement is surfaced not resolved. **Must NOT:** assert
  attack/actor/maliciousness; use group/software/campaign `uses` relationships; add scoring.
- **G2.5 — (Optional, later) Elastic EQL `sequence` as an input signal.** Mirrors the G1.1 Elastic-adapter
  pattern: consume Elastic EQL `sequence` output as a candidate signal, re-expressed as our own
  `CorrelationLink`s with a full, inspectable `CorrelationBasis` — never treated as the finished, authoritative
  chain (per [03](../03-system-data-flow.md)'s existing note on this exact point). **Tests:** offline determinism
  via a mocked/fake client; Elastic-specific fields confined to the adapter, exactly as G1.1's guard tests
  enforce for `elastic_detections/`. **Must NOT:** treat the EQL result as authoritative; bypass
  `CorrelationBasis`/provenance for links sourced this way.

## Alternatives rejected

- **Weighted correlation (numeric edge weights / a correlation "score").** Rejected: reintroduces the exact
  arbitrary-points pattern ADR-0002 exists to forbid, one layer earlier and with none of its safeguards.
- **ATT&CK-based correlation** (grouping by shared technique, or by ATT&CK group/software/campaign
  relationships). Rejected: this *is* attribution, performed without ADR-0002's diagnosticity weighting,
  `Unattributed` floor, or single-technique guard — see §ATT&CK boundary.
- **Host/user-based grouping** (the design's own first draft). Rejected after review: conflates identifier
  reliability with behavioral meaning; a shared host or (especially) a shared administrator/service account
  routinely spans large volumes of genuinely unrelated activity — see §Problem statement and §7.
- **Temporal-only grouping** (grouping purely by proximity in time, with no structural relationship).
  Rejected as a *group-forming* mechanism: proximity alone is noise on any moderately busy host; retained only
  as a later, contextual, versioned-window signal for *ordering* an already-formed group (G2.4), never for
  forming one.
- **Elastic EQL `sequence` as the authoritative chain.** Rejected as primary: doc 03 already establishes that
  Elastic's native correlation is consumed only as one input signal, re-expressed with this project's own
  inspectable edges and basis, so results stay explainable and testable independent of Elastic's internals
  (kept as optional G2.5, not the core mechanism).
- **An overly large domain model** (adding `EvidenceCluster` alongside `CorrelationGroup`, or a full
  `BehavioralFeature`-equivalent inside Phase 2). Rejected: `EvidenceCluster` would be a second grouping
  abstraction for one concept; `BehavioralFeature`-style discriminating-power vectors are attribution
  machinery (ADR-0002 D3) and do not belong in a layer that must perform no attribution (§Decision D10).

## Security / adversarial considerations

- **Busy hosts** (many concurrent, unrelated processes) — cannot produce a merged group: `SAME_HOST_ID`/
  `SAME_HOST_NAME` are contextual-only under every condition (§7–8); a busy host yields as many groups as its
  actual lineage/entity structure dictates, plus a dense web of contextual host links that never merges them.
- **Administrator accounts** — `SAME_USER_ID`/`SAME_USER_NAME` are contextual-only; an admin's many daily
  actions form only as many groups as their real causal structure, never one group by virtue of the account.
- **Service accounts** — the sharpest instance of the same risk, since these identities are shared by design;
  treated identically to the administrator case, not as a special exception.
- **Shared infrastructure** (CDN/NAT/common egress) — `SAME_DESTINATION_IP` is contextual-only and explicitly
  flagged in its `uncertainty_note`; never forms or merges a group.
- **Unrelated simultaneous activity on one host** — simultaneity plus co-residence alone satisfies no
  structural dimension; structurally impossible to merge under this design.
- **Process-name masquerading** — structural links use `entity_id`, which in-telemetry name spoofing cannot
  forge; `process.name` sameness is not itself a correlation dimension at all (name-based host/user matching
  is contextual and explicitly flagged; process *name* matching between two different processes was never
  proposed as a dimension in this design).
- **Missing telemetry / event loss** — structural links are pairwise-observed only; no link (and, later, no
  sequence edge) is ever inferred transitively across a missing node — a gap is surfaced explicitly (G2.4),
  never bridged.
- **Clock skew** — no structural dimension depends on timestamps; ordering (G2.4) carries
  `timestamp_precision` and falls back to parallel/unordered under skew or tied precision rather than forcing
  an order.
- **Replay duplicates** — deterministic ids + idempotent persistence (§Determinism and idempotency) mean
  re-ingesting the same telemetry produces the same links/groups, never duplicates — directly serving CR-1.
- **Deliberate attacker imitation** — this layer has no actor model and no technique-rarity input, so imitating
  a known actor's TTPs creates no special correlation signal; imitation only groups the attacker's own
  telemetry by the same causal facts as any other activity. Attribution-level imitation defenses (ADR-0002
  D10/D21) are unaffected and unbypassed by anything in this layer, because this layer never reasons about
  actors at all.

## Relationship to ADR-0001 and ADR-0002

This ADR implements the **stage-6 "Correlation" slot** [03](../03-system-data-flow.md) already reserved between
the evidence graph and attribution, and it exists to satisfy one specific, previously-unimplemented
requirement of ADR-0002: **D16/CR-1's de-duplication of correlated evidence**, which the attribution
methodology assumes is available to it but which nothing before this ADR provides. It changes **nothing** in
ADR-0002's scoring methodology, decision rule, candidate generation, or evidence-evaluation factors — those
remain exactly as specified in [07](../07-attribution-scoring-spec.md) and are Phase 3's concern. Concretely, this
ADR hands the future attribution layer two things it needs and nothing it forbids: (1) a deterministic
de-duplication grouping (`CorrelationGroup`, satisfying CR-1) and (2) a structured, fully provenance-backed
view of related activity — with **zero** candidate objects, **zero** likelihood/confidence values, **zero**
scoring vocabulary, and **zero** ATT&CK-actor reasoning anywhere in it, consistent with ADR-0001 D1/D2/D5's
layering (Elastic/detection is data plane; a dedicated, deterministic engine owns each differentiator; ML/
non-deterministic reasoning stays off the correctness path) and ADR-0002 D1/D4 (attribution alone performs
comparative, evidence-first candidate reasoning — correlation supplies its inputs, never its conclusions).

## Consequences

**Positive:** the attribution layer gains exactly the de-duplication input ADR-0002 already assumed it would
have; every correlation conclusion is traceable to a specific field on specific raw telemetry; the
structural/contextual split makes "why grouped" answerable without a score; the layer is source-agnostic from
day one, so a future non-Windows telemetry source needs no correlation-engine changes.

**Negative / costs:** today's synthetic fixtures and the Sysmon adapter under-populate the stable identifiers
(`entity_id`, `host.id`, `user.id`) this layer relies on for its strongest signals, so the G2.3 golden corpus
must be deliberately authored to exercise the structural path, not merely assembled from existing fixtures;
the contextual-only treatment of host/user is a deliberately conservative choice that will, correctly, leave
some real single-host/single-user intrusions represented as multiple small groups rather than one, until
process-lineage telemetry connects them structurally.

**Neutral:** the correlation-config content hash and (later) any temporal window are intentionally
tunable/reversible parameters, exactly like G1.0's rule-pack content hash, without changing this ADR's
structural decisions.

## Alternatives considered for a Phase-2 name

"AttackChain" (used in [03](../03-system-data-flow.md) and [06](../06-evidence-model.md)) was deliberately **not**
adopted as a Phase-2 object name: it pre-asserts "attack," a judgment this layer must never make. The neutral
`CorrelationGroup`/`BehavioralSequence` naming is used instead throughout this ADR and is intended to
supersede "AttackChain" terminology in any future implementation, without requiring an edit to docs 03/06
themselves (their content remains valid as data-flow/entity-model documentation; this ADR's naming applies
going forward for actual implementation).

## Follow-up

**Accepted 2026-09-15**, as recorded above — no decision was modified at acceptance (unlike ADR-0001 D8/M1 or
ADR-0002 D22/M2, this ADR required no in-flight correction; the one substantive correction, D2, was already
incorporated into the design before it was drafted and reviewed — see the acceptance rationale). `correlation/`
package code may still not be written yet: that gate is now G2.0's own start, a separate, later step from this
ADR's acceptance (§Implementation gates), not a re-statement of pre-acceptance pending status. The docs/03 ·
docs/06 "AttackChain" terminology synchronization (§Alternatives considered for a Phase-2 name) also remains
outstanding and is not resolved by this acceptance.

**G2.5 status (clarified 2026-09-16, after G2.0–G2.4.3 were all implemented and checkpointed):** G2.5 remains
exactly as originally specified above — **"(Optional, later)"** — with that optionality now made explicit
rather than merely implied: G2.5 is **deferred** (not scheduled as part of any currently active gate),
**non-blocking for Phase 2 completion** (every other Phase 2 gate, G2.0–G2.4.3, is independent of it and does
not require it), and **not a prerequisite for Phase 3** (the future attribution layer consumes
`CorrelationGroup`/`BehavioralSequence` output regardless of which upstream mechanism produced the underlying
`CorrelationLink`s — G2.5 would only ever be one additional, optional input signal alongside the existing
telemetry sources, never a required one, per its own §Implementation gates text above). This is a
confirmation of already-decided optionality, not a new decision; G2.5's scope, boundary, and Must-NOT list
above are unchanged.

---

## Amendment A (2026-09-25) — Process interaction: remote-thread injection is structural, process access is contextual

- **Status:** ACCEPTED (2026-09-25, owner) — design only; implementation is a later gate.
- **Trigger:** ADR-0008 Wave 1 batch B added Sysmon 8 (CreateRemoteThread) and 10 (ProcessAccess), which
  record one process instance acting on another (`Observation.process` = actor, `Observation.target_process` =
  acted upon, both with collector-asserted process GUIDs). The existing three structural dimensions cannot
  express this. On the real OTRF sample, `mavinject.exe` injects a thread into `notepad.exe` (start
  `KERNEL32!LoadLibraryW`), and Notepad's subsequent activity would not join the injector's attribution unit.

**A1 — New structural dimension `PROCESS_INTERACTION` (remote-thread injection only).** Two Observations are
linked when one is a remote-thread-creation event whose `target_process.entity_id` equals the other's
`process.entity_id`. It passes this ADR's structural test (§Structural dimensions): the operating system,
through the sensor, asserts that code from the source instance began executing inside the target instance —
a direct causal act between two specific execution instances, like `PROCESS_LINEAGE`. Directional: the basis
records the injecting Observation first. The injector side needs no new rule — the event's own
`process.entity_id` already links it through `SAME_PROCESS_ENTITY`.

**A2 — Causality bound (not a tuned threshold).** A target-side Observation is linked only if its timestamp is
**at or after** the injection event's timestamp. The injected process's earlier activity was not caused by the
injection and must not be pulled into the injector's group. Equal timestamps are linked (the sensor's own
ordering resolution); this is a causal rule with no free parameter.

**A3 — Identifiers required.** Both `process.entity_id` (source) and `target_process.entity_id` must be present
and non-empty; a pid-only event forms no link (pids are reused — the same reason ADR-0003 already rejects pid
matching).

**A4 — Process access (`ProcessAccess`, Sysmon 10) is contextual only.** Opening a handle to another process
is extremely common benign behaviour (in two small real samples, 309 events — mostly `svchost.exe` touching
unrelated processes). Making it group-forming would merge unrelated activity into single units and degrade
attribution. It is therefore a new **contextual, attach-only** dimension `PROCESS_ACCESS_TARGET`, recorded in
the explanation but never used to form or merge a group. Suspicious access (e.g. to `lsass.exe`) is already
represented as *evidence* by detection content; correlation does not need to treat it as structure.

**A5 — Vocabulary change.** `LinkClass` grows from nine to eleven members: `PROCESS_INTERACTION`
(structural) and `PROCESS_ACCESS_TARGET` (contextual). Structural classes become four. This is a closed,
versioned vocabulary change; stored links remain valid (their classes are unchanged).

**A6 — Validation required at implementation.** Tests must show: the real OTRF injection chain
(PowerShell → mavinject → Notepad) forms one group through `PROCESS_LINEAGE` + `PROCESS_INTERACTION`; Notepad
activity before the injection time stays out; a pid-only remote thread forms no link; process-access events
never merge groups; determinism and idempotency hold as for the existing dimensions.

**Known limitation (recorded).** Injection into a long-lived shared host process (e.g. `explorer.exe`) links
all of that process's *later* activity, including benign activity, to the injector — the same class of risk as
the existing long-lived-process limitation (§Known limitations). No window or cap is added now; if the corpus
shows this degrades group quality, a fix follows the same evidence-justified, versioned-configuration rule.

**A7 — Clarification at implementation: the witness need not be Evidence (2026-09-25).** Correlation
operates on Evidence-bearing Observations, but on real telemetry the remote-thread event itself is rarely
Evidence: on the OTRF mavinject sample the production Sigma pack fires only on the mavinject process
creation, not on the Sysmon 8 event. A1 is therefore implemented on *process instances*: a remote-thread
Observation — whether it is Evidence or a caller-supplied `context_observations` entry (telemetry no rule
fired on) — **attests** S→T, and Evidence on S is linked to Evidence on T that is not confidently before the
injection. The witness is recorded in the link's `provenance.source_observation_ids` and never becomes a
group member. Links are one hop only (never transitive through other instances). The same witness rule
applies to contextual `PROCESS_ACCESS_TARGET`.

**Implementation record (2026-09-25).**

- *Code:* `LinkClass` gains `PROCESS_INTERACTION` (structural) and `PROCESS_ACCESS_TARGET` (contextual) —
  eleven members, four structural (A5). `correlate_structurally` and `contextualize` take optional
  `context_observations`; method versions `structural-correlation 1.1`, `contextual-correlation 1.1`. The
  replay correlation pipeline passes every Observation that produced no Evidence as a witness.
- *Causality bound (A2), exactly:* a target-side Observation is excluded only when it is **confidently
  before** the injection — compared at the two timestamps' common declared precision (ADR-0004 D6's
  granularity table); raw comparison when a precision is undeclared. Equal and precision-tied timestamps
  are linked.
- *Scope of A2 (recorded precisely):* A2 governs which `PROCESS_INTERACTION` links exist. It does not
  override `SAME_PROCESS_ENTITY`, which links every Evidence item of one instance regardless of time. So
  pre-injection target activity joins the group **only** when post-injection target Evidence exists (it is
  then the same instance, by that dimension's unconditional rule); pre-injection activity alone never joins.
- *Validation (A6), all passing (18 tests):* synthetic link, direction and basis; A2 exclusion, equality
  and precision ties; A3 (missing target, pid-only source or target, no host scope, non-remote-thread
  event); host scoping; one hop only; determinism/idempotency under input reordering; access never forms
  or merges a group but attaches to existing groups. **Real OTRF mavinject → notepad:** the Sysmon 8
  witness links the detected mavinject process creation to notepad loading the injected
  `C:\ProgramData\T1055.dll` 15 ms after the thread (test Evidence on real telemetry — no production rule
  fires on that load); notepad's start-up activity 7 s before the injection stays out; mavinject's two
  handle opens on notepad are attached as `PROCESS_ACCESS_TARGET` context only.
- *Recorded limitations:* (1) the behavioral-sequence engine (ADR-0004) has no injection ordering basis,
  so a group joined by `PROCESS_INTERACTION` gets no edge between injector and target steps (pinned by a
  test); adding one is an ADR-0004 amendment, deferred until a corpus case needs it. (2) The long-lived
  shared host process risk stated above remains.

## Amendment B (2026-09-25) — Process identity for pid-only telemetry (PROPOSED)

- **Status:** ACCEPTED (2026-09-25, owner delegation "whatever is recommended, go ahead"; required by the
  real-recording measurement below). Implementation in progress — see the implementation record.
- **Trigger:** PowerShell 4103/4104 (ADR-0008) identify the host process by pid only. Under ADR-0003 they
  form no structural link, so a malicious script block cannot join the process tree that launched it.
- **B1 — Resolve, do not match.** A pid-only Observation is never compared to another by pid. Instead a
  deterministic resolution step binds `(host scope, pid, timestamp)` to one process instance GUID when,
  and only when, the telemetry proves that instance was the pid's owner at that time: a process-start
  (Sysmon 1) with that pid at or before the timestamp, and a process-end (Sysmon 5) for that instance after
  it — or no later start of the same pid on that host and no end before it within the same continuous
  telemetry window. Anything short of that proof leaves the Observation unresolved (fail closed).
- **B2 — Provenance.** A resolved identity is recorded as resolved (with the Sysmon Observation ids that
  proved it), never presented as collector-asserted.
- **B3 — Prerequisite.** Sysmon 5 (process terminated) must be supported first; without end events a
  pid-reuse gap cannot be excluded.

**Amendment B — evidence from real recordings (2026-09-25).** Measured on OTRF's APT3 CALDERA recording
(63,412 Observations, full pipeline, production Sigma pack, D3 precedence applied): 18,314 Evidence items, of
which **18,074 (98.7 %) come from PowerShell logging events — none with a process GUID**. Each such event forms
its own single-Observation group, so the attack splits into **9,034 correlation groups, 9,031 of them one
Observation** (only 3 groups join more than one Observation). The flood is real, correct content firing on the
CALDERA agent's polling loop (two `ps_module` rules, 8,984 detections each). Without B1 the attribution unit
for real PowerShell-heavy intrusions is meaningless. Every corpus recording carries Sysmon 5 (process
terminated) events (81–607 each), which B1/B3 need. Amendment B is therefore promoted from optional to
**required before corpus v2 families are built**.

**Amendment B implementation record, part 1 — the resolver (2026-09-25).**

- *Sysmon 5* (process terminated) is supported: `event.category` process, `event.type` end, action
  `process_end`, with the instance's `ProcessGuid`/pid (ADR-0008; `sigma-field-map/8` adds the Sigma
  `process_termination` scope — the pinned release has no importable rule for it yet, so coverage is unchanged).
- *Resolver:* `correlation/process_identity.py` — `resolve_process_identities(observations)` implements B1
  exactly: the latest process start on the same host with that pid not confidently after the event must be
  confidently later than every other such start (else `AMBIGUOUS_START`); its end, if any, must not be
  confidently before the event (else `ENDED_BEFORE`); with no end, the binding is accepted only when the host's
  telemetry records process ends at all (else `NO_END_COVERAGE`). Timestamps are compared at their common
  declared precision (ADR-0004 D6). B2: each resolution carries its basis (`start_and_end` /
  `start_not_ended`) and the Observation ids that prove it; Observations are never rewritten, so a resolved
  identity can never pass for a collector-asserted one. Source-agnostic; pure; deterministic.
- *Real-data validation* (the resolver never reads the process image, so the owner image is an independent
  check): APT3 CALDERA — 12,659 of 12,679 PowerShell events resolved (99.8 %), **all** to `powershell.exe`
  instances, the ~9,000 fragments collapsing onto 108 process instances (the two CALDERA agent processes carry
  4,887 and 4,538 events); APT3 Empire — 15,530 of 15,772 (98.5 %), all to `powershell.exe`. Refusals are
  explicit (`no_start` 20 / 242: no recorded start for that pid). Security pid-only events resolve too
  (CALDERA 446 of 492; Empire 1,990 of 4,244 — many 4624 logons belong to processes started before recording).
- *Tests:* 13 (every proof rule and refusal, pid reuse, precision ties, host scoping, determinism, Sysmon 5
  golden record, and the real CALDERA check when the cache is present).
- *Not yet wired into correlation* — that needs Amendment C first.

## Amendment C (2026-09-25) — Scalable link materialization for equivalence relations (PROPOSED)

- **Status:** ACCEPTED and IMPLEMENTED (2026-09-25, owner delegation) — see the record below.
- **Trigger:** `SAME_PROCESS_ENTITY` and the contextual same-value dimensions (`SAME_HOST_*`, `SAME_USER_*`,
  `SAME_DESTINATION_IP`) are equivalence relations materialized today as **every pair**; ADR-0004's sequence
  engine requires that full pairwise closure and compares every pair. On real data this is infeasible: one
  resolved CALDERA agent process carries ≈9,000 Observations (≈18,000 Evidence items) → ≈1.6 × 10⁸
  `SAME_PROCESS_ENTITY` links, and `SAME_HOST_NAME` over one host is the same order.
- **C1 — Chain materialization.** For an equivalence relation, the members of each class are ordered by
  (`timestamp`, `observation_id`, `evidence_id`) and only **consecutive** members are linked: *n − 1* links per
  class, each still a true, directly observed pairwise fact. Connectivity — and therefore every group's
  membership and `group_id` (computed from members alone) — is identical to the pairwise form. Non-equivalence
  relations (`PROCESS_LINEAGE`, `PROCESS_INTERACTION`, `SHARED_OBSERVATION`) are unchanged.
- **C2 — Resolved identities (Amendment B wiring).** A pid-only node resolved by B1 joins its instance's
  `SAME_PROCESS_ENTITY` class. A link with a resolved endpoint records `field_path` `process.pid` (not
  `process.entity_id`) and carries the proof Observation ids in its provenance, so explanations always show that
  the identity was proved, not asserted. Resolved nodes also serve as `PROCESS_INTERACTION` targets/sources.
- **C3 — Sequence engine (ADR-0004 amendment).** `TEMPORAL_SAME_ENTITY` ordering takes a class as the connected
  component of its same-entity links (no longer requiring the pairwise closure), sorts its steps by timestamp and
  forms tie buckets by ADR-0004 D6's precision-aware comparison, emitting the same Hasse-reduced consecutive
  edges and tie gaps as today; a non-transitive tie still fails closed. Output for existing (small) inputs is
  unchanged; only the verification step changes.
- **C4 — Contextual attachment.** With chained contextual links each member is touched by at most two links of a
  dimension, so a group's `contextual_link_ids` name representative neighbours rather than every pair — the
  explanation "shares host X with …" stays true; contextual links remain attach-only.
- **Validation required:** group memberships and ids identical to the pairwise form on every existing corpus and
  test; sequence outputs unchanged on existing fixtures; the real APT3 recordings correlate within bounded time
  and memory, and the resulting unit count is reported.

**Amendments B (part 2) and C — implementation record (2026-09-25).**

- *Wiring (B/C2):* `correlate_structurally` resolves pid-only identities from the Evidence and context
  Observations it is given (`correlation/process_identity.py`) and places a resolved node in its instance's
  `SAME_PROCESS_ENTITY` class; links with a resolved endpoint record `field_path` `process.pid` and carry the
  proof Observation ids. `structural-correlation 1.2`, `contextual-correlation 1.2`.
- *Chain materialization (C1/C4):* `SAME_PROCESS_ENTITY` and the contextual same-value dimensions link
  consecutive members in (`timestamp`, `observation_id`, `evidence_id`) order. **Instance-level relations**
  (`PROCESS_LINEAGE`, `PROCESS_INTERACTION`, `PROCESS_ACCESS_TARGET`) link one fact once: from the source
  instance's first chain member to the child Observation's first Evidence / the target's first member not
  confidently before the attesting event. Recorded semantic consequence: a lineage edge is anchored at the
  parent's **earliest** observed step — the telemetry never says which later step of the parent created the
  child, so no per-step lineage edge is claimed (test `test_d_genuine_convergence_two_distinct_parents` updated).
  `SHARED_OBSERVATION` stays pairwise (bounded by one event's techniques).
- *Latent defect removed:* under pairwise materialization, **any** process with two Observations that each
  matched two rules (e.g. T1059 + T1059.001 — routine on real data) produced several links for one step pair and
  the sequence engine refused the unit ("ambiguous grounding"). The chain gives exactly one link per step pair;
  the engine's own guard is kept and still tested with hand-built duplicate links.
- *Sequence engine (C3):* verifies the chain (every consecutive step pair grounded; extra links tolerated) instead
  of the full pairwise closure; ties are sought only within the coarsest declared granularity (1 s — exact, since
  truncation cannot tie timestamps further apart); buckets must be contiguous and pairwise tied (else fail
  closed); edges cite the chain link crossing the bucket boundary, gaps the link into the later tied step.
  Identical output for strictly ordered steps. The contract's cycle check is now iterative (a real 9,000-step
  chain exceeded Python's recursion limit). Group assembly and contextual attachment are indexed (no
  groups × links scans).
- *Group identity preserved:* `group_id` depends only on membership, which chain connectivity leaves unchanged;
  the frozen corpus v1 rebuilds with the same identity. Updated tests pin link *cardinality* only (chains instead
  of all pairs, "connected by" instead of "directly linked"); every protected property (no merge, attachment to
  both groups, fail-closed guards) is still asserted. 1,695 tests pass.
- *Real-data result (full pipeline: adapters → D3 precedence → Sigma → Evidence → structural + contextual
  correlation → behavioral sequences):*

  | Recording | Before B/C | After B/C | Time |
  |---|---|---|---|
  | APT3 CALDERA (63,558 obs, 18,314 Evidence) | 9,034 groups (9,031 single-Observation) | **29** — the two CALDERA agent chains (9,045 / 9,018 Evidence: T1003.001/.002/.004/.005/.006, T1021.006, T1106, …) and two PowerShell persistence chains (T1053.005, T1098, T1685.001) | ≈2 min |
  | APT3 Empire (87,044 obs, 33 Evidence) | — | **4** — the main HR001 chain: PowerShell → `whoami`, `ftp` (T1033, T1059.001, T1202, T1685) | ≈2 min |

  The 22 remaining small CALDERA units are single `cmd.exe`/PowerShell Observations whose process has no other
  evidence — genuine singletons, not fragmentation.

## Amendment D (2026-09-30) — Fixed-length member-set identifiers

**Status:** Accepted. Found by the first live Elasticsearch verification (ADR-0009 Amendment B).

**Problem (observed, not hypothetical).** `compute_group_id` joined one SHA-256 digest per member Evidence
(`corr-group::<h1>::<h2>::…`); `compute_step_id`, `compute_sequence_id` and
`compute_sequence_parallel_group_id` did the same per member step / branch. Id length therefore grew linearly
with unit size. On real telemetry the APT3 Empire main unit's `group_id` was 1,396 bytes, and the largest
group id in the corpus v2 inventory was **596,980 characters** (a 9,000-Evidence CALDERA chain). Elasticsearch
rejects document ids over 512 bytes (`action_request_validation_exception`), so no large unit could be
persisted; such ids would also exceed the 32,766-byte keyword-term limit and any sane URL length for the
read-model API. The in-memory test client accepted them, which is why only the live cluster exposed it.

**Decision.** Each member list is reduced to **one** digest:
`member_set_digest = SHA-256( concat( SHA-256(member) for member in sorted(set(members)) ) )`.

- `group_id = corr-group::<member_set_digest(evidence_ids)>[::method_content_hash]` — 76 characters without, 142
  with the method hash, whatever the group size.
- `step_id = behavioral-step::<H(group_id)>::<member_set_digest(evidence_ids)>`;
  `sequence_id = behavioral-sequence::<H(group_id)>::<member_set_digest(step_ids)>[::method_content_hash]`;
  a parallel group's branch tokens (already one digest per branch) are reduced the same way.

**Properties preserved.** Determinism and order-independence (sorted, de-duplicated input); the `"::"`
delimiter-collision fix of G2.0 (each per-member digest is exactly 64 hex characters, so the concatenation is
unambiguous and two different member sets map to different digests up to a SHA-256 collision); membership-only
identity (still true — Amendment C's "group identity preserved" holds for the new format). All other ids
(links, edges, gaps, hypotheses, assessments, attribution-layer ids) were audited: each is built from a fixed
number of digests and is unchanged.

**Consequences.** Every group/step/sequence id changes format once. Nothing downstream parses ids. The corpus v2
inventory (`data/calibration/corpus/v2/inventory/`), the only stored artefact holding real group ids, is
regenerated (largest group id now 76 characters). Annotations key units by anchor Observation, not id: re-running
the labelling gives the identical set of (anchor, label / exclusion reason) entries for every recording — only
the `-uN` numbering of equal-sized *excluded* APT29 units permutes, because the inventory breaks size ties by
group id. The rebuilt corpus (`calibration-corpus-version::25531bf9…`, 14 cases) has the unchanged readiness
verdict: not ready, the same six violations. The test
`test_member_set_ids_have_a_fixed_length_whatever_the_member_count` pins the length independence.

## Amendment E (2026-10-01) — Process identity requires the acting principal to be the process's own (B3)

**Status:** Accepted (owner delegation: "whatever is recommended, go ahead").

**Problem (measured, latent).** Amendment B binds any pid-only Observation to the process instance that owned
the pid (B1). Windows Security events record the *acting* account (`Subject*`) beside the process that performed
the operation, and for service processes the two differ: the service impersonates the client it serves. On the
four OTRF attack recordings, **2,042** Security Observations resolved to such a shared service instance acting
for another account — e.g. 180 object-access events of `WmiPrvSE.exe` (NETWORK SERVICE) serving `pgustavo`
(APT3 CALDERA), 761 privileged-service events of `svchost.exe` (SYSTEM) serving `dschrute` (APT29 day 2), and
`lsass.exe` serving `pbeesly` / `dschrute`. Few carried Evidence yet, so no unit had been merged wrongly; but any
rule firing on them would have grouped unrelated principals' activity under one "same process instance" —
exactly the hub merge §6 forbids for hosts and users. Domain-controller events (`lsass.exe` serving a remote
client) are refused today only because the DC's lsass start was never recorded; a recording that captured a DC
boot would have glued every client's reconnaissance together.

**Decision (B3).** A pid-only Observation is bound to the instance B1 selects only if its acting principal is
consistent with the instance owner (the `user` of the proving process-start Observation). Consistent when:
either principal is unknown or logged as `-` (nothing proves impersonation — e.g. PowerShell logging, which
records only a SID); the account names are equal (case-insensitive); or the owner is a built-in service account
(SYSTEM, LOCAL SERVICE, NETWORK SERVICE) and the event names the host's own machine account `HOST$` — the same
identity in its network form, which is how Windows logs SYSTEM's own actions. Otherwise the Observation stays
unresolved with the new reason `PRINCIPAL_MISMATCH`, and it forms no structural link. Source-agnostic: only
`user`, `host` and `process` are read. `PROCESS_IDENTITY_METHOD_VERSION` 1.0 → 1.1.

**Why this is the right line.** Structural means "same instance of execution" (§5). A service thread executing
on behalf of another principal is that principal's request, not a continuation of the service's own behavior;
the service instance is a *container* for many principals' requests — the contextual case. The rule is
conservative in the safe direction: it only removes bindings, never adds one, and it never infers a principal.

**What it keeps.** The APT29 day-2 explicit-credential logons (4648) by `dschrute`'s `powershell.exe` still
bind to that process (same principal) and stay in the lateral-movement unit; SYSTEM's own actions logged as
`HOST$` (16,442 Observations on the four recordings) and 17 with no acting account logged still bind.

**Measured effect.** Refused as `PRINCIPAL_MISMATCH`: APT3 CALDERA 186, Empire 13, APT29 day 1 140, day 2
1,703. Every corpus v2 unit is unchanged (by anchor and Evidence count), labels are identical and the readiness
verdict is unchanged — the rule removes latent hub bindings; none had yet merged a unit.

**Not decided here — for the owner.** Domain-controller events (Kerberos 4768/4769/4771, SAM / directory
access 4661/4662, network logons, share access) have no client-side process this telemetry can prove: the
client's network requests are made by `lsass` / the kernel, which are hubs themselves. They therefore stay
outside units, and a single-Evidence Observation forms no group (§8), so e.g. a lone Kerberoasting detection is
not attribution-visible. Whether a lone Evidence should become a unit of its own is an attribution-semantics
decision (it changes what `support(h)` counts), recorded as an open question rather than taken silently.
