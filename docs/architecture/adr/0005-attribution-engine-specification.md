# ADR-0005 — Attribution Engine Specification (Phase 3)

- **Status:** ACCEPTED
- **Date:** 2026-09-16 (proposed)
- **Deciders:** project owner (pending review)
- **Supersedes / superseded by:** —
- **Related:** [ADR-0001](0001-evidence-graph-core-architecture.md) ·
  [ADR-0002](0002-attribution-scoring-and-evidence-methodology.md) ·
  [ADR-0003](0003-correlation-and-behavioral-chain-layer.md) ·
  [ADR-0004](0004-behavioral-sequence-reconstruction.md) ·
  [06 evidence model](../06-evidence-model.md) · [07 scoring spec](../07-attribution-scoring-spec.md) ·
  [08 validation & calibration](../08-validation-and-calibration.md) ·
  [10 final architecture review](../10-final-architecture-review.md)

> The decisions below (D1–D21) are **PROPOSED**, not yet accepted. This ADR resolves the architectural
> prerequisites the final architecture review ([10](../10-final-architecture-review.md)) named as blocking
> Phase 3 — the combination-diagnosticity/evidence-independence algorithm (**C3.1**, D-3/M4), the coverage
> model (D-2/M3, never written for either Phase 2 or Phase 3), and the reconciliation of docs
> [06](../06-evidence-model.md)/[07](../07-attribution-scoring-spec.md)/[08](../08-validation-and-calibration.md)'s
> entity model — written before ADR-0003/0004 existed — against the real, accepted Phase 0–2 domain model. It
> does **not** re-decide anything ADR-0002 already accepted (D1–D22): every decision below is either a direct
> application of an already-accepted ADR-0002/doc-07/doc-08 rule to the real Phase 0–2 objects, or an explicit
> resolution of a gap those documents themselves named as open (D-3, D-4, D-2) without inventing a decision
> those documents leave to calibration (§D17). This ADR does **not** satisfy C3.2 (calibration corpus) or
> C3.3 (blind-actor-holdout apparatus) — those remain implementation/validation work, tracked in
> §Implementation Gates, not resolved by drafting this document.

## Context

Phase 2 (ADR-0003/ADR-0004, both ACCEPTED, all gates G2.0–G2.4.3 checkpointed — see the Phase 2 closure commit
`0b3c9df`) delivers exactly two things to Phase 3, per ADR-0003 D10 and ADR-0004 D17: a deterministic
de-duplication grouping (`CorrelationGroup`) and a structured, fully provenance-backed behavioral view
(`BehavioralSequence`) — "nothing it forbids." Phase 3's own methodology (ADR-0002, ACCEPTED 2026-09-11) was
written and accepted *before* Phase 2's concrete domain model existed, against a design sketch (docs
06/07/08, all still **Status: PROPOSED**) that used different, never-implemented entity names
(`RawEvent`/`TechniqueAssertion`/`BehavioralFeature`). ADR-0003 itself already anticipated this: it explicitly
rejected building `BehavioralFeature` as a Phase-2 object, calling it "attribution machinery [that] belongs to
Phase 3, not here." This ADR is that deferred work: it takes ADR-0002's already-accepted *decisions* (D1–D22)
as fixed and binding, and defines the concrete Phase-3-owned domain model, algorithms, and boundaries needed
to implement them against the *real* `CorrelationGroup`/`BehavioralSequence`/`Evidence`/`Observation` objects
Phase 0–2 actually built — resolving the final architecture review's own named blockers (D-2, D-3) in the
process.

**What this ADR is not:** it does not reopen ADR-0001/0002/0003/0004; it does not choose calibration values
(every threshold ADR-0002/doc-07 already marks as a `calibration_version` parameter remains one here); it does
not build the validation corpus or the blind-actor-holdout harness (C3.2/C3.3 remain separate, later gates);
it does not write code.

## Decision

### D1 — Attribution unit

**One `CorrelationGroup` is exactly one attribution unit, producing exactly one `AttributionResult`.**

- Each `CorrelationGroup` has exactly one `BehavioralSequence` (already guaranteed 1:1 by ADR-0004 D1); an
  `AttributionResult` is computed from that one group and its one sequence, never from a set of groups.
- **Phase 3 MUST NOT merge `CorrelationGroup`s.** No cross-group attribution object exists in this ADR. If two
  groups happen to be attributed to the same candidate actor, that is two independent `AttributionResult`s
  that happen to agree — never a merged third object. Recognizing that as "one campaign" across groups is
  explicitly out of scope for this ADR (§Non-goals) — a future, separately-justified gate, not invented here.
- **Phase 3 MUST NOT mutate any Phase 2 object.** `CorrelationGroup`, `BehavioralSequence`, `CorrelationLink`,
  `Evidence`, `Observation` are frozen dataclasses; Phase 3 objects only ever *reference* their ids, exactly
  as `CorrelationGroup` itself references `CorrelationLink` ids rather than embedding link objects (G2.0's own
  stated rationale, reused here without modification).
- **Why this preserves CR-1.** ADR-0003's CR-1 de-duplication unit *is* `CorrelationGroup` — "these Evidence
  items arose from a chain of observations that... should not be independently counted as separate
  corroborating behaviors." Attributing at any finer grain (e.g. per-`Evidence` or per-`BehavioralStep`) would
  let one causally-connected behavior be scored as if it were several independent behaviors, reopening exactly
  the double-counting failure CR-1 exists to prevent — one layer up, at the attribution layer instead of the
  correlation layer. Attributing at any coarser grain (merging groups) would require inventing a new
  de-duplication unit ADR-0003/0004 never defined and could silently attribute unrelated activity to one
  hypothesis. One group → one unit is the only choice consistent with CR-1's own stated meaning.

### D2 — Coverage model

**Resolved: a new, Phase-3-owned `CoverageProfile` contract**, the direct implementation of D-2/M3 (doc 10),
answering ADR-0002 D7/D8's own requirement precisely and minimally — not over-engineered:

```
CoverageState (closed, four-value enum):
  OBSERVED_PRESENT                        # the technique was actually observed (Evidence exists)
  OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE  # telemetry could have shown it; it did not appear -> contradiction
  NOT_OBSERVABLE                          # the required data source/component was not collected at all
  UNKNOWN                                 # coverage could not be determined -> fails closed, never assumed

CoverageProfile (frozen, deterministic identity):
  coverage_id: str                  # compute_coverage_profile_id(group_id, technique_stix_id)
  group_id: str                     # the CorrelationGroup (attribution unit) this coverage fact is scoped to
  technique_stix_id: str            # the ATT&CK technique/sub-technique this entry answers for
  attack_kb_version: str            # which pinned KB's data-source/component requirement was checked
  state: CoverageState
  data_sources_required: tuple[str, ...]   # the ATT&CK data source/component names checked (from the pinned KB)
  data_sources_available: tuple[str, ...]  # which of those were actually present in this case's telemetry
  observation_interval: TimeSpan | None    # the case's own observed time window, when a narrower scope applies
  provenance: AttributionProvenance        # derived_from: the case's own Observation.raw_reference sources
                                            # that established (or failed to establish) each data source
  schema_version: str
```

This satisfies every capability the audit required (technique/sub-technique, data source, availability, an
optional observation interval, a four-way state, provenance, versioning) and adds nothing beyond it — no
per-host/per-sensor topology model, no continuous coverage percentage, no separate "sensor inventory" object.
`CoverageState` is deliberately the same shape discipline every other closed enum in this codebase already
uses (`LinkClass`, `OrderingBasisKind`, `GapReason`): four values, fail-closed default (`UNKNOWN`), no
open-ended text status.

**Where it lives, decided explicitly:**

- **It is an input to the Attribution Engine**, not a Phase 2 output — Phase 2 never computes or needs
  coverage (nothing in ADR-0003/0004 asks "was there adequate telemetry"). It is computed by Phase 3 itself,
  once per `(CorrelationGroup, technique)` pair, from the case's own real `Observation.raw_reference`/`event`
  metadata cross-referenced against the pinned KB's per-technique data-source/component requirements (already
  present on the raw `attack-pattern` STIX objects `AttackKnowledge` loads, unused until now).
- **It is part of attribution provenance** — `CoverageProfile.coverage_id`s are referenced (not duplicated)
  from `ContradictingEvidence`/`AttributionAssessment.confidence` reasons and from `NextEvidence` (§D14), the
  same "store ids, not objects" pattern `CorrelationGroup.structural_link_ids` already established.
- **Persisted independently or embedded — an implementation, not an architecture, decision**, deferred to the
  same choice ADR-0004 D18 already made for `BehavioralSequence`: it may be embedded in the `AttributionResult`
  document (mirroring D18's own reasoning — no independent lifecycle outside the result that computed it) or
  cached separately for reuse across results sharing the same `(group_id, attack_kb_version)` pair, since
  re-deriving it is a pure, deterministic function with no case-specific side effects either way. This ADR
  requires only that its *fields* and *determinism* are as specified above; the storage shape is deferred to
  the implementation gate that builds it.
- Missing-telemetry handling is now precisely wired: `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` →
  `ContradictingEvidence` (lowers likelihood, D7); `NOT_OBSERVABLE`/`UNKNOWN` → coverage gap only (lowers
  confidence, never likelihood, D8) — see §D11.

### D3 — Combination diagnosticity

**This is the algorithm doc 10's D-3/M4 named as the single most important missing piece before Phase 3.**
Resolved below as a deterministic, inspectable, calibration-versioned method — not an invented formula chosen
for convenience, but the *simplest function satisfying every property ADR-0001 D8 and ADR-0002 D3/D6/D16/D18
already require*, with every free parameter explicitly left to calibration rather than guessed here.

**Atomic feature.** One technique or software id `x` (a real STIX id from `Evidence.attack_ref`/
`BehavioralStep.technique_stix_ids`).

**Prevalence `g(x)`:**

```
g(x) = |{ active groups in the pinned KB whose uses-profile contains x }|
       ------------------------------------------------------------------
       |{ active groups in the pinned KB }|
```

- **Domain:** `g(x) ∈ [0, 1]`. `x` ranges over technique STIX ids *and* software (malware/tool) STIX ids —
  the identical function, over the identical KB `uses` relationship data, per ADR-0001 D8-as-modified/M1
  ("software-extended") and ADR-0002 D18/CR-4 ("prevalence extends to software").
- **"Active" is load-bearing and new:** only non-`revoked`, non-`x_mitre_deprecated` groups count in *both*
  numerator and denominator — resolving the gap the Phase 3 audit found (the ATT&CK loader currently exposes
  revoked/deprecated objects unfiltered; this ADR requires the traversal layer in §D6 to filter them,
  deterministically, from every prevalence computation).
- **Edge case — `x` has zero resolvable `uses` relationships at all:** `g(x)` is **undefined**, not `0`. This
  is the single most dangerous boundary value for the `1 − g(x)` formulation — an undefined `g(x)` silently
  treated as `0` would produce `D(x)=1` (maximum, false discrimination) from the mere *absence* of resolvable
  data, not from any genuine rarity signal. It is therefore handled **fail-closed regardless of the underlying
  cause** (sparse ATT&CK documentation, a malformed relationship, a not-yet-ingested object — this ADR does not
  attempt to distinguish among them): `g(x)` is never treated as `0`, and the neutral-prior fallback below
  applies unconditionally whenever it is undefined.

**Atomic diagnosticity:**

```
D(x) = 1 − g(x)
```

- **Domain:** `D(x) ∈ [0, 1]`. Monotonically decreasing in `g(x)` (doc 07 §2 item 3, verbatim requirement,
  operationalizing ADR-0002 D3). `D(x) → 0` as `g(x) → 1` (used by every active group ⇒ zero discrimination —
  exactly doc 07 §2.3's own worked description). `D(x) → 1` as `g(x) → 0` (used by almost no active group ⇒
  maximally discriminating).
- **This is the baseline functional form, not the final calibrated one.** ADR-0002 D14 and doc 07 §2.3
  are explicit that `D`'s *exact shape* is a `calibration_version` parameter, fit on the (not-yet-existing)
  corpus — this ADR fixes `1 − g(x)` as the structurally-required, zero-hand-tuning **default** (it already
  satisfies every stated property with no fitting at all), and calibration (§D17) may later replace it with a
  different monotonically-decreasing, `[0,1]`-bounded transform of `g(x)` if corpus evidence supports one —
  never a differently-*shaped* claim (e.g. never a real-world-frequency claim), only a differently-*curved*
  documentation-relative one.

**Candidate-type invariance (required, explicit rule).** `g(x)`/`D(x)` (and `g(C)`/`D(C)`, below) are
properties of the evidence feature itself, computed exactly once, relative to the **active group population**
defined above — never a property of, or re-scoped to, the candidate being evaluated. The identical `g(x)`/`D(x)`
value is used whether the `Hypothesis` under assessment names a `Group` candidate or a `Campaign` candidate
(§D7): **Campaign candidates do not receive a separate, campaign-relative prevalence denominator**, and none is
computed anywhere in this ADR. Candidate type therefore has no effect on the definition or computation of
diagnosticity — it affects only which `Candidate`/`Hypothesis` rows the resulting `D` value is joined against in
the ACH matrix (§D8). This is not a campaign prior (§D7's "no candidate priors of any kind" is unaffected) and
does not alter `D`'s meaning as a documentation-relative diagnosticity/separation heuristic established above.

**Combination feature.** A set `C = {x1, ..., xk}` of technique/software ids genuinely co-occurring within
one attribution unit (i.e., asserted by distinct `BehavioralStep`s in the same `CorrelationGroup`'s
`BehavioralSequence` — see §D4 for what "distinct" means here).

```
g(C) = |{ active groups whose uses-profile is a superset of C }|
       -------------------------------------------------------
       |{ active groups in the pinned KB }|

D(C) = 1 − g(C)
```

Identical shape to the atomic case, computed over group-profile *intersection* instead of single membership —
the direct, minimal generalization, per ADR-0002 D6's requirement that "distinctive combinations" dominate and
CR-5's caveat that this is a **profile-union approximation**, not literal per-intrusion co-occurrence (stated
explicitly below, not silently assumed away).

**Avoiding double-counting components (required, explicit rule).** `support(h)` (§D8) sums over a
**maximal, non-overlapping partition** of the attribution unit's observed technique/software set into (a)
combination features with a genuinely narrower `g(C) < min(g(x) for x in C)` (i.e. the combination is
*more* discriminating than any of its parts alone — otherwise it is not a real combination signal, just a
looser grouping), and (b) atomic features for everything not claimed by any such combination. A technique
already credited as a member of a scored combination is **never also separately scored as an atomic feature**
— exactly the rule the audit required, stated as a partition constraint rather than an ad hoc subtraction.

**Deterministic partition selection (required, explicit rule).** More than one valid maximal, non-overlapping
partition can satisfy the criterion above for the same observed technique/software set. When this happens, the
partition used to compute `support(h)` is selected deterministically, never left to implementation-defined
iteration order:

1. Prefer the valid partition that **minimizes `Σ g(C)`** summed across its selected combination features `C`
   (i.e. the most-discriminating available grouping, since lower `g(C)` means higher `D(C)`).
2. If multiple partitions remain tied under (1), select the partition whose combination features — each
   canonicalized as a sorted tuple of its member `technique_stix_id`/`software_stix_id`s — sort first under
   lexicographic ordering of those canonical tuples.

This rule exists solely to guarantee a deterministic `support(h)`, and therefore a reproducible
`determinism_hash` (§D16/§D20), across implementations and across repeated runs of identical input. It
introduces no probability, no actor prior, and no analyst-facing score, and it does not change what `D`
means: `D` remains the same documentation-relative diagnosticity/separation heuristic defined above — this
rule only fixes *which* partition is scored when the definition above admits more than one.

**Sequence/kill-chain-order contribution — deliberately capped, per CR-5.** Observed tactic-progression order
(from `BehavioralSequence.edges`, never re-derived or altered — ADR-0004 D16's "no tactic-based ordering"
carries forward unchanged) may contribute a **small, bounded increment** to an *already-established*
combination's `D(C)` when the observed order matches a documented typical progression for the groups sharing
that combination — it is never its own independent, high-`D` feature, and never contributes anything to a
combination that does not already clear the "narrower than its parts" test above. This directly encodes
ADR-0002 D6/D19: "sequence matching is low-weight and flagged" — the cap's exact magnitude is a
`calibration_version` parameter (§D17), not chosen here; what is fixed is that it can only ever be a bounded
*addition* to an existing combination score, never a standalone one.

**Sparse/zero-support and undefined-`g(x)` fallback (required, explicit):** if `g(x)` (or `g(C)`) is
undefined (zero resolvable relationships), or the number of active groups it was computed over falls below a
minimum-support count, `D(x)`/`D(C)` **is not computed from the formula above** — it falls back to a fixed
**neutral prior** (a `calibration_version` constant; not chosen here — see doc 07 §2.7, restated) and the
affected assessment's confidence is capped and flagged "outside validated regime" (§D10, §D19). This is the
same fallback ADR-0002/doc-07 already specify; this ADR only makes precise *when* it triggers (undefined `g`,
or below-minimum-support `g`).

**Documentation bias — represented, not solved (as ADR-0002/ADR-0001 both already concede is the honest
limit):** every `D(x)`/`D(C)` value carried in an `EvidenceAssessment` (§D5/§D8) is stored alongside its own
`g(x)`, the active-group count it was computed over, and `attack_kb_version` — inspectable one hop away from
any score, exactly as doc 07 §2.6 requires. This is the entire mitigation this ADR provides; reporting bias in
the underlying ATT&CK documentation itself is not something any formula can correct, and none is claimed to.

**Worked-case behavior, explicitly traced:**

- *Single generic technique only* (`g(x)` high): `D(x) ≈ 0` for every named candidate that could use it →
  `support(h) ≈ support(Unattributed)` for all → correctly routes to insufficient (doc 07 Example A) — and is
  *additionally, independently* blocked by D20/CR-6's single-technique guard (§D13) regardless of `D`.
- *Distinctive combination* (`g(C)` low): `D(C)` high, dominates `support(h)` for the one or few candidates
  whose profile contains `C` — correctly separates them from `Unattributed` and from other candidates
  (doc 07 Example B).
- *Sparse/incomplete relationship coverage*: neutral-prior fallback (above), never a false-high `D`.

**Why this satisfies ADR-0001 D8 and ADR-0002 D18, explicitly:** `g(x)`/`g(C)` are pure counts over the pinned
KB's own `uses` relationships — they assert nothing about real-world frequency, only about how many
*documented, tracked* group profiles include `x`/`C`; `D` is derived with zero hand-tuning (a count-ratio, not
a fitted-per-actor weight); every input is inspectable; `D` is bounded `[0,1]` and never asserted as a
probability anywhere in this ADR. **`D` and `g` may be shown to an analyst only as an inspectable,
documentation-relative, labeled number in a drill-down explanation ("127 of 180 tracked groups use this
technique → low discriminating weight") — never as a headline percentage, never framed as a probability or
confidence score, and never the sole analyst-facing summary** (doc 07 §2.6 vs. §13, reconciled precisely: §2.6
requires inspectability, §13 forbids headline-probability framing — both hold simultaneously under this rule).

**[Amended 2026-09-17 — see Post-acceptance Amendment A]** `support(h)` additionally **normalizes the aggregate
of these `D(x)`/`D(C)` contributions by candidate profile breadth** (operationalizing ADR-0002 D16, which this
ADR applies rather than re-decides). The `g(x)`/`D(x)`/`g(C)`/`D(C)` definitions above, the active-Group
population, combination admissibility, maximal-partition selection, and the deterministic tie-break are all
**unchanged** by that amendment: profile-breadth normalization is a separate, *candidate-level* aggregation
step applied **once** to `raw_support(h)`, never a change to *feature-level* diagnosticity. See
[Post-acceptance Amendment A](#post-acceptance-amendments) for the full definition.

### D4 — Evidence independence

Two related, both grounded in real Phase 2 objects, neither duplicating the correlation engine:

**Likelihood-independence (feeds `support(h)`, §D3/§D8).** The unit of independent behavioral evidence is one
distinct `BehavioralStep` asserting one technique/software id. Multiple `Evidence` items already collapsed
into one `BehavioralStep` (G2.4.1's `SHARED_OBSERVATION` collapse) are — correctly, already — one unit; this
ADR adds nothing here, it inherits G2.4.1's guarantee unchanged. Two **distinct** `BehavioralStep`s asserting
the same technique (e.g. two separate process instances both using T1059, connected by real
`SequenceEdge`s/`SequenceGap`s) are genuinely two independent behavioral acts, not redundant detections of one
act — CR-1 (D16) de-duplicates "the same underlying behavior," not "repeated use of one technique," so both
contribute independently to `support(h)`. **This can never, by itself, escape D20's single-technique guard**
(§D13) — repeating one technique any number of times is still evidence of only one technique.

**Confidence-independence (corroboration, "Diamond breadth," §D10).** Distinct *evidence types*
(`EvidenceType.BEHAVIORAL`/`EVIDENTIARY`/`PROCEDURAL`/`CONTEXTUAL`, the real, already-implemented G0.3 enum)
agreeing on the same candidate is what raises *confidence* — this is a different independence axis from the
likelihood one above, and the two must never be conflated: a candidate with ten behavioral steps all of the
same `EvidenceType` has high likelihood-independence but low confidence-corroboration; one technique observed
via both behavioral and evidentiary evidence types has the reverse. No new correlation logic is required for
either axis — both are pure, deterministic reads over already-existing `BehavioralStep.evidence_ids` →
`Evidence.evidence_type`, never a re-derivation of what G2.1/G2.2/G2.4.1 already computed.

### D5 — Entity-model reconciliation

Docs 06/07/08's `TechniqueAssertion`/`BehavioralFeature` chain is **not implemented and is not adopted** —
ADR-0003 already explicitly rejected `BehavioralFeature` as Phase-2 scope, and no `TechniqueAssertion` stage
exists anywhere in the real pipeline (`Evidence.attack_ref` already carries a direct, validated technique
reference — a separate assertion object would duplicate it for no new guarantee). The real chain Phase 3
builds on is:

```
raw telemetry → Observation → DetectionResult → Evidence
  → CorrelationLink / CorrelationGroup (G2.1–G2.3)
  → BehavioralSequence { BehavioralStep, SequenceEdge, SequenceGap, SequenceParallelGroup } (G2.4.0–G2.4.3)
  → [NEW, this ADR] CoverageProfile, EvidenceAssessment, Hypothesis, Candidate,
     AttributionAssessment, NextEvidence → AttributionResult
```

Six new, Phase-3-owned contracts (`CoverageProfile` already specified in §D2) — each frozen, each storing ids
into the objects above rather than copying them (the identical discipline `CorrelationGroup`/`BehavioralStep`
already established), each with a deterministic id via the existing SHA-256/`"::"`-join convention
(`compute_link_id`/`compute_group_id`/`compute_step_id` — reused unchanged, never a fourth incompatible id
scheme):

```
Candidate (frozen, deterministic identity, KB-version-scoped — not case-scoped):
  candidate_id: str            # compute_candidate_id(actor_or_campaign_stix_id) — stable across every
                                # AttributionResult that considers it, since it names a KB fact, not a case fact
  actor_ref: str | None        # the canonical (alias-collapsed) intrusion-set STIX id, via §D6
  campaign_ref: str | None     # OR a campaign STIX id — exactly one of actor_ref/campaign_ref is set
  alias_stix_ids: tuple[str, ...]     # every alias id collapsed into this one candidate, via §D6
  attack_kb_version: str
  generation_basis: tuple[str, ...]   # the technique/software stix_ids that placed it in the set (D7)
  schema_version: str
  # sentinel: UNATTRIBUTED_CANDIDATE_ID — a fixed, non-KB-derived constant identifying the null hypothesis;
  # always present in every candidate set (D4/D7).

Hypothesis (frozen, deterministic identity, one per (group, candidate) pair):
  hypothesis_id: str           # compute_hypothesis_id(group_id, candidate_id)
  group_id: str                # the attribution unit (D1)
  candidate_id: str
  evidence_assessment_ids: tuple[str, ...]   # ids into EvidenceAssessment, never embedded copies
  coverage_notes: tuple[str, ...]            # CoverageProfile.coverage_id references
  alternative_explanations: tuple[str, ...]  # plain-language, incl. possible-deception (D12)
  schema_version: str

EvidenceAssessment (frozen, deterministic identity — the real ACH-matrix cell, D8):
  assessment_id: str           # compute_evidence_assessment_id(hypothesis_id, step_id, technique_stix_id)
  hypothesis_id: str
  step_id: str                 # the real BehavioralStep.step_id this assessment is about
  technique_stix_id: str
  role: EvidenceRole           # closed 2-value enum: SUPPORTING | CONTRADICTING
  relevance: Relevance         # closed 3-value enum: CONSISTENT | INCONSISTENT | UNKNOWN (KB uses-derived)
  diagnosticity_ref: str       # a reference to the D(x)/D(C) computation (g(x), group count, kb version) —
                                # never a bare float stored with no explanation attached
  coverage_id: str | None      # set only when role/relevance depends on a CoverageProfile entry (D11)
  schema_version: str
  # "DiscriminatingEvidence" (doc 06 §7) is NOT a fourth object -- it is the derived subset of
  # EvidenceAssessment entries above a diagnosticity threshold, a VIEW, computed at read time,
  # exactly as doc 06 itself already says ("a view over the links, not a separate assertion").

AttributionAssessment (frozen, deterministic identity, one per Hypothesis):
  assessment_id: str           # compute_attribution_assessment_id(hypothesis_id, calibration_version)
  hypothesis_id: str
  likelihood: Likelihood       # value object: {wep_band, separation_from_null_band, separation_from_next_band}
                                # -- categorical only, see D9; never a raw number
  confidence: Confidence       # value object: {band, reasons: tuple[str, ...]} -- see D10
  uncertainty: str             # explicit residual, plain language
  next_evidence_id: str | None # NextEvidence reference (D14)
  calibration_version: str
  attack_kb_version: str
  methodology_version: str
  schema_version: str

NextEvidence (frozen, deterministic identity — a derived view, may be recomputed rather than independently
              stored, exactly like BehavioralStep.contextual_annotations):
  next_evidence_id: str        # compute_next_evidence_id(group_id, technique_stix_id, calibration_version)
  group_id: str
  target_technique_stix_id: str
  rationale: str                          # which coverage gap, which separation it would most affect
  affected_hypothesis_ids: tuple[str, ...]
  schema_version: str

AttributionResult (frozen, deterministic identity — the ONE persistence unit, mirroring ADR-0004 D18 exactly):
  result_id: str                # compute_attribution_result_id(group_id, calibration_version, attack_kb_version)
  group_id: str                 # D1 -- the attribution unit
  sequence_id: str               # the group's one BehavioralSequence
  candidate_hypothesis_ids: tuple[str, ...]   # ranked; each resolves to a Hypothesis + AttributionAssessment
  leading_hypothesis_id: str     # may be the UNATTRIBUTED_CANDIDATE_ID's own Hypothesis
  supporting_evidence_ids: tuple[str, ...]     # EvidenceAssessment ids, role=SUPPORTING
  contradicting_evidence_ids: tuple[str, ...]  # EvidenceAssessment ids, role=CONTRADICTING
  discriminating_evidence_ids: tuple[str, ...] # the derived high-diagnosticity view (see EvidenceAssessment)
  uncertainty: str
  ranking_explanation: str
  provenance: AttributionProvenance    # see below
  attack_techniques_involved: tuple[str, ...]  # mechanical union over the sequence's own technique_stix_ids
  attack_kb_version: str
  ti_kb_version: str | None            # None permitted -- no TI-enrichment layer exists yet (see Open Questions)
  methodology_version: str
  calibration_version: str
  dataset_ref: str
  engine_version: str
  determinism_hash: str
  schema_version: str

AttributionProvenance (frozen value object, no independent identity -- mirrors CorrelationProvenance exactly):
  method: str
  method_version: str
  source_group_id: str
  source_sequence_id: str
  source_evidence_ids: tuple[str, ...]        # non-empty, canonicalized -- same invariant as every prior
  source_observation_ids: tuple[str, ...]     # provenance contract in this codebase
  method_content_hash: str | None             # = calibration_version's own content hash, when applicable
```

No object above duplicates a Phase 2 contract's content — every one references Phase 2 by id
(`group_id`/`sequence_id`/`step_id`/`technique_stix_id`), the same discipline `CorrelationGroup` itself
already uses for `structural_link_ids`. `EvidenceRole`/`Relevance`/`CoverageState` are closed enums, matching
`LinkClass`/`OrderingBasisKind`/`GapReason`'s own established shape.

### D6 — ATT&CK knowledge traversal

**Resolved: extend `attack_knowledge/`, additively (Option A) — never make Phase 3 parse raw STIX directly.**
This is exactly what the loader's own docstring already anticipates ("deferred to whichever later gate
actually needs it"), and matches this project's own repeated precedent of adding a new, additive sibling
capability rather than reopening a frozen module (mirrored by every G2.x gate this session).

**Conceptual interface required** (not code — names and shapes only, for a future implementation to build
against, built *on top of* the existing, unmodified, frozen `AttackKnowledge`):

- `active_groups()` / `active_campaigns()` — every `intrusion-set`/`campaign` object **excluding**
  `revoked`/`x_mitre_deprecated` ones (the filtering §D3 requires and which does not exist today).
- `aliases_for(stix_id) -> frozenset[str]` — the canonical id plus every alias STIX id collapsed to it, from
  the object's own `aliases`/`x_mitre_aliases` STIX field (raw data already loaded; no traversal exists yet).
- `techniques_used_by(actor_or_campaign_stix_id) -> frozenset[str]` and `software_used_by(...)` — resolved by
  walking `relationship` objects with `relationship_type == "uses"` and matching `source_ref` — the literal
  "which techniques does group G use" example the loader's own docstring names as deferred.
  `groups_using_technique(technique_stix_id)` / `groups_using_software(software_stix_id)` — the reverse
  lookup §D3's `g(x)` requires.
- `group_profile(stix_id) -> frozenset[str]` — the full technique+software `uses` set for one group/campaign,
  needed for §D3's combination prevalence `g(C)`.

**Version awareness**: every result is implicitly scoped to the one `AttackKnowledge` instance passed in —
mirroring the loader's own "one pinned artifact, no path argument" design; no new version parameter is
introduced.

**No hard-coded actors anywhere**: every one of the above is a pure function of the loaded, frozen STIX
objects — zero project-owned actor/technique vocabulary, exactly continuing G0.2's own stated discipline.

### D7 — Candidate generation

Directly implements ADR-0002 D4/D15/CR-3, doc 07 §3, using §D6's new capability and §D3's active-group
filtering:

1. Collect the attribution unit's observed technique/software ids: the union of `technique_stix_ids` across
   every `BehavioralStep` in the `CorrelationGroup`'s `BehavioralSequence`.
2. **Candidate set** = every *active* group/campaign (via §D6) whose profile intersects that set — a
   recall-oriented net over the **entire pinned universe**; no configured/"supported" actor list exists
   anywhere (D15/CR-3).
3. Collapse aliases via `aliases_for()` (§D6) — one candidate per canonical actor identity, never one per
   alias.
4. **Always add `UNATTRIBUTED_CANDIDATE_ID`** (§D5) — mandatory, present in every candidate set unconditionally.
5. **No candidate priors of any kind** — candidate generation reads only the case's own observed
   techniques/software and the pinned KB; it never reads a prior attribution result, an analyst hint, or any
   named-actor input.

**Behavior in every named scenario, explicitly traced:**

- *No group matches*: candidate set = `{Unattributed}` only → trivially insufficient.
- *Only generic techniques match*: many candidates generated (the net is deliberately recall-oriented, per
  D15), but §D3's `D≈0` for all of them routes to insufficient at scoring time (§D13) — generation and
  discrimination are correctly separate steps, never conflated.
- *Multiple groups match*: the ordinary ACH case, proceeds to §D8.
- *Only software matches*: identical machinery, over the software half of the `g(x)`/`D(x)` computation
  (D18/M1's software extension).
- *Only one technique matches*: candidate(s) generated normally (generation is recall-oriented), but §D13's
  single-technique guard (D20/CR-6) caps it at *scoring* time regardless of `D` — it can never win outright.
- *ATT&CK relationship data sparse for the observed technique*: falls back to §D3's neutral-prior path;
  candidate generation itself is unaffected (a technique with sparse `uses` data can still place a candidate
  in the recall net — sparsity affects *discrimination*, never *inclusion*).

### D8 — ACH matrix

Rows = `EvidenceAssessment` entries (one per real `(BehavioralStep, technique_stix_id)` pair that is relevant
to at least one candidate, §D4/§D5); columns = `Candidate` (incl. `Unattributed`). Each cell already carries
everything doc 06 §7 requires: `role`, `relevance`, a `diagnosticity_ref` (never a bare float, §D3), and
provenance (`step_id`/`technique_stix_id`, resolving back through the real Phase 2 chain).

**Cells are derived, not persisted** — the matrix itself is a computation-time structure, recomputed fresh
from `(CorrelationGroup, BehavioralSequence, Candidate set, pinned KB, calibration_version)` each time
attribution runs, exactly mirroring how `BehavioralStep.contextual_annotations` is derived rather than
independently asserted (ADR-0004's own precedent). Only the *resulting* `EvidenceAssessment`/`Hypothesis`/
`AttributionAssessment`/`AttributionResult` objects are candidates for persistence (§D5), and per ADR-0004
D18's own precedent, only `AttributionResult` is the required persistence unit — the rest may be embedded
within it rather than independently stored, an implementation detail this ADR does not force either way.

### D9 — Likelihood

```
Likelihood (frozen value object):
  wep_band: str                    # a calibrated WEP band name (e.g. "likely") -- exact band set/thresholds
                                    # are a calibration_version parameter, not chosen here (D17)
  separation_from_null: SeparationBand    # categorical, e.g. CLEAR | MARGINAL | OVERLAPPING -- never a
                                          # raw number rendered to the analyst (doc 07 §4/§13)
  separation_from_next: SeparationBand
```

`support(h)` (the internal ordering statistic computed via §D3/§D8, `Σ supporting D·relevance − Σ
contradicting D·contradiction_strength`, `Oc` folded in once §D10's confidence factors are defined at
implementation time) ranks candidates; separation from the `Unattributed` floor and from the next candidate is
converted to the two `SeparationBand` fields via calibrated thresholds — never displayed as the raw
`support(h)` value. Likelihood is always comparative (never a lone absolute number) and always shows the
field of candidates, never a forced single leader when scores are close (doc 07 §5's "roughly even chance"
rule, unchanged). No threshold value is chosen in this ADR — `τ_separation` and every WEP-band cutoff remain
`calibration_version` parameters (§D17).

**[Amended 2026-09-17 — see Post-acceptance Amendment A]** The `support(h)` expression named here (`Σ supporting
D·relevance − Σ contradicting D·contradiction_strength`) is `raw_support(h)`, the *pre-normalization* aggregate.
Its complete, authoritative form applies one further step — division by `ProfileBreadth_effective(h)`,
operationalizing ADR-0002 D16 — as defined in [Post-acceptance Amendment A](#post-acceptance-amendments). This
is **not a competing formula**: §D9's expression is a named sub-expression of the amended `support(h)`, and the
normalized value is likewise never displayed as a raw number or a probability.

### D10 — Confidence

```
Confidence (frozen value object):
  band: ConfidenceBand              # closed 3-value enum: HIGH | MODERATE | LOW
  reasons: tuple[ConfidenceReason, ...]   # each a closed-enum categorical factor, never a numeric weight:
                                          # COVERAGE_GAP | RELIABILITY | CORROBORATION | CONSISTENCY |
                                          # CONTRADICTION_LOAD | OUTSIDE_CALIBRATED_REGIME
```

Bounded by the weakest of: coverage completeness (§D2/§D11), evidence reliability (`Oc`/Admiralty grades —
already-real G0.3/G1.0 metadata), corroboration breadth (§D4's confidence-independence axis), temporal/
campaign consistency, contradiction load, and calibration availability (§D3's neutral-prior fallback forces
`OUTSIDE_CALIBRATED_REGIME` and caps the band, never lets confidence rise past it).

**Imitation cap — a categorical rule, not a numeric penalty (ADR-0002 D21/CR-7, restated as a binding
structural gate):** `Confidence.band` **MUST NOT be `HIGH`** when the leading hypothesis's discriminating
evidence set (§D3's "which `EvidenceAssessment`s actually separate this candidate") is drawn *solely* from
one `EvidenceType` with no independent corroboration (§D4) across behavioral/evidentiary/procedural/
contextual types. This is a boolean gate evaluated before the band is finalized, never a subtracted score.
Likewise, a lead driven primarily by candidate profile richness (§D3's profile-breadth normalization) biases
the result toward the `OUTSIDE_CALIBRATED_REGIME` reason and abstention (§D13), never toward confidence.

### D11 — Contradiction / missing evidence

Wired directly to `CoverageProfile.state` (§D2), never conflated (doc 07 §9, restated as binding):

| `CoverageState` | Consequence |
|---|---|
| `OBSERVED_PRESENT` | Ordinary `SupportingEvidence` via the real `Evidence`/`BehavioralStep` — no `CoverageProfile` reference needed beyond confirming presence. |
| `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` | `ContradictingEvidence` (`EvidenceAssessment.role = CONTRADICTING`) for the candidate that characteristically uses the technique — lowers **likelihood**. |
| `NOT_OBSERVABLE` | A coverage gap — lowers **confidence** only (`ConfidenceReason.COVERAGE_GAP`), feeds `NextEvidence` (§D14); likelihood unaffected. |
| `UNKNOWN` | Treated identically to `NOT_OBSERVABLE` for methodology purposes — fails closed, never assumed to be either present or adequately absent (doc 06 U3/U4, restated). |

### D12 — Deliberate imitation

Restated as binding invariants (no new content — every one is already decided by ADR-0002 D10/D21/CR-7,
made concrete against the real objects above):

- TTP overlap alone can never produce `Confidence.band = HIGH` (§D10's categorical gate).
- Common/public tooling/LOTL techniques structurally cannot dominate `support(h)` — `D(x) ≈ 0` for anything
  used by most active groups (§D3), independent of any special-casing.
- `TEMPORAL_PROXIMITY`/`SAME_DESTINATION_IP`/other contextual `CorrelationLink`s remain contextual-only input
  (never behavioral/structural evidence, per this session's own ADR-0004 D20 invariants) — they may inform
  `Confidence`'s corroboration factor, never `Likelihood`'s support computation.
- Profile richness cannot dominate (§D3's profile-breadth normalization, §D10's regime-cap).
- Candidate overlap is handled comparatively by construction (ACH, §D8) — never a special-cased override.
- Possible deception is an `alternative_explanations` entry on `Hypothesis` (§D5), never a silent
  reassignment of the leading candidate.
- Every confidence cap in this ADR is categorical (`ConfidenceBand`/`ConfidenceReason` enum membership),
  never a numeric subtraction — no arbitrary penalty value is introduced anywhere in this document.

### D13 — Abstention

The exact decision rule, doc 07 §11, restated as this ADR's own binding rule with every threshold left
unresolved (calibration-gated, §D17):

Emit a non-`Unattributed` leading hypothesis **only if all four hold**:

1. Leading candidate's separation over the `Unattributed` floor exceeds `τ_separation` (calibrated).
2. Leading candidate's `Confidence.band` meets `min_confidence` (calibrated floor).
3. Leading candidate is separated from the 2nd by ≥ `τ_margin` (calibrated), **or** the result is explicitly
   reported as a tie/competing set.
4. **The separation is attributable to a distinctive combination or independent corroboration — never a
   single technique alone, regardless of `D`** (D20/CR-6, unconditional, not calibration-gated — this
   condition's *existence* is fixed by this ADR; only the separation/confidence/margin numeric floors above
   are calibration parameters).

Otherwise: `AttributionResult.leading_hypothesis_id` = the `Unattributed` candidate's own `Hypothesis`, with
`ranking_explanation` stating exactly which discriminating evidence is missing, which `CoverageProfile` gaps
exist, and the `NextEvidence` reference — a fully-populated, valid result (doc 06 §10), never an empty or
degraded one.

### D14 — Next-evidence guidance

`NextEvidence` (§D5) is a **derived, deterministic view**, never an invented priority score: for every
`CoverageProfile` entry in state `NOT_OBSERVABLE`/`UNKNOWN` tied to a technique with non-neutral-prior `D(x)`
(§D3), compute the counterfactual separation between the top two hypotheses **if** that technique were
confirmed present — i.e., re-run the *same* deterministic `support(h)` computation (§D3/§D8/§D9) under that
one hypothetical, and rank candidate next-evidence items by how much it would change the current top-2
separation. This is a straightforward, inspectable re-application of already-defined machinery — no new
heuristic, no fabricated impact score.

### D15 — Provenance

Full chain, unbroken, every hop either already real (Phase 0–2) or newly defined above:

```
raw telemetry → Observation → DetectionResult → Evidence
  → CorrelationLink → CorrelationGroup → BehavioralSequence → BehavioralStep
  → EvidenceAssessment → Hypothesis → AttributionAssessment → AttributionResult
```

`AttributionProvenance` (§D5) carries `source_group_id`/`source_sequence_id`/`source_evidence_ids`/
`source_observation_ids` plus `method`/`method_version`/`method_content_hash` — the identical
`DerivationProvenance`/`CorrelationProvenance` shape, never a third, incompatible provenance scheme.
`AttributionResult` additionally stamps all six required version identifiers (§D20). No Phase 2 provenance
field is altered, shortened, or bypassed — Phase 3 only ever *extends* the existing chain one hop further,
exactly as G2.1→G2.2→G2.3→G2.4.0→G2.4.1→G2.4.2→G2.4.3 each did to the one before it.

### D16 — Determinism

Phase 3 MUST be fully deterministic, under the same discipline every Phase 0–2 module already enforces —
explicitly forbidden, restated for this layer:

- No `uuid4()`, no `datetime.now()`/wall-clock dependence anywhere in scoring or id composition.
- No unordered iteration affecting output — every collection (`candidate_hypothesis_ids`,
  `supporting_evidence_ids`, etc.) sorted by its own deterministic id before being returned, exactly like
  every G2.x module's own `sorted(..., key=lambda x: x.id)` convention.
- No non-deterministic ids — every new id in §D5 is composed via the existing SHA-256/`"::"`-join convention
  (`_sha256_hex` + `"::"`.join), never a random or incrementing counter.
- **No external live ATT&CK lookups** — every §D6 capability operates only over the one pinned, already-loaded
  `AttackKnowledge` instance; no network access, no "latest" resolution, ever.
- No mutable methodology state — `calibration_version`, `methodology_version`, and every threshold they name
  are immutable, versioned, frozen configuration, read at computation time, never accumulated/adapted online.

### D17 — Calibration boundary

**`calibration_version`**: an opaque, content-hashed identifier (the identical `RulePack.content_hash`/
`TemporalProximityConfig.content_hash` convention — SHA-256 over the canonical, frozen parameter set) computed
once when a calibration procedure (doc 08 §4) freezes its fitted parameters.

**Calibration MAY determine:**

- `D`'s functional parameters, within the structural form §D3 fixes (monotonic, `[0,1]`-bounded,
  documentation-relative) — e.g. a fitted non-linear transform of `g(x)` replacing the `1 − g(x)` baseline.
- WEP-band thresholds (§D9), confidence-band thresholds (§D10), `τ_separation`/`min_confidence`/`τ_margin`/the
  `Unattributed` null floor (§D13), the minimum-support threshold and neutral-prior value (§D3), and the
  sequence-order bonus cap (§D3).
- **[Amended 2026-09-17 — see Post-acceptance Amendment A]** the numeric value of `min_profile_floor`, and any
  later-fitted non-linear replacement of the baseline **linear** profile-breadth normalization (§D3 /
  Amendment A). The `ProfileBreadth(h)` definition, the `max(…, min_profile_floor)` floor *structure*, the
  aggregate-before-normalization placement, and the linear baseline itself are **structural** (fixed by the
  amendment), not calibration-tunable.

**Calibration MUST NOT determine or change:**

- The candidate universe (§D7 — always the full, active, pinned KB; calibration never prunes it).
- Provenance of any kind (§D15).
- Raw `Evidence`/`Observation` (Phase 0–2, immutable to Phase 3 entirely).
- `CorrelationGroup` membership or `BehavioralSequence` ordering (Phase 2, frozen — §D1).
- ATT&CK `uses`/alias relationships (§D6 — sourced only from the pinned KB, never adjusted by calibration).

A KB version bump, a methodology change (a future amendment to this ADR), or a corpus change all require a new
`calibration_version` (doc 08 §4.6) — recalibration is mandatory whenever any of these three change, never
optional.

### D18 — Validation / leakage

Architectural requirements this ADR binds Phase 3 to — **the harness/corpus themselves are not built by this
ADR** (C3.2/C3.3 remain separate implementation/validation gates, §Implementation Gates):

- **Tier 1 (pipeline correctness)**: ATT&CK/CALDERA-derived scenarios verifying the *machinery* (candidate
  generation → ACH → decision rule) behaves as specified. May legitimately reuse ATT&CK-derived data.
- **Tier 2 (attribution generalization)**: independent/real-incident-sourced cases, never derived from the
  same ATT&CK tooling `D` is computed from. **Accuracy claims require tier 2; tier 1 alone never suffices**
  (doc 08 §7a, binding).
- **Scenario-family split**: calibration/held-out partitions drawn so no near-duplicate scenario appears on
  both sides.
- **Blind-actor holdout**: periodically remove one group's KB profile entirely and confirm the system returns
  `Unattributed` ("untracked actor"), not the nearest famous match — the direct C3.3 test.
- **No actor labels leaking into the scoring path**: `D`/`g(x)` are computed only from the pinned KB's `uses`
  relationships, never from a corpus case's own expected-label annotation.
- **No temporal leakage**: a case's `CoverageProfile`/evidence must reflect only what was knowable at the
  case's own observation time — no future KB version or future corpus knowledge informs a past case's result.

### D19 — Failure / fail-closed

| Condition | Required response |
|---|---|
| ATT&CK object referenced by `Evidence.attack_ref` missing from the pinned KB | Raise (construction-time failure) — never silently drop the evidence. |
| Malformed/unresolvable `uses` relationship | Excluded from `g(x)`/`g(C)` with the gap counted toward the minimum-support fallback (§D3) — never silently miscounted as "0 groups use this." |
| Incomplete candidate profile (some relationships resolvable, others not) | `g(x)` computed only over what *is* resolvable; the assessment is flagged via the same neutral-prior path when support is too thin (§D3). |
| Coverage unknown | `CoverageState.UNKNOWN` (§D2) — never assumed `NOT_OBSERVABLE` or `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE`. |
| Broken/missing provenance on any new object | Construction-time failure (`__post_init__`-style validation), mirroring every Phase 0–2 contract's own discipline unchanged. |
| Contradictory evidence | **Not a failure** — this is normal ACH input, recorded as `ContradictingEvidence` (§D11), never raised as an error. |
| Missing/absent `calibration_version` | Hard failure — Phase 3 MUST NOT run without a frozen `calibration_version` (this is C3.2 itself, restated as a runtime invariant, not a soft default). |
| Non-deterministic ordering risk | Structurally prevented by §D16 (sorted-by-id collections) — not a runtime check, a construction discipline. |

### D20 — Versioning

Six independent version identities, exactly as ADR-0002 D12/doc 06 §10/doc 08 §7 already require, restated as
binding on `AttributionResult` (§D5):

| Identifier | What it pins | Recalibration/revalidation required on change? |
|---|---|---|
| `attack_kb_version` | The pinned ATT&CK bundle every `D(x)`/candidate/coverage fact was computed against | Yes — new `calibration_version` required (D17), tier-1 revalidation required |
| `ti_kb_version` | Any future TI-enrichment snapshot (none exists yet — may be `None`, §Open Questions) | Yes, when it exists |
| `methodology_version` | This ADR's own revision (docs 06/07 in the original design; this ADR going forward) | Yes — any amendment to D1–D21 requires a new `methodology_version` and full revalidation |
| `calibration_version` | The frozen parameter set (D17) | N/A — this *is* the versioned artifact |
| `dataset_ref` | The specific case's own telemetry/fixture content hash | No — identifies input, not method |
| `engine_version` | The implementing code's own commit/build identity | Recommended but not methodology-gating |

`determinism_hash` = a deterministic function of all six identifiers plus the case's own input hash
(`group_id` + `sequence_id` + the resolved evidence/candidate set) — identical inputs and versions always
produce an identical hash, exactly ADR-0002 D12's own requirement.

### D21 — Phase 3 non-goals

Explicitly preserved, each grounded in an already-cited decision above — no new prohibition is invented here:

- No ML on the correctness path (ADR-0001 D5; ADR-0002 "Alternatives considered").
- No live OSINT/external attribution input at scoring time (§D18 — independent data is a *validation* input,
  never a live attribution one).
- No direct Elastic queries from the Attribution Engine (ADR-0001 D2 — Elastic is data-plane only; Phase 3
  consumes only the already-materialized Phase 2 chain).
- No modification of any Phase 2 object (§D1).
- No hard-coded actor list, ever (§D6/§D7, D15/CR-3).
- No posterior probability output (`P(group|evidence)`) anywhere (ADR-0002 D9).
- No analyst-facing numeric score/percentage of any kind (§D3's `D` inspectability caveat notwithstanding —
  that is a labeled, documentation-relative drill-down number, never a headline score).
- No attribution from a single technique, ever, regardless of `D` (§D13, D20/CR-6).
- No opaque/black-box model anywhere in the decision path (every step above is an inspectable, deterministic
  computation).
- **No automatic cross-`CorrelationGroup` campaign merging** (§D1 — a deliberate, G2.5-style deferral, not an
  oversight; a future, separately-justified gate if ever pursued).
- No production-SOC-scale performance requirement (none is specified anywhere in the accepted architecture;
  not invented here — CLAUDE.md's own "do not over-engineer for enterprise requirements" applies unchanged).

## Attribution Domain Model

See §D5 for the complete, authoritative object list (`CoverageProfile`, `Candidate`, `Hypothesis`,
`EvidenceAssessment`, `AttributionAssessment`, `NextEvidence`, `AttributionResult`, `AttributionProvenance`)
and §D2 for `CoverageState`. Every object is frozen, deterministically identified, and references Phase 0–2
objects by id only.

## Candidate Generation

See §D6 (ATT&CK traversal capability) and §D7 (generation algorithm and worked-case behavior).

## ACH and Evidence Assessment

See §D3 (diagnosticity), §D4 (independence), §D8 (matrix structure).

## Likelihood and Confidence

See §D9 (likelihood), §D10 (confidence), §D12 (imitation guards).

## Abstention

See §D13 (decision rule) and §D11 (contradiction/coverage wiring).

## Provenance and Determinism

See §D15 (provenance chain) and §D16 (determinism discipline).

## Calibration Boundary

See §D17.

## Validation Boundary

See §D18. Building the corpus and the blind-actor-holdout harness themselves are implementation/validation
gates (below), not satisfied by this document.

## Non-goals

See §D21.

## Implementation Gates

Architecture-level prerequisites that follow *directly* from this ADR — not a full Phase 3 implementation
plan (deliberately not drafted here per instruction). Classified exactly as required:

- **Architectural prerequisite (must precede any implementation gate below):** this ADR itself reaching
  ACCEPTED status.
- **Implementation work:**
  - Extend `attack_knowledge/` with the §D6 traversal capability (active-group filtering, alias resolution,
    `uses`-relationship traversal, reverse lookup, group-profile assembly).
  - Implement `CoverageProfile` construction (§D2) from real case telemetry + the pinned KB's per-technique
    data-source requirements.
  - Implement the §D3 diagnosticity computation (`g(x)`, `g(C)`, `D`, the neutral-prior fallback, the
    combination-partition rule).
  - Implement candidate generation (§D7), the ACH matrix (§D8), likelihood/confidence construction (§D9/§D10),
    the decision rule (§D13), and `NextEvidence` (§D14).
  - Implement the new domain contracts and their deterministic-id helpers (§D5), following the exact
    two-tier "raw dataclass + sanctioned builder" pattern G2.0/G2.4.0 already established.
  - Implement `AttributionResult` persistence (mirroring ADR-0004 D18's shape — one document per result).
- **Validation work (satisfies C3.2/C3.3, not satisfied by this ADR):**
  - Build the labeled golden corpus (all nine case types, doc 08 §2) — **C3.2's prerequisite**.
  - Run the calibration procedure (doc 08 §4) and freeze the first `calibration_version` — **completes C3.2**.
  - Build the blind-actor-holdout harness and scope the generalization claim — **completes C3.3**.
  - Run the full doc 08 §3 metric suite against the held-out split.
- **Optional/future work:** independent/real-incident validation data acquisition (D22/aspirational); a
  `ti_kb_version`-bearing TI-enrichment layer (currently `None`, §Open Questions); cross-group campaign
  correlation (explicitly deferred, §D21); G2.5 (already, separately, formally deferred at Phase 2 closure).

C3.1 (doc 10) is satisfied by this ADR's own §D3/§D4 once accepted. **C3.2 and C3.3 are not satisfied by
drafting or accepting this ADR** — they require the validation work listed above to actually exist.

## Open Questions

Genuinely unresolved by the accepted methodology without an arbitrary choice — marked OPEN rather than
silently decided:

1. **Software-evidence reachability.** §D3/§D7 assume `Evidence`/`BehavioralStep` can carry software
   (`malware`/`tool`) STIX references, not only technique ones. Checked against the real Phase 1 detection
   layer: every rule in the current `fixtures/phase1_core_rules.json` maps only to `attack-pattern` (technique)
   objects — **no rule currently produces software-typed evidence**. Whether Phase 1's detection-rule schema
   needs extending to support software mapping, or whether software evidence is expected to arrive via a
   different, not-yet-built enrichment path, is genuinely open and not resolved by this ADR.
2. **Campaign-specific scoring treatment beyond diagnosticity.** §D3's candidate-type-invariance rule fixes
   `g(x)`/`D(x)`/`g(C)`/`D(C)` as group-population-relative and applied identically to `Campaign` candidates —
   Campaign candidates use the same already-defined evidence diagnosticity machinery; no separate
   campaign-relative `D` formula exists, and this is no longer open. What remains genuinely open is narrower:
   doc 07 §1's "tighter than a group" language may still motivate a distinct *calibration-version* parameter
   (e.g. a stricter `τ_separation`/`min_confidence` applied specifically when the leading candidate is a
   `Campaign`) in a future calibration round. Whether such a parameter is ever introduced is open, but it is a
   calibration-boundary question (§D17) — it would tune an existing threshold per candidate type, never define
   a second diagnosticity population or a campaign prior.
3. **`ti_kb_version` / TI-enrichment layer.** Doc 06 §3 mentions Admiralty source-reliability grading for
   enrichment evidence; no TI-enrichment ingestion path exists anywhere in Phase 0–2. `AttributionResult`
   permits `ti_kb_version = None` (§D5) until such a layer exists; when/whether to build one is open.
4. **`D`'s calibrated (non-baseline) functional shape.** §D3 fixes the *baseline* form (`1 − g(x)`) and its
   required properties; the *final*, calibration-fitted shape is correctly and deliberately left to the (not
   yet built) calibration procedure — not "open" in the sense of blocking implementation, but explicitly not
   decided here, by design (doc 07 §2.3/§2.4).
5. **Minimum-support threshold and neutral-prior value (§D3).** Calibration-version parameters; genuinely
   undetermined until real corpus data exists — by design, not an oversight.

Every other decision requested by the audit is resolved above (D1–D21); none of the five items here blocks
*drafting* an implementation against this ADR — they narrow specific parameter values or a small scope
extension, not the architecture itself.

## Consequences

**Positive:** Phase 3 now has a concrete, implementable domain model built on the real Phase 0–2 objects
rather than docs 06/07/08's stale, never-built entity chain; the single most consequential gap doc 10
identified (D-3, combination diagnosticity) has a defensible, inspectable, documentation-relative resolution;
the coverage-model gap (D-2, blocking both Phase 2 and Phase 3 per doc 10, never resolved for either) is
closed with a minimal four-state contract; every numeric quantity remains internal, categorical-banded, and
never a probability, preserving ADR-0002's central differentiator intact.

**Negative / costs:** six new domain contracts plus an ATT&CK traversal capability must be built before any
scoring code runs; the golden corpus and blind-actor-holdout harness (C3.2/C3.3) remain substantial,
un-started work this ADR does not shortcut; the combination-diagnosticity baseline (`1 − g(x)`) is a genuine
new claim this ADR introduces (not merely restating ADR-0002) and must itself be validated on real corpus
data before being trusted, exactly like any other calibration-gated quantity.

**Neutral:** the baseline `D` formula, the neutral-prior fallback, and the sequence-order cap are all
structurally fixed here but numerically open — recalibration remains the same tunable, reversible mechanism
ADR-0002 D14 already established for every other quantity in this layer.

## Follow-up

On review: if accepted, status → ACCEPTED (dated), and the Implementation-work items above may begin under
this ADR's own gates — C3.2/C3.3 remain hard blockers on any *scoring* code path regardless (per doc 10, restated
in §Implementation Gates) even after this ADR itself is accepted. If any Open Question above is resolved
during review, record it here as a dated addendum, mirroring the practice already established for ADR-0004's
own post-acceptance clarifications, never as a silent edit to the D1–D21 text.

## Post-acceptance amendments

Dated additions made after this ADR reached ACCEPTED status. Each is recorded here and cross-referenced from
the decision it affects by a visible, dated marker; **the original D1–D21 decision text above is left intact
and is never silently rewritten** — matching the practice this ADR's own §Follow-up established and ADR-0004's
`## Post-acceptance clarifications` already demonstrated. An amendment that changes methodology (as Amendment A
does — unlike ADR-0004's clarifications, which only recorded how an accepted decision was satisfied)
additionally states its compatibility impact and what remains calibration-controlled or deferred.

### Amendment A (2026-09-17) — Profile-breadth normalization of `support(h)`

**What was missing.** ADR-0002 D16 (ACCEPTED) requires that `support(h)` (a) de-duplicates correlated evidence,
(b) is dominated by high-`D` discriminating evidence, **and (c) is normalized by candidate profile breadth** —
and that `support`/`D` are never shown as probabilities. This ADR's opening scope commits to *applying*
ADR-0002's accepted decisions, not re-deciding them. §D3/§D8/§D9 as originally written operationalize (a) (via
§D4's independence rules) and (b) (via the maximal-partition/combination machinery) but **never operationalize
(c)** — no candidate-profile-breadth normalization appears in any original formula. §D10 and §D12 nevertheless
already refer to "§D3's profile-breadth normalization" as an existing mechanism. This amendment supplies the
missing operationalization, making §D3/§D9 internally consistent with ADR-0002 D16 and making §D10/§D12's
existing references accurate. It reopens no other decision, in this ADR or in ADR-0002.

**Sections amended:** §D3 (adds the profile-breadth-normalization definition below), §D9 (the authoritative
`support(h)` is the normalized form below — §D9's existing `Σ supporting … − Σ contradicting …` expression is
exactly `raw_support(h)`, a *named sub-expression* of it, not a competing formula), and §D17 (adds two
calibration parameters below). §D10/§D12 need no wording change — their existing references become accurate
once §D3 carries this mechanism.

**Structural definitions (fixed here; not calibration).** Let `candidate_stix_id(h)` be the canonical
intrusion-set (Group) or campaign STIX id the hypothesis `h` names (§D5/§D7). The `Unattributed` null
hypothesis has **no** `candidate_stix_id` and is **outside this definition's domain**: it is never scored
through ATT&CK `uses` relationships and receives no ATT&CK-derived support (§D3/§D7 unchanged); its support
remains the neutral empty aggregate.

```
ProfileBreadth(h)           = | group_profile(knowledge, candidate_stix_id(h)) |
ProfileBreadth_effective(h) = max( ProfileBreadth(h), min_profile_floor )

raw_support(h) =
      Σ  over atomic features x not covered by a chosen combination:  occurrence_count(x, h) · D(x)
    + Σ  over combination features C in h's chosen maximal partition:  D(C)
    − Σ  over contradicting evidence e (feature x_e):                  D(x_e) · contradiction_strength(x_e, h)

support(h) = raw_support(h) / ProfileBreadth_effective(h)
```

- **`ProfileBreadth(h)`** is the number of **distinct ATT&CK technique/software STIX ids** in the candidate's
  own full `uses` profile, read via the already-existing §D6 traversal capability (`group_profile(...)`, built
  in Gate 3.1 — no new traversal mechanism is introduced). It reuses that function's own semantics exactly:
  every STIX id counted atomically, with **no special parent/sub-technique de-duplication** (identical to how
  `g(x)`/`D(x)` already treat base and sub-techniques), **no external statistic**, and **no separate
  Group-vs-Campaign definition** (see below).
- **`occurrence_count(x, h)`** is the number of distinct `BehavioralStep`s asserting technique/software `x`
  that are `SUPPORTING`/`CONSISTENT` for `h` — the independent-repetition multiplicity §D4 already establishes,
  **unchanged**. Multiplicity is summed into `raw_support(h)` **before** normalization (see aggregation
  placement below); D4 is not modified.
- **`D(x)`, `g(x)`, `D(C)`, `g(C)`**, combination admissibility, maximal-partition selection, and the
  deterministic tie-break are all **unchanged**. `D(x)` is **not** redefined to include profile size; `g(x)`
  remains computed over the **active-Group population** exactly as §D3 fixes; diagnosticity is **not** made
  candidate-type-specific. Profile breadth is a *candidate-level* normalization quantity, kept mathematically
  separate from *feature-level* discriminating diagnosticity.
- **`contradiction_strength(x_e, h)`** remains an **explicit symbolic term with no defined numeric form** —
  deferred, unchanged, to the later coverage/contradiction methodology. (Gate 3.4 currently produces no
  `CONTRADICTING` cell; that is an implementation state, not a methodological decision. This amendment does
  **not** define the term as zero and does **not** use profile normalization as a substitute for contradiction
  handling.)

**Group vs. Campaign — one identical rule, an acknowledged data-driven asymmetry.** The formula is applied
**identically** to Group and Campaign candidates — no type multiplier, no type-specific denominator, no
balancing constant. Because ATT&CK's object model scopes a `campaign` object (a bounded operation) more
narrowly than an `intrusion-set` object (an actor's entire tracked history), Campaigns have structurally
smaller `ProfileBreadth` on average than Groups (measured on the pinned v19.0 KB via the Gate 3.1 traversal
layer: active Groups mean ≈ 32.7 / median 21.5 / max 149 over 174; active Campaigns mean ≈ 23.5 / median 20.0 /
max 82 over 56). A uniform denominator therefore produces **different proportional effects** between the two
candidate types. This is a documented, **data-driven property of ATT&CK's own documentation structure — not
silently corrected here**, and not a violation of §D3's candidate-type-invariance rule, which fixes the
invariance of the *feature-level* `g(x)`/`D(x)` basis (unchanged), a different quantity from this
*candidate-level* normalization.

**Small-profile floor.** The `max( …, min_profile_floor )` **structure** is fixed here — it bounds the
amplification a single coincidental match against a tiny profile could otherwise produce (a small denominator
would inflate one match's weight). The **numeric value** of `min_profile_floor` is **not chosen here**; it is a
`calibration_version` parameter (§D17 addition). A small-profile candidate is **never dropped from scoring**
and is **never** marked `OUTSIDE_CALIBRATED_REGIME` merely for having a small profile — that flag remains
reserved for the §D3 undefined/zero-active-match `g` fallback, unchanged.

**Baseline transform.** Linear division is the **structural baseline**, mirroring §D3's own "`1 − g(x)` is the
zero-hand-tuning baseline" discipline for `D`. Calibration **MAY** later replace it with a different
monotonically-decreasing transform of `ProfileBreadth_effective(h)` if corpus evidence supports one — never a
differently-*shaped* claim, never chosen here. No log scaling is introduced now.

**Aggregation placement (no double normalization).** Normalization is applied **exactly once**, to the
aggregate `raw_support(h)`, **after** all atomic (including §D4 multiplicity) and combination contributions are
summed. **Individual per-feature contributions are not normalized.** The intended flow is:

```
per-feature / per-combination diagnosticity contribution
      ↓  (summed, D4 multiplicity preserved)
raw_support(h)
      ↓  (single division by ProfileBreadth_effective(h))
support(h)
```

**Not a probability.** `support(h)`, `raw_support(h)`, `D`, and `ProfileBreadth(h)` are all internal,
documentation-relative construction quantities. None is a probability; the normalized `support(h)` **must not**
be presented to an analyst as a probability, percentage, or confidence; and this amendment introduces **no**
arbitrary point system (§D3's central "documentation-relative, never a probability" framing is preserved
unchanged).

**Explainability (a requirement on the eventual result — not implemented by this documentation amendment).**
When Gate 3.5's implementation is later updated to apply this amendment, the per-hypothesis support summary
must retain enough to explain normalization end to end: `raw_support_value` (the pre-normalization aggregate),
`support_value` (the post-normalization result), `profile_breadth` (the raw `ProfileBreadth(h)`), and
`profile_breadth_floor_applied` (whether `min_profile_floor` changed the effective denominator) — audit and
explainability fields, never probabilities. Per-feature `EvidenceContribution` fields
(`g_value`/`d_value`/`contribution_value`/`assessment_ids`) are **unchanged**.

**Calibration boundary (extends §D17).** Added to §D17's "Calibration MAY determine" list: (i) the numeric
value of `min_profile_floor`; (ii) any later-fitted non-linear replacement of the baseline linear
profile-breadth normalization defined here. Everything else this amendment defines — the `ProfileBreadth`
definition, the `max(…)` floor structure, the aggregate-before-normalization placement, and the linear baseline
itself — is **structural**, not calibration-tunable.

**Backward-compatibility impact.**

- The `EvidenceContribution` contract and its `contribution_value` are **unchanged**; per-feature diagnosticity
  is **unchanged**.
- The semantic meaning of the aggregate `HypothesisSupportSummary.support_value` changes from *raw* aggregate
  support to *profile-breadth-normalized* support. `raw_support(h)` is preserved as a distinct, additionally
  retained value (`raw_support_value`).
- The Gate 3.5 *implementation* (`comparative_analysis.py`) is **not changed by this documentation amendment**.
  When it is later updated, its `_summarize_hypothesis` / `HypothesisSupportSummary` aggregation gains the
  single normalization step and the four explainability fields above, and existing Gate 3.5 tests that assert
  aggregate `support_value` numbers will need updated expectations (per-feature `EvidenceContribution`
  assertions will not).

**Explicitly out of scope of this amendment (unchanged status).** The `>8`-distinct-feature combination-search
computational bound (an implementation-only limit tracked separately; this ADR still specifies no maximum
combination size); the numeric definition of `contradiction_strength` (deferred to the coverage/contradiction
methodology); Gate 3.6's likelihood/WEP ranking (which, once Gate 3.5 applies this amendment, may consume the
normalized `support(h)`); and every already-established calibration numeric value.

### Amendment B (2026-09-17) — Coincidental-overlap null, distinctiveness-vs-repetition, and actor/campaign separation

**A post-acceptance additive clarification/extension**, recorded in the same dated style Amendment A and
ADR-0004's `## Post-acceptance clarifications` already established; **the original D1–D21 decision text above
is left byte-for-byte intact and is never silently rewritten.** Like Amendment A, this amendment changes
methodology (not merely records how an accepted decision was satisfied), so it additionally states its
compatibility impact and what remains calibration-controlled or deferred (see the §Compatibility and §Calibration
subsections below).

**Why Amendment B is required.** The Pre-G3.6 methodology audit found three defects that would otherwise be
carried into the (not-yet-built) Gate 3.6 likelihood/confidence/abstention layer:

- **B2 — the `Unattributed` null is trivially beaten.** §D9 already speaks of "separation from the
  `Unattributed` floor," and doc 07 §5 / ADR-0002 CR-2 require that floor to be a **non-zero absolute
  coincidental-overlap level**. The Gate 3.5 *implementation* left `support(Unattributed) = 0.0` (an
  implementation choice, never an ADR decision), so **any** candidate with a single supporting cell trivially
  "beats the null." The CR-2 defense against forcing a known label onto an absent/under-represented actor
  (doc 09 Scenario 8 — "the single most dangerous failure this project must avoid") is therefore currently
  inert. This amendment fixes the floor's *structural form*; it does not change §D9's already-accepted "floor"
  wording.
- **B5 — repetition can substitute for distinctiveness.** §D4 (ACCEPTED) deliberately treats distinct
  `BehavioralStep`s asserting one technique as independent acts, and Gate 3.5 sums them as
  `D(x)·occurrence_count(x)`. §D4 itself states this "can never, by itself, escape D20's single-technique
  guard," deferring the bound to the abstention layer — but §D13's guard alone does not catch separation
  *dominated* by one repeated (or one high-`D` atomic, or one single-source) contributor *among several*. This
  amendment defines how the likelihood layer consumes support so that repetition cannot substitute for
  distinctive behavioral diversity, and freezes a concentration mechanism — **without modifying §D4**.
- **B6 — Group and Campaign supports live on different scales yet were to be ranked together.** Amendment A's
  profile-breadth normalization divides by the candidate's own profile size; because ATT&CK scopes a `campaign`
  more narrowly than an `intrusion-set` (Amendment A's own measured asymmetry: active Groups median ≈ 21.5,
  Campaigns median ≈ 20.0, but different means/maxima and different proportional effects), ranking Groups and
  Campaigns in one actor-likelihood space compares different scales. This amendment resolves **Open Question #2**
  by separating actor attribution (Groups) from campaign contextualization (Campaigns), rather than inventing a
  cross-type normalization.

**What Amendment B does not do.** It resolves **B2, B5 and B6** at the *structural-methodology* level only. It
**does not invalidate any D1–D21 decision** (see §Compatibility with D1–D21 below — every apparent interaction
was checked and none is contradicted); it **does not select any numeric value** (every threshold it names
remains a `calibration_version` parameter); it **does not build the calibration corpus, freeze a
`calibration_version`, implement Gate 3.6, modify any contract, or modify the Gate 3.5 implementation**. It
requires a **`methodology_version` bump** (§Methodology versioning). **G3.6 remains blocked** until a frozen
`calibration_version` exists (C3.2, §D19 hard-fail) **and** the coverage-construction (B3) and
`evidence_type`-plumbing (B4) prerequisites are met — Amendment B does not clear any of those.

Neutral note (no legal claim): Amendment B defines a **more precise computational mechanism** coupling a
candidate-independent ATT&CK-derived coincidence baseline, profile-normalized comparative actor evidence, a
distinct-feature decision basis, composition-aware concentration control, an explicit repetition/persistence
separation, actor/campaign separation, coverage-aware abstention, and provenance/version determinism. Its
**novelty relative to prior art remains undetermined** and is out of scope here; no patentability claim is made.

**Revision 2 (2026-09-17, pre-acceptance).** This still-**unaccepted** DRAFT was revised after a hostile
pre-acceptance audit to place the entire Gate 3.6 decision path on a **single, consistent distinct-feature
basis** (the subsection immediately below) and to tighten the null framing, the persistence-vs-corroboration and
diversity-vs-independence language, the combination-dominance corroboration condition, and the
campaign-contextualization anti-circularity/multi-attribution rules. The revision edits **only** this
unaccepted Amendment B text; **D1–D21 and Amendment A remain byte-for-byte unchanged**, and no previously
*accepted* decision is rewritten. Where a paragraph below supersedes earlier Revision-1 wording of this same
amendment, it says so explicitly.

**Revision 3 (2026-09-17, pre-acceptance).** A second hostile pre-acceptance audit found four surgical
precision defects, corrected here (still editing **only** this unaccepted DRAFT; D1–D21 and Amendment A remain
byte-for-byte unchanged): (1) the decision path uses **two explicitly-assigned forms** of decision support
(un-normalized and profile-breadth-normalized), not "one basis"; (2) the concentration denominator is renamed
`contributor_separation(h)` and is stated to be a **different quantity** from `separation_from_null(h)`;
(3) `ProfileBreadth` and every G3.6 prevalence/traversal quantity **must count active ATT&CK targets only** (a
G3.6 traversal prerequisite; the Gate 3.1 layer is **not** modified now); (4) the combination-dominance
independent-corroboration exemption **fails closed** (denied) when independence cannot be established. Where a
paragraph below supersedes earlier Revision-1/Revision-2 wording of this same amendment, it says so explicitly.

#### Decision-path scale: two assigned forms of one distinct-feature decision-support family

Two distinct aggregates are defined here and are **never interchangeable**; every later B2/B5 rule names which
one it uses.

- **RAW SUPPORT** — the multiplicity-preserving *explanatory/provenance* aggregate. This is exactly Amendment A's
  `raw_support(h)` (`Σ` atomic `D(x)·occurrence_count(x)` `+ Σ` combination `D(C) − Σ` contradicting …),
  **unchanged** (D4/Amendment A intact). It is retained on every hypothesis for explanation and provenance, and
  as the *source* of a **bounded persistence signal** for confidence (§B5) — it is **never** consumed by the
  likelihood / separation-from-null / concentration / abstention decision.
- **DECISION SUPPORT** `decision_support(h)` — the *distinct-feature* aggregate the Gate 3.6 decision path
  consumes:

  ```
  decision_support(h) = Σ over h's distinct decision contributors:  contribution(contributor)
  ```

  where each **distinct atomic feature** `x` contributes `contribution(x) = D(x)` **at most once** (repeated
  occurrences of an already-counted technique add **no** additional decision support), each **admissible
  combination** `C` contributes `contribution(C) = D(C)` **once**, a combination's member features are **not**
  separately counted (§D3 maximal partition, unchanged), and a feature whose `g` is undefined contributes `0`
  (the §D3 `OUTSIDE_CALIBRATED_REGIME` fallback, unchanged). Any diminishing-returns softening of "count once"
  is a `calibration_version` curve, never chosen here.

**Two explicitly-assigned FORMS of the one distinct-feature decision-support family (supersedes any earlier
"one basis" wording).** DECISION SUPPORT exists in two mathematically distinct but related forms of the **same**
distinct-feature family:

- **A. UN-NORMALIZED** `decision_support(h)` — the distinct-feature decision support defined above, **before**
  profile-breadth normalization.
- **B. NORMALIZED** `decision_support_norm(h) = decision_support(h) / ProfileBreadth_effective(h)` — the
  cross-Group comparative quantity, using Amendment A's identical Group `ProfileBreadth_effective` mechanism.

**The decision path uses this one distinct-feature decision-support family in two explicitly assigned forms;
each downstream decision quantity MUST consume the form specified here, and no downstream operation may
substitute one form for another:**

- **UN-NORMALIZED `decision_support` MUST be used for:** `separation_from_null(h)`; the concentration contributor
  decomposition; and concentration's own `contributor_separation(h)` quantity (§B5).
- **NORMALIZED `decision_support_norm` MUST be used for:** cross-Group likelihood comparison/ranking;
  `separation_from_next`; and the margin from the next hypothesis.

**These two quantities answer different questions and are NOT interchangeable:** `separation_from_null(h)` (on
the un-normalized form) asks whether the candidate's observed distinct-feature support clears the
candidate-independent coincidence baseline; `decision_support_norm(h)` compares candidates *after* accounting
for profile breadth. No sentence in this amendment may be read as making `decision_support_norm(h)` directly
comparable to `decision_support(Unattributed)`.

**Leader definition (unambiguous).** The **leader** is the eligible **Group** actor hypothesis with the highest
`decision_support_norm(h)`. Being top-ranked does **not** by itself qualify for attribution: the leader MUST
**also** independently clear the un-normalized `separation_from_null` requirement and every other §D13 condition
(§Abstention below). Ranking and null-clearance are on deliberately different forms and are evaluated
separately.

**Unattributed has no profile breadth.** The `Unattributed` hypothesis names no actor and has no candidate
profile breadth; it is represented solely by its **un-normalized, candidate-independent null baseline**
(`decision_support(Unattributed)`, §B2) and **MUST NOT** be divided by any actor profile breadth or given a
`decision_support_norm`.

**RAW SUPPORT and Amendment A's `support_value` remain valid explainability/intermediate quantities**, retained
on every hypothesis, but are **never** substituted for either DECISION SUPPORT form in a decision. **This
subsection supersedes every Revision-1 phrase computing separation/concentration on `raw_support(h)` and every
Revision-2 "one basis" phrase.**

**Active-target policy for `ProfileBreadth` and every prevalence/traversal quantity (G3.6 traversal
prerequisite; binding).** The Gate 3.1 `group_profile()` implementation currently returns the raw `uses` target
set **without** active-filtering the target technique/software, so revoked/deprecated targets currently inflate a
profile. For G3.6 this is resolved, not deferred: **`ProfileBreadth` MUST count only *active* ATT&CK target
objects** (revoked/deprecated target techniques/software MUST NOT contribute), and **every ATT&CK
prevalence/traversal quantity the G3.6 decision methodology consumes** (`g(x)`, `g(C)`, `group_profile`,
combination superset checks, and `attributed-to` resolution) **MUST apply the same active-object policy
consistently**, deterministically, pinned to ATT&CK v19.0. This is a **G3.6 traversal prerequisite**: the Gate
3.1 traversal layer MUST be extended/adjusted to provide active-target behavior **before** G3.6 implementation.
**This amendment does not modify Gate 3.1 source now** — it specifies the requirement for the appropriate later
gate.

#### B2 — Coincidental-overlap null baseline

**Structural rule (fixed here; not calibration).** The `Unattributed` null hypothesis's DECISION SUPPORT is no
longer `0`. It is an explicit, **candidate-independent** baseline computed on the **same distinct-feature
DECISION basis** as every candidate (above), over the *case's own* observed decision features:

```
decision_support(Unattributed) = Σ over the case's distinct observed decision features f:  contribution(f) · g(f)
```

where, using the **same** feature/combination partitioning §D3 and the DECISION SUPPORT rule above already fix
for a real candidate (never a new or parallel scheme, never multiplicity):

- the case's observed feature set is partitioned **once** by the existing deterministic maximal-partition rule
  (§D3) into distinct atomic features and admissible combination blocks;
- for a **distinct atomic** feature `x` (not absorbed into a combination), `contribution(x) = D(x)` (**once**,
  no `occurrence_count` — repetition is not part of the decision basis, §B5) weighted by its coincidental-match
  base rate `g(x)`;
- for a **combination** `C`, `contribution(C) = D(C)` weighted by `g(C)`; its member features are **not**
  separately counted (no double-counting);
- a feature whose `g` is undefined/zero-active-match (the §D3 `OUTSIDE_CALIBRATED_REGIME` fallback) contributes
  `0` to the null exactly as it already contributes `0` to a candidate's decision support — unchanged.

`g(f)` is the already-defined §D3 base rate (fraction of active Groups whose `uses` profile contains `f`).

**This is a deterministic heuristic expected-overlap baseline under a feature-independence approximation — not a
validated statistical claim.** `contribution(f)·g(f)` reads as "this feature's decision contribution, times the
documented base rate at which a tracked Group carries it," but the sum treats features as independent, which they
are **not** (ATT&CK `uses` profiles are correlated). The baseline is therefore an **approximation**, and this
amendment explicitly does **not** claim it is a statistical expectation, a probability, a statistical
significance test, a calibrated p-value, or a claim about real-world prevalence. It is an internal,
**documentation-relative construction value** (documentation-relative precisely because `g(x)` is, §D3/D18/CR-4),
never presented to an analyst as a probability or percentage. Because the null and a candidate's decision support
are both built from the same `g`, they share the same documentation bias and it partially cancels in the
*separation*.

**Requirements this baseline satisfies (all structural):** candidate-independent (a pure function of the observed
decision features and the pinned KB, never of any candidate); deterministic and closed-form (no random sampling,
no permutation, no RNG — respecting §D16); computed over the **same** pinned `AttackKnowledge`; using the **same**
distinct-feature partitioning; on the **same DECISION SUPPORT scale** as a real candidate's `decision_support(h)`;
reproducible; and introducing **no arbitrary constant** and **no candidate-relative circularity** (the null is an
evidence-set baseline, never the top of the candidate field).

**Behaviour by prevalence, explicitly (since `D(f)·g(f) = (1−g(f))·g(f)`):**

- **Rare** features (`g→0`): near-zero coincidental expectation — a random Group is unlikely to carry them, so
  a genuine rare-feature match is *not* coincidental (its diagnostic weight is realized in the candidate's
  support, not in the null).
- **Moderately prevalent** features (`g≈0.5`): the largest contribution to the null — exactly the features a
  random Group is *both* reasonably likely to share *and* that still carry non-trivial `D`; the coincidental-
  overlap risk the null exists to model.
- **Common** features (`g→1`, and the endpoint `g=1` exactly): `D→0` (or `D=0`), so their contribution to the
  null →0 (or `0`) — they carry no discrimination for anyone, consistent with §D3/§D12's "common tooling cannot
  dominate." The endpoint `g=0` (exactly zero active matches) is the *undefined* case and contributes `0` via
  the §D3 fallback above — never `D=1`. No endpoint requires an arbitrary constant.

**Separation-from-null and the calibrated margin.** `separation_from_null(h)` is the leader's **UN-NORMALIZED
decision support relative to this baseline** — `decision_support(h) − decision_support(Unattributed)`, **both on
the un-normalized decision-support form** (never `decision_support_norm`, never `raw_support`) — and the
calibrated `τ_separation` (§D13 condition 1) is the **margin the leader must clear *above* this non-zero
baseline**, not a threshold above `0`. Because the null and a candidate's decision support are both built from
the same `g`, they share the same documentation bias and it partially cancels in the *separation*. This is a
**separate** abstention criterion from cross-Group ranking, which uses `decision_support_norm` (above).

**Critical scope note — B2 is necessary but not sufficient.** In doc 09 Scenario 8 (true actor absent; famous
Groups match a *fraction* of a distinctive combination) the partial atomic matches can still exceed this
coincidental floor; what prevents the false named attribution there is that no tracked Group holds the full
distinctive **combination** `D(C)`, *together with* the B5 distinctive-basis/concentration guard below. B2
guards against winning on accumulated moderate overlap; B5 guards against winning on a single/partial/repeated
contributor. Both are required, and they are consumed jointly by §D13's decision rule.

#### B5 — Distinctiveness, repetition, and concentration

**`raw_support(h)` is unchanged and still retains occurrence multiplicity.** §D4's independence rule and
Amendment A's `raw_support(h)` aggregate (`Σ` atomic `D(x)·occurrence_count(x)` `+ Σ` combination `D(C) − Σ`
contradicting …) remain exactly as accepted — repeated `BehavioralStep`s remain independent acts and remain
fully explainable via the per-feature `EvidenceContribution` values. **§D4 is not modified.**

**Likelihood consumption (the new rule, defined in an existing methodology gap).** Gate 3.6's likelihood
construction — which §D9 leaves to implementation and this ADR has not previously specified — **MUST NOT** let
unbounded repetition of one technique substitute for distinctive behavioral diversity. It therefore consumes
**DECISION SUPPORT** (the single distinct-feature basis above), never `raw_support`. Concretely: `100` occurrences
of technique `A` do **not** produce `100×` the diagnostic likelihood of `A`; they produce **one** distinct-feature
decision contribution `D(A)`, with the multiplicity retained only in `raw_support` for explanation and as a
bounded persistence signal for confidence (below). This is explicitly a **G3.6 likelihood-*consumption* rule in
a previously-unspecified gap, not a contradiction of §D4**: §D4 governs `raw_support`'s independence units
(unchanged); §D4 itself already states repetition "can never, by itself, escape D20's single-technique guard,"
i.e. it always anticipated a downstream bound — this amendment supplies that bound.

**Persistence vs. corroboration — kept strictly distinct; diversity is not independence.** Two different
confidence signals must never be conflated (and neither is ever likelihood):

- **PERSISTENCE** = repetition of substantially the same behavior/evidence pattern (the `raw_support`
  multiplicity). It may feed confidence **only** through a **bounded** persistence treatment whose transform is a
  `calibration_version` parameter (never chosen here) — it must **never** become a disguised second likelihood
  score, and repetition of a non-distinctive behavior must not lift confidence for a lead with no distinctive
  decision support.
- **CORROBORATION** = agreement across **genuinely distinct** evidence. **Evidence-type diversity is *not*
  statistical independence**: two evidence types drawn from the **same `Observation`**, or correlated detections
  of the same underlying event, are **not** independent corroboration and must not be counted as such. Whether
  corroboration qualifies as independent is decided at the **confidence/provenance layer** (distinct
  `Observation`s, genuinely distinct evidence types), not asserted merely because `EvidenceType` values differ.
  This amendment makes no independence claim from type-difference alone.

**Concentration mechanism (structural definition on the DECISION basis; threshold calibration-controlled).**
Concentration is computed **entirely on DECISION SUPPORT**, never on `raw_support` — this supersedes the
Revision-1 `raw_support`-based definition. Each of the leader's own decision contributors (one distinct atomic
feature, or one admissible combination block — repeated occurrences add **no** contributor, and a combination's
members are not separately counted) has a **net-of-coincidence** decision share:

```
net(contributor)       = contribution(contributor) · ( 1 − g(contributor) )      # = D(f)·(1−g(f)); ≥ 0
contributor_separation(h) = Σ over h's own valid decision contributors:  net(contributor)
concentration(h)       = max_contributor[ net(contributor) ]  /  contributor_separation(h)
```

using the **un-normalized** decision-support form (never `decision_support_norm`, never `raw_support`), the same
distinct-feature basis and §D3 admissible-combination partitioning, with combination members never separately
counted.

- **`contributor_separation(h)` is NOT `separation_from_null(h)` (renamed and distinguished, per the audit).**
  They are **different quantities** and this amendment does not force them to be equal:
  `separation_from_null(h) = decision_support(h) − decision_support(Unattributed)` (§B2) is the **abstention**
  criterion against the **candidate-independent global** null built over the *entire* observed decision-feature
  universe; `contributor_separation(h)` is the **concentration** denominator built **only over the candidate's
  own matched decision contributors** (each net of its own coincidence, `D·(1−g)`). Their feature partitions
  differ — the candidate covers its matched features, while `Unattributed` is a global baseline over the observed
  decision-feature universe — so the two are deliberately distinct and are used for distinct decisions.
- **Same decomposition for numerator and denominator (so `concentration(h) ∈ [0, 1]` is guaranteed):** the
  denominator `contributor_separation(h)` is the sum of the very per-contributor `net(·)` terms the numerator
  takes the maximum of, and every `net ≥ 0` (since `0 ≤ g ≤ 1`). This `[0,1]` guarantee applies to concentration
  built on `contributor_separation(h)`, **not** to `separation_from_null(h)`.
- **Domain — evaluated only when `contributor_separation(h) > 0`.** If `contributor_separation(h) ≤ 0`,
  concentration is **undefined / not eligible**, and the attribution path **fails closed** to insufficient
  evidence via §D13 — concentration never divides by zero and never goes out of range.
- **Coincidence-discounting is automatic:** `net = D·(1−g) = D²`, so a **common** repeated feature (`g→1`)
  contributes `≈0` to both numerator and denominator and can never dominate concentration; a **rare** distinctive
  feature (`g→0`) contributes near its full `D`. **Repeated occurrences of one technique are a single
  contributor** (repetition remains raw-support/persistence information only, never an extra concentration
  contributor), so repetition cannot inflate concentration into a false dominance — and a case whose only
  decision contributor is one repeated technique is a **single-distinct-feature** case caught by §D13 condition 4
  directly.

**The load-bearing structural distinction:** a **legitimate distinctive combination** dominating is *acceptable*
(§D3/§D6 want distinctive combinations to dominate); a **single atomic feature, a repeated technique, or a
single evidence source** dominating is *not*. Concretely:

- A hypothesis whose `contributor_separation(h)` is dominated (concentration above `τ_concentration`) by a
  **single atomic / repeated-technique / single-source** contributor **cannot** satisfy §D13's
  distinctive-evidence condition (D13 condition 4) merely through that dominance or through repetition.
- A hypothesis whose `contributor_separation(h)` is dominated by a genuinely **admissible distinctive
  combination** (`g(C) < min g(x)`, §D3) **may** satisfy it **only when that combination is independently
  corroborated** — and, per §B5, "independently corroborated" here **requires** corroborating evidence from
  **distinct `Observation`s** and genuinely distinct evidence types, **not** duplicated/correlated detections of
  the same underlying event and **not** same-`Observation` evidence types. The confidence/provenance layer
  (§D10/§D4), not this metric, determines whether that condition is met. **Fail-closed independence rule
  (binding):** if independence **cannot be established** from the available provenance/evidence metadata, the
  independent-corroboration exemption **MUST be DENIED** — the candidate is then treated as **failing** the
  exemption and follows the normal concentration/abstention path (unknown independence ≠ independent
  corroboration; this is abstain-safe). This amendment does **not** define the future independence algorithm;
  that is the confidence/provenance gate's job. **Caveat retained (§D6/CR-5):** an admissible combination is a
  **profile-union approximation** — a superset match over group profiles does **not** establish that the
  techniques co-occurred within a single real intrusion; the exemption inherits that low-weight/flagged caveat.

`τ_concentration` — the fraction above which a non-combination-dominated separation is treated as
over-concentrated — is a **`calibration_version` parameter, not chosen here.** No numeric value is selected.

**Contract note.** This amendment **does not modify any Gate 3.2 contract** (`EvidenceAssessment`,
`HypothesisSupportSummary`, etc.); the concentration mechanism and its fields are defined here as a G3.6
computation over already-available data. The explainability fields it will require on the eventual result are
listed in §Explainability requirements below.

#### B6 — Actor attribution and campaign contextualization

**Structural rule (fixed here; not calibration).** Group candidates and the `Unattributed` null form the
**actor-attribution hypothesis space** — the only space in which likelihood, separation-from-null,
separation-from-next, confidence, and abstention are computed. **Campaign candidates are contextualization, not
actor hypotheses**, and **MUST NOT be directly ranked against Groups as competing actors**.

- Where the pinned KB provides a valid `attributed-to` relationship **Campaign → Group**, the campaign may
  **reinforce contextual corroboration**, **explain operational context**, and **appear in the analyst
  explanation** for the corresponding Group — feeding the Group's **confidence/corroboration** (§D10/§D4), but
  **never independently increasing that Group's actor *likelihood*** (§D9), and never manufacturing a likelihood
  the Group's own evidence did not earn.
- Where **no** `attributed-to` Group exists, the campaign is surfaced as **known-operation / contextual evidence
  with the actor unresolved** — never promoted into the actor-likelihood space, never collapsed onto the nearest
  Group.

**Anti-circularity rule (binding).** A `Campaign → Group` `attributed-to` edge is **ATT&CK knowledge context,
never case-specific proof** that this telemetry belongs to that Group. A campaign matched using the **same**
evidence already consumed by a Group's actor likelihood **MUST NOT** re-inject that evidence into the Group's
confidence — the following chain is explicitly **forbidden**: *campaign matched by TTPs → `attributed-to` Group →
Group confidence boost → the same TTP evidence counted again.* Campaign context may influence a Group's confidence
**only** through genuinely **independent contextual evidence** (e.g. campaign timing/victimology) **not already
counted** in that Group's actor-likelihood basis; the confidence/provenance layer enforces the non-overlap.

**Multi-attributed campaigns (binding).** A campaign with more than one `attributed-to` Group — `Campaign C →
Group A` *and* `Campaign C → Group B` — matched by the case evidence does **not** increase the likelihood of `A`,
does **not** increase the likelihood of `B`, does **not** split or duplicate confidence between them, does
**not** equalize them, and does **not** by itself create actor evidence for either. It is reported as
context: *"activity consistent with Campaign C, which ATT&CK associates with {A, B}; the actor is unresolved by
this evidence."* Each of `A` and `B` must independently earn any actor likelihood from its own Group-level
decision support, exactly as any other Group candidate.

**What is unchanged.** The dynamic candidate universe (§D7/D15/CR-3), campaign candidate *generation* (§D7),
and the ACH candidate *columns* including campaigns (§D8) all remain intact — campaign candidates are still
generated and still materialize ACH cells. **Amendment B changes only how campaign hypotheses are *consumed* by
the likelihood/assessment layer.** This is a decision in the previously-unspecified Gate 3.6 consumption layer,
consistent with §D3's candidate-type-invariance (which it does not touch: `g`/`D` remain Group-population-
relative and identical for all feature computations) and with §D3's own explicit statement that candidate type
"affects only which `Candidate`/`Hypothesis` rows the resulting `D` value is joined against." It **resolves Open
Question #2** (see §Open questions resolved).

#### Abstention decision (explicit decision-scale assignment)

Restates §D13 for this amendment's two-form model — no D13 threshold is chosen here; every numeric floor remains
calibration-controlled. The leading Group actor hypothesis is the one with the highest **`decision_support_norm(h)`**
(§Decision-path scale). Identifying the leader does **not** select a winner: the leader is emitted as a
non-`Unattributed` attribution **only if it independently satisfies every applicable condition**, each on its
assigned form and **never combined into a single score**:

1. **Separation from null** — `separation_from_null(h) = decision_support(h) − decision_support(Unattributed)`
   (un-normalized form, §B2) exceeds the calibrated `τ_separation`.
2. **Margin / separation-from-next** — `decision_support_norm(h)` exceeds the next Group hypothesis by the
   calibrated `τ_margin`, **or** the result is reported as a competing set (§D13.3).
3. **Confidence** — meets the calibrated `min_confidence` floor (§D10; coverage/persistence/corroboration).
4. **Concentration** — `concentration(h)` (on `contributor_separation(h)`) is within `τ_concentration`, **or**
   the dominant contributor is an admissible distinctive combination that clears the **fail-closed**
   independent-corroboration exemption (§B5).
5. **Distinctive-combination / independent-corroboration** where applicable, and the **single-technique guard**
   (§D13.4), and every other §D13 condition.

If **any** required condition fails (including unknown independence, which fails closed), the outcome is
`Unattributed` + **"Insufficient evidence for attribution."** No premature actor ranking, numeric confidence
score, probability, or point total is produced; "insufficient evidence" is always a valid outcome.

#### Calibration boundary

This amendment fixes **structure** and defers **every numeric value**, mirroring §D17 and Amendment A's own
discipline.

**Structural (fixed by Amendment B, not calibration-tunable):**

- the RAW-SUPPORT vs DECISION-SUPPORT distinction and the **two explicitly-assigned forms** — un-normalized
  `decision_support` and profile-breadth-normalized `decision_support_norm` — with each downstream operation's
  assigned form (Decision-path scale);
- the candidate-independent, un-normalized coincidental-overlap null `decision_support(Unattributed) =
  Σ contribution(f)·g(f)`, deterministic, a heuristic expected-overlap baseline (B2);
- the distinct-feature likelihood-consumption basis, the preservation of multiplicity in `raw_support`, and the
  persistence-vs-corroboration separation (B5);
- `contributor_separation(h)` and the concentration *definition* on it (`net = D·(1−g)`, domain `> 0`, range
  `[0,1]`), its distinctness from `separation_from_null`, and the combination-vs-single-contributor distinction
  with its distinct-`Observation`/distinct-type, **fail-closed** independent-corroboration condition (B5);
- **active-target `ProfileBreadth`** and the consistent active-object policy for every prevalence/traversal
  quantity (Decision-path scale);
- the **fail-closed unknown-independence** rule (B5);
- the Group-only actor-likelihood space, Campaign contextualization, the anti-circularity rule, and
  multi-attributed-campaign semantics, including `attributed-to` reinforcement semantics (B6).

**Calibration-controlled (`calibration_version` parameters; no value chosen here):** `τ_separation` (now the
margin above the non-zero null), `τ_margin`, `τ_concentration`, `min_profile_floor`, any later-validated fitted
replacement of the linear null baseline, WEP-band cutoffs, confidence-band cutoffs, the §D3 minimum-support
count, and any diminishing-returns multiplicity curve (if ever justified on corpus evidence). No numeric value
is selected in this amendment.

#### ATT&CK attributed-to traversal prerequisite

B6 requires a **deterministic** ATT&CK traversal capability, additive to `attack_knowledge/` in the same
Option-A style §D6 already established (the current Gate 3.1 traversal layer deliberately omits it —
"no campaign-attribution (`attributed-to`) traversal ... not required by this gate"):

```
Campaign  --attributed-to-->  Group
```

Requirements: operates over the **one pinned, already-loaded `AttackKnowledge`** only (no network, no "latest"
resolution — §D16); the **`attributed-to` relationship object itself must be active** (non-revoked/
non-deprecated) **and the target Group must itself be active** (§D3/§D6 filtering applied to both the edge and
its target); **real STIX `relationship` objects only** (`relationship_type == "attributed-to"` with matching
`source_ref`/`target_ref`), **never an inferred, heuristic, or fabricated relationship, and never any
case-specific attribution implied** by the edge; **deterministic ordering** (sorted-by-id, §D16). **This
amendment does not implement the traversal** — it records it as a **Gate 3.6 prerequisite** to be built as
implementation work under §Implementation Gates.

#### Explainability requirements

When Gate 3.6 is later implemented against this amendment, the per-hypothesis attribution summary must retain
enough to explain the B2/B5 mechanisms end to end — **audit/explainability fields, never probabilities** (this
documentation amendment implements none of them):

- `decision_support_value` — the leader's **un-normalized** `decision_support(h)` (distinct-feature,
  B5/Decision-path scale);
- `decision_support_norm_value` — the **profile-breadth-normalized** `decision_support_norm(h)` used for
  cross-Group ranking/margin (Decision-path scale);
- `support_unattributed` — the computed non-zero coincidental-overlap baseline, `decision_support(Unattributed)`
  (B2, un-normalized; the null has no profile breadth);
- `separation_from_null` — `decision_support(h) − decision_support(Unattributed)` (un-normalized form, B2);
- `contributor_separation` — `Σ net(contributor)` over the candidate's own decision contributors (B5), **not**
  equal to `separation_from_null`;
- `separation_top_contributor_fraction` — `concentration(h) = max net / contributor_separation(h)`, in `[0, 1]`
  (B5);
- `dominant_contributor_is_combination` — whether the dominant contributor is an admissible distinctive
  combination (B5, the exemption condition);
- `distinct_feature_count` — the number of distinct atomic features underlying the decision basis (B5);
- `max_occurrence_count` — the largest single-technique repetition observed (B5, the **persistence** signal that
  feeds confidence, never likelihood);
- `separation_survives_lowD_removal` — whether the separation persists when low-`D` terms are removed (doc 07 §4).

These extend, and do not replace, Amendment A's four already-required support-explainability fields
(`raw_support_value`, `support_value`, `profile_breadth`, `profile_breadth_floor_applied`), which remain valid
explanation/provenance quantities (RAW SUPPORT and Amendment A's normalized `support_value`) alongside the
DECISION SUPPORT fields above — the two are recorded separately and never conflated.

#### Compatibility with D1–D21

Every D1–D21 decision was checked for contradiction; **none is contradicted.** No apparent contradiction was
found that would require stopping.

- **D1 — intact.** One `CorrelationGroup` remains exactly one attribution unit; nothing here merges groups or
  changes the unit. B6 operates on the one unit's candidate columns.
- **D3 — intact.** `g(x)`/`D(x)` remain **Group-population-relative** and candidate-type-invariant; B2's null
  reuses the identical `g`, and B6 introduces **no** campaign-relative population or campaign prior (Open Q2's
  explicit constraint is honored).
- **D4 — clarified, not contradicted.** `raw_support`'s occurrence multiplicity is preserved verbatim; the new
  DECISION SUPPORT / distinct-feature basis is a *likelihood-consumption* rule in a gap §D4 itself anticipated
  ("can never, by itself, escape" the guard), not a redefinition of §D4's independence units. RAW SUPPORT and
  DECISION SUPPORT are held separately and never conflated.
- **D5 — intact.** The `UNATTRIBUTED_CANDIDATE_ID` sentinel *representation* is unchanged; only its **computed
  support value** moves from the implementation's `0.0` to the B2 baseline. `Candidate`/`Hypothesis`/
  `EvidenceAssessment` contracts are unchanged. **D6 — intact:** combination/`uses` semantics and the additive
  traversal-extension pattern are reused, not altered; the `attributed-to` capability is a new additive sibling,
  exactly as §D6 permits.
- **D7/D8 — intact.** Dynamic full-universe candidate generation and the ACH matrix (including campaign columns)
  are unchanged; only campaign *consumption* by the later likelihood layer changes.
- **D9 — clarified.** `raw_support(h)`/Amendment A's `support(h)` remain the internal evidence aggregate and a
  valid explainability quantity; §D9's existing "separation from the `Unattributed` floor" wording is honored —
  Amendment B specifies that the *likelihood ranking* consumes **DECISION SUPPORT** (distinct-feature,
  breadth-normalized), supplies the floor's structural value, and adds the concentration consumption, never a
  competing formula and never a probability.
- **D10 — clarified.** Confidence, coverage, and the imitation cap remain a separate axis; **persistence**
  (repetition) and **corroboration** (distinct-`Observation`, distinct-type evidence) feed confidence here — kept
  strictly distinct, bounded, and never likelihood; evidence-type diversity is explicitly not treated as
  statistical independence — reinforcing, not weakening, the two-axis separation.
- **D11 — intact.** Contradiction remains coverage-dependent and `contradiction_strength` remains deferred;
  Amendment B introduces no contradiction handling and does not use the null as a contradiction substitute.
- **D13 — intact and strengthened.** Abstention is made *harder to trivially avoid* by the non-zero null
  (condition 1 now measures against a real baseline) and by the concentration condition supplementing condition 4
  (single-technique guard); no D13 threshold is chosen.
- **D15 — intact.** No numeric uncertainty value is introduced; provenance obligations are unchanged (the new
  explainability fields are categorical/audit values, not fabricated scores).
- **D16 — intact.** The null, the concentration metric, and the `attributed-to` traversal are all deterministic,
  closed-form, sorted-by-id, and free of RNG/wall-clock/live-lookup.
- **D18/D19 — intact.** Tier-1/Tier-2 validation separation, blind-actor holdout, and the **hard
  `calibration_version` prerequisite** all still bind; Amendment B does not create a `calibration_version` and
  does not relax §D19's hard-fail.
- **D20 — intact, with a required bump.** Six version identities remain; Amendment B is a methodology change and
  therefore **requires a new `methodology_version`** (below) and revalidation on acceptance.
- **D21 — intact.** No new prohibition is weakened: no ML, no live OSINT, no posterior probabilities, no
  analyst-facing numeric score, no single-technique attribution, no cross-group campaign merging — B6's campaign
  contextualization is explicitly *not* a cross-`CorrelationGroup` merge (it stays within the one unit).
- **Open Question #2 — resolved** (see §Open questions resolved).

**Compatibility with Amendment A (explicit).** Amendment A established `support(h) =
raw_support(h) / ProfileBreadth_effective(h)` as the authoritative ordering statistic and stated G3.6 *may*
consume it. Amendment B **does not erase Amendment A's terminology or change `raw_support(h)`/`support_value`**:
those remain valid explainability/intermediate quantities on every hypothesis. It **clarifies** that G3.6 actor
likelihood consumes a **DECISION SUPPORT** family (distinct-feature, multiplicity-bounded) in two forms, of which
the normalized `decision_support_norm(h) = decision_support(h) / ProfileBreadth_effective(h)` reuses **the
identical Group `ProfileBreadth_effective` mechanism** Amendment A defined — so Amendment A's normalization
machinery is reused, not replaced. **`decision_support_norm(h)` is a new G3.6 decision-path quantity, NOT a
silent rewrite of Amendment A's `support_value`** (`raw_support(h) / ProfileBreadth_effective(h)`): the two
differ in their numerator (distinct-feature decision support vs. multiplicity-preserving raw support) and both
are retained separately. This is a permitted clarification of *how* G3.6 consumes the existing support machinery
(Amendment A wrote "may consume"), not a contradiction of Amendment A or of D1–D21.
The behavioral change (likelihood no longer multiplicity-driven; a non-zero null) is the reason for the
`methodology_version` bump below.

#### Methodology versioning

Amendment B changes methodology (the `Unattributed` support value, the likelihood-consumption basis, and campaign
consumption all change observable results and therefore `determinism_hash`), so per §D20 it **requires a new
`methodology_version`** and full revalidation on acceptance, and — per §D17 — a **new `calibration_version`** once
calibration exists. The repository establishes **no concrete `methodology_version` string literal** anywhere yet
(none exists in code; Amendment A likewise bumped methodology without pinning a literal), so **the exact
`methodology_version` identifier must be assigned at acceptance**, distinct from and superseding both the original
ADR-0005 acceptance and the Amendment A revision. This amendment does not invent one.

#### Preconditions for G3.6

Unchanged by drafting this amendment; restated so the gate is unambiguous. G3.6 (likelihood/separation +
confidence + abstention + result emission) may proceed only when **all** hold:

1. **Amendment B ACCEPTED** (dated) with the `methodology_version` assigned — resolves B2/B5/B6 structurally.
2. **B1** — the golden corpus is built and the first `calibration_version` is frozen (C3.2); §D19 hard-fails any
   scoring path without it. This unblocks `τ_separation`, `τ_concentration`, `min_profile_floor`, and the band
   cutoffs.
3. **B3** — a `CoverageProfile` construction path exists (§D2), *or* G3.6 explicitly scopes confidence to fail
   closed on absent coverage — required for §D10/§D11.
4. **B4** — `evidence_type` (and the backing `Evidence`/`Observation` ids) are threaded into the G3.6 input
   contract — required for §D4/§D10/§D12 (the imitation defense) and for provenance.
5. **`attributed-to` traversal** implemented (§ATT&CK attributed-to traversal prerequisite) — required for B6.
6. **Active-target traversal** — the Gate 3.1 traversal layer extended so `ProfileBreadth`, `g(x)`, `g(C)`,
   `group_profile`, and combination superset checks count only **active** ATT&CK target objects
   (§Decision-path scale). Required before any normalized/decision-support quantity is computed.
7. **Fail-closed independence semantics** — G3.6 treats unknown independence as *not* independent corroboration
   (§B5), so the combination-dominance exemption denies by default; the operational independence check itself is
   deferred to the confidence/provenance gate. These dependencies do **not** exist in the codebase yet.

#### Open questions resolved

- **Open Question #2 (campaign-specific scoring treatment beyond diagnosticity) — RESOLVED.** Campaign candidates
  are **not** ranked in the actor-likelihood space; they are consumed as contextualization and, via
  `attributed-to`, as confidence/corroboration reinforcement of the corresponding Group, never as independent
  actor likelihood. No campaign-relative diagnosticity population and no campaign prior is introduced (§D3
  unchanged). The narrower calibration-boundary sub-question Open Q2 left open — whether a *stricter*
  per-candidate-type `τ_separation`/`min_confidence` is ever fitted — remains a `calibration_version` question,
  now moot for actor ranking since Campaigns no longer occupy that space.

#### Remaining deferred questions

Unchanged and still deferred (Amendment B resolves none of these): the numeric definition of
`contradiction_strength` (coverage/contradiction methodology); the `ti_kb_version`/TI-enrichment and Admiralty
source-reliability layer (Open Q3); `D`'s calibrated non-baseline functional shape (Open Q4); the minimum-support
threshold and neutral-prior value (Open Q5); the `>8`-distinct-feature combination-search computational bound; the
software-evidence reachability question (Open Q1); and **every calibration numeric value** named above.

Newly named by Amendment B but deferred to the confidence/provenance methodology (not resolved here): the
**bounded persistence-to-confidence transform** (structurally required to be bounded and calibration-controlled,
B5) and the **operational independence check** that decides when corroboration counts as independent — i.e. the
concrete "distinct `Observation`s / distinct evidence types / not correlated detections" test that gates both the
confidence corroboration factor and the combination-dominance exemption (B5/B6). Amendment B fixes the
*principle* (diversity ≠ independence; same-`Observation` agreement does not qualify) and defers the *mechanism*
to the confidence/provenance layer and its own later gate.

#### Amendment B status

**Status: ACCEPTED** (2026-09-17)

**Acceptance record.** Amendment B — as it stands at **Revision 3** — is **formally accepted on 2026-09-17**,
following the final hostile pre-acceptance audit (verdict: PASS WITH NON-BLOCKING FINDINGS). The Revision 1 /
Revision 2 / Revision 3 history above is preserved intact as the record of how this amendment reached its
accepted form; the accepted technical content is the Revision-3 text and no Revision-3 methodology was rewritten
at acceptance. The three non-blocking findings (N-1 "likelihood consumption" form wording, N-2 "valid
contributor" definition, N-3 explicit concentration-vs-normalization purpose sentence) are recorded as
non-blocking and are **not** applied here — they may be polished in a future dated clarification without
reopening the accepted methodology.

Per §D20 this acceptance carries a `methodology_version` bump; the exact identifier is assigned per
§Methodology versioning (no literal convention exists in the repository yet).

**Acceptance of this methodology is NOT authorization to begin G3.6 implementation.** G3.6 remains blocked by its
stated prerequisites, each an independent hard gate: the calibration corpus and a frozen `calibration_version`
(C3.2, §D19 hard-fail); the active-target ATT&CK traversal extension; `CoverageProfile` construction (B3);
`evidence_type` / `Observation` provenance plumbing (B4); the `attributed-to` traversal; and the confidence-layer
requirements. None of these is satisfied by accepting the methodology, and none may be bypassed on the strength
of this acceptance.

### Amendment C (2026-09-21) — Coverage model under pinned ATT&CK v19 (`CoverageProfile` construction, B3)

**What this amends, and what it preserves.** This amendment records the implementation-facing interpretation of
**§D2 (Coverage model)** under the pinned knowledge base `enterprise-attack-19.0`. It is **additive**: §D2's
original decision text — including its prose that the required data-source/component requirement is "already
present on the raw `attack-pattern` STIX objects `AttackKnowledge` loads" — is **left intact above and is not
rewritten or erased**. That original wording is retained as the historical record of what §D2 assumed at
acceptance. This amendment states, dated, the current pinned-v19 interpretation that supersedes only that one
mechanistic assumption; every other §D2 decision (the four-value `CoverageState`, the fail-closed `UNKNOWN`
default, the §D11 state→consequence wiring, `compute_coverage_profile_id`, `attack_kb_version` stamping) is
**unchanged**.

**What was missing / factually superseded.** §D2 was written against a pre-v17 ATT&CK data model in which each
`attack-pattern` carried an `x_mitre_data_sources` string list. The repository pins `enterprise-attack-19.0`, in
which: (a) **no** technique carries `x_mitre_data_sources` (or any `data_source*`/`data_component*`) field;
(b) the 38 `x-mitre-data-source` catalog objects are **orphaned** — not reachable from any technique by any
relationship or reference; and (c) per-technique detection information is expressed through the newer
detection-strategy / analytic / log-source / data-component graph. §D2's original derivation mechanism therefore
cannot be applied to the pinned data. The final-architecture review (doc 10, milestone **M3** / checklist
**C2.1**) had already flagged the coverage model as load-bearing but underspecified and required a dedicated
mini-spec before Phase 2/3; that mini-spec did not previously exist.

**Canonical coverage vocabulary (locked).** `data_sources_required`, `data_sources_available`, and (via ADR-0006)
`CalibrationCase.coverage_assumptions` use the **active `x-mitre-data-component` object name** vocabulary. This is
the only technique-linked, telemetry-granularity ATT&CK vocabulary reachable in the pinned v19 graph; ATT&CK
data-source catalog objects are orphaned, and analytic log-source `name`/`channel` values are collector-specific.
No new ontology is introduced — this selects an existing ATT&CK object type's `name`.

**Required-side derivation (locked).** For a technique `T`, `required(T)` is the set of active data-component
names reachable via `T ← active detects ← active detection-strategy → active analytic →
x_mitre_log_source_references[].x_mitre_data_component_ref → active data-component`. Pinned `AttackKnowledge`
only; active filtering at every hop (the accepted active-object policy); dangling references skipped fail-closed;
deterministic sorted-unique output; no KB mutation; an empty result is valid and drives `UNKNOWN`.

**Available-side (locked).** `data_sources_available` is an explicit caller-supplied tuple of canonical
data-component names — never inferred inside construction. Production passes `available = ()`; calibration passes
the case's declared `coverage_assumptions`.

**Four-state coverage rule (locked; no thresholds).** With `observed` = the group has an active `Evidence` whose
`attack_ref` resolves to `T`:

| `observed` | `required` | `required ∩ available` | `CoverageState` |
|:----------:|:----------:|:----------------------:|:----------------|
| present    | (any)      | (any)                  | `OBSERVED_PRESENT` |
| not present| `≠ ∅`      | `≠ ∅`                  | `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` |
| not present| `≠ ∅`      | `= ∅`                  | `NOT_OBSERVABLE` |
| not present| `= ∅`      | (n/a)                  | `UNKNOWN` |
| not present| indeterminate / malformed / unresolved availability | (n/a) | `UNKNOWN` |

"Adequate coverage" is binary (`required ≠ ∅` and `required ∩ available ≠ ∅`) — **no thresholds, percentages,
weights, or per-technique exceptions**, consistent with §D2's deliberate exclusion of a continuous coverage
percentage. The §D11 state→consequence wiring is unchanged.

**Production fail-closed availability (locked).** Production currently constructs coverage with `available = ()`.
`SourceRef.source_type` is opaque by architecture (G0.3), so no heuristic `source_type`/ECS → ATT&CK mapping is
permitted in B3 and no availability is inferred. Because `required ∩ available` is then always empty, production
**never** emits `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` and coverage never lowers likelihood in production —
satisfying this amendment set's own §"Preconditions for G3.6" item 3 ("a `CoverageProfile` construction path
exists (§D2), *or* G3.6 explicitly scopes confidence to fail closed on absent coverage"). A future
telemetry-to-ATT&CK availability mapping is a separate, independently-accepted research/data-artifact task and is
not created by B3.

**Anti-circularity (restated as binding).** `CoverageProfile` construction may read only the pinned ATT&CK
detection graph, the technique identity, technique observation presence, and caller-supplied telemetry
availability. It must not read candidate generation, `g(x)`, `g(C)`, `D(x)`, ACH results, hypotheses, likelihood,
confidence, WEP, abstention, or `AttributionResult`. Coverage is an independent observability/contradiction
input, never an additional attribution signal.

**Authoritative specification.** The full implementation-facing methodology is
`docs/architecture/11-coverage-model.md`. This amendment is a dated additive clarification; it does not erase the
historical §D2 text and reopens no other decision in this ADR.
