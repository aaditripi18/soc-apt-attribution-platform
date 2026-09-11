# 06 — Evidence Model

**Status: PROPOSED** (specification; no code). Defines every entity in the attribution provenance chain and
the rules governing it. Implements [ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md);
mechanics live in [07 scoring spec](07-attribution-scoring-spec.md).

## The provenance chain

```
RawEvent → Observation → Evidence → TechniqueAssertion → BehavioralFeature
        → Candidate → {SupportingEvidence, ContradictingEvidence, DiscriminatingEvidence}
        → Hypothesis → AttributionAssessment (Likelihood / Confidence) → AttributionResult
```

**Universal rules (apply to every entity below):**

- **U1 — Provenance is mandatory.** Every non-raw entity stores `derived_from`: the IDs of the entities it
  was derived from. No entity may exist without a path back to `RawEvent`s.
- **U2 — Immutable knowledge references.** Any reference to ATT&CK/TI knowledge stores the **KB version**
  used, so the meaning is reproducible.
- **U3 — No silent inference.** Each entity lists *what must NOT be inferred automatically*. Violating it is
  a validation failure, not a judgment call.
- **U4 — Uncertainty is carried, not hidden.** Entities that can be uncertain carry an explicit
  `quality`/`uncertainty` annotation (see §Uncertainty), never an unexplained float.
- **U5 — Determinism.** Given the same inputs and versions, entity construction is deterministic.

---

## Knowledge entities (loaded, not derived — from pinned ATT&CK/TI)

**`AttackTechnique` / `AttackSubTechnique`** — ATT&CK technique with `id` (e.g., T1059.001), tactic(s),
data sources/components, and the set of groups/software that use it. **Provenance:** ATT&CK KB version.
**Must NOT:** be edited case-side; be created ad hoc (only from the pinned bundle).

**`ThreatActor` (Group) / `Campaign` / `Software`** — ATT&CK `intrusion-set`/`campaign`/`malware|tool`,
including **alias set** and `uses`/`attributed-to` relationships. **Must NOT:** treat two aliases of one
actor as distinct actors; infer relationships not present in the KB.

**`CoverageProfile`** — per technique, the ATT&CK data sources/components required to observe it
(DeTT&CT-style). **Purpose:** decide whether an "expected-but-missing" behavior could even have been seen.
**Must NOT:** assume coverage; unknown coverage defaults to "unknown," which lowers confidence.

---

## Case entities (derived during an investigation)

### 1. `RawEvent`
- **Purpose:** the atomic ground truth — a single normalized (ECS) telemetry event in Elastic.
- **Required fields:** `event_id` (Elastic `_index`/`_id`), timestamp, host, and the ECS fields relevant to
  detection (process, user, command line, hashes, network, etc.), `dataset_ref` (name@content-hash).
- **Provenance:** is the root; carries dataset/source identity.
- **Relationships:** referenced by `Observation`.
- **Validation:** must resolve to a real event in Elastic/replay; timestamp present.
- **Must NOT infer:** anything — it is raw. No enrichment stored here.

### 2. `Observation`
- **Purpose:** a *detected fact* — the output of a detection rule/analytic matching one or more events.
- **Required fields:** `observation_id`, `rule_ref` (rule id + version), `matched_fields` (which fields
  caused the match), `entities` (host/user/process/etc.), `time_span`, `observation_confidence` (see
  §Observation confidence).
- **Provenance (`derived_from`):** the `RawEvent` ids that matched.
- **Relationships:** produces `Evidence`; participates in `AttackChain` (doc 03).
- **Validation:** every matched field must exist on a referenced event; rule_ref must resolve.
- **Must NOT infer:** a technique beyond what the rule's logic asserts; an entity not present in the events;
  intent or attribution.

### 3. `Evidence`
- **Purpose:** an observation *interpreted as bearing on attribution* — the bridge from "something happened"
  to "this means something." One observation can yield multiple evidence items (behavioral, IOC, procedural).
- **Required fields:** `evidence_id`, `evidence_type` ∈ {behavioral (TTP), evidentiary (IOC/infrastructure),
  procedural, contextual (victimology/targeting)}, `reliability` grade, `quality` annotation, `derived_from`.
- **Provenance:** the `Observation`(s); if enriched, the enrichment source + **Admiralty source grade**.
- **Relationships:** feeds `TechniqueAssertion` (behavioral/procedural) or links directly as evidentiary
  corroboration; becomes Supporting/Contradicting/Discriminating relative to a hypothesis.
- **Validation:** `evidence_type` set; behavioral evidence must map to ≥1 technique; evidentiary evidence
  must carry a source grade.
- **Must NOT infer:** that evidentiary artifacts (IOCs) are decisive (they are corroborating only, per
  ADR-0002); that an enrichment hit is reliable without a source grade.

### 4. `TechniqueAssertion`
- **Purpose:** the claim "this evidence supports (or contradicts) ATT&CK technique/sub-technique T."
- **Required fields:** `assertion_id`, `technique_ref` (+ KB version), `polarity` ∈ {supports, contradicts},
  `basis` (the rule/analytic + matched fields = the *why*), `observation_confidence` inherited/combined,
  `sub_technique_granularity` (technique vs sub-technique).
- **Provenance:** the `Evidence`/`Observation` and the ATT&CK KB.
- **Relationships:** aggregates into `BehavioralFeature`; is the unit shown as "why technique T is
  supported."
- **Validation:** `technique_ref` resolves in the pinned KB; basis non-empty; polarity set.
- **Must NOT infer:** a sub-technique when the evidence only supports the parent technique (granularity must
  match the evidence); a technique from analyst intuition without a rule/analytic basis.

### 5. `BehavioralFeature`
- **Purpose:** the case's *behavioral profile* — the structured, combination-aware representation
  attribution actually reasons over (not a bag of technique IDs).
- **Required fields:** `feature_id`, `technique_set` (with per-technique support strength +
  **discriminating power**), `tactic_coverage` (which tactics are represented), `sequence` (observed
  tactic/kill-chain ordering), `combinations` (notable co-occurring technique sets), `derived_from`.
- **Provenance:** the contributing `TechniqueAssertion`s.
- **Relationships:** compared against `Candidate` behavioral profiles to generate evidence links.
- **Validation:** every element traces to ≥1 assertion; discriminating power is computed from the pinned KB,
  not stored by hand.
- **Must NOT infer:** that a technique combination is an actor fingerprint; ordering not supported by
  observation timestamps.

### 6. `Candidate`
- **Purpose:** a threat actor/campaign under comparison — **generated from evidence**, never assumed.
- **Required fields:** `candidate_id`, `actor_ref`/`campaign_ref` (+ alias set, KB version),
  `generation_basis` (which observed techniques/software placed it in the set).
- **Provenance:** the techniques/software that implicated it + the ATT&CK KB.
- **Relationships:** the subject of a `Hypothesis`; linked to Supporting/Contradicting/Discriminating
  evidence.
- **Validation:** must have a non-empty `generation_basis` (no candidate without evidentiary reason);
  aliases collapsed to one candidate.
- **Must NOT infer:** inclusion because an actor is famous/expected; distinct candidates for aliases of one
  actor.
- **Special candidate — `UnattributedHypothesisTarget`:** a mandatory null "actor" representing "matches no
  tracked actor well," always present so "insufficient evidence" can win (ADR-0002 D5). Its support is an
  **absolute coincidental-overlap floor** ([07 §5](07-attribution-scoring-spec.md), CR-2): a named candidate
  must exceed *coincidental* overlap on *distinctive* evidence to beat it — the guard against forcing a known
  label onto an under-represented or absent actor.
- **Universe (CR-3):** the candidate universe is the **entire pinned group+campaign set**; there is no
  configured actor list. Any display-time pruning is by diagnosticity, never prominence; the full set is
  retained for scoring.

### 7. Evidence-to-hypothesis links: `SupportingEvidence`, `ContradictingEvidence`, `DiscriminatingEvidence`
- **Purpose:** the ACH cell — how a specific evidence item bears on a specific candidate.
- **Required fields:** `link_id`, `evidence_ref`, `candidate_ref`, `role` ∈ {supporting, contradicting},
  `diagnosticity` (how much this item *separates* candidates; computed), `relevance` (does the candidate use
  this technique/software per KB), `contribution` (operationalized in [07](07-attribution-scoring-spec.md)).
- **`DiscriminatingEvidence`** is the subset of links with **high diagnosticity** — evidence that is
  consistent with few candidates (it is a *view* over the links, not a separate assertion).
- **`ContradictingEvidence`** includes the **expected-but-missing** case: a technique the candidate
  characteristically uses that is absent *despite adequate `CoverageProfile`*; if coverage was inadequate,
  it is recorded as a **coverage gap** (affecting confidence), **not** contradiction.
- **Provenance:** the `Evidence` + `Candidate` + KB relationships.
- **Validation:** role set; diagnosticity/relevance computed from KB (not hand-set); expected-but-missing
  requires a coverage check.
- **Must NOT infer:** contradiction from KB absence alone ("group not known to use T" ≠ "group cannot use
  T" — this is *weak* contradiction, graded accordingly); high diagnosticity for common techniques;
  **attribution from a single technique however rare — rarity is a weight, not proof (CR-6);** **duplicate
  contributions from correlated observations of the same technique — causally-related detections of one
  behavior contribute once (CR-1).**

### 8. `Hypothesis`
- **Purpose:** the complete case for one candidate under ACH.
- **Required fields:** `hypothesis_id`, `candidate_ref`, `supporting[]`, `contradicting[]`,
  `discriminating[]` (views over links), `coverage_notes`, `alternative_explanations` (incl. possible
  deception, per ADR-0002 D10), `derived_from`.
- **Provenance:** all evidence links + coverage profiles used.
- **Relationships:** scored into an `AttributionAssessment`; ranked against sibling hypotheses.
- **Validation:** must include contradicting/absent evidence if any exists (a hypothesis may not present
  only supporting evidence — an explicit anti-confirmation-bias rule).
- **Must NOT infer:** a likelihood/confidence value inside the hypothesis (that is the assessment's job);
  suppression of contradicting evidence.

### 9. `AttributionAssessment` (Likelihood + Confidence)
- **Purpose:** the two-axis judgment for a hypothesis. **The two axes are separate fields.**
- **Required fields:**
  - `likelihood`: WEP band (e.g., "likely") + the **relative** support ordering it came from + the
    separation from the next hypothesis.
  - `confidence`: {high, moderate, low} + the reasons (completeness/coverage, reliability, corroboration,
    consistency, contradiction load, calibration availability).
  - `uncertainty`: explicit residual (what is unknown / unresolved contradictions).
  - `next_evidence`: the observation/technique that would most change the ranking (+ the coverage gap it
    addresses).
  - version stamps (see §Versioning).
- **Provenance:** the `Hypothesis` + the scoring/calibration version.
- **Validation:** likelihood and confidence are **never** combined into one number internally; STIX mapping
  is output-only.
- **Must NOT infer:** high confidence from strong likelihood (or vice-versa) — they are orthogonal by
  construction.

### 10. `AttributionResult`
- **Purpose:** the final, explainable answer for an investigation.
- **Required fields (minimum):** `candidate_hypotheses[]` (ranked, each with its assessment),
  `relative_likelihood` summary, `confidence` summary, `supporting_evidence`, `contradicting_evidence`,
  `discriminating_evidence`, `uncertainty`, `provenance` (full chain refs), `attack_techniques_involved`,
  `behavioral_features_involved`, `attack_kb_version`, `ti_kb_version`, `methodology_version`,
  `calibration_version`, `dataset_ref`, `engine_version`, `determinism_hash`, and a **ranking explanation**
  ("why the leading hypothesis ranks above alternatives," in terms of discriminating evidence and
  contradiction).
- **The insufficient-evidence result** is a valid `AttributionResult` whose leading hypothesis is
  `Unattributed`, stating *why* (which discriminating evidence is missing, which coverage gaps, what would
  change it). See [07](07-attribution-scoring-spec.md) §Decision rule.
- **Validation:** all minimum fields present; every listed conclusion resolves to provenance;
  determinism_hash reproducible.
- **Must NOT infer:** an actor attribution when the decision rule is not met; a single headline percentage.

---

## Uncertainty model (how U4 works)

Uncertainty is carried as **graded annotations + bands**, combined by **conservative, inspectable rules**,
never as multiplied pseudo-probabilities:

- Each `Observation`/`Evidence` carries `observation_confidence` and `reliability` grades.
- These propagate to `TechniqueAssertion` and `BehavioralFeature` (an assertion is no more reliable than its
  weakest necessary input).
- `Hypothesis` confidence is **bounded by its weakest critical link** (ADR-0002 D11): thin/low-reliability
  bases cap confidence regardless of likelihood.
- Coverage gaps widen `uncertainty` and lower `confidence`; they never change `likelihood`.
- Where precision is unjustified, values are **qualitative bands** (high/moderate/low; WEP), not decimals.

## Versioning (reproducibility, ADR-0002 D12)

Every `AttributionResult` stamps: **`attack_kb_version`** (pinned STIX release), **`ti_kb_version`**,
**`methodology_version`** (this spec), **`calibration_version`** (the fitted thresholds), plus
`dataset_ref` (name@content-hash) and `engine_version` (commit). Identical values ⇒ identical
`determinism_hash`. Changing any version is a new, traceable result — never a silent change.
