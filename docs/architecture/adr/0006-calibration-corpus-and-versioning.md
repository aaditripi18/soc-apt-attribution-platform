# ADR-0006 — Calibration Corpus & Versioning (Phase 3 prerequisite B1)

- **Status:** ACCEPTED (2026-09-17)
- **Date:** 2026-09-17 (proposed) · 2026-09-17 (accepted)
- **Deciders:** project owner (accepted after a final hostile pre-acceptance architecture re-audit — verdict PASS WITH NON-BLOCKING FINDINGS, READY FOR ACCEPTANCE)
- **Supersedes / superseded by:** —
- **Related:** [ADR-0001](0001-evidence-graph-core-architecture.md) ·
  [ADR-0002](0002-attribution-scoring-and-evidence-methodology.md) ·
  [ADR-0003](0003-correlation-and-behavioral-chain-layer.md) ·
  [ADR-0004](0004-behavioral-sequence-reconstruction.md) ·
  [ADR-0005](0005-attribution-engine-specification.md) (incl. **Amendment B, ACCEPTED 2026-09-17**) ·
  [07 scoring spec](../07-attribution-scoring-spec.md) · [08 validation & calibration](../08-validation-and-calibration.md) ·
  [research 07 datasets](../../research/07-datasets-and-synthetic-telemetry.md)

> This ADR is **ACCEPTED** (2026-09-17). It records the **architecture** for the calibration corpus and the
> calibration-versioning system named as prerequisite **B1** by accepted ADR-0005 Amendment B. It **does not**
> create the corpus, generate calibration data, fit any parameter, select any numeric value, build the
> blind-actor-holdout harness, or write any Gate 3.6 / scoring / confidence code. It treats ADR-0001/0002/0003/
> 0004/0005 (including Amendment B) as **authoritative and unchanged**; it neither reopens nor reinterprets any
> accepted decision. The next step after drafting is a separate hostile architecture audit; acceptance is a
> later, separate step.

## Context

ADR-0005 §D17/§D19 and Amendment B make a **frozen `calibration_version` a hard runtime prerequisite** for any
Gate 3.6 scoring path (`AttributionAssessment`/`AttributionResult` require a non-empty `calibration_version`;
§D19 hard-fails without one). Amendment B enumerates the calibration-controlled quantities (`τ_separation`,
`τ_margin`, `τ_concentration`, `min_profile_floor`, band cutoffs, persistence transform, minimum-support,
diminishing-return, future independence parameters) but — correctly — **chooses no numeric values**. doc 08
already sketches a labeled corpus, a scenario-family split, six-version reproducibility, tier-1/tier-2
separation, and a blind-actor holdout (CR-8/D22). This ADR consolidates and hardens that design against the
**accepted Amendment B** (two-form decision support, `contributor_separation ≠ separation_from_null`,
active-target policy, fail-closed independence) so that a later implementation engineer knows exactly what
calibration may change, what it may not, what data may enter it, and how versions and leakage are controlled.

**What this ADR is not.** It is not the corpus, not the fitting procedure's numeric objective (see §D-F3/Open
Questions), not any fitted parameter, not a modification of any Phase 0–2 fixture, and not authorization to begin
Gate 3.6. The existing `fixtures/*` remain **structural-regression** fixtures only and are not touched.

## Relationship to existing ADRs

| ADR | Scope | Relationship to ADR-0006 |
|---|---|---|
| ADR-0001 | Evidence-graph core architecture | Provenance-first, deterministic, no ML on the correctness path — inherited unchanged. |
| ADR-0002 | Attribution methodology & validation principles (D1–D22) | Governs; D18/D22/CR-8 (anti-circular, blind-actor holdout, tier separation) are the backbone of this ADR. Unchanged. |
| ADR-0003 | Correlation & behavioral-chain layer (CR-1 de-duplication) | The de-duplication unit (`CorrelationGroup`) fixes the calibration unit. Unchanged. |
| ADR-0004 | Behavioral sequence reconstruction | Supplies the one `BehavioralSequence` per group. Unchanged. |
| ADR-0005 (incl. Amendment B) | Attribution engine specification | **Authoritative.** ADR-0006 calibrates the parameters ADR-0005 §D17/Amendment B leave open, over the structural quantities they fix; it changes none of them. |
| **ADR-0006** | **Calibration corpus & versioning** | Defines the calibration/validation data, leakage/split policy, blind-actor holdout, versioning, fitting boundary, reproducibility, provenance, and the B1 gate. |

## Decisions

### D1 — Calibration is not training (core principle)

**There is no learned classifier on the correctness path** (ADR-0001 D5; ADR-0002 "alternatives rejected").
Calibration **fits a small set of thresholds / band cutoffs / bounded parameters over already-defined structural
quantities** — nothing else. Calibration **MUST NOT** learn or alter: technique→actor associations; per-actor
weights; ATT&CK `uses` relationships; ATT&CK diagnosticity (`g`/`D`); aliases; candidate-generation rules. All of
those remain derived solely from pinned ATT&CK v19.0 (§D14, §D17-list of ADR-0005 restated). Calibration that
touched any of them would be training and is prohibited.

### D2 — The five separate calibration pathways (no combined score)

Calibration is partitioned into **five pathways that are never merged into a single scalar** (Amendment B
§Decision-path scale / §Abstention; ADR-0002 D2 likelihood⟂confidence):

1. **Null separation** — `τ_separation`, fit on **un-normalized** `separation_from_null(h) = decision_support(h)
   − decision_support(Unattributed)`.
2. **Ranking / margin** — WEP band cutoffs and `τ_margin`, fit on **normalized** `decision_support_norm(h)`.
3. **Concentration** — `τ_concentration`, fit on `concentration(h) = max net / contributor_separation(h)`.
4. **Persistence** — a **bounded** transform of `raw_support` multiplicity feeding **confidence only** (never
   likelihood).
5. **Confidence** — categorical confidence band cutoffs over coverage/reliability/corroboration/consistency/
   contradiction/regime factors.

**There is no combined scalar attribution score anywhere**, and calibration may not create one.

### D3 — Structural vs calibration parameters

| STRUCTURAL (fixed by methodology; calibration MUST NOT change) | CALIBRATION (numeric, corpus-fit; no value chosen here) |
|---|---|
| Two-form decision-support model (`decision_support` / `decision_support_norm`) | `τ_separation` |
| `D = 1 − g` | `τ_margin` |
| Distinct-feature **count-once** rule | `τ_concentration` |
| `Unattributed` null formulation `Σ contribution(f)·g(f)` | `min_profile_floor` **value** |
| `contributor_separation(h)` | WEP band cutoffs |
| `concentration = max net / contributor_separation`, domain `> 0` | confidence band cutoffs |
| Concentration range `[0,1]` guarantee | persistence-transform **parameters** (within the bound, §D4) |
| Profile-breadth normalization **mechanism** `max(ProfileBreadth, min_profile_floor)` | minimum-support **parameter** |
| Active-target ATT&CK policy | diminishing-return **parameters** (within the bound, §D4) |
| Single-technique guard (D13.4) | future independence **parameters** |
| Likelihood/confidence separation | — |
| Fail-closed independence (unknown ≠ corroborated) | — |
| **Bounded, monotone form** of the persistence transform (§D4) | later-validated fitted replacement of the linear **null baseline** (Amendment B-permitted) |
| **Bounded, monotone form** of the diminishing-return curve (§D4) | later-fitted non-linear replacement of **profile-breadth normalization** (Amendment A/B-permitted) |

**No numeric value is selected in this ADR.**

**On the two Amendment B-permitted fitted replacements (fidelity note).** Accepted ADR-0005 Amendment B/§D17
classifies as calibration-controlled (a) *any later-validated fitted replacement of the linear null baseline* and
(b) *any later-fitted non-linear replacement of the linear profile-breadth normalization*. They are listed in the
CALIBRATION column above for boundary completeness. **The current architecture keeps the structural definitions
(the `Σ contribution·g` null and the `max(ProfileBreadth, min_profile_floor)` linear normalization) exactly as
they stand; this ADR does not replace them and chooses no replacement now.** Any such replacement is permitted
**only after** the required later validation/calibration gate and **only within Amendment B's constraints** —
monotone, `[0,1]`-bounded/documentation-relative, never a differently-*shaped* claim (e.g. never a real-world-rate
or probability claim), and requiring a new `calibration_version` (and, for the null, `methodology_version`
review). Until then the structural forms are binding.

### D4 — Persistence / diminishing-return structural bound (records finding F-1)

The **existence and functional *form*** of the persistence transform (§D2 pathway 4) and of any diminishing-return
curve softening the distinct-feature "count once" (Amendment B §B5 / Decision-path scale) are **structurally
constrained to be bounded and monotone**: they may only ever produce a **bounded, non-decreasing** contribution,
and the persistence transform may feed **confidence only**. Calibration may select **parameters within** those
constraints; calibration **must never** be permitted to turn persistence (or repetition) into a second likelihood
signal or an unbounded contribution. The **exact functional form** (e.g. logarithmic, capped, or a specific
concave curve) is **not chosen here** and is recorded as **open question F-1** (§Open Questions) — to be resolved,
within these structural bounds, before the fitting sub-gate.

### D5 — Calibration unit

- **SCORING UNIT** (structural): one **attribution case** = one `CorrelationGroup` + its one `BehavioralSequence`
  + an **expected-output shape**. Derived directly from ADR-0005 §D1 (attribution is computed per group).
- **SPLIT GROUP** (structural): **`scenario_family_id`**, one level above the case.

**Sub-case splitting is invalid.** Splitting by observation, evidence item, or correlation link would place
causally-related material of one incident on both sides of a split — the CR-1 double-counting/leakage failure one
layer up. **All splits operate at `scenario_family_id`.**

**Scenario-family construction (precise enough to implement later; avoids the impossible "one actor may never
recur" requirement).** A `scenario_family_id` groups material that is **causally related or near-duplicate**, keyed
by the *strongest applicable* shared origin, in priority order:

1. same real incident (incident id), or same emulation run (plan id + run id);
2. same telemetry session / capture (host + session/capture id + time window);
3. same synthetic scenario **template + generator seed**;
4. near-duplicate telemetry (content-similarity above a documented threshold);
5. same ATT&CK **technique-combination signature** *when produced by the same template/seed lineage*.

**Same-actor coexistence across folds is explicitly permitted** when the cases are **genuinely independent**
(different incidents/runs/sessions/templates/seeds and not near-duplicates): the goal is leakage prevention, not a
prohibition on an actor recurring. Only *causally related or near-duplicate* families move together; the
**blind-actor holdout (§D8)** is a *separate, deliberate* actor-level exclusion for anti-circular validation, not
the default split rule.

### D6 — Calibration case schema (conceptual; no records created)

```
CalibrationCase:
  case_id                       # deterministic content hash of the case's frozen inputs
  scenario_family_id            # the split-grouping key (§D5)
  source_kind                   # SYNTHETIC | REPLAY | EMULATED | REAL_INCIDENT
  source_ref                    # dataset name@version + acquisition provenance (§D15)
  license                       # SPDX id + redistribution constraint (§D15)
  attack_kb_version             # the pinned KB this case was authored/labelled against
  telemetry_provenance          # source -> Observation -> Evidence chain refs (immutable Phase 0-2 ids)
  correlation_group_id          # the attribution unit under test
  sequence_id                   # its one BehavioralSequence
  ground_truth:
    actor_label                 # from DATASET/incident/emulation provenance -- NOT ATT&CK uses-inference (§D9)
    actor_label_source          # emulation-plan | incident-report | dataset-annotation | UNKNOWN
    campaign_context            # optional, dataset-sourced
    label_semantics             # ATTRIBUTABLE | UNATTRIBUTABLE_BY_DESIGN | DISPUTED | UNKNOWN (§D7)
    label_confidence            # the dataset's own categorical confidence in the label
  expected_output_shape         # doc 08: leading-hypothesis band, confidence band, discriminating-evidence set,
                                #   expected contradiction, expected next-evidence, OR "insufficient" -- a SHAPE, not just a label
  coverage_assumptions          # declared data-source availability (feeds CoverageProfile, prerequisite B3)
  case_role                     # CALIBRATION | HELD_OUT_VALIDATION | BLIND_ACTOR_HOLDOUT | TIER1_STRUCTURAL | EXCLUDED
  corpus_schema_version
```

**Ground-truth actor labels MUST come from dataset / legitimate incident / emulation provenance, never from
ATT&CK's own `uses` relationships** — otherwise the corpus would test the knowledge base against itself (§D9).

**`expected_output_shape` must be independently authored, not ATT&CK-derived (anti-circular).** The
`expected_output_shape` — and **especially any expected discriminating-evidence set** — MUST be authored from the
case's own **independent ground-truth / dataset provenance** (the emulation plan, incident report, or dataset
annotation), and **MUST NOT be mechanically derived from ATT&CK `Group→uses→Technique/Software` relationships or
any other ATT&CK annotation**. Deriving the expected discriminating evidence from the same `uses` data the engine
scores against would make the discriminating-evidence-correctness metric (§D18) circular — rewarding reproduction
of ATT&CK's own annotations rather than genuine attribution.

### D7 — Label semantics (no silent negatives)

`label_semantics` is a closed four-value set:

- `ATTRIBUTABLE` — a legitimately-sourced actor label exists.
- `UNATTRIBUTABLE_BY_DESIGN` — the case is a genuine negative/benign/insufficient case (a *designed* negative,
  not an absence of information).
- `DISPUTED` — attribution is contested in the source.
- `UNKNOWN` — ground truth is unavailable/uncertain.

A case with an uncertain actor label, disputed campaign attribution, incomplete ATT&CK mapping, inadequate
coverage, weak provenance, or unavailable ground truth is `DISPUTED`/`UNKNOWN` and **MUST NOT silently become a
negative / `Unattributed` example.** It may be **excluded from one calibration operation** (e.g. positive
ranking) while remaining valid for **another** (e.g. abstention behavior), via `case_role`.

### D8 — Corpus types (five, strictly separated)

| Type | Purpose | May tune parameters? |
|---|---|---|
| **A. Structural-regression fixtures** (`fixtures/*`, unchanged) | ingestion/detection/correlation/sequence machinery | No — not attribution at all |
| **B. Attribution calibration corpus** | fit the §D3 calibration parameters | **Yes (calibration split only)** |
| **C. Held-out validation corpus** | measure metrics (§D18) | **No** |
| **D. Blind-actor holdout corpus** | anti-circular validation (§D8-holdout / §D2 of ADR-0002 D22) | **No** |
| **E. Tier-2 real-incident / generalization data** | generalization/accuracy claims | **No** |

Existing `fixtures/*` **remain structural-regression only and are not modified.** Synthetic/replay data (Type B/C)
may calibrate the mechanism; **synthetic/replay data MUST NOT by itself establish real-world attribution
accuracy** (§D14). Real-incident data (Type E) is **aspirational and never blocks this architecture** (ADR-0002
D22).

**Required category — Campaign contextualization (Amendment B §B6).** The calibration/validation corpus MUST
include a dedicated **campaign-contextualization** category that exercises the accepted §B6 semantics: Campaigns
**do not rank as actors** and never receive actor likelihood; campaign matching is **contextualization only**;
`Campaign --attributed-to--> Group` is knowledge context, never case-specific proof; **multi-attributed** campaigns
(`C → {A, B}`) split/duplicate/equalize no actor likelihood or confidence; there is **no direct Campaign→actor
likelihood shortcut**; and the anti-circularity rule (campaign evidence already consumed by a Group's actor
likelihood is not re-injected into that Group's confidence) holds. These cases verify §B6 behavior; they cannot
override it (it is structural).

### D9 — Leakage control (hard split rules)

All split operations run at **`scenario_family_id`** level (§D5); **no row/observation/evidence/correlation-link
split is permitted.** Leakage is prevented across: same incident; same actor *scenario* (causally related);
same campaign; same host/session; near-duplicate telemetry; same synthetic template; same generator seed; same
ATT&CK technique-combination signature (of the same template/seed lineage). The four populations —
**CALIBRATION**, **HELD-OUT VALIDATION**, **BLIND-ACTOR HOLDOUT**, **FINAL TEST** — are disjoint by
`scenario_family_id`. **Validation/test data never tunes any parameter.**

### D10 — Blind-actor holdout (primary anti-circular strategy)

Implements ADR-0002 D22 / CR-8. **Actor-level**, executed under scenario-family grouping:

- A **held-out actor's scenario families are excluded from all parameter fitting**; held-out actors must not
  influence any fitted threshold. The **ablated condition below is used only for validation / anti-circularity
  evaluation**, never for calibration fitting.

- **KB-ablation experiment (validation-only) — complete identity-ablation surface.** For the evaluation
  condition, an **evaluation-only, derived ATT&CK knowledge condition** is constructed in which the held-out
  actor cannot be rediscovered through **any** indirect identity route. The ablation removes/suppresses, at
  minimum:
  1. the held-out Group's active **`uses` relationships** to ATT&CK **techniques/sub-techniques** *and* to
     ATT&CK **malware/tools (software)** — i.e. the full `group_profile` surface (technique + software), not
     technique edges alone;
  2. any **Campaign-context route** that could re-identify the held-out actor: a `Campaign --attributed-to-->`
     the held-out Group, and any equivalent campaign attribution/context that would expose the held-out actor's
     identity during evaluation (whether via candidate generation or analyst-facing context);
  3. any **alias / identity route** that could directly re-associate the held-out actor;
  4. any **other ATT&CK relationship/path** that would allow candidate generation *or* analyst-facing
     attribution context to re-identify the held-out actor indirectly.

  Under the ablated evaluation condition the following **MUST be recomputed from that ablated knowledge
  condition**, never copied from the original KB: dynamic candidate generation; the active-Group candidate
  universe; `g(x)`; `D(x)`; profile breadth; profile-breadth-floor application; and the `Unattributed` null
  baseline. The experiment then confirms the system returns `Unattributed` ("untracked actor") rather than the
  nearest famous match (the direct CR-2 null-floor / famous-group-bias test), and that the held-out actor is
  **not re-identified through campaign, software, alias, or any other indirect ATT&CK route**.

  **Production artifact is immutable.** This ablation is a **validation-time, evaluation-only derived condition**
  and **never** modifies the version-controlled production ATT&CK v19.0 artifact, its content hash, or its
  recorded `attack_kb_version` (ADR-0005 §D16). **Fail-closed:** if the held-out actor cannot be cleanly removed
  from an identity route without changing *unrelated* ATT&CK semantics, the evaluation **MUST fail closed**
  (treat the holdout as invalid for that actor) rather than silently weaken the ablation.

- **Justification for actor-level** (over technique/scenario-level): attribution is an *actor* judgment
  (ADR-0005 §D1/§D2), so the generalization unit is the actor; a finer holdout would leave the actor's other
  cases in calibration and leak.

**This ADR does not implement the holdout or create the holdout corpus** — it specifies the required ablation
surface and recomputation; the implementation is a later validation gate. No performance claim is made.

### D11 — ATT&CK circularity: three distinct sources

Kept strictly distinct (structural):

1. **`attack_kb_version`** — supplies candidate generation, `g`/`D`, profile breadth. Documentation-relative,
   reporting-biased (ADR-0002 CR-4).
2. **Calibration data** — supplies the case telemetry and expected-output shapes.
3. **Ground-truth labels** — supplied by independent dataset/incident/emulation provenance (§D6/§D9).

Calibration **MUST NOT alter ATT&CK relationships** (ADR-0005 §D17). **Documentation-relative ceiling (records
finding F-2):** *because candidate generation and diagnosticity are both derived from the same pinned ATT&CK
knowledge base, calibration results characterize performance **relative to that knowledge representation and this
corpus**. They do **not** establish real-world attribution accuracy or real-world false-attribution rates.* Every
calibration/validation report must carry this ceiling; blind-actor holdout (§D10) and tier-1/tier-2 separation
(§D18) partially mitigate but do not remove it.

### D12 — Calibration version (deterministic content identity, not a Git commit)

```
calibration_version = hash(
    calibration_corpus_version,     # content identity of the CALIBRATION-split cases (§D13)
    split_definition,               # which scenario_family_ids are calibration / held-out / blind / test
    fitting_procedure_version,      # the fitting spec/algorithm identity (§D16/F-3)
    fitted_parameter_set,           # the frozen numeric artifact (all thresholds/floors/band cutoffs)
    attack_kb_version,              # dependency: g/D/breadth change => recalibrate
    methodology_version,            # dependency: Amendment B semantics
    engine_version,                 # implementing-code identity at fit time
    seed_if_allowed                 # only if stochastic fitting is ever approved (§D17)
)
```

- It is an **opaque content hash plus a human-readable structured composite** carrying its dependencies (mirroring
  `RulePack.content_hash`/`TemporalProximityConfig.content_hash`).
- **Same corpus + different fitting procedure/version ⇒ different `calibration_version`.**
- **Same KB + different calibration corpus ⇒ different `calibration_version`.**
- **Different ATT&CK KB ⇒ recalibration required** (new `calibration_version`; cross-KB reuse is incompatible,
  ADR-0005 §D17).

**Never conflate** `attack_kb_version`, `methodology_version`, `calibration_corpus_version`, `calibration_version`,
`engine_version` — each is an independent identity (ADR-0005 D20).

### D13 — Calibration corpus version & manifest (separate from `calibration_version`)

`calibration_corpus_version` is the **content identity of the corpus itself**, distinct from the fitted
`calibration_version`. The eventual corpus carries a **manifest** with at minimum: `corpus_schema_version`; overall
corpus content hash; **per-case content hashes**; source/version; license; acquisition provenance; transformation
provenance; ATT&CK version; split assignment; and case-role metadata — mirroring the existing
`data/attack/enterprise/v19.0/manifest.json` discipline. **This ADR does not create the manifest or the corpus.**
Adding validation-only cases changes `calibration_corpus_version` but need not force a refit — and calibration
must never consume held-out/validation cases (§D9).

### D14 — Real vs synthetic; the accuracy boundary

The architecture must function with **synthetic/replay only** (the realistic initial state): CALDERA (Apache-2.0),
Atomic Red Team (MIT), OTRF Security-Datasets (MIT) as bundleable Type B/C substrate; EVTX-ATTACK-SAMPLES (GPL-3.0)
**local-only, never redistributed**. **Three notions kept distinct:** *calibration usefulness* (synthetic is
adequate to fit thresholds), *validation credibility* (mechanism correctness yes; accuracy no), *external validity*
(requires Tier-2 real-incident data). Synthetic data **cannot** prove real-world attribution accuracy; where Tier-2
is thin, generalization is declared **under-validated** and the system stays **abstention-biased** (doc 08 §7a).

### D15 — Dataset provenance & licensing

Every external dataset used for calibration must eventually record: **SPDX license; source; version; acquisition
provenance; transformation provenance; redistribution constraint.** The previously-researched distinctions are
preserved (Security-Datasets/Atomic MIT and CALDERA Apache-2.0 = bundleable with NOTICE; EVTX GPL-3.0 = local-only).
**No new dataset is selected or added in this ADR.**

### D16 — Parameter fitting boundary (future; no values chosen)

For each calibration parameter, the eventual fitting spec states structural input / fitting input / objective
category / calibration-only restriction / validation requirement / structural bounds:

| Parameter | Structural input | Fitting input | Objective (category) | Restriction | Structural bound |
|---|---|---|---|---|---|
| `τ_separation` | un-normalized `separation_from_null` | its distribution over calibration cases | abstention-correctness ⊕ ranking retention | calibration split only; held-out validated | scalar `> 0` |
| `τ_margin` | `decision_support_norm(top)−(second)` | its distribution | competing-set vs single-leader correctness | " | `≥ 0` |
| `τ_concentration` | `concentration(h)` | its distribution | suppress single-feature/imitation without killing combinations | " | `∈ (0,1]` |
| `min_profile_floor` | active-Group `ProfileBreadth` distribution | that distribution | damp small-profile amplification; drop no candidate | **global**, not actor-specific | integer `≥ 1` |
| WEP band cutoffs | banded likelihood outcomes vs shapes | reliability data | likelihood reliability | " | monotone |
| confidence band cutoffs | confidence factors vs shapes | reliability data | confidence reliability | " | monotone |
| persistence parameters | `raw_support` multiplicity | that signal | bounded persistence → confidence | within §D4 bound | bounded, monotone |
| minimum-support | active-group counts | those counts | honest §D3 fallback trigger | " | `≥` threshold |
| diminishing-return parameters | distinct-feature contributions | those | bounded softening of count-once | within §D4 bound | bounded, monotone |

**Normalized-ranking pathway parameters are coupled (must be fit coherently).** `min_profile_floor` *defines*
`decision_support_norm` (via `ProfileBreadth_effective`); `τ_margin` operates on that normalized form; and the WEP
band cutoffs consume the same normalized likelihood/ranking pathway. These pathway-2 parameters therefore
**MUST be fit coherently under one fitting procedure** — never independently in a way that would produce
inconsistent normalized decisions (e.g. a floor fit against one objective and a margin fit against another over a
now-different normalized quantity). (`τ_separation` and `τ_concentration` remain on the *un-normalized* forms, §D2,
and are not part of this coupling.)

The fitting **optimizes ranking + abstention + reliability jointly** and **rejects any change that improves ranking
but worsens calibration** (doc 08 §4). **The exact optimization objective and search procedure are not resolved
here — deferred as F-3 (§Open Questions); no objective is chosen.**

### D17 — Reproducibility

Calibration must be **deterministic** (ADR-0005 §D16 discipline extended to this layer): canonical case ordering
(sort by `case_id`); canonical serialization; content hashing; stable floating-point handling (fixed rounding /
stable summation order); explicit environment/version metadata; **deterministic search initially** (bounded,
ordered — no RNG). A pinned `seed` becomes a mandatory `calibration_version` input **only if** stochastic fitting is
later approved. **`calibration_version` computation MUST be independent of Python hash iteration order /
`PYTHONHASHSEED`:** every unordered structure (sets, dicts, id collections) MUST be **canonically sorted before any
serialization or hashing**, so identical inputs yield an identical `calibration_version` regardless of interpreter
hash seed — the same sorted-by-id discipline every Phase 0–2 contract already enforces. **Same corpus + split +
fitting procedure + versions ⇒ identical `fitted_parameter_set` ⇒ identical `calibration_version`.**

### D18 — Validation metric suite (design only; nothing computed)

Reported **separately, never a single headline composite** (doc 08 §3 + Amendment-B additions): ranking quality;
abstention quality (**corpus false-attribution rate — the most important**; a property of the evaluated
corpus/split, **not** a real-world attribution or false-attribution rate — §D11/F-2); competing-actor correctness; `Unattributed`/
null discrimination; **margin behavior**; **concentration behavior**; **null-separation behavior**; likelihood
reliability (WEP-band vs hit rate); confidence reliability (do high-confidence claims fail less); discriminating-
evidence correctness; contradiction surfacing; explanation faithfulness; determinism (`determinism_hash`
stability). **Tier-1 (machinery) results are never reported as attribution accuracy; accuracy requires Tier-2**
(ADR-0002 D18/§7a).

### D19 — Repetition, imitation, and the two axes (restated as corpus requirements)

- **Repetition:** the corpus must include one-observation / repeated-behavior / repeated-detection / multiple-
  distinct-observation / multiple-evidence-type / correlated-detection / genuinely-distinct-evidence cases. These
  **verify** (they cannot override) the structural invariants: repetition → `raw_support`/persistence only, never
  decision likelihood, never an extra concentration contributor; evidence-type diversity ≠ independence; same-
  `Observation`/correlated detections are not independent corroboration; **unknown independence fails closed**
  (Amendment B §B5).
- **Deliberate imitation:** a dedicated category (an actor reproducing another's *publicly documented* TTPs)
  measures whether the system **reduces confidence / abstains** via the evidence-type-diversity cap + deception
  alternative (ADR-0005 §D10/§D12) — **no actor blacklist, no hard-coded imitation rule**. **Multi-vector imitation
  is an acknowledged limitation**, measured, not immunized.
- **Likelihood vs confidence:** calibration maintains **separate reliability analysis** for the two axes; no single
  combined scalar.
- **Campaign contextualization (cross-reference §D8):** the corpus additionally carries the dedicated
  campaign-contextualization category defined in §D8 — verifying (never overriding) that Campaigns do not rank as
  actors, that `attributed-to` is context not proof, and that multi-attributed campaigns manufacture no actor
  likelihood/confidence (Amendment B §B6).

### D20 — Preserved Amendment B definitions (authoritative, not restated as new)

This ADR consumes, unchanged, from accepted ADR-0005 Amendment B: `decision_support(Unattributed) = Σ distinct
decision features contribution(f)·g(f)` (a **deterministic heuristic expected-overlap baseline under a feature-
independence approximation — not a statistical null, probability, p-value, significance test, or real-world
prevalence**; `τ_separation` is calibrated against **observed corpus behavior only**); `contributor_separation(h) =
Σ valid net(contributor)` with `net = D·(1−g)`; `concentration = max net / contributor_separation`, evaluated only
when `contributor_separation > 0`; and `contributor_separation ≠ separation_from_null` (calibration must not
conflate them). `ProfileBreadth_effective = max(ProfileBreadth, min_profile_floor)` — mechanism structural, value
calibration-controlled, **global, not actor-specific, not test-set-optimized, ATT&CK-version-dependent, recalibrated
on any KB change**.

## Consequences

**Positive:** Gate 3.6 now has a defensible, provenance-first, deterministic, anti-circular calibration
architecture whose boundary between structural methodology and fitted parameters is explicit; `calibration_version`
and `calibration_corpus_version` are content identities distinct from KB/methodology/engine versions; the corpus
schema, leakage/split policy, and blind-actor holdout are specified precisely enough to implement later; and the
documentation-relative ceiling is recorded so no calibration result is ever read as a real-world rate.

**Negative / costs:** building the corpus, the manifest, the split/holdout tooling, and the fitting procedure
remains substantial, un-started work; the exact fitting objective (F-3) and persistence/diminishing-return form
(F-1) are genuinely open; Tier-2 real-incident data is scarce, so external validity stays under-validated.

**Neutral:** every numeric value remains a calibration parameter, fit later and revalidated on any KB/methodology
change — the same tunable/reversible mechanism ADR-0002 D14 / ADR-0005 §D17 already establish.

## B1 gate definition

**B1 is complete when the ARCHITECTURE is accepted — not when thresholds are selected.** B1 acceptance requires all
of: calibration unit (§D5); corpus schema (§D6); corpus semantics/label semantics (§D6/§D7); leakage/split policy
(§D5/§D9); blind-actor holdout (§D10); provenance/quality/exclusion rules (§D6/§D7/§D15); the four-way version model
+ `calibration_version`/`calibration_corpus_version` (§D12/§D13); the fitting boundary (§D3/§D16); reproducibility
(§D17); the validation-metric suite (§D18); and these acceptance criteria (§Acceptance criteria). **Parameter
selection is a later fitting sub-gate**, gated on the corpus existing and on F-1/F-3 being resolved, and on a
frozen `calibration_version` before any Gate 3.6 scoring runs (ADR-0005 §D19).

## Acceptance criteria

This ADR is accepted only if **all** of the following objective checks hold; each maps to a specific section a
reviewer can verify:

1. **What calibration may change** is enumerated (the CALIBRATION column of §D3 + §D2 pathways + §D16 table).
2. **What calibration is forbidden to change** is enumerated (§D1 prohibitions + STRUCTURAL column of §D3 + §D11).
3. **What data may enter calibration** is specified (§D8 Type B, §D9 calibration split, §D14 substrate).
4. **What data must remain held out** is specified (§D8 Types C/D/E, §D9 disjoint populations, §D10 blind actors).
5. **Leakage is prevented** by a stated split unit and grouping rule (§D5 `scenario_family_id`, §D9 hard rules).
6. **Blind-actor holdout** has a complete, stated ablation surface + recomputation + fail-closed (§D10).
7. **Versions are distinctly identified** (§D12 `calibration_version` composite, §D13 `calibration_corpus_version`,
   both distinct from `attack_kb_version`/`methodology_version`/`engine_version`).
8. **Reproducibility** is deterministic and hash-seed-independent (§D17).
9. **What must be calibrated later** vs **what is structurally fixed** are separated (§D3/§D16 vs §D3/§D20).
10. **No numeric parameter value** is chosen anywhere in the ADR (verifiable by inspection).

## Open questions

Recorded rather than silently resolved. Each states whether it blocks **ADR-0006 acceptance**.

- **F-1 — persistence / diminishing-return exact functional form.** The bounded, monotone *bound* is fixed (§D4);
  the exact form (e.g. logarithmic/capped/concave) is unresolved. **Blocks ADR-0006 acceptance?** **No** (the bound
  is sufficient for the architecture). Resolve before the fitting sub-gate.
- **F-2 — documentation-relative ceiling / interpretation of calibration results.** Recorded and binding (§D11).
  **Blocks acceptance?** **No** — it is a stated interpretive constraint, not an unresolved decision.
- **F-3 — exact fitting objective functional + deterministic search procedure.** Unresolved (§D16). The procedure
  **must** be deterministic, bounded, reproducible, calibration-only, overfitting-resistant, held-out-validated, and
  incapable of changing ATT&CK relationships. **Blocks acceptance?** **No** — recorded as a later fitting sub-gate;
  the architecture does not depend on the specific objective. **No mathematical objective is chosen here.**
- **Q3 — availability of real-incident Tier-2 data.** **Blocks acceptance?** **No** (aspirational, ADR-0002 D22);
  it gates *accuracy claims*, not the architecture.
- **Q4 — isolated CALDERA/Atomic lab vs replay-only corpus construction.** **Blocks acceptance?** **No**; a
  corpus-build-gate concern.
- **Q5 — operational independence check** (Amendment B deferral to the confidence/provenance layer).
  **Blocks acceptance?** **No** — the fail-closed default holds meanwhile (§D19).
- **Q6 — separate campaign-context confidence pathway** (Amendment B §B6 contextualization). **Blocks acceptance?**
  **No**; a post-corpus refinement.

**None of the open questions blocks accepting this architecture.**

## Follow-up

On review: if accepted, status → ACCEPTED (dated). Recommended subsequent artifacts (not created here): the
calibration-case / corpus-manifest schema document; the `calibration_version` / `calibration_corpus_version`
specification (may live in this ADR); and the fitting-procedure + split specification (must resolve F-1/F-3 before
the fitting sub-gate). **No corpus, no calibration data, no fitted parameters, and no `calibration_version` artifact
are created until this ADR is accepted**, and all Gate 3.6 scoring remains hard-gated on a frozen
`calibration_version` regardless (ADR-0005 §D19).

## Status

**Status: ACCEPTED** (2026-09-17)

**Acceptance record.** ADR-0006 is **formally accepted on 2026-09-17** as the binding architecture for the
calibration corpus and calibration-versioning system (Phase 3 prerequisite **B1**), following the final hostile
pre-acceptance architecture re-audit (verdict: **PASS WITH NON-BLOCKING FINDINGS**, explicitly **READY FOR
ACCEPTANCE**), which confirmed the blocker **BLOCK-1** (blind-actor KB-ablation surface, §D10) is resolved and
that non-blocking findings **NB-1–NB-7** were addressed. The three residual, explicitly non-blocking findings
recorded by that re-audit — **NB-A** (cross-reference the `attributed-to`-traversal prerequisite from §D10),
**NB-B** (note that ablated-condition `g`/`D` recomputation is intended, not a defect), and **NB-C** (§D9 ↔ §D5
same-actor-coexistence parenthetical) — are retained as **future documentation follow-ups**; they change no
behavior and are not applied at acceptance.

Acceptance of this **architecture** is **not** authorization to begin Gate 3.6, to build the corpus, to fit any
parameter, or to create a `calibration_version`. Those remain independent later gates: the corpus and a **frozen
`calibration_version`** (§D19 of ADR-0005 hard-fails scoring without one), the active-target `attributed-to`
traversal, `CoverageProfile` construction (B3), `evidence_type`/`Observation` provenance plumbing (B4), the
confidence-layer requirements, and the resolution of open questions F-1/F-3 before the fitting sub-gate. **No
numeric calibration parameter value is selected by this ADR or by its acceptance.**

## Post-acceptance clarifications

Dated additive clarifications made after this ADR reached ACCEPTED status, recorded here without rewriting the
original decision text above (matching ADR-0004's own `## Post-acceptance clarifications` practice). Each records
how an accepted decision is interpreted; none changes a schema or an accepted decision.

### Clarification (2026-09-21) — `coverage_assumptions` vocabulary and calibration/production separation

Recorded alongside the coverage-model methodology lock (ADR-0005 Amendment C, 2026-09-21;
`docs/architecture/11-coverage-model.md`). This clarifies §D6's `coverage_assumptions` field; it changes **no**
`CalibrationCase` schema and reopens no decision.

1. **Vocabulary.** `CalibrationCase.coverage_assumptions` is interpreted as a tuple of **canonical active ATT&CK
   v19 `x-mitre-data-component` names** — the same vocabulary the `CoverageProfile` required-side derivation
   produces (ADR-0005 Amendment C; doc 11 §2). This makes a case's declared availability directly comparable to
   the pinned-KB required set, so a `CoverageProfile` state can be computed for calibration cases.

2. **Calibration-only.** These declarations are a **calibration-path input only**: they supply
   `available_data_components` when a `CoverageProfile` is constructed for a labeled calibration case.

3. **Production does not consume calibration declarations.** Production inference never reads a
   `CalibrationCase.coverage_assumptions` value. Because `available_data_components` is a caller-supplied argument
   and production callers pass the empty tuple, there is no path by which a declared calibration value reaches a
   production `CoverageProfile`.

4. **Production availability is currently empty (fail-closed).** Until an independently approved
   telemetry-to-ATT&CK availability mapping exists, production passes `available = ()` and coverage fails closed
   (only `OBSERVED_PRESENT` / `NOT_OBSERVABLE` / `UNKNOWN` are reachable; adequate-absence, and therefore any
   coverage-driven contradiction, is never produced in production). This uses ADR-0005 Amendment B's accepted
   fail-closed allowance. `SourceRef.source_type` is opaque by architecture (G0.3); no heuristic
   `source_type`/ECS → ATT&CK mapping is introduced here.

5. **Coverage methodology reference.** The full construction methodology is
   `docs/architecture/11-coverage-model.md`.

6. **No schema change.** `CalibrationCase.coverage_assumptions` remains the existing `tuple[str, ...]` field
   (§D6, B1.2); this clarification pins the **meaning** of its values, not its shape. `case_id` inputs
   (`CASE_ID_INPUT_FIELDS`) are unchanged.
