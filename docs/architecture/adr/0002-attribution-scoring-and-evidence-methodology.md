# ADR-0002 — Attribution Scoring & Evidence Methodology

- **STATUS: ACCEPTED** (2026-09-11)
- **Date:** 2026-09-11 (proposed) · 2026-09-11 (accepted)
- **Deciders:** project owner (accepted after the final architecture review)
- **Related:** [ADR-0001](0001-evidence-graph-core-architecture.md) · detail in
  [06 evidence model](../06-evidence-model.md), [07 scoring spec](../07-attribution-scoring-spec.md),
  [08 validation & calibration](../08-validation-and-calibration.md) · grounds in research
  [08 methodology](../../research/08-attribution-methodology-foundations.md) /
  [10 audit](../../research/10-research-audit.md)

> This ADR records the **decisions**; the three companion docs hold the precise definitions, formulae, and
> test design. The decisions are **ACCEPTED** as of 2026-09-11 (following
> [10 final review](../10-final-architecture-review.md)), with **D22 modified per M2** (below); reversibility
> is noted per decision. Acceptance does **not** start implementation — the attribution engine (Phase 3)
> remains gated on conditions C3.1–C3.3 in the final review (combination/dedup spec, a frozen
> `calibration_version` from a real corpus, and the D22-as-modified validation).
>
> **Acceptance rationale:** the final review classified 21 of 22 decisions ACCEPT (four spec/calibration-
> gated) and D22 MODIFY (now applied); none rejected. After the stress test the methodology avoids arbitrary
> scoring by construction, separates likelihood from confidence, generates candidates over the full ATT&CK
> universe, can abstain, and is honest about its residual limits (imitation, reporting bias, a validation
> ceiling). The open work is specification and calibration concentrated in Phase 3 — not a flaw in the
> methodology's structure — so it is sound to adopt now.

## Context

ADR-0001 chose an evidence-graph core whose entire justification is **explainable, evidence-based,
reproducible APT attribution**. This ADR fixes *how attribution actually reasons*. The failure mode to
avoid is explicit and was named by the project owner:

> `APT Group X → Technique T1059 → +10 points → 87% confidence`

That is prohibited because (a) it hand-assigns points with no operational meaning, (b) it treats a
near-ubiquitous technique as discriminating, (c) it accumulates rather than *discriminates*, and (d) it
collapses two different questions ("how well does evidence fit?" and "how good is the evidence?") into one
fabricated percentage. The methodology below is designed to make each of those errors structurally
impossible.

## Decisions (all PROPOSED)

- **D1 — Attribution is comparative (ACH), not accumulative.** We adopt **Analysis of Competing
  Hypotheses**: enumerate candidate hypotheses and score **evidence against all of them**, emphasizing
  **diagnostic** and **disconfirming** evidence. Evidence consistent with every candidate contributes ~0.
  *Reversibility: low (foundational).*
- **D2 — Two independent axes (ICD-203), never collapsed.** Every assessment reports **Likelihood** (how
  well evidence supports a hypothesis, *relative* to the alternatives) and **Confidence** (how strong,
  reliable, complete, and well-grounded that evidentiary basis is) as separate, separately-derived values.
  *Reversibility: medium.*
- **D3 — Weights are *diagnosticity*, derived from the pinned knowledge base — never hand-assigned.** The
  only "weights" are (i) **discriminating power** of a technique/combination, computed from the ATT&CK
  Group×Technique data, and (ii) **observation confidence** and (iii) **source reliability**, derived from
  detection/enrichment metadata. All are inspectable, versioned, and calibrated (see
  [07](../07-attribution-scoring-spec.md) §"Weights"). *Reversibility: medium.*
- **D4 — Candidates are generated *from the evidence*, never assumed.** The candidate set is derived from
  the ATT&CK groups/campaigns that use the observed techniques/software; the system never starts from a
  named actor and seeks support for it. An explicit **"Unattributed / Unknown" null hypothesis** is always
  in the set. *Reversibility: low.*
- **D5 — "Insufficient evidence for attribution" is a first-class, expected output.** Attribution is emitted
  only when a candidate beats the null hypothesis by a validated margin *and* meets a minimum confidence
  floor; otherwise the result is explicitly "insufficient." Detecting suspicious activity never forces an
  attribution. *Reversibility: low.*
- **D6 — Diagnosticity favors distinctive *combinations/sequences*, not single technique IDs.** Behavioral
  features operate over sub-technique combinations, tactic coverage, and kill-chain ordering — never
  "technique ID = actor fingerprint." Rarity contributes discrimination but is **never treated as proof**.
  *Reversibility: medium.*
- **D7 — Contradiction and "expected-but-missing" are first-class.** Evidence that argues *against* a
  candidate is stored and displayed. "Expected-but-missing" counts as contradiction **only where telemetry
  coverage was adequate** to have seen it. *Reversibility: medium.*
- **D8 — Missing telemetry lowers *confidence*, not likelihood.** Coverage gaps (DeTT&CT-style) reduce
  confidence and generate "next-evidence" guidance; they never fabricate support or contradiction.
  *Reversibility: medium.*
- **D9 — Bayesian/likelihood-ratio reasoning is used as a *frame*, not as fabricated posteriors.** We use
  likelihood-ratio *thinking* (diagnostic evidence; contradiction as negative evidence; comparative
  hypotheses) but **do not output calibrated posterior probabilities**, because ATT&CK gives technique
  *presence*, not reliable conditional frequencies `P(technique|group)`. Claiming precise posteriors would
  be exactly the false-precision this ADR forbids. Likelihood is reported as an **ordered, WEP-banded,
  relative** assessment whose band thresholds are calibrated on the corpus. *Reversibility: medium.*
- **D10 — False-flag/deception and aliasing are modeled explicitly.** Actor aliases are normalized via the
  KB alias set (not treated as competing hypotheses). Deception is surfaced as an **alternative
  explanation** with lowered confidence whenever easily-planted (evidentiary) artifacts point one way while
  hard-to-fake (behavioral) evidence points another. *Reversibility: medium.*
- **D11 — Uncertainty propagates explicitly and conservatively.** Confidence is **no stronger than its
  weakest critical link**; uncertainty is carried as inspectable annotations/bands, not hidden floats, and
  never multiplied as if independent probabilities. *Reversibility: medium.*
- **D12 — Deterministic and fully versioned.** Same input + ATT&CK KB version + TI KB version + methodology
  version + calibration version ⇒ identical result. Every result carries all four versions plus input hash
  and engine commit. *Reversibility: low.*
- **D13 — Standards serialization at the boundary only.** Internal two-axis assessment maps to **STIX 2.1
  `confidence`** (via `stix2.confidence.scales`) and WEP/Admiralty/DNI vocabularies **only for
  output/interoperability**, documented so the two axes are not silently merged. *Reversibility: high.*
- **D14 — Every quantity must have an operational meaning and a test.** No mathematical construct is
  admitted for sophistication's sake; each has a stated meaning and a headless test in
  [08](../08-validation-and-calibration.md). *Reversibility: low.*

## Decisions added by the stress test (all PROPOSED — see [09](../09-methodology-stress-test.md))

The stress test found three genuine defects (quantity-over-quality, double-counting, residual famous-group
bias) and several risks. The following decisions harden the methodology; none changes its structure.

- **D15 — Full candidate universe; no fixed list (CR-3).** The universe is the entire pinned group+campaign
  set; display pruning is by diagnosticity only, never prominence; the full set is retained for scoring.
  *Reversibility: low.*
- **D16 — Support resists volume and correlation (CR-1).** `support(h)` de-duplicates correlated evidence
  (one behavior = one contribution), is dominated by high-`D` discriminating evidence (not sums of common
  ones), and is normalized by candidate profile breadth. `support`/`D` are never shown as probabilities.
  *Reversibility: medium (calibration-tunable).*
- **D17 — `Unattributed` has an absolute coincidental-overlap floor (CR-2).** A named candidate must exceed
  coincidental overlap on distinctive evidence to beat the null — protecting against forcing a known label
  onto an absent/under-represented actor. *Reversibility: low.*
- **D18 — `D`'s claim is bounded (CR-4).** `D` is a documentation-relative separation *heuristic*, not a
  probability or real-world rate; it is subject to reporting bias; rarity is a weight, not proof; prevalence
  extends to software. *Reversibility: medium.*
- **D19 — Combination/sequence caveat (CR-5).** Group profiles are unions over intrusions; profile
  co-occurrence weakly implies single-attack combination; sequence matching is low-weight and flagged.
  *Reversibility: medium.*
- **D20 — No attribution from a single technique (CR-6).** Regardless of `D`, a lead needs a distinctive
  combination or independent corroboration; single-technique leads are capped and routed to insufficient.
  *Reversibility: medium.*
- **D21 — Imitation/reporting-bias guards (CR-7).** Confidence may not be "high" on TTP overlap alone
  without independent corroboration; leads driven by profile richness bias toward abstention; output is
  phrased "consistent with," never "is." *Reversibility: medium.*
- **D22 — Anti-circular validation (CR-8; MODIFIED per final review M2).** The **primary** anti-circular
  mechanism is **blind-actor holdout** — remove a group's profile from the KB and confirm the system returns
  "untracked actor" (not the nearest famous match) — together with **strict separation of
  pipeline-correctness tests from attribution-generalization tests**. **Independent / real-incident
  validation data is aspirational, not a prerequisite**: it is pursued where licensable public incident data
  can be found, but its **absence must never block the project or a phase**. When such data is unavailable,
  the **generalization claim is explicitly scoped to the available validation corpus** ("validated at
  pipeline level and via blind-actor holdout; generalization to real-world incidents under-validated"), and
  the system stays biased toward abstention. The ceiling is documented openly. *Reversibility: low.*

## Explicit evaluation of candidate techniques (as requested)

| Technique | Use it? | Rationale |
|---|---|---|
| **ACH** | **Yes (core)** | Natural fit for competing hypotheses + disconfirmation; comparative by construction (D1). |
| **Discriminating evidence** | **Yes (core)** | The principled replacement for arbitrary weights; derived from the KB (D3, D6). |
| **Likelihood ratios / Bayesian** | **As a frame, bounded (D9)** | Correct reasoning shape, but no reliable `P(evidence\|group)` exists → we refuse to output fabricated posteriors; use diagnostic, relative, calibrated bands instead. |
| **ATT&CK procedure knowledge** | **Yes, cautiously** | Procedure-level matches are more diagnostic than technique presence, but risk shared-tooling false positives → treated as high-diagnosticity evidence *with* deception/aliasing checks. |
| **STIX 2.1 confidence** | **Yes (serialization only, D13)** | Standard output vocabulary; not the internal representation. |
| **Admiralty / WEP / DNI** | **Yes (vocabulary)** | Admiralty grades *source/info* reliability (feeds confidence); WEP bands *likelihood*; DNI/None-Low-Med-High for confidence. Vocabulary + mapping, not fabricated math. |
| **ICD-203 likelihood/confidence separation** | **Yes (core, D2)** | The single most important structural decision. |

## Consequences

**Positive:** structurally prevents the prohibited scoring pattern; every conclusion is comparative,
diagnostic, inspectable, and reproducible; "insufficient evidence" and contradiction are normal outputs;
avoids false mathematical precision; testable headless.

**Negative / costs:** the diagnosticity and calibration machinery must be specified and validated carefully
(a real research effort, phased); combination/sequence diagnosticity is limited by ATT&CK data sparsity and
must degrade honestly; "expected-but-missing" requires a coverage model (DeTT&CT-style) to be sound.

**Neutral:** the exact diagnosticity function and band thresholds are **calibration-version parameters**,
intentionally tunable/reversible without changing the methodology's structure.

## Alternatives considered (and rejected for now)

- **Additive point scoring** (the prohibited pattern) — rejected: arbitrary, non-diagnostic, collapses axes.
- **Full Bayesian posterior over groups** — rejected as *primary*: requires conditional frequencies we do
  not have; would fabricate precision. Retained only as reasoning *frame* (D9).
- **Supervised ML classifier over TTP vectors** — deferred: opacity conflicts with the explainability
  principle and there is insufficient labeled data; may return later strictly as an *optional, interpretable*
  enhancement that never sits on the correctness path.

## What this ADR resolves in [05](../05-architecture-open-questions.md)

Resolves **Q2** (scoring methodology — this ADR + [07](../07-attribution-scoring-spec.md)) and **Q7**
(aliasing/false-flag — D10). Sharpens **Q6** (validation/calibration — [08](../08-validation-and-calibration.md)).
Leaves open: the *fitted* calibration values (need the corpus), and the concrete corpus contents.

## Follow-up

On approval: status → ACCEPTED (dated); open **ADR-0003** only if the calibration approach needs to change
after first corpus results. No engine code until this ADR and its companion specs are approved.
