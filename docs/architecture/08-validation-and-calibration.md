# 08 — Validation & Calibration

**Status: PROPOSED** (specification; no code). Defines how the methodology in
[07](07-attribution-scoring-spec.md) is proven *before and during* implementation, entirely **headless**
(no frontend). Implements the testability/reproducibility requirements of
[ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md) and sharpens open question **Q6**.

**Principle:** a capability is "done" only when it passes this suite deterministically. This is the concrete
guard against the previous version's hard-coded/simulated results.

---

## 1. The labeled golden corpus

A versioned set of **cases**, each = (input telemetry/observations) + (expected output *shape*). Inputs come
from permissively-licensed, reproducible sources ([research 07](../research/07-datasets-and-synthetic-telemetry.md)):
Security-Datasets (MIT) and CALDERA/Atomic (Apache/MIT) for generated scenarios; EVTX fixtures (GPL) used
**locally only**. Each case is pinned by content-hash and annotated with the ATT&CK version it was authored
against.

Expected outputs are **shapes, not just labels** — e.g., not "APT29" but: *leading hypothesis APT29 at
"likely", confidence "moderate", discriminating evidence = {…}, contradiction X surfaced, next-evidence = Y*.
This lets tests check the **reasoning**, not only the answer.

## 2. Required case types (all must exist before trusting attribution)

| Case type | Purpose | Expected-output shape |
|---|---|---|
| **Positive** | true actor present with discriminating behavior | correct leader, appropriate likelihood + confidence, correct discriminating evidence |
| **Negative (benign / no APT)** | ordinary or non-attributable activity | **"Insufficient evidence"**; no actor forced |
| **Common-technique-only** | only ubiquitous techniques (the prohibited-pattern trap) | **"Insufficient evidence"** — proves `D≈0` cancellation |
| **Ambiguous** | evidence genuinely fits none strongly | "Insufficient" or wide uncertainty; no false precision |
| **Competing-group** | two actors fit nearly equally | **tie / "roughly even chance"** set, not a forced winner |
| **Incomplete-telemetry** | discriminating data source missing | lowered **confidence** (not likelihood) + correct next-evidence |
| **Expected-but-missing** | characteristic behavior absent *with* coverage | correct **contradiction** lowering that candidate |
| **False-flag / deception** | planted evidentiary artifacts vs. contrary behavioral evidence | behavioral leader, capped confidence, explicit deception alternative |
| **Alias** | indicators map to aliased actor | aliases collapsed to one candidate; no duplicate hypotheses |

Coverage requirement: every case type is represented; positives span multiple actors and multiple tactics;
no single actor dominates the corpus (guards against overfitting `D`).

## 3. Evaluation metrics (each tied to a methodology property)

- **Ranking correctness** — is the true actor ranked above alternatives / in top-k on positives?
- **Abstention correctness** — does the system say "insufficient" on negative/common-only/ambiguous cases?
  (Tracks false-attribution rate — arguably the *most important* metric here.)
- **Competing-case correctness** — are near-ties reported as ties, not forced winners?
- **Calibration** — over all "likely / high-confidence" claims, are they right at the expected rate?
  Reported as a **reliability diagram** + a calibration error metric, separately for the **likelihood** axis
  (WEP bands vs. observed hit rate) and the **confidence** axis (do high-confidence claims fail less often
  than low). Calibration is a **first-class metric**, not an afterthought.
- **Discriminating-evidence correctness** — does the cited discriminating evidence actually separate the
  candidates (spot-checked against the labeled rationale)?
- **Contradiction surfacing** — are known contradictions/expected-but-missing detected?
- **Explanation faithfulness** — does the stated ranking explanation reference the evidence that actually
  drove the ranking (no post-hoc rationalization)?
- **Determinism** — identical inputs+versions ⇒ identical `determinism_hash`.

**Non-goal:** a single "accuracy" number. Ranking, abstention, and calibration are reported separately
because a system that is 100% accurate on positives but never abstains is *dangerous*, not good.

## 4. Calibration procedure

1. Split the corpus into **calibration** and **held-out** partitions (by scenario family, so near-duplicates
   don't leak across the split).
2. On the calibration split, fit the **calibration-version parameters**: the `D` functional form/threshold,
   the likelihood WEP-band thresholds, and the decision-rule constants `τ_separation`, `min_confidence`,
   `τ_margin` ([07](07-attribution-scoring-spec.md) §§2,5,11) — optimizing ranking **and** calibration
   jointly (a change that helps ranking but harms calibration is rejected).
3. **Freeze** the parameters as a named `calibration_version`.
4. Validate on the held-out split; report all §3 metrics.
5. If held-out calibration is poor or coverage of a regime is thin, **widen the "insufficient" region** (bias
   toward abstention) rather than shipping overconfident bands.
6. Re-run whenever the ATT&CK KB version or methodology version changes → new `calibration_version`.

**Insufficient calibration data behavior:** if a case falls outside the regime the calibration covers,
`D` uses the neutral prior and confidence is capped/flagged "outside validated regime"
([07](07-attribution-scoring-spec.md) §2.7) — the suite asserts this happens rather than the system
guessing.

## 5. Regression tests

- **Frozen expected-output shapes** per corpus case; a diff is a regression to review (not auto-accepted).
- **Determinism test** on every case (`determinism_hash` stable).
- **Anti-arbitrariness guards** (assert structural properties, independent of tuning):
  - common-technique-only ⇒ insufficient;
  - removing an evidence item never *adds* a candidate;
  - no result contains a single merged likelihood×confidence number;
  - every emitted attribution satisfies the decision rule;
  - every conclusion resolves to provenance back to `RawEvent`s.
- **Calibration-drift test:** if a KB/methodology bump shifts calibration beyond a threshold, fail loudly and
  require a new `calibration_version`.

## 6. Headless testability (no frontend)

All of the above run as data-in/data-out over the engine's read models: feed a case's observations, get an
`AttributionResult` JSON, assert on its fields. The frontend is never in the loop for validation — it only
renders results the tests already trust. This enforces CLAUDE.md principle 10 from the other direction: the
backend must stand on its own.

## 7. Reproducibility requirements (what makes results repeatable)

A result is reproducible iff these are all pinned and recorded on it:

- `attack_kb_version` (pinned `attack-stix-data` release),
- `ti_kb_version` (enrichment snapshot),
- `methodology_version` (docs 06/07 revision),
- `calibration_version` (frozen parameters from §4),
- `dataset_ref` (name@content-hash),
- `engine_version` (commit).

Same six ⇒ identical `determinism_hash`. Any change is a new, labeled result — the corpus + versions are the
"lab notebook" that makes the whole methodology auditable.

## 7a. Anti-circular validation (CR-8 — added by the stress test)

A real risk: if the corpus is built entirely from ATT&CK-derived tooling (CALDERA/Atomic) and scored with an
ATT&CK-derived `D`, we are partly **testing the knowledge base against itself**. Mitigations, required before
attribution is considered validated:

- **Two test tiers, kept separate:**
  1. **Pipeline-correctness tests** — ATT&CK-derived scenarios that verify the *machinery* (extraction →
     assertion → graph → ACH → decision rule) behaves as specified. These may legitimately use
     ATT&CK-derived data because they test mechanics, not generalization.
  2. **Attribution-generalization tests** — cases drawn from **independent / real-incident** sources **not**
     derived from the ATT&CK tooling used for `D` (e.g., public incident reports, third-party datasets),
     used to check whether attribution *generalizes* beyond the KB it reasons over.
- **Do not report attribution accuracy from tier-1 alone.** Generalization claims require tier-2.
- **Document the ceiling:** where independent data is scarce, state plainly that generalization is
  under-validated and keep the system biased toward abstention in those regimes.
- **Blind-actor holdout:** periodically remove a group's profile from the KB and confirm the system returns
  "untracked actor" (Scenario 8) rather than forcing the nearest famous match — a direct test of the null
  floor (CR-2) and famous-group bias (CR-7).

## 8. How this validates the methodology (not just the code)

- **Positives + ranking** validate that discriminating evidence works.
- **Negatives/common-only/ambiguous + abstention** validate that arbitrary attribution is *structurally*
  avoided.
- **Competing + calibration** validate that likelihood is honest and comparative.
- **Incomplete-telemetry + expected-but-missing** validate the confidence/likelihood separation.
- **False-flag + alias** validate deception and identity handling.
- **Determinism + versioning** validate reproducibility.

If any category cannot be made to pass, the methodology — not just the implementation — needs revision, and
that revision is an ADR amendment, done before more code.
