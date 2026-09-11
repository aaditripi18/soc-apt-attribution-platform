# 10 — Final Architecture Review (Acceptance Gate)

**Status: REVIEW ARTIFACT.** A final critical pass over the whole proposed architecture before acceptance.
ADR statuses are **left unchanged (still PROPOSED)**; this document records verdicts and required
modifications for the owner to action at acceptance. Nothing is implemented.

Reviewed: [CLAUDE.md](../../CLAUDE.md), all of `docs/research/`, all of `docs/architecture/` — with focus on
[ADR-0001](adr/0001-evidence-graph-core-architecture.md), [ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md),
[06 evidence model](06-evidence-model.md), [07 scoring spec](07-attribution-scoring-spec.md),
[08 validation](08-validation-and-calibration.md), [09 stress test](09-methodology-stress-test.md),
[03 data flow](03-system-data-flow.md), [04 boundaries](04-component-boundaries.md),
[05 open questions](05-architecture-open-questions.md).

Verdict vocabulary: **ACCEPT** (sound, adopt as-is) · **MODIFY** (sound intent, wording/mechanism must
change — corrected text given) · **REJECT** (wrong; remove/replace) · **DEFER** (do not decide now; not
needed until a later phase).

---

## A. Executive assessment

The architecture is **coherent, well-grounded, and faithful to [CLAUDE.md](../../CLAUDE.md)**. The core
thesis — Elastic as data plane, a provenance-first evidence graph, ACH attribution with a two-axis
likelihood/confidence methodology that can abstain — is the right shape and directly counters every named
failure of the previous version. The stress test ([09](09-methodology-stress-test.md)) already found and
corrected the most dangerous methodology defects (quantity bias, double-counting, famous-group bias, the
missing null floor).

**Bottom line:** the *architecture* (ADR-0001) is ready to build against; the *attribution methodology*
(ADR-0002) is structurally sound but its **quantitative core is calibration-gated and three sub-systems are
underspecified** (coverage model, combination-diagnosticity algorithm, independent validation). Those block
**Phase 3 (attribution)**, not **Phase 0–2**. Two decisions need modification (ADR-0001 **D8**, ADR-0002
**D22**); none needs rejection.

**Overall readiness (see §G): READY WITH CONDITIONS.**

### Focus-area coverage map (the 25 review points)

| # | Focus area | Addressed by | Status |
|---|---|---|---|
| 1 | Full ATT&CK, no manual actor list | ADR-0002 D15; [07 §3](07-attribution-scoring-spec.md); [09 §A](09-methodology-stress-test.md) | ✅ solid |
| 2 | Elastic's role vs ours | ADR-0001 D2; [04](04-component-boundaries.md) | ✅ solid |
| 3 | Evidence provenance to source telemetry | ADR-0001 D4; [03 invariant](03-system-data-flow.md); [06 U1](06-evidence-model.md) | ✅ solid |
| 4 | Evidence graph architecture | ADR-0001 D4/D9; [06](06-evidence-model.md) | ✅ solid |
| 5 | Candidate generation over full universe | ADR-0002 D4/D15 | ✅ solid |
| 6 | ATT&CK reporting bias | ADR-0002 D18/D21; [09 §C](09-methodology-stress-test.md) | ⚠️ mitigated, residual (honest) |
| 7 | Discriminating power `D` | ADR-0002 D3/D18; [07 §2](07-attribution-scoring-spec.md) | ⚠️ **algorithm underspecified** |
| 8 | Common vs distinctive techniques | ADR-0002 D3/D20 | ✅ solid |
| 9 | Combinations & sequences | ADR-0002 D6/D19 | ⚠️ **algorithm underspecified** |
| 10 | Shared tooling/malware | ADR-0002 D18 (D over software); [09 §D](09-methodology-stress-test.md) | ✅ handled |
| 11 | False flags / imitation | ADR-0002 D10/D21 | ⚠️ mitigated, hard residual (honest) |
| 12 | Contradictory evidence | ADR-0002 D7; [06 §7](06-evidence-model.md) | ✅ solid |
| 13 | Missing telemetry vs negative evidence | ADR-0002 D7/D8; [07 §9](07-attribution-scoring-spec.md) | ⚠️ **depends on coverage model (underspecified)** |
| 14 | Mandatory Unattributed/null | ADR-0002 D5/D17 | ✅ solid (floor computation is calibration-gated) |
| 15 | Likelihood vs confidence | ADR-0002 D2; [07 §5/§6](07-attribution-scoring-spec.md) | ✅ solid |
| 16 | Abstention | ADR-0002 D5; [07 §11](07-attribution-scoring-spec.md) | ✅ solid |
| 17 | No fake probabilities / point scoring | ADR-0002 D3/D9/D16 | ✅ solid |
| 18 | No double-counting | ADR-0002 D16; [07 §4](07-attribution-scoring-spec.md) | ⚠️ **"independent evidence" needs precise definition** |
| 19 | Calibration | [08 §4](08-validation-and-calibration.md) | ⚠️ **corpus does not exist yet** |
| 20 | Independent validation / blind-actor holdout | ADR-0002 D22; [08 §7a](08-validation-and-calibration.md) | ⚠️ **data source unresolved → MODIFY** |
| 21 | Reproducibility & versioning | ADR-0001 D10; ADR-0002 D12; [06 §Versioning](06-evidence-model.md) | ✅ solid |
| 22 | Scope realism (personal project) | [02 phasing](02-recommended-architecture.md) | ⚠️ ambitious; Phase 3 is the risk |
| 23 | Sophisticated analyst frontend later | ADR-0001 D11; [02](02-recommended-architecture.md) | ✅ enabled |
| 24 | No SIEM re-creation | ADR-0001 D2; [04 bright line](04-component-boundaries.md) | ✅ solid |
| 25 | Realistic telemetry via Elastic | ADR-0001 D2; [03](03-system-data-flow.md) | ✅ solid |

---

## B. ADR-0001 decision-by-decision review

| Dec | Summary | Verdict | Note |
|---|---|---|---|
| D1 | Adopt Evidence-Graph Core (Option B) | **ACCEPT** | Best-justified against the 14 criteria; matches the thesis. |
| D2 | Elastic = data plane only | **ACCEPT** | Clean bright line ([04](04-component-boundaries.md)); directly answers focus 2/24. |
| D3 | ATT&CK from pinned STIX | **ACCEPT** (condition) | Must pin a **specific named `attack-stix-data` version** at Phase 0 and stamp it everywhere. |
| D4 | One provenance-first evidence graph | **ACCEPT** | The spine of provenance (focus 3/4). |
| D5 | Deterministic; ML deferred | **ACCEPT** | Aligns with explainability principle. |
| D6 | ACH competing hypotheses | **ACCEPT** | Correct backbone. |
| D7 | Two-axis confidence (ICD-203) | **ACCEPT** | The most important structural choice (focus 15). |
| **D8** | **Discriminating-technique weighting** | **MODIFY** | **Stale vs the stress test.** As written it says "weight techniques by actor-characteristic rarity," which reads like the pre-hardening claim. **Corrected decision:** *"Weight evidence by **discriminating power `D`**, a **documentation-relative separation heuristic** computed from the pinned ATT&CK Group×{Technique **and Software**} matrix — never a probability or real-world rate. Rarity is a weight, not proof; **no attribution from a single technique**; discrimination is driven by **distinctive combinations** (with the profile-union caveat) and normalized against candidate profile size. Validate on labeled scenarios before trust."* (Aligns D8 with ADR-0002 D16/D18/D19/D20/D21.) |
| D9 | Embedded graph first, `GraphStore` port | **ACCEPT** | Right deferral; full ATT&CK fits in memory. The DB choice itself is **DEFER** (Q3). |
| D10 | Reproducibility by construction | **ACCEPT** | Strong; foundational (focus 21). |
| D11 | Frontend renders, never computes | **ACCEPT** | Enforces CLAUDE.md principle 10 (focus 23). |
| D12 | Detection content license split | **ACCEPT** (condition) | Sound; needs the **concrete minimal Phase-1 ruleset** pinned (ties to Q4/Q6). |
| D13 | Windows/endpoint-first for v1 | **ACCEPT** (owner confirm) | Sound default; awaits owner's explicit yes (Q5). |
| D14 | Personal-scale deployment | **ACCEPT** (owner confirm) | Sound; awaits owner's footprint confirmation (Q10). |

**ADR-0001 result:** 13 ACCEPT (4 carrying conditions/confirmations), **1 MODIFY (D8)**, 0 REJECT. The graph
**DB** choice is DEFER (already deferred by D9).

---

## C. ADR-0002 decision-by-decision review

| Dec | Summary | Verdict | Note |
|---|---|---|---|
| D1 | ACH, not accumulative | **ACCEPT** | Core; verified across [09 §B](09-methodology-stress-test.md) scenarios. |
| D2 | Two independent axes | **ACCEPT** | Never merged; orthogonality test in [08](08-validation-and-calibration.md). |
| D3 | Weights = diagnosticity, not hand-assigned | **ACCEPT** | The anti-arbitrary-scoring keystone (focus 17). |
| D4 | Candidates from evidence; null present | **ACCEPT** | Focus 5/14. |
| D5 | "Insufficient evidence" first-class | **ACCEPT** | Focus 16; demonstrated in scenarios 1,2,6,8. |
| D6 | Diagnosticity favors combinations, not single IDs | **ACCEPT** (spec-gated) | Right principle; **the combination-diagnosticity algorithm is underspecified** (see §D-3). |
| D7 | Contradiction + expected-but-missing first-class | **ACCEPT** (spec-gated) | Correct; **depends on the coverage model** (§D-2). |
| D8 | Missing telemetry → confidence, not likelihood | **ACCEPT** | The key correctness distinction (focus 13). |
| D9 | Bayesian as frame, no fabricated posteriors | **ACCEPT** | Honest; avoids false precision (focus 17). |
| D10 | False-flag/aliasing explicit | **ACCEPT** | With honest residual limit on imitation (focus 11). |
| D11 | Uncertainty conservative/bounded | **ACCEPT** | "No stronger than weakest link." |
| D12 | Deterministic + fully versioned | **ACCEPT** | Focus 21. |
| D13 | STIX serialization at boundary only | **ACCEPT** | Keeps axes un-merged internally. |
| D14 | Every quantity has meaning + test | **ACCEPT** | Good discipline gate. |
| D15 | Full universe; no fixed list | **ACCEPT** | Directly satisfies focus 1. |
| D16 | Support resists volume/correlation | **ACCEPT** (spec-gated) | Right; **"independent evidence" and the concentration/normalization mechanism need precise definition** (§D-3/focus 18). |
| D17 | Null absolute coincidental-overlap floor | **ACCEPT** (calibration-gated) | Critical (scenario 8); **floor computation is calibration-gated** (§D-4). |
| D18 | `D` claim bounded (heuristic, software-extended) | **ACCEPT** | Focus 6/7/10. |
| D19 | Combination/sequence caveat | **ACCEPT** | Honest about profile-union limitation (focus 9). |
| D20 | No attribution from a single technique | **ACCEPT** | Focus 8. |
| D21 | Imitation/reporting-bias guards | **ACCEPT** | "Consistent with," never "is" (focus 6/11). |
| **D22** | **Anti-circular validation** | **MODIFY** | Intent is right, but as written it **requires independent/real-incident data that is not identified and may be unobtainable at personal scale** — a requirement that could silently block the whole validation story. **Corrected decision:** *"Primary anti-circular mechanism = **blind-actor holdout** (remove a group's profile from the KB; confirm the system returns 'untracked actor,' not the nearest famous match) plus **strict separation of pipeline-correctness tests from attribution-generalization tests**. Independent/real-incident validation is **aspirational**: pursued where licensable public incident data can be found, but its absence does **not** block phases — instead the **generalization claim is explicitly scoped down** ('validated at pipeline level; generalization under-validated') and the system stays biased toward abstention. Document the ceiling openly."* |

**ADR-0002 result:** 21 ACCEPT (4 spec/calibration-gated), **1 MODIFY (D22)**, 0 REJECT.

**Why no REJECTs (I looked for them):** candidate rejection targets would be over-engineering or a
principle violation. The heaviest constructs (combination diagnosticity, coverage model, null floor) are all
*load-bearing for correctness*, not decoration; and the honest limitations (imitation, `D` bias) are
disclosed rather than hidden. Nothing rises to REJECT. The genuine risk is **scope**, addressed in §D-6/§G.

---

## D. Critical unresolved issues

These are the issues that genuinely matter before/within implementation. Each names the blocking phase.

**D-1 — Independent validation data source (blocks *generalization claims*, not Phase 0–2).**
ADR-0002 D22/CR-8 mandate independent, non-ATT&CK-derived validation, but **no source is identified**, and
licensable, labeled, real-incident telemetry is hard to obtain for a personal project. *Resolution:* the
D22 MODIFY above — blind-actor holdout as the primary mechanism, independent data aspirational, the
generalization claim scoped down honestly. Without this modification the validation story is either
circular or blocked.

**D-2 — Coverage model (`CoverageProfile`) is load-bearing but underspecified (blocks Phase 2/3).**
The missing-telemetry-vs-contradiction distinction (D7/D8 — a *central* correctness claim) and part of
confidence depend on accurately knowing, per technique, which ATT&CK data sources/components are needed and
whether the case's telemetry provided them. This is described only as "DeTT&CT-style, adapted"
([04](04-component-boundaries.md), [06](06-evidence-model.md)). *Needs its own mini-spec* (data-source →
detectability mapping, how "adequate coverage" is decided) before Phase 2, and it must be honest about the
fact that DeTT&CT coverage is itself an approximation.

**D-3 — Combination-diagnosticity and "independent evidence" algorithms are underspecified (blocks Phase 3).**
Combination diagnosticity is called the *dominant* likelihood weight ([07 §1](07-attribution-scoring-spec.md)),
yet no algorithm is given, and CR-5 concedes the underlying data (profile-union co-occurrence) is weak. The
de-duplication rule (D16/focus 18) likewise needs a precise definition of "independent evidence" (what makes
two observations causally the same behavior). *Both need a written algorithm + honest sparsity handling*
before the attribution engine is built.

**D-4 — All quantitative parameters are calibration-gated and the corpus does not exist (blocks Phase 3).**
`D`'s functional form, the null-floor level, `τ_separation`, `min_confidence`, `τ_margin`, and the
concentration check are — correctly — calibration-version parameters. But there is **no corpus yet** to fit
or validate them ([08](08-validation-and-calibration.md) is a design, not data). *Phase 0 must build the
initial golden corpus; Phase 3 cannot start until calibration data exists.* This is expected in the phasing,
but must be stated as a hard gate.

**D-5 — Phase-1 prerequisites not yet pinned (blocks Phase 1, small).**
Q1 (normalized-event contract fields), Q4 (concrete minimal detection-content set), Q5 (Windows-first
confirm), Q6 (which golden-corpus cases). All are small and resolvable, but extraction code should not begin
until Q1/Q4 are written down and the initial corpus subset exists.

**D-6 — Scope realism for the attribution engine (project risk, not a blocker).**
Phases 0–2 are very achievable. **Phase 3** (calibrated ACH + combination diagnosticity + coverage model +
false-flag + next-evidence information-gain) is genuinely ambitious for a personal project. *Recommendation:*
treat combination diagnosticity (D-3) and the coverage model (D-2) as the two riskiest sub-systems; be
willing to ship a **reduced but honest** first attribution (single-technique-guarded, distinct-combination
based, abstaining freely) and add sophistication only as calibration supports it.

**Not unresolved (confirmed adequate):** provenance/traceability (focus 3), Elastic boundary (2/24),
full-universe candidate generation (1/5), two-axis separation (15), abstention (16), no-fake-probabilities
(17), reproducibility (21). These are specified well enough to build.

---

## E. Required modifications (to apply at acceptance — not applied here)

| ID | Modification | Target |
|---|---|---|
| **M1** | Rewrite **ADR-0001 D8** to the corrected text in §B (align with the stress-test hardening: documentation-relative `D`, software-extended, combination-first, single-technique guard, profile-normalized). | ADR-0001 |
| **M2** | Rewrite **ADR-0002 D22** to the corrected text in §C (blind-actor holdout primary; independent data aspirational; generalization claim scoped down; ceiling documented). | ADR-0002 |
| **M3** | Add a **Coverage-Model mini-spec** (D-2) before Phase 2 defining data-source→detectability mapping and the "adequate coverage" test. | new doc (e.g., `11-coverage-model.md`) |
| **M4** | Add a **combination-diagnosticity + evidence-independence algorithm spec** (D-3), with explicit sparsity handling, before Phase 3. | extend [07](07-attribution-scoring-spec.md) or new ADR-0003 |
| **M5** | Define the **initial golden corpus contents** (D-4/D-5, Q6) and the **Phase-1 event contract + minimal ruleset** (Q1/Q4) as Phase-0/1 deliverables. | new `corpus/README` + [05](05-architecture-open-questions.md) resolution |
| **M6** | Record the owner's confirmations for **Windows-first (Q5/D13)** and **deployment shape (Q10/D14)**. | [05](05-architecture-open-questions.md) |

M1 and M2 are decision-text corrections; M3–M6 are prerequisite specs/confirmations scheduled by phase. None
requires re-architecting.

---

## F. Final architecture recommendation

**Adopt the Evidence-Graph Core architecture (ADR-0001) and the Attribution Scoring & Evidence Methodology
(ADR-0002), with modifications M1 and M2 applied and M3–M6 scheduled by phase.**

The architecture is technically credible, faithful to the project's principles, and — crucially — puts the
build effort exactly on the differentiator while refusing to re-create a SIEM or a re-typed ATT&CK. The
methodology, after the stress test, avoids arbitrary scoring by construction and is honest about its own
limits (imitation, reporting bias, a validation ceiling). The remaining gaps are **specification and
calibration work concentrated in Phase 3**, not architectural flaws — so they can be resolved *inside* the
phased plan rather than blocking the start.

No decision warrants rejection. Two need modification (D8, D22). Four sub-systems need specs/data before the
attribution engine (Phase 3) — none before scaffolding and the evidence-mapping foundation (Phases 0–2).

---

## G. Implementation readiness assessment

### READY WITH CONDITIONS

Rationale: the architecture is ready to build against, and **Phase 0 has no architectural blockers**, but
there are explicit conditions per phase — and hard gates before the attribution engine.

**Phase 0 (scaffolding, Elastic-in-Docker, pinned-ATT&CK load, initial golden corpus, CI) — may start once:**
- C0.1 A specific `attack-stix-data` version is chosen and pinned (D3 condition).
- C0.2 Owner confirms deployment shape (Q10/D14) and Windows-first scope (Q5/D13) — M6.
- C0.3 M1 (D8 rewrite) and M2 (D22 rewrite) are applied to the ADRs, and ADR-0001/0002 are moved to ACCEPTED
  as part of the same acceptance action.

**Phase 1 (telemetry → observation → ATT&CK technique) — may start once:**
- C1.1 Normalized-event contract fields written (Q1).
- C1.2 Minimal detection-content set for the corpus techniques pinned (Q4/D12).
- C1.3 Initial golden-corpus subset for technique mapping exists (Q6/M5).

**Phase 2 (correlation / attack-chain) — may start once:**
- C2.1 Coverage-model mini-spec exists (M3/D-2).

**Phase 3 (attribution engine) — MUST NOT start until:**
- C3.1 Combination-diagnosticity + evidence-independence algorithm specified (M4/D-3).
- C3.2 Calibration corpus (positive/negative/ambiguous/competing/incomplete/false-flag/alias) exists and the
  calibration procedure has produced a frozen `calibration_version` (D-4).
- C3.3 D22-as-modified validation (blind-actor holdout) is in place and the generalization claim is scoped
  (M2/D-1).

**Not ready to implement now (correctly deferred):** the attribution engine's quantitative core, the coverage
model, and any generalization claim. **Ready to implement now (under C0.x):** repository/module scaffolding,
Elastic-in-Docker, reproducible pinned-ATT&CK loading, dataset replay, the initial golden corpus, and CI —
i.e., all of Phase 0.

**One-line gate:** *Accept both ADRs with M1/M2 applied → begin Phase 0 under C0.1–C0.3 → do not touch the
attribution engine until C3.1–C3.3 are met.*

---

*ADR statuses unchanged (still PROPOSED). No application code written. Awaiting the owner's acceptance
decision and the confirmations in M6.*
