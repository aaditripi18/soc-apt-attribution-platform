# 09 — Methodology Stress Test

**Status: PROPOSED (review artifact).** A rigorous conceptual test of the attribution methodology
([ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md), [06](06-evidence-model.md),
[07](07-attribution-scoring-spec.md), [08](08-validation-and-calibration.md)) **before** it is frozen. This
document *finds real weaknesses* and prescribes corrections; the corrections have been applied back into the
methodology docs (see §F), and ADR-0002 remains **PROPOSED**.

Illustrative note: scenarios use plausible ATT&CK technique IDs and **generic group labels (Group-A/B/…)**.
IDs are illustrative and not verified against the pinned KB; nothing here configures a real actor list.

---

## A. Full ATT&CK scalability assessment

**Requirement:** support the full pinned ATT&CK Enterprise KB — all tactics, techniques, sub-techniques,
groups, software, campaigns, procedures, relationships, aliases — with no hard-coded APT list.

**How the knowledge layer represents the full universe.** The `attack_knowledge` layer loads the entire
pinned `attack-stix-data` Enterprise bundle: every `x-mitre-tactic`, `attack-pattern` (technique +
sub-technique), `intrusion-set` (group), `malware`/`tool` (software), `campaign`, and every `relationship`
(`uses`, `attributed-to`) and alias. The **candidate universe = all `intrusion-set` + `campaign` objects in
the bundle** (typically 150+ groups, 20+ campaigns for a recent version) — not a curated subset. `g(t)` and
`D` are computed over this **entire** group set, so they scale with, and are defined by, the full KB.

**How candidate generation narrows dynamically (evidence-first).** For a case, the candidate set is derived
at runtime: every group/campaign with a `uses` edge to ≥1 observed technique **or** matched software
([07 §3](07-attribution-scoring-spec.md)). The universe is the whole KB; the *filter* is the evidence. The
ACH step then discriminates within that filtered set. Nothing enumerates "the APT groups we support."

**Fixed-actor-list audit — where a small list could sneak in, and the verdict:**

| Location | Risk | Verdict |
|---|---|---|
| Candidate generation ([07 §3](07-attribution-scoring-spec.md)) | none — full-universe `uses` filter | ✅ clean |
| Worked examples (APT29/Group-A/B) | could be *read* as a configured set | ⚠️ **clarify** these are illustrative (applied) |
| Display pruning of a large candidate set | truncating to "top N *famous*" would reintroduce a fixed list | ⚠️ **corrected** — prune for display by **diagnosticity only**, retain full set internally (CR-3) |
| Validation corpus ([08](08-validation-and-calibration.md)) | over-representing famous groups overfits `D` | ⚠️ **corrected** — corpus balance + independent cases (CR-8) |
| Group-profile completeness | not a fixed list, but famous groups have richer profiles → bias | ⚠️ **corrected** — profile-size normalization (CR-7) |

**Scalability concern that is real (not a fixed-list bug):** when observed techniques are common, the
candidate net can be *most of the KB*. That is **correct for recall** (ACH + low `D` handles it), but the
system must never shrink that net by prominence. Correction CR-3 makes net-pruning diagnosticity-driven and
internal-set-complete. Performance is a non-issue at personal scale (a few hundred candidates × a few dozen
evidence items is trivial).

**Conclusion:** the design is genuinely full-KB and evidence-driven. The only scalability risks are
*bias* risks (profile richness, corpus balance, display pruning), corrected in §F — not fixed-list defects.

---

## B. Eight worked scenarios

Each runs the **actual** methodology objects. "Decision" applies the [§11](07-attribution-scoring-spec.md)
rule; bands are illustrative (exact thresholds are calibration-version parameters).

### Scenario 1 — Common techniques only
- **Observations:** O1 `cmd.exe`→`powershell` (rule R-proc), O2 remote file copy, O3 host discovery.
- **Evidence:** E1–E3 behavioral.
- **Assertions:** T1059 (Command/Scripting), T1105 (Ingress Tool Transfer), T1082 (System Info Discovery) —
  all high `g(t)`.
- **Behavioral feature:** three high-prevalence techniques, no distinctive combination, partial tactic
  coverage (Execution, C2-ish, Discovery).
- **Candidates:** huge net (most groups use these).
- **Supporting / contradicting / discriminating:** supporting links exist for ~all candidates; **`D≈0`** for
  each technique ⇒ **no discriminating evidence**; contributions cancel across columns.
- **ACH:** every `support(h) ≈ support(Unattributed)`.
- **Likelihood:** flat; no separation.
- **Confidence:** low (thin, common, coverage of discriminating data sources absent).
- **Uncertainty:** high — activity is generic.
- **Decision:** **INSUFFICIENT EVIDENCE. Abstain: YES.**
- **Analyst sees:** "Activity uses only common techniques (T1059/T1105/T1082) shared across most tracked
  groups; nothing distinguishes any actor. No attribution. To progress: capture discriminating behaviors
  (persistence/lateral-movement specifics)."

### Scenario 2 — Common techniques + one distinctive technique
- **Observations:** O1–O3 as above + O4 a rare persistence sub-technique (illustrative T1547.014, low
  `g(t)`).
- **Assertions:** commons (D≈0) + T1547.014 (**D high**).
- **Candidates:** the commons net, but only a few groups `use` T1547.014 → Group-A among them.
- **Discriminating evidence:** the single rare technique separates Group-A from most others.
- **ACH:** `support(Group-A)` rises above `Unattributed` on **one** high-`D` item; but it rests on a *single
  technique*.
- **Likelihood:** Group-A leans "likely" *relative*.
- **Confidence:** **low** — single-technique basis, no combination, possible shared/rare-tool coincidence.
- **Decision (post-CR-6):** **DOES NOT emit a firm attribution on one technique.** Reports Group-A as
  *leading hypothesis, low confidence*, explicitly flagged as resting on a single distinctive technique;
  **effectively abstains from a confident call. Abstain (confident): YES; leaning: recorded.**
- **Analyst sees:** "One distinctive technique (T1547.014) points toward Group-A, but a single technique is a
  fragile basis (possible shared tooling/coincidence). Low confidence. To confirm: look for Group-A's
  characteristic *combination* — e.g., its typical credential-access + lateral-movement pairing."

### Scenario 3 — Two groups with highly overlapping ATT&CK profiles
- **Observations:** a distinctive *combination* C = {T-a, T-b, T-c} that is rare across the KB but shared by
  **both** Group-A and Group-B (who have near-identical profiles).
- **Discriminating evidence:** C strongly separates {A,B} from the rest of the universe (high combination
  diagnosticity) but **does not** separate A from B (D between A and B ≈ 0).
- **ACH:** `support(A) ≈ support(B) ≫ support(Unattributed)`.
- **Likelihood:** A and B **roughly even**; the *pair* clearly beats Unattributed.
- **Confidence:** moderate–high (good, coherent evidence) — a textbook "high confidence, genuinely
  ambiguous" case.
- **Decision:** **ATTRIBUTE TO THE {A,B} CLUSTER; report A/B as a competing set, roughly even. Abstain on a
  single actor: YES. Abstain on the cluster: NO.**
- **Analyst sees:** "Behavior matches the closely-related cluster {Group-A, Group-B}; the two cannot be
  distinguished on current evidence (identical relevant TTPs). Confidence moderate–high. To separate A from
  B: <the one technique/infrastructure that differs>."
- **Demonstrates:** likelihood ⟂ confidence (ambiguous yet confident).

### Scenario 4 — Strong evidence for Group-A + contradictory evidence for Group-A
- **Observations:** distinctive combination consistent with Group-A **and** O-x, an adequately-covered
  behavior that Group-A characteristically uses but which is **absent** (expected-but-missing) **plus** O-y,
  an observed behavior Group-A is not known to use.
- **Contradicting evidence:** expected-but-missing (coverage adequate → real contradiction, [§9](07-attribution-scoring-spec.md)) + weak contradiction from O-y (KB-absence = *weak*, [06 §7](06-evidence-model.md)).
- **ACH:** `support(A)` gets a positive distinctive block minus a contradiction block.
- **Likelihood:** A still leads but **downgraded**.
- **Confidence:** **reduced** by unresolved contradiction.
- **Decision:** depends on residual separation; typically **A leading at "likely," moderate→low confidence,
  contradictions displayed**, or drops to competing if contradiction is large. **Abstain: possibly, if the
  contradiction erases the margin.**
- **Analyst sees:** "Leaning Group-A on <distinctive combination>, but Group-A characteristically performs
  <O-x>, which was absent despite adequate telemetry — a genuine argument against A. Confidence reduced. To
  resolve: <next-evidence>."

### Scenario 5 — Two competing groups supported ~equally (different evidence)
- **Observations:** subset S1 (distinctive to Group-A) **and** subset S2 (distinctive to Group-B), both
  present, comparable diagnosticity, no overlap.
- **ACH:** `support(A) ≈ support(B)`, both ≫ Unattributed, but for **different** reasons.
- **Likelihood:** roughly even A/B.
- **Confidence:** moderate–high if coverage good; the ambiguity is *real* (both genuinely present) — could
  indicate two actors, or one imitating another (flag deception alternative).
- **Decision:** **Report competing set {A,B}; surface the deception/co-activity alternatives. Abstain on
  single actor: YES.**
- **Analyst sees:** "Evidence independently supports both Group-A (via S1) and Group-B (via S2). Possible
  explanations: two actors, or imitation. Cannot select one. Next-evidence: <item that only one performs>."

### Scenario 6 — Very sparse / incomplete telemetry
- **Observations:** one or two observations; large `CoverageProfile` gaps (most discriminating data sources
  absent).
- **ACH:** whatever support exists is thin.
- **Likelihood:** may lean, but on little.
- **Confidence:** **low** — capped by coverage ([§6](07-attribution-scoring-spec.md)); cannot meet
  `min_confidence`.
- **Decision:** **INSUFFICIENT EVIDENCE (fails the confidence floor). Abstain: YES**, with prominent
  next-evidence.
- **Analyst sees:** "Too little telemetry to attribute; key data sources (<list>) were not collected.
  No attribution. Enable <data sources> to observe <discriminating techniques>."

### Scenario 7 — Expected behavior absent, but coverage also incomplete
- **Observations:** distinctive combination consistent with Group-A; Group-A also characteristically uses
  T-z, which is **absent** — but the data source for T-z was **not collected**.
- **Key distinction ([§9](07-attribution-scoring-spec.md), D8):** the absence of T-z is a **coverage gap**,
  **NOT** contradiction — we could not have seen it.
- **Likelihood:** **unchanged** by the absence (no penalty).
- **Confidence:** **lowered** by the coverage gap.
- **Decision:** A may lead on present evidence but **confidence capped**; often "leaning A, low–moderate
  confidence"; may or may not clear the floor. **Abstain: borderline — decided by the floor.**
- **Analyst sees:** "Evidence leans Group-A. Group-A usually also does T-z, which we **could not observe**
  (data source <x> absent) — this is a visibility gap, not evidence against A. Confidence limited until
  <data source> is collected."
- **Demonstrates:** missing-with-coverage (Scenario 4) vs missing-without-coverage (here) are handled
  differently — the central D7/D8 correctness point.

### Scenario 8 — Strong, coherent evidence; true actor absent/under-represented in the KB
- **Observations:** a distinctive, internally coherent combination + sequence, adequately covered — but the
  real actor is **not in ATT&CK** (or has a stub profile).
- **Candidates:** generation only nets known groups with `uses` edges to the observed techniques → only
  **partial** matches (each known candidate matches a *fraction* of the distinctive combination).
- **ACH (post-CR-2):** `Unattributed` carries an **absolute coincidental-overlap floor**; because no known
  candidate's *distinctive* fit clears that floor, **`Unattributed` wins or ties**.
- **Likelihood:** best known candidate does **not** separate from `Unattributed`.
- **Confidence:** the *activity* is coherent (so "this is a real, distinctive intrusion" is high-confidence),
  but **named** attribution confidence is low.
- **Decision:** **"Distinctive activity, but does not match any tracked actor well — likely an
  untracked/under-reported actor. No named attribution." Abstain on a named actor: YES.**
- **Analyst sees:** "Behavior is distinctive and coherent but matches no tracked group's profile beyond
  coincidental overlap. Most consistent with an actor not (well) represented in ATT&CK <version>. Named
  attribution withheld."
- **Demonstrates why CR-2 is essential:** without an absolute null floor, partial matches to a rich famous
  profile could **falsely beat** `Unattributed` — the single most dangerous failure this project must avoid.

**Scenario summary:** the methodology abstains in 1, 2 (confident), 6, 8; reports competing sets in 3, 5;
downgrades with contradiction in 4; distinguishes coverage-gap from contradiction in 7. **No scenario emits
a confident single-actor attribution from thin or common evidence** — the design intent holds, *given the
§F corrections* (especially CR-2 and CR-6).

---

## C. D-metric critique

**What `D` can legitimately claim:** a **documentation-relative separation weight** — "within the pinned KB,
how much does consistency with this technique/combination narrow the field of *tracked* groups?" It is a
ranking/weighting device, computed transparently from `g(t)`.

**What `D` cannot claim:**
- It is **not** `P(technique | group)` or any probability. (Reinforced; CR-4.)
- It is **not** a measure of how *characteristic* a technique is *of a specific actor* — that is the group's
  own profile, a different thing.
- It is **not** a real-world base rate — only ATT&CK-*reported* usage.
- It is **not** robust to reporting bias (below).
- It says **nothing** about techniques/actors absent from the KB.

**Reporting bias.** `g(t)` counts *documented* group usage. Heavily-reported groups (a handful of famous
APTs) contribute a disproportionate share of `uses` edges, so: (a) some techniques look more common than
they are; (b) rare-looking techniques may just be under-reported; (c) famous groups match more evidence
simply by having larger profiles. `D` inherits all of this. **This is the metric's chief limitation** and
drives the famous-group and quantity biases in §D/§E. Mitigations (CR-4/CR-7): weaken the claim, normalize by
profile size, bias toward abstention, never present `D` as truth about reality.

**Rare techniques.** High `D`, but **rarity is not proof** (CR-4). A lone rare technique can be shared
tooling, coincidence, or a plant. Hence **no attribution on a single technique** regardless of `D` (CR-6);
discrimination must come from a **distinctive combination** or independent corroboration.

**Common techniques.** `D≈0`; contribute ~0 to discrimination (correct). They still matter for
coverage/expected-behavior reasoning, not for lifting a hypothesis.

**Technique combinations.** Combinations are the intended signal — but the honest limitation (CR-5): an
ATT&CK **group profile is a union over many intrusions and years of reporting**, so co-occurrence *in a
profile* is only weak evidence of co-occurrence *in one attack*, and ATT&CK provides little reliable
**sequence/order** data per group. Therefore combination diagnosticity from profile co-occurrence is an
**approximation**, and observed-**sequence** matching must be **low-weight and flagged**, not treated as a
precise signature.

**Missing ATT&CK reporting.** Distorts `D` (both directions). Handled by the neutral-prior fallback +
confidence cap ([07 §2.7](07-attribution-scoring-spec.md)) and by never treating KB-absence as strong
contradiction ([06 §7](06-evidence-model.md)).

**New ATT&CK versions.** `D` changes with each version → every result stamps `attack_kb_version`; `D` and
calibration are recomputed per version; a result is valid only for its stamped version ([06 §Versioning](06-evidence-model.md)).

**Should `D` ever be a probability?** **No — never.** It is an ordering/weighting statistic. `support(h)` is
likewise never a probability and must **never** be rendered as a percentage (CR-1). Presenting either as a
probability would be exactly the false precision ADR-0002 forbids.

**Verdict on `D`:** keep it, but **weaken every claim to "documentation-relative separation,"** and add the
single-technique guard, profile-size normalization, combination/sequence caveats, and software-prevalence
extension. `D` is a useful heuristic, not a statistic — the docs must say so plainly.

---

## D. Failure-mode analysis

For each: **Detect? · Uncertainty · Likelihood · Confidence · Abstain? · Resolver.**

| Failure mode | Detected? | Uncertainty | Likelihood | Confidence | Abstain? | What resolves it |
|---|---|---|---|---|---|---|
| **Famous-group bias** | Partially (structural `D` helps; profile richness still leaks) | ↑ | can be inflated by volume | **capped** (CR-7) | biased toward abstain when lead rests on richness | profile-size normalization; distinctive-combination requirement |
| **Incomplete ATT&CK profiles** | Yes (null wins) | ↑ | best known candidate doesn't clear null | low (named) | Yes | external TI; procedure evidence |
| **False flags (planted IOCs)** | Yes (behavioral vs evidentiary split) | ↑ | stays on behavioral leader | capped | not necessarily | independent behavioral/infra corroboration |
| **Shared tooling** | Yes (shared software → low `D`, cancels) — *needs `D` over software, CR-4* | ↑ | not lifted by shared tool | n/a | if only shared tooling → Yes | actor-specific behavior beyond the tool |
| **Commodity techniques** | Yes (= common, `D≈0`) | ↑ | not lifted | low | Yes | discriminating behavior |
| **Reused malware** | Yes (low `D`; evidentiary-not-decisive) | ↑ | not lifted alone | capped | often Yes | behavioral corroboration |
| **Compromised infrastructure** | Yes (infra = evidentiary, low weight) | ↑ | not lifted alone | capped | often Yes | behavioral/victimology corroboration |
| **Adversary imitation (behavioral)** | ⚠️ **Weakly — hard limit** (imitation defeats behavioral priority) | ↑ | can be misled | **must not be "high" on TTP overlap alone (CR-7)** | not automatically | independent axes (infra/victimology/procedure); often unresolvable |
| **Deceptive ATT&CK-like behavior** | ⚠️ Weakly (same as imitation) | ↑ | can be misled | capped; output says "consistent with," never "is" | not automatically | independent corroboration; explicit deception hypothesis |
| **Conflicting telemetry** | Yes (contradictions on multiple candidates) | ↑ | all lowered | lowered | often Yes | resolve the conflict / more telemetry |
| **Alias ambiguity** | Yes (KB alias collapse) | ↑ if outside KB alias set | n/a | slightly lowered | no | KB alias completeness; TI |
| **Sparse evidence** | Yes | ↑↑ | thin | low (floor fails) | Yes | more telemetry |
| **New / unseen actors** | Yes (**null floor**, CR-2) | ↑ | best known ≤ null | low (named) | Yes (named) | new TI / KB update |

**Honest hard limits (cannot be fully solved by this or any TTP-based methodology):**
- **Behavioral imitation / deliberate TTP mimicry** defeats the behavioral-priority heuristic. The only
  defenses are (a) never claim *high* confidence on TTP overlap alone without independent corroboration, (b)
  always frame output as "consistent with," and (c) surface deception as an explicit alternative. Residual
  risk remains and is stated to the analyst. (CR-7.)
- **Attribution is inherently uncertain**; the methodology's job is to be *honest about* that, not to
  eliminate it. Abstention and two-axis reporting are the mechanisms.

---

## E. Methodology integrity audit

Does the current spec accidentally do any prohibited thing? Verdicts and fixes:

| # | Accidental behavior | Present? | Fix |
|---|---|---|---|
| 1 | Treats technique **presence** as proof | **Risk** (single distinctive technique could over-attribute) | **CR-6** — no attribution on a single technique; require combination/corroboration |
| 2 | Treats **rarity** as proof | **Risk** (same path) | **CR-4/CR-6** — rarity is a weight, not proof; explicit statement |
| 3 | Produces **fake probabilities** | No, but `support(h)` could be *mis-shown* as % | **CR-1** — forbid rendering support/`D` as probability/percentage |
| 4 | **Conflates** likelihood & confidence | No (structurally separate); verified by orthogonality test | none (keep the test) |
| 5 | Rewards **quantity over quality** | **YES — real defect** (summation lets many low-`D` items accumulate; favors rich profiles) | **CR-1** — dominance by top discriminating evidence + normalize by profile breadth; don't let near-zero terms sum to a win |
| 6 | **Double-counts correlated evidence** | **YES — real defect** (multiple rules on one behavior → repeated assertions for one technique) | **CR-1** — de-duplicate: causally-related observations of the same technique contribute **once**; define evidence independence |
| 7 | Treats **missing = negative** without coverage | No — explicitly correct (D7/D8, §9) | none (this is a strength) |
| 8 | **Forces attribution** when insufficient | No — decision rule + null | strengthened by **CR-2** (null absolute floor) |
| 9 | **Silently favors famous groups** | **YES — real residual risk** (reporting bias + profile richness + quantity) | **CR-4/CR-7** — weaken `D`, normalize by profile size, bias to abstain, state the bias openly |
| 10 | Depends on a **fixed actor list** | No | reinforced by **CR-3** (full universe; diagnosticity-only display pruning) |
| 11 | **Circular validation** (test against the same ATT&CK used to generate hypotheses) | **YES — real risk** (corpus derived from ATT&CK-based tooling) | **CR-8** — require independent/real-incident cases; separate pipeline-correctness from attribution-generalization; document the ceiling |

**Five genuine defects found** (#5, #6, #9) plus **two risks needing hardening** (#1/#2, #8, #11). None
require redesign; all are fixable within the existing architecture.

---

## F. Required corrections (applied to the methodology docs in this pass)

| ID | Correction | Applied to |
|---|---|---|
| **CR-1** | `support(h)` must be **dominated by top discriminating evidence**, **normalized by candidate profile breadth**, with **correlated evidence de-duplicated** (one behavior contributes once); `support`/`D` **never** shown as a probability/percentage. | [07 §4](07-attribution-scoring-spec.md), [06 §7/§Uncertainty](06-evidence-model.md), ADR D16 |
| **CR-2** | Define the **`Unattributed` null hypothesis support as an absolute coincidental-overlap floor**; a named candidate must exceed it on *distinctive* fit or the null wins (protects new/unseen/under-represented actors). | [07 §5/§11](07-attribution-scoring-spec.md), ADR D17 |
| **CR-3** | State the **candidate universe = full pinned group+campaign set**; any display-time pruning is **by diagnosticity, never prominence**; full set retained internally; examples are illustrative, not a configured list. | [07 §3](07-attribution-scoring-spec.md), ADR D18 |
| **CR-4** | **Weaken `D`'s claim** to "documentation-relative separation weight, not a probability or real-world rate, subject to reporting bias"; **rarity ≠ proof**; extend prevalence/`D` to **software**. | [07 §1/§2](07-attribution-scoring-spec.md), [06 §7](06-evidence-model.md), ADR D19 |
| **CR-5** | **Combination/sequence caveat:** group profiles are unions over intrusions; profile co-occurrence ≠ single-attack combination; sequence data is sparse → **sequence matching low-weight + flagged**. | [07 §1/§4](07-attribution-scoring-spec.md) |
| **CR-6** | **No attribution on a single technique** regardless of `D`; require a distinctive **combination** or independent corroboration; single-technique leads are capped and routed to insufficient/low-confidence. | [07 §11](07-attribution-scoring-spec.md), ADR D20 |
| **CR-7** | **Reporting-bias / imitation mitigations:** normalize behavioral-consistency by profile size; **confidence may not be "high" on TTP overlap alone** without independent corroboration; output says **"consistent with," never "is"**; bias toward abstention when a lead rests on profile richness. | [07 §6/§10](07-attribution-scoring-spec.md), ADR D21 |
| **CR-8** | **Circular-validation mitigation:** corpus must include **independent/real-incident** cases not derived from ATT&CK tooling; separate *pipeline-correctness* tests from *attribution-generalization* tests; document the generalization ceiling. | [08](08-validation-and-calibration.md) |

---

## G. Final recommendation

### ACCEPT WITH MODIFICATIONS

**Rationale.** The methodology's **skeleton is sound and survives the stress test**: ACH comparison, the
two-axis (likelihood/confidence) separation, evidence-first candidate generation, the mandatory
`Unattributed` null, coverage-aware contradiction, and the explicit insufficient-evidence decision rule all
behave correctly across the eight scenarios and the failure-mode battery. No structural redesign is needed.

However, the test found **three genuine defects** — quantity-over-quality via summation (E-5),
double-counting of correlated evidence (E-6), and residual famous-group bias (E-9) — plus **risks** around
single-technique/rarity over-attribution (E-1/E-2), an under-defined null floor (E-8, critical for
Scenario 8), and circular validation (E-11). These are real and would have produced misleading attributions
if frozen as-is. They are corrected in §F (CR-1…CR-8), applied to the methodology docs, and reflected as new
PROPOSED decisions in ADR-0002.

**Honest residual limitations** (documented, not "solved"): deliberate **behavioral imitation** can mislead
any TTP-based attributor; `D` remains a **reporting-biased heuristic**, not a statistic; and validation faces
a **generalization ceiling** until independent incident data is included. The methodology's response to all
three is the same and is correct: **prefer abstention, cap confidence, and frame every result as "consistent
with," never proof.**

**ADR-0002 remains PROPOSED.** With CR-1…CR-8 applied, it is ready for your acceptance decision; nothing here
is frozen and no implementation has begun.
