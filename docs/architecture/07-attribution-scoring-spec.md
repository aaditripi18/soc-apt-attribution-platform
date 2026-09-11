# 07 — Attribution Scoring Specification

**Status: PROPOSED** (specification; no code). The operational mechanics implementing
[ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md) over the entities in
[06 evidence model](06-evidence-model.md). Validation is in [08](08-validation-and-calibration.md).

**Guiding rule (repeated deliberately):** every quantity below has a stated *operational meaning* and a
*headless test*. Nothing exists to look sophisticated. Where we cannot justify precision, we use graded
bands, not decimals.

---

## 0. What we are computing, in plain terms

For an investigation we produce, per candidate actor, an answer to two separate questions:

- **Likelihood:** *relative to the other candidates*, how well does the observed behavior fit this actor's
  known behavior, giving most weight to evidence that actually distinguishes actors and subtracting for
  evidence that argues against?
- **Confidence:** independently, how much good evidence do we have, how complete was our telemetry, how well
  does it corroborate, and how much of it is in a regime we have actually validated?

We never merge these. We never emit an attribution unless a candidate clearly beats "Unattributed" with
adequate confidence.

---

## 1. Evidence evaluation factors (each defined operationally)

Every factor below is either **derived from the pinned KB** or **from detection/enrichment metadata** — none
is hand-assigned per actor.

| Factor | Operational definition | Source | Feeds |
|---|---|---|---|
| **Observation confidence** `Oc` | Reliability of *this* detection: rule fidelity (known FP propensity / rule maturity) × completeness of the matched events. Bands: high/med/low. | rule metadata, event completeness | confidence; caps a link's contribution |
| **Evidence reliability** | Grade of the evidence item itself (behavioral > evidentiary by default per ADR-0002). | evidence_type + Oc | confidence |
| **Source reliability** (enrichment) | **Admiralty** source-reliability (A–F) × info-credibility (1–6) for any TI/IOC input. | feed metadata | confidence; caps evidentiary links |
| **Technique/software prevalence** `g(x)` | Fraction of ATT&CK Groups (pinned KB) documented to use technique/**software** `x`. Factual about *documentation*, **not** real-world frequency (CR-4). | ATT&CK Group×{Technique,Software} | discriminating power |
| **Discriminating power** `D(x)` | A **documentation-relative separation weight** — how much consistency with `x` narrows the field of *tracked* groups. High when few groups use `x`, ~0 when most do. Derived from `g(x)` (and combination prevalence). **Not a probability, not a real-world rate, and subject to reporting bias** (CR-4). **Rarity is a weight, never proof** (CR-6). | computed from KB | likelihood weighting |
| **Relevance** `r(e,h)` | Does candidate `h` use the technique/software behind evidence `e` (per KB)? ∈ {consistent, inconsistent, unknown}. | ATT&CK `uses` | polarity of a link |
| **Temporal coherence** | Do the observations form a time-ordered progression consistent with an attack (kill-chain order), vs. random scatter? | observation timestamps | confidence; chain validity |
| **Contextual relevance** | Do targeting/victimology/sector context align with a candidate's known targeting? | contextual evidence + KB | supporting/contradicting (graded low — soft) |
| **Behavioral consistency** | Fraction of the candidate's *characteristic* behaviors present, and absence of behaviors it never uses. | feature vs KB profile | likelihood + contradiction |
| **Cross-technique / combination** | Diagnosticity of co-occurring technique *combinations* (more discriminating than single techniques). **Caveat (CR-5):** an ATT&CK group profile is a *union over many intrusions*, so profile co-occurrence only weakly implies single-attack combination; observed **sequence/order** matching is **low-weight and flagged** because reliable per-group sequence data does not exist. | KB co-occurrence (approximate) | likelihood weighting (dominant, but caveated) |
| **Campaign-level consistency** | Do the features match a known *campaign* profile (tighter than a group)? | ATT&CK Campaign data | likelihood; can raise specificity |
| **Supporting evidence** | Consistent + relevant evidence links. | links | likelihood (+) |
| **Contradicting evidence** | Inconsistent links + expected-but-missing (coverage permitting). | links | likelihood (−); confidence context |
| **Missing expected evidence** | Characteristic behavior absent where coverage was adequate. | KB profile × CoverageProfile | contradiction (if covered) / confidence gap (if not) |
| **Alternative explanations** | Other candidates or benign/deception explanations that also fit. | ACH set | uncertainty; confidence |
| **False-flag / deception** | Easily-planted evidentiary artifacts point one way while hard-to-fake behavior points another. | evidence_type split | confidence (−); alternative explanation |
| **Alias uncertainty** | Ambiguity in mapping observed indicators to a single tracked actor identity. | KB alias set | uncertainty |
| **Incomplete telemetry** | Required data sources for discriminating techniques were absent. | CoverageProfile | confidence (−); next-evidence |

---

## 2. The only "weights," and the seven required properties

The methodology has exactly one learned/derived weighting quantity — **discriminating power `D`** — plus
metadata-derived confidences (`Oc`, source grades). Per the ADR, we answer the seven required questions for
`D`:

1. **Why it exists:** to make *diagnostic* evidence count and *common* evidence not — the principled
   replacement for arbitrary points. Without it, ubiquitous techniques would dominate (the prohibited
   pattern).
2. **How derived:** solely from the pinned ATT&CK Group×{Technique,Software} matrix. `D(x)` is a
   **monotonically decreasing function of `g(x)`** (group-prevalence of the technique **or software**, CR-4).
   For combinations, from co-occurrence across group profiles (approximate — CR-5). **No per-actor
   hand-tuning.** `D` is a **documentation-relative heuristic, never a probability** (CR-4).
3. **How normalized:** `D ∈ [0,1]`; `D→0` as `g(t)→1` (all groups use it ⇒ zero discrimination); `D` higher
   as `g(t)` shrinks. The exact functional form is a **calibration-version parameter** (its *properties* are
   fixed here; its shape is fit, not guessed).
4. **How calibrated:** the functional form + any thresholds are fit on a **calibration split** of the corpus
   to maximize correct *ranking* and *calibration* (§6) — not to fit any single actor.
5. **How validated:** on a held-out split (§8 in [08](08-validation-and-calibration.md)); a change to `D`
   that improves one case but worsens calibration is rejected.
6. **How analysts inspect it:** every technique/combination shows its `g(t)`, the group count it came from,
   the KB version, and the resulting `D` — one click from any score. `D` is never a bare number on screen.
7. **Insufficient calibration data:** if the KB/corpus cannot support a stable `D` (e.g., too few groups, or
   a technique/combination unseen in the corpus), `D` falls back to a **neutral prior** and the affected
   assessment's **confidence is capped** and flagged "outside validated regime." We degrade to honesty, never
   to invented precision.

---

## 3. Candidate generation (evidence-first; full universe; no hard-coded answer)

**Candidate universe (CR-3):** the universe is the **entire pinned ATT&CK KB** — *all* `intrusion-set`
(group) and `campaign` objects (typically 150+ groups). There is **no configured or "supported" actor
list** anywhere in the system; the named groups in this spec's examples are illustrative only.

1. Collect the case's `TechniqueAssertion`s (supports-polarity) and any matched `Software`.
2. **Candidate set** = every ATT&CK Group/Campaign that `uses` ≥1 of those techniques or software (a
   recall-oriented net over the full universe; the ACH step, not this step, does the discrimination).
3. Always add the **`Unattributed` null hypothesis** (its support is defined in §5).
4. Collapse aliases to single candidates via the KB alias set.

**Display pruning (CR-3):** when the net is large, any pruning for presentation is **by diagnosticity
contribution only — never by prominence/fame**; the **full candidate set is always retained internally** for
the ACH math. Truncating to "top-N famous groups" is prohibited (it would re-introduce a fixed list and
famous-group bias).

This guarantees candidates arise **from evidence**. There is no path where the system names an actor first
and then searches for support (ADR-0002 D4). A test asserts that removing an evidence item can only *remove*
candidates, never leave a candidate with empty `generation_basis`.

---

## 4. ACH comparison (how candidates are compared)

Build the ACH matrix: rows = evidence items, columns = candidates (incl. `Unattributed`). Each cell is a
link with `role` (supporting/contradicting), `relevance`, and `diagnosticity D`.

**Per-hypothesis relative support** is assembled as a transparent, inspectable combination over
**independent, de-duplicated** evidence:

```
support(h) = Σ over independent supporting evidence:  D(x) · Oc(x) · relevance(x,h)
           − Σ over independent contradicting evidence: D(x) · Oc(x) · contradiction_strength(x,h)
```

subject to the following ACH-critical properties **and** the anti-bias corrections:

- **Non-diagnostic cancellation:** evidence consistent with *all* candidates has `D≈0` and/or cancels across
  columns — it cannot lift any hypothesis (this is what kills the "T1059 → +points" pattern).
- **Comparison is relative:** what matters is the **separation** between candidates, not any absolute total.
- **De-duplication of correlated evidence (CR-1):** multiple detections arising from the *same underlying
  behavior* (causally-related observations that assert the *same* technique) count **once**. "Independent
  evidence" = evidence from distinct behaviors/data sources. This prevents one behavior that trips several
  rules from being counted many times.
- **Dominance by discriminating evidence, not volume (CR-1):** `support(h)` must be **driven by its
  highest-`D` items**, not by summing many near-zero-`D` terms. A candidate may **not** win by matching a
  large *quantity* of common techniques. Operationally: the separation between candidates must be
  attributable to a small set of high-`D` (discriminating) evidence; if it is not, there is no real
  discrimination and the result trends to *insufficient*. (A concentration check — e.g., separation must
  survive when low-`D` terms are removed — is a calibration-version parameter.)
- **Profile-breadth normalization (CR-1/CR-7):** raw support is **normalized by the candidate's KB profile
  size** so that groups with large, richly-documented profiles cannot out-score others merely by having more
  `uses` edges to match against. Absolute match *count* is not rewarded; *distinctive* match is.

We deliberately do **not** call `support(h)` a probability, and it is **never rendered as a
percentage/score to the analyst** (CR-1). It is an internal **ordering statistic**; §5 maps
*ordering + separation* to a WEP band via calibrated thresholds.

**Answering the required analyst questions** falls out directly:

- *Why is A more consistent than B?* → the `DiscriminatingEvidence` where A is consistent and B is not (high
  `D` links separating them).
- *What argues against A?* → A's `ContradictingEvidence` (inconsistent links + covered expected-but-missing).
- *What would most reduce uncertainty?* → §7 next-evidence.

---

## 5. Likelihood construction (Axis 1)

- Rank candidates by `support(h)`.
- Convert to a **WEP band per candidate** using calibrated thresholds on **separation from the
  `Unattributed` baseline and from the next candidate** — not on the raw magnitude. Close scores ⇒
  overlapping bands ⇒ reported as "roughly even chance" between them (never a forced winner).
- Likelihood is explicitly **relative and comparative**; the result always shows the *field*, not a lone
  leader.

**The `Unattributed` null floor (CR-2 — critical).** `support(Unattributed)` is **not** zero; it is an
**absolute coincidental-overlap floor**: the level of support a candidate would attract *by chance* from
common/low-`D` overlap given the case's evidence. A named candidate therefore has to exceed **coincidental
overlap** on **distinctive** (high-`D`) evidence to beat the null. Consequences:
- If the best-fitting known group matches only a *fraction* of a distinctive combination (e.g., the true
  actor is absent/under-represented in the KB — Scenario 8), its distinctive support does **not** clear the
  floor and **`Unattributed` wins** → "does not match any tracked actor well."
- This is the primary defense against **forcing a known label onto an unknown actor** and against
  **famous-group partial matches** beating the truth. The floor level is a calibration-version parameter,
  fit so that genuine positives clear it and coincidental/partial matches do not.

**Operational meaning test:** if two candidates have near-equal, high support and no discriminating evidence
separates them, both must land at "roughly even chance," and the result must say so. If no candidate clears
the null floor, the result is *insufficient* (§11).

## 6. Confidence construction (Axis 2, independent)

Confidence is a **band (high/moderate/low)** derived from, and **bounded by the weakest of**:

- **Completeness/coverage:** did our telemetry (CoverageProfile) actually include the data sources for the
  *discriminating* techniques? Poor coverage ⇒ low confidence regardless of likelihood.
- **Evidence quality/reliability:** `Oc` and Admiralty grades of the load-bearing evidence.
- **Corroboration (Diamond breadth):** do independent evidence types agree (capability + infrastructure +
  victimology), or does everything rest on one technique?
- **Consistency:** temporal coherence + campaign consistency.
- **Contradiction load:** unresolved contradictions lower confidence.
- **Calibration availability:** is this case within the validated regime (§2.7)? If not, cap confidence.

**TTP-overlap / imitation cap (CR-7):** confidence **may not be "high"** when the lead rests **solely on
TTP overlap** without independent corroboration (infrastructure, victimology, or procedure-level evidence),
because behavioral **imitation** can manufacture TTP overlap. Likewise, when a lead is driven by a
candidate's **profile richness** rather than distinctive evidence (§4 normalization), the system **biases
toward abstention**. All analyst-facing output is phrased **"consistent with," never "is"** — attribution is
a judgment about consistency, not proof of identity.

**Orthogonality test:** the spec must produce (a) "likely, low confidence" (clear but thin) and (b) "roughly
even, high confidence" (rich but ambiguous) on the corresponding corpus cases. If it cannot, the two axes
have been wrongly coupled.

## 7. Next-evidence (uncertainty reduction)

For each **unobserved but checkable** discriminating technique/behavior, estimate how much observing it (or
confirming its adequately-covered absence) would change the **separation** between the top hypotheses. Report
the highest-impact item together with the **coverage gap** that currently blocks it (e.g., "enable Sysmon
EID 7 to observe T1574.002, which best separates A from B"). Operational, inspectable, and directly tied to
the coverage model — not a vague suggestion.

## 8. Uncertainty propagation

- Grades on observations/evidence propagate upward; an assertion/feature is **no stronger than its weakest
  necessary input**.
- Hypothesis **confidence is bounded by its weakest critical link** (thin basis caps confidence).
- Coverage gaps and alias ambiguity widen `uncertainty` and lower `confidence`; they never alter
  `likelihood`.
- Combination is via **conservative band rules**, never multiplication of invented independent
  probabilities. (E.g., "min-bound" the confidence band across critical links; do not "average away" a weak
  link.)

## 9. Missing telemetry

Handled in two distinct ways, never conflated:

- **Discriminating technique not covered:** lowers confidence + generates next-evidence. Likelihood
  unchanged.
- **Characteristic behavior absent *with* adequate coverage:** becomes **contradiction** for that candidate
  (expected-but-missing), which *does* lower its likelihood — because we looked and it wasn't there.

## 10. Deception, aliasing, alternatives

- **Deception:** if `DiscriminatingEvidence` for a candidate is dominated by **evidentiary** (easily-planted)
  artifacts while **behavioral** evidence points elsewhere, raise a **possible-deception alternative
  explanation** and cap confidence. Behavioral evidence outranks evidentiary in `D` by default.
- **Aliasing:** aliases pre-collapsed (§3); residual identity ambiguity recorded as `uncertainty`.
- **Alternatives:** the `Unattributed` hypothesis and benign explanations are always in the matrix; strong
  alternatives lower confidence in the leader.

## 11. Decision rule — attribute vs. "insufficient evidence"

Emit an actor attribution **only if all hold**:

1. Leading candidate's support **separation over the `Unattributed` floor** (§5) exceeds the calibrated
   `τ_separation`.
2. Leading candidate's **confidence ≥ `min_confidence`** (calibrated floor).
3. Leading candidate is **separated from the 2nd candidate** by ≥ `τ_margin`, *or* the result is explicitly
   reported as a **tie/competing set** (A and B, roughly even).
4. **Distinctive-basis requirement (CR-6):** the separation must be attributable to a **distinctive
   combination** or independent corroboration — **never a single technique alone**, regardless of its `D`.
   A lead resting on one technique is capped in confidence and routed to *insufficient / leaning-low-confidence*.

Otherwise → **`AttributionResult` = "Insufficient evidence for attribution,"** stating the missing
discriminating evidence, coverage gaps, and next-evidence. Detecting suspicious activity **never** forces
attribution (ADR-0002 D5). `τ_separation`, `min_confidence`, `τ_margin` (and the §5 null-floor level and §4
concentration check) are **calibration-version parameters** fit and validated in
[08](08-validation-and-calibration.md), inspectable and versioned — not magic constants.

---

## 12. Worked examples (illustrative; exact bands set by calibration)

**Example A — the prohibited pattern, corrected.** Case = only `T1059` (command interpreter), a technique
used by most groups (`g(t)` high ⇒ `D≈0`). Candidate set is large; no discriminating evidence; every
`support(h)` ≈ `support(Unattributed)`. **Result:** *Insufficient evidence* — "common technique only; no
discriminating behavior; coverage of discriminating data sources missing." Contrast the forbidden system,
which would have emitted "APT-X 87%."

**Example B — genuine discrimination.** Case = a rare sub-technique + a distinctive *combination/sequence*
that few groups exhibit (`D` high), plus matching campaign timing, adequate coverage, no contradictions.
`support(A)` separates clearly from `Unattributed` and from B; corroboration across capability + timing.
**Result:** A "likely–very likely," confidence "moderate–high," with the discriminating combination shown as
the reason and any residual alias/coverage caveats listed.

**Example C — ambiguous / competing.** Case features fit A and B nearly equally; the one technique that would
separate them is in an uncovered data source. **Result:** A and B "roughly even chance," confidence lowered
by the coverage gap, next-evidence = "enable <data source> to observe <technique>." No forced winner.

**Example D — possible false flag.** Behavioral evidence (hard to fake, high `D`) fits A; several IOCs
(easily planted, evidentiary) point to B. **Result:** leading hypothesis A on behavioral grounds, confidence
capped, explicit **possible-deception** alternative noting the B-pointing evidentiary artifacts — never a
silent attribution to B.

---

## 13. What is intentionally NOT in the methodology

- No additive per-actor/per-technique point tables.
- No single headline percentage; no internal merge of likelihood and confidence; **`support(h)` and `D` are
  never rendered as probabilities/percentages** to the analyst (CR-1).
- No claimed posterior probabilities `P(group|evidence)` (no reliable frequency data — §D9 of the ADR).
- **No attribution from a single technique**, however rare (CR-6); **no reward for quantity** of common
  evidence (CR-1); **no win by profile richness** (CR-1/CR-7).
- No treating `D` as truth about the real world — it is a documentation-relative heuristic (CR-4).
- No ML on the correctness path (deferred; optional + interpretable only).
- No attribution emitted below the calibrated decision rule (incl. the §5 null floor).
