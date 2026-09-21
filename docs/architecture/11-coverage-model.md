# 11 — Coverage Model (CoverageProfile construction under pinned ATT&CK v19)

**Status:** Methodology-locked (2026-09-21). Implementation-facing specification for Phase-3 prerequisite **B3**.

**Relationship to the ADRs.** This document is the authoritative construction specification the
final-architecture review (`docs/architecture/10-final-architecture-review.md`, milestone **M3** /
checklist **C2.1**) required before Phase 2/3 and that did not previously exist. It operationalises the
`CoverageProfile` / `CoverageState` contract defined in **ADR-0005 §D2** and cross-referenced by **ADR-0005
Amendment C (2026-09-21)**, and it pins the vocabulary of **ADR-0006** `CalibrationCase.coverage_assumptions`
(**ADR-0006 Post-acceptance clarification, 2026-09-21**). It changes no accepted ADR decision and introduces no
scoring. Where it deviates from ADR-0005 §D2's original wording (the legacy `x_mitre_data_sources` field), that
deviation is recorded, dated, and explained here and in ADR-0005 Amendment C; the original §D2 text is preserved
intact.

---

## 1. Purpose and scope

This document defines exactly how a `CoverageProfile` is **constructed** for one
`(CorrelationGroup, technique)` pair (ADR-0005 §D2), from the pinned ATT&CK knowledge base and the case's own
telemetry facts, in the Phase-3 prerequisite gate **B3 (P3)**.

**In scope:** the canonical coverage vocabulary; the deterministic derivation of `data_sources_required`; the
meaning and source of `data_sources_available`; the four-state decision rule; fail-closed/unknown behaviour;
active-object and determinism requirements; the anti-circularity boundary; identity/versioning.

**Out of scope (explicit non-goals — see §12):** attribution scoring, likelihood, confidence, WEP, abstention,
G3.6, candidate generation, ACH, calibration fitting, `calibration_version`, and any telemetry-to-ATT&CK
availability mapping.

This document defines *construction* only. How a constructed `CoverageProfile` is **consumed** (contradiction /
coverage-gap wiring) is already fixed by ADR-0005 §D11 and is not re-decided here.

---

## 2. ATT&CK v19 canonical vocabulary

The pinned knowledge base is **`enterprise-attack-19.0`**. The canonical coverage vocabulary — the string values
that populate `data_sources_required`, `data_sources_available`, and `CalibrationCase.coverage_assumptions` — is:

> **active `x-mitre-data-component` object names.**

Rationale (verified against the pinned bundle):

- **Legacy `attack-pattern.x_mitre_data_sources` is absent.** In `enterprise-attack-19.0` **zero** techniques
  carry an `x_mitre_data_sources` (or any `data_source*` / `data_component*`) field. ADR-0005 §D2's original
  "already present on the raw `attack-pattern` STIX objects" mechanism reflects a pre-v17 ATT&CK representation
  and does not exist in the pinned data.
- **`x-mitre-data-source` catalog objects are orphaned.** The 38 `x-mitre-data-source` objects (e.g. "Windows
  Registry", "Pod") have **no relationship or reference to any technique** in v19 and carry no
  `x_mitre_data_source_ref` linkage on data-components; they are therefore not a usable technique-linked
  required vocabulary.
- **Analytic log-source `name` / `channel` values are collector-specific** (e.g. `WinEventLog:Security`,
  `auditd:SYSCALL`, with `EventCode=4768`-style channels) — unstable, SIEM-specific, and further from the ADR's
  "data source/component" concept.
- **Data-components are the technique-linked observability unit.** They are the only telemetry-granularity
  ATT&CK objects reachable from a technique in v19 (via the detection graph, §3), and 93% of active techniques
  resolve to at least one; the ADR field is itself named "data source/**component**". Data-component names
  (e.g. "Process Creation", "WMI Creation", "Network Connection Creation") are the selected canonical unit.

No new ontology is invented: the vocabulary is an existing ATT&CK object type's `name`.

---

## 3. Required data-component derivation (`data_sources_required`)

For a technique `T` (an `attack-pattern` STIX id), `required(T)` is the set of **active** data-component names
reachable through the pinned v19 detection graph:

```
T  (attack-pattern)
   ← detects                       (relationship; source = detection-strategy, target = T)
detection-strategy  (x-mitre-detection-strategy)
   → x_mitre_analytic_refs
analytic  (x-mitre-analytic)
   → x_mitre_log_source_references[].x_mitre_data_component_ref
data-component  (x-mitre-data-component)
   → name
```

Derivation rules (all mandatory):

- **Pinned `AttackKnowledge` only.** No network, no "latest ATT&CK" lookup, no fallback to any other KB version.
- **Active filtering at every hop.** The technique, the detection-strategy, the analytic, and the data-component
  must each be active (neither `revoked` nor `x_mitre_deprecated`), using the existing `is_active` semantics
  (the same active-object policy accepted for P2). An inactive object at any hop contributes nothing.
- **Dangling references fail closed.** An `analytic_ref` / `x_mitre_data_component_ref` that does not resolve in
  the pinned KB is skipped; it never raises and never fabricates a value.
- **Deterministic output.** `required(T)` is returned as a **sorted, de-duplicated tuple** of data-component
  names — independent of dict/set/filesystem iteration order and `PYTHONHASHSEED`.
- **No mutation.** The KB is never modified.
- **Empty is a valid result.** If no active data-component resolves (≈7% of active techniques, predominantly
  Reconnaissance / Resource-Development techniques that are inherently not host-observable), `required(T) = ∅`,
  which drives `UNKNOWN` (§5).

Sub-technique handling (rollup to a parent technique's data-components) is **not** part of this lock; B3 resolves
each technique id on its own. Any parent/child rollup is a deferred, separately-accepted refinement.

---

## 4. Available data-components (`data_sources_available`)

`data_sources_available` is an **explicit input** to the construction function — never inferred inside it. It is a
tuple of canonical data-component names (§2). Two paths supply it, and only these two:

- **Production:**
  ```
  available_data_components = ()
  ```
  until an independently approved telemetry-to-ATT&CK availability mapping exists (§6). Production construction
  callers pass the empty tuple.

- **Calibration:**
  ```
  available_data_components = CalibrationCase.coverage_assumptions
  ```
  provided those declared values use the canonical data-component vocabulary (§2, §7).

The construction function does not know or care which path it is on; it consumes only the tuple it is given. This
keeps the calibration/production separation a property of *who calls it with what*, not a branch inside coverage
logic (§7).

---

## 5. Coverage state semantics

Let `observed` be true iff the `CorrelationGroup` has an **active** `Evidence` whose `attack_ref` resolves to
`T` (the existing observed-technique signal). Let `required = required(T)` (§3) and `available` be the supplied
set (§4). The four-state decision is exactly:

| `observed` | `required` | `required ∩ available` | → `CoverageState` |
|:----------:|:----------:|:----------------------:|:------------------|
| present    | (any)      | (any)                  | `OBSERVED_PRESENT` |
| not present| `≠ ∅`      | `≠ ∅`                  | `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` |
| not present| `≠ ∅`      | `= ∅`                  | `NOT_OBSERVABLE` |
| not present| `= ∅`      | (n/a)                  | `UNKNOWN` |
| not present| indeterminate / malformed / unresolved availability | (n/a) | `UNKNOWN` |

"Adequate coverage" is defined **binarily**: coverage is adequate for `T` iff `required ≠ ∅` **and**
`required ∩ available ≠ ∅` (at least one required data-component was collectable). **No thresholds, percentages,
weights, or per-technique exceptions are introduced** — this is faithful to §D2's categorical four-value model,
which deliberately excludes any continuous coverage percentage. This is an honest approximation (a DeTT&CT-style
"is the required telemetry present at all"), documented as such.

---

## 6. Production fail-closed policy

Production currently constructs coverage with `available = ()` (§4). The consequences are deliberate and
protective:

- **`source_type` is opaque by architecture.** `SourceRef.source_type` is defined (gate G0.3) as an opaque
  adapter label "never interpreted here". Deriving ATT&CK data-components from it would fabricate interpretation
  the domain layer deliberately avoided.
- **No heuristic `source_type` / ECS → ATT&CK mapping is permitted** in B3. No inferred availability is allowed.
- **No false contradictions.** With `available = ()`, `required ∩ available` is always empty, so production can
  **never** emit `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` and therefore coverage **never lowers likelihood** in
  production. Non-observed techniques resolve to `NOT_OBSERVABLE` (`required ≠ ∅`) or `UNKNOWN` (`required = ∅`),
  which lower **confidence only** (ADR-0005 §D11).
- **No false confidence.** Absent telemetry is never treated as positive/adequately-absent evidence; it always
  fails closed.
- **Amendment B allowance.** ADR-0005 Amendment B (Rev 3) preconditions for G3.6 explicitly permit "a
  `CoverageProfile` construction path exists (§D2), *or* G3.6 explicitly scopes confidence to fail closed on
  absent coverage." Production fail-closed availability satisfies this while still emitting real
  `OBSERVED_PRESENT` / `NOT_OBSERVABLE` / `UNKNOWN` states.

A future production telemetry-to-ATT&CK availability mapping (`{source_type, ECS event metadata} → data-component
names`) is a **separate, independently-accepted methodology / data-artifact task** — a versioned, reproducible,
research-validated mapping — and is explicitly **not** created by B3 or by this document.

---

## 7. Calibration separation

The calibration and production paths share the construction function and the canonical vocabulary, but their
availability inputs are strictly separated:

```
CALIBRATION:
    labeled case → declared coverage_assumptions (canonical data-component names)
                 → available → CoverageProfile   (all four states reachable)

PRODUCTION:
    real telemetry → no approved mapping currently exists
                   → available = ()
                   → fail-closed CoverageProfile  (only PRESENT / NOT_OBSERVABLE / UNKNOWN)
```

**Calibration declarations must never become production telemetry evidence.** The only calibration path that can
produce `OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` (and hence a coverage-driven contradiction) is one where a human
authored `coverage_assumptions` for a labeled case. Because `available_data_components` is a caller-supplied
argument and production callers pass `()`, there is no code path by which a declared calibration value reaches a
production construction. This is the anti-leak boundary.

---

## 8. Anti-circularity boundary

`CoverageProfile` construction **MAY read**:

- the pinned ATT&CK detection graph (technique ↔ detection-strategy ↔ analytic ↔ data-component);
- technique identity (`technique_stix_id`);
- technique observation **presence** (`Evidence.attack_ref` resolving to the technique);
- telemetry **availability** (the caller-supplied data-component set / sensor coverage).

`CoverageProfile` construction **MUST NOT read**:

- candidate generation or candidate sets;
- `g(x)`, `g(C)`, `D(x)`;
- ACH matrix results;
- attribution hypotheses;
- likelihood, confidence, WEP, abstention;
- `AttributionResult` or any final attribution decision.

Coverage is an **independent observability / contradiction input** computed *before* and *independently of*
ranking. For an observed technique it adds no second signal beyond the `Evidence` that already supports it; its
only additional discrimination is distinguishing *absent-with-coverage* (contradiction) from *absent-without-
coverage* (gap), which is §D2/§D11's stated purpose — not an attribution signal.

---

## 9. Active / deterministic requirements

Any B3 (P3) implementation MUST:

- consider **active techniques only**;
- traverse **active detection-strategies only**, **active analytics only**, **active data-components only**;
- treat revoked / deprecated objects at any hop as contributing nothing;
- skip **dangling / unresolved references** fail-closed (never raise, never fabricate);
- operate on the **pinned `AttackKnowledge` only** — no network;
- produce **deterministic, sorted, de-duplicated** outputs;
- be **`PYTHONHASHSEED`-independent** (no reliance on dict/set/filesystem iteration order);
- **never mutate** `AttackKnowledge`.

These reuse the accepted P2 active-object semantics (`is_active`) rather than defining a second notion of
"active".

---

## 10. Versioning / identity

- `CoverageProfile.coverage_id` is composed by the **existing** `compute_coverage_profile_id(group_id,
  technique_stix_id)` contract (ADR-0005 §D2). No new hashing/versioning scheme is introduced.
- Every `CoverageProfile` stamps `attack_kb_version` (the pinned bundle whose detection graph was traversed), so
  a coverage fact is reproducible and only interpreted against the KB version that produced it. A KB version
  change re-derives coverage (a pure, deterministic function).

---

## 11. Failure / unknown behaviour

All failure modes fail closed, per the locked methodology:

| Condition | Behaviour |
|---|---|
| unknown / non-`attack-pattern` `technique_stix_id` | fail closed — construction rejects the input (`UnknownAttackEntityError`-class), never returns a state |
| inactive (revoked/deprecated) technique | contributes no requirements; treated as `required = ∅` → `UNKNOWN` for a non-observed technique |
| inactive detection-strategy / analytic / data-component | skipped at that hop; excluded from `required` |
| dangling `analytic_ref` / `data_component_ref` | skipped fail-closed |
| `required = ∅` (no derivable requirement) | `UNKNOWN` (never `NOT_OBSERVABLE`, never adequate-absence) |
| malformed / indeterminate availability | `UNKNOWN` |
| no approved production availability mapping | `available = ()` → non-observed techniques are `NOT_OBSERVABLE` or `UNKNOWN`, never adequate-absence |

`UNKNOWN` is treated identically to `NOT_OBSERVABLE` downstream (ADR-0005 §D11): it lowers confidence only and is
never assumed present or adequately absent.

---

## 12. Explicit non-goals

This document does **not** define, and B3 does **not** implement:

- attribution scoring, likelihood, confidence, WEP, abstention;
- G3.6 decision support, separation-from-null, contributor separation, concentration;
- candidate generation, ACH, comparative-analysis mathematics;
- calibration fitting, `calibration_version`, golden-corpus data;
- blind-actor ablation, §D18 validation metrics;
- any telemetry-to-ATT&CK availability mapping;
- any frontend.

B3 constructs the `CoverageProfile` contract so those later, separately-gated stages can consume it — nothing
more.
