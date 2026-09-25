# 15 — Calibration corpus v2 design (resolves Stage-5 findings F5-1..F5-4)

**Status:** ACCEPTED (2026-09-24, owner accepted all §8 decisions as proposed, DC-1 as superseded by ADR-0007) — design only. DC-1 is now specified in full by
[ADR-0007](adr/0007-detection-content-and-predicate-language.md) (ACCEPTED), which supersedes DC-1's scope
bullet; wherever DC-1 below and ADR-0007 differ (scope, revoked-ID handling, operators), ADR-0007 governs. No code, rules, fixtures, datasets, or ADR changes are made by
this note. Owner decisions are listed in §8. Corpus v1 (`data/calibration/corpus/v1/`) stays frozen and unmodified.

**Why this exists.** The Stage-5 harness ([14 §Stage 5](14-c3.2-corpus-build.md)) ran v1 through the real engine
and found it cannot support fitting (ADR-0006 F-3 "insufficient data → fail closed"):

| Finding | Observed on v1 |
|---|---|
| F5-1 | Actor labels are synthetic (`EMU-*`); candidates are ATT&CK Groups → ranking retention has no ground truth |
| F5-2 | Top-candidate `concentration` = 1.0 in every case → nothing to fit `τ_concentration` on |
| F5-3 | Two calibration/held-out pairs have identical decision features → held-out gate not independent |
| F5-4 | Both negatives have 0 features → no hard negative for `τ_separation` |

---

## 1. Root cause (fact, verified 2026-09-24 against the loaded KB and rule packs)

The whole detection layer maps to **five** ATT&CK techniques, all very common across the 174 active v19.0 Groups:

| Rule (core pack) | Technique | Active Groups using it | `g` |
|---|---|---|---|
| encoded PowerShell | T1059.001 PowerShell | 85 | 0.489 |
| procdump LSASS | T1003.001 LSASS Memory | 44 | 0.253 |
| rundll32 JS proxy | T1218.011 Rundll32 | 26 | 0.149 |
| Office spawns cmd | T1059.003 Windows Command Shell | 73 | 0.420 |
| PowerShell ingress | T1105 Ingress Tool Transfer | 86 | 0.494 |

The calibration extension pack adds two rules with **no** technique mapping (evidence-type coverage only).

So every case, however it is authored, can express at most a subset of five common techniques. That — not the
annotations — is why cases have 1–2 features, 53–151 candidates, and degenerate concentration. **No corpus
redesign fixes F5-1..F5-4 without real detection content first.** This is the prior version's failure mode
("weak relationships between telemetry and techniques") showing up at the calibration layer, and it is the
still-open architecture question **Q4 (detection-content strategy)** from
[05](05-architecture-open-questions.md), deferred since Phase 0 (doc 13 CL-1).

Distinguish: *fact* = the table above; *decision* = everything in §2–§6.

---

## 2. DC-1 — Detection content: import a pinned SigmaHQ subset (resolves Q4 for v1 scope)

**Proposal.** Follow ADR-0001 D12's accepted license split and use **SigmaHQ rules (DRL 1.1)** as the
redistributable content source, imported into our existing JSON `DetectionRule` format by a **restricted,
fail-closed importer**. Elastic prebuilt rules (ELv2, EQL/KQL) stay the fallback and are not used for the corpus.

- **Pinned source.** One tagged SigmaHQ release, SHA-256-pinned at acquisition (same discipline as the ATT&CK
  bundle, doc 11). DRL attribution in a `NOTICE` beside the imported pack and in each rule's `rule_source`.
- **Parsing.** pySigma (LGPL-2.1, verified in research 03) used **only to parse** Sigma YAML into its rule model —
  no backend, no query conversion. We translate the parsed model into our `FieldCondition`s.
- **ATT&CK mapping.** From the Sigma rule's own `attack.tXXXX` tags, each resolved against pinned v19.0.
  Unknown/revoked/deprecated IDs → the rule is rejected, never silently remapped. `mapping_source = "sigma"`,
  `mapping_basis` = the Sigma rule id + title. Nothing hand-mapped.
- **OR handling.** Our engine is AND-only by design (rules.py: "a behavior needing OR is better expressed as two
  separate rules"). The importer expands a Sigma condition into disjunctive normal form → one of our rules per
  conjunct, all sharing the Sigma rule id. Rules whose DNF exceeds a fixed bound are rejected.
- **Supported subset.** Selections with field equality / `contains` / `startswith` / `endswith` and Sigma's
  default case-insensitivity; `1 of` / `all of` / `and` / `or` / `not` only where `not` is over a single field
  that can be expressed. **Rejected (reported, never approximated):** `re`, `cidr`, `base64offset`, `windash`
  where not expandable, correlation/aggregation rules, keyword-only (fieldless) searches.
- **Field mapping.** Sigma Windows/Sysmon field names → our ECS-aligned `field_path`s via one explicit,
  versioned table (e.g. `Image` → `process.executable`, `CommandLine` → `process.command_line`). Unmapped
  field → rule rejected. Known gap (fact): our `Process` entity has `parent_name` but no parent executable
  path, so `ParentImage|endswith: '\x.exe'` maps only when the value reduces to a bare basename; anything else
  is rejected until a deliberate `Process` contract extension (decided in ADR-0007, not assumed here).
- **Scope — SUPERSEDED by ADR-0007 D1 (2026-09-24, owner: the platform must handle all ATT&CK Groups and
  techniques).** The earlier "import only rules the chosen plans need" is withdrawn: the **whole eligible
  generic Sigma set** is imported for production detection, and a per-technique / per-Group coverage report
  measures full-universe reach. The corpus uses whatever subset its scenarios exercise; corpus work never
  narrows production detection.

**Prerequisite: predicate-language extension.** Sigma needs `startswith`, `endswith`, and case-insensitive
matching; our four operators (`equals`/`contains`/`in`/`exists`, case-sensitive) cannot express it faithfully.
rules.py says to extend deliberately, never speculatively — this is that deliberate extension, and it changes
the `MATCH_OPERATORS` contract, so it needs its own ADR (**ADR-0007**, §7 T1). Existing rules keep their current
case-sensitive semantics; case-insensitivity is an explicit per-condition flag, not a global change.

---

## 3. DC-2 — Actor labels and the ranking-retention rule (resolves F5-1)

- Attributable cases are labelled with the **real ATT&CK Group the emulation plan emulates** (e.g. "APT29"),
  `actor_label_source = emulation-plan`. The label comes from the plan's own provenance, never from ATT&CK
  `uses` (ADR-0006 §D6/§D9).
- **Evaluation rule (for the fitting objective's ranking term):** a case's label resolves to one ATT&CK Group
  STIX id by **identity resolution only** — the KB's name/alias lookup (`resolve_alias`), which uses no
  `uses` relationship. A ranking "hit" = the top-ranked **Group** candidate's `actor_ref` equals that id.
  Campaign candidates never count as the actor (Amendment B §B6). An ambiguous or unresolvable label fails
  closed: the case is excluded from ranking metrics and kept for abstention metrics (§D7 pattern).
- No `CalibrationCase` contract change: `actor_label` stays an authored string; resolution happens at
  evaluation time against the same pinned KB, and the resolved id is recorded in the evaluation output.

**Circularity (stated, not hidden).** Public emulation plans are built from the same CTI reporting ATT&CK's
Group pages cite. A plan-derived case ranking its own Group first therefore partly measures agreement between
two views of the same reporting — the ADR-0006 §D11 documentation-relative ceiling applies to every ranking
number. The anti-circular test remains the **blind-actor KB-ablation** (§D10): the emulated Group is removed
from the KB and the engine must return `Unattributed`, not the nearest famous Group.

---

## 4. DC-3 — Data sources

| Source | What | License | Kind | Use |
|---|---|---|---|---|
| **S1** | Synthetic fixtures authored step-by-step from **CTID Adversary Emulation Library** full plans (verified 2026-09-24: APT29, Blind Eagle, Carbanak, FIN6, FIN7, menuPass, OceanLotus, OilRig, Sandworm, Turla, Wizard Spider) | Apache-2.0 | `synthetic` (template + seed) | calibration + held-out |
| **S2** | **OTRF Security-Datasets** `compound/apt29` — real host telemetry from a replication of MITRE ATT&CK Evaluations Round 2 APT29 (day 1 ≈ 367 MB, day 2 ≈ 1.6 GB zips; mostly Sysmon, plus Security/PowerShell/WMI) | MIT | `replay` | blind-actor holdout only |
| **S3** | Hard negatives: CTID **micro** emulation plans (behaviors "common across multiple threat actors": e.g. AD enumeration, log clearing, named pipes, process injection) + benign admin activity | Apache-2.0 | `synthetic` | calibration + held-out negatives |

- **S1 authoring rule.** Each fixture reproduces the plan's documented procedure for Windows-endpoint steps as
  ECS-aligned records that go through the unmodified adapter → detection → correlation → sequence pipeline.
  Expected-output shape is authored from the plan. Steps with no Windows-endpoint telemetry are omitted and the
  omission is recorded in `coverage_assumptions`, not faked.
- **S2 handling.** Too large to vendor: acquisition script + pinned SHA-256 + local cache outside git, same
  "capture hash at acquisition" rule as doc 11. Replayed through the existing Sysmon adapter.
- **S3 labels.** `unattributable_by_design`, expected `insufficient_evidence`: these behaviors are chosen
  *because* many actors share them. This is exactly the population `τ_separation` must reject (F5-4).
- **No live emulation** in this step. Running CALDERA/Atomic on an isolated VM (doc 12 safety rule) is a later,
  optional upgrade that would turn S1-style cases into `emulated` cases.

---

## 5. DC-4 — Families, splits, blind actor

- **Family (ADR-0006 §D5):** one family per *(plan, scenario)* — e.g. APT29 scenario 1 and scenario 2 are two
  families; reruns/seeds of the same template stay in one family.
- **Multiple attribution units per family.** Real plans produce several correlation groups (hosts/process
  trees). The v1 builder's "one family, one case" first-slice constraint must be lifted (the general mapping
  its own docstring defers). All units of a family share its split. Partial-visibility variants of a scenario
  are units of the same family, never new families. This is also what gives concentration real variation
  (F5-2): units with 3–6 features alongside sparse ones.
- **Blind actor = APT29.** S2 gives two independent real-telemetry families; the S1 APT29 plan families join the
  blind population too, so **no APT29 material is ever in calibration**. A second, S1-only blind actor is chosen
  at authoring time.
- **Imitation** (§D19): one plan's distinctive procedure reproduced under another actor's label, kept as its own
  family. Identical decision features across splits are permitted **only** for declared imitation families.

---

## 6. DC-5 — Fitting-readiness gate (fail-closed validator)

A new read-only validator, run on the corpus + Stage-5 harness output before fitting. Fitting refuses to start
unless it passes. **The numbers below are proposed minimums for the owner to confirm, not derived values.**

| Check | Proposed minimum |
|---|---|
| Calibration families | ≥ 12, attributable ones spanning ≥ 4 distinct actors |
| Held-out families | ≥ 8, same category coverage as calibration |
| Hard negatives (S3) | ≥ 3 families in calibration, ≥ 2 in held-out, each with ≥ 2 observed features |
| Multi-feature units | ≥ 30 % of attributable calibration units have ≥ 3 distinct decision features |
| Concentration spread | top-candidate `concentration` not constant across calibration units |
| Cross-split evidence identity | no calibration unit shares its exact decision-feature set with a held-out/blind unit, except declared imitation families |
| Label resolution | every attributable label resolves to exactly one active ATT&CK Group |
| Existing validators | category completeness, split/leakage, provenance — unchanged |

---

## 7. Work breakdown (one task per turn, in order)

| # | Task | Output |
|---|---|---|
| T1 | ADR-0007: detection content (Sigma import) + predicate-language extension — **drafted** | ADR, owner acceptance |
| T2 | Predicate extension (`startswith`, `endswith`, `case_insensitive`, `negate`, `has_element`) | code + tests |
| T3 | Sigma importer (full eligible generic set, DNF expansion, field map, tag→v19.0 resolution) + pinned SigmaHQ release + NOTICE | code + tests + import report |
| T4 | Full-universe coverage report (all 697 techniques, all 174 Groups); then choose plans/scenarios against it | report + plan selection |
| T5 | Builder: multiple units per family; cross-split identity + fitting-readiness validators | code + tests |
| T6 | Author S1 plan fixtures (several turns, a few plans each) | fixtures + annotations |
| T7 | Author S3 hard negatives | fixtures + annotations |
| T8 | S2 APT29 acquisition script + replay into blind population | script + hashes |
| T9 | Build v2, run Stage-5 harness + readiness gate, confirm F5-1..F5-4 resolved | doc 14 Stage 6 |

After T9: fitting grid / `fitting_procedure_version` → `fitting.py` → frozen `calibration_version` → G3.6.

---

## 8. Owner decisions needed

1. **DC-1:** Accept SigmaHQ (DRL 1.1) via a pySigma-parsed restricted importer as the detection-content source,
   with Elastic rules as fallback only? (Resolves Q4.)
2. **DC-1:** Accept the predicate-language extension, to be written up as ADR-0007?
3. **DC-2:** Accept real-Group labels from emulation plans + alias-only resolution as the ranking-hit rule, with
   the §D11 ceiling stated on every ranking number?
4. **DC-3:** Accept S1 (CTID plans, synthetic) + S2 (OTRF APT29, blind only) + S3 (micro plans, negatives)?
   S2 means downloading ~2 GB outside git.
5. **DC-4:** APT29 as the blind actor?
6. **DC-5:** Confirm or change the proposed readiness minimums.

---

## 9. Implementation record

**T5 — multi-unit builder, cross-split identity and fitting-readiness gate (2026-09-25).**

- *Multi-unit families (DC-4):* an annotation may declare `units`, each with `anchor_scenario_ids` (replay
  scenarios the unit must contain — group ids are content hashes an author cannot know in advance), its own
  expected-output shape, and unit coverage assumptions (added to the family's). The builder maps every
  produced correlation group to exactly one declared unit and fails closed when an anchor is unknown, yields
  no correlated evidence, or spans two units; when two units claim one group; or when a group is claimed by
  none (an undeclared unit means an incomplete annotation). An annotation without units keeps the single-unit
  contract, so **corpus v1 rebuilds byte-identically** (its existing tests unchanged). Builder method 0.2.
- *Decision inputs:* each case's own unit is selected by its frozen group/sequence ids (drift still fails
  closed); each family is replayed once; every `CaseDecisionInput` now carries `observed_features` — the unit's
  distinct observed decision features, the same candidate-independent set the `Unattributed` baseline uses
  (no second definition). Method 0.2.
- *Fitting-readiness gate (DC-5):* `calibration/readiness.py` — `validate_fitting_readiness` /
  `require_fitting_ready`, with the owner-accepted DC-5 minimums as `ReadinessThresholds` (echoed in the
  report). Checks: calibration families ≥ 12 spanning ≥ 4 resolved actors; held-out families ≥ 8; hard-negative
  families ≥ 3 / ≥ 2 (every unit ≥ 2 observed features); ≥ 30 % of attributable calibration units with ≥ 3
  features; top-candidate concentration not constant; no calibration unit with exactly the observed-feature
  set of a held-out/blind unit unless a family is declared `deliberate_imitation`; every attributable label
  resolves to exactly one active Group by alias only; category, split and provenance reports valid **and tied
  to this corpus version** (a report built without the manifest is refused). Defined choices, stated: top
  candidate = greatest `decision_support` (floor-independent, ties by id), concentration at an explicit floor
  (default the structural bound 1).
- *Validation:* run on the frozen v1 corpus, the gate **independently rediscovers all four Stage-5 findings** —
  unresolvable `EMU-*` labels (F5-1), constant concentration (F5-2), cross-split identical feature sets outside
  the declared imitation families (F5-3), no hard negatives (F5-4) — plus the family-count shortfalls (7 / 7),
  and reports no existing-validator or missing-input problem. Relabelling one family "APT29" resolves by alias
  to G0016, as DC-2 designs. Multi-unit building is proven on real v1 content (two v1 fixtures merged replay to
  exactly the two groups they produce alone), with every fail-closed path tested. 18 tests.
- *Next:* T6 — author S1 plan fixtures from the CTID Adversary Emulation Library (Apache-2.0), a few plans per
  turn, mapped to the now-available Sysmon/PowerShell/Security telemetry and the Sigma pack.
