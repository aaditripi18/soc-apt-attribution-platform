# ADR-0007 — Detection Content (Sigma import) & Predicate-Language Extension

- **Status:** PROPOSED (2026-09-24)
- **Date:** 2026-09-24 (proposed)
- **Deciders:** project owner
- **Supersedes / superseded by:** —
- **Resolves:** open question **Q4** (detection-content strategy & conversion, [05](../05-architecture-open-questions.md)),
  deferred since Phase 0 ([13](../13-phase-0-implementation-plan.md) CL-1)
- **Related:** [ADR-0001](0001-evidence-graph-core-architecture.md) D5/D10/D12/D13 ·
  [ADR-0005](0005-attribution-engine-specification.md) §D3 · [ADR-0006](0006-calibration-corpus-and-versioning.md) §D9/§D11 ·
  [11 coverage model](../11-coverage-model.md) · [12 deployment & endpoint scope](../12-deployment-and-endpoint-scope.md) ·
  [15 corpus v2 design](../15-corpus-v2-design.md) · [research 03 detection engineering](../../research/03-detection-engineering.md)

> PROPOSED. Records how detection content enters the platform and how the rule predicate language grows to
> express it. Creates no code, rules, or packs. ADR-0001..0006 are unchanged; ADR-0001 D12 (license split) is
> implemented, not reopened.

## Context

**The platform goal is full-universe attribution** — any active ATT&CK Group, any technique, never a fixed
list (ADR-0002 CR-1/D15, stress test doc 09). The attribution engine already meets this: candidates, `g`/`D`,
profile breadth and the `Unattributed` baseline are computed over the whole pinned KB. **Detection is the
bottleneck.** Facts, measured 2026-09-24 against pinned Enterprise v19.0 and the repo's rule packs:

| Quantity | Count |
|---|---|
| Active Groups | 174 |
| Active techniques + sub-techniques | 697 |
| Techniques used by ≥ 1 active Group | 492 |
| …of those, listing the Windows platform | 361 |
| …of those, with no ATT&CK data component (not telemetry-observable per ATT&CK) | 35 |
| Group-used techniques not on Windows (largest: Resource Development 44, Reconnaissance 34) | 131 |
| **Techniques our detection rules map to today** | **5** (T1059.001, T1059.003, T1003.001, T1218.011, T1105) |
| Sysmon event types our adapter normalizes | 2 (Event ID 1 process create, 3 network connect) |

So evidence can only ever name ~1 % of the technique space, which is the root cause of the Stage-5 corpus
findings (doc 14 F5-1..F5-4) and a repeat, one layer down, of the prior version's "weak telemetry→technique
relationships" failure.

Observable coverage of a technique is the product of **three independent layers**, and each must be measured
separately or the gap is misattributed:

1. **Rule** — does any detection rule map to the technique?
2. **Translation** — can that rule be expressed faithfully in our predicate language?
3. **Telemetry** — does an adapter produce the Observation kind and fields the rule reads?

This ADR decides layers 1–2 and makes layer 3 a measured, planned gap. It does not claim a coverage figure
that has not been measured.

## Decisions

### D1 — Full-universe scope principle (binding)

- Detection content targets **all** of ATT&CK Enterprise v19.0. There is **no technique, tactic, or Group
  allowlist** anywhere in the importer, rule packs, or engine.
- **Corpus work never narrows production detection.** Doc 15's "import only rules the chosen emulation plans
  need" is superseded by this decision: the whole eligible Sigma set (D2) is imported; a corpus uses whatever
  subset its scenarios exercise.
- Coverage is **measured and published** (D9), per technique and per Group, never asserted.

### D2 — Source: pinned SigmaHQ generic rules (DRL 1.1)

- **Source:** one tagged SigmaHQ release (candidate at writing: `r2026-07-01`, 2026-07-09 — pinned, with
  archive SHA-256 captured **at acquisition**, never fabricated in advance, same discipline as doc 11).
- **Included:** the **generic ("core") rule set at `experimental`/`test`/`stable` status and `medium` level
  or above** — i.e. the Core++ package scope (Releases.md). Generic rules "match on attacker techniques",
  which is the kind of evidence the engine is designed to reason over.
- **Excluded for now (separate later decision):**
  - **Emerging-Threats rules** — they "match on patterns of specific threat actors or exploits". Evidence from
    a rule written from one actor's report would echo that actor's ATT&CK profile back at the engine (ADR-0006
    §D11 circularity, and CLAUDE.md "evidence-driven, not label-driven"). Revisit with an explicit
    circularity analysis.
  - **Threat-hunting rules** (investigation, not detection) and `low`-level rules (noise).
  - `deprecated` / `unsupported` status.
- **Elastic prebuilt rules** stay the ADR-0001 D12 fallback, not imported: ELv2, and EQL sequences / ES|QL
  exceed the single-Observation engine (rules.py Phase-1 boundary).

### D3 — ATT&CK mapping from Sigma tags (anti-circular)

- `attack.tNNNN[.NNN]` → resolved against pinned v19.0. If the ID resolves to a **revoked** object, follow
  ATT&CK's own `revoked-by` relationship (deterministic, KB-authoritative) and record that in
  `mapping_basis`; if it resolves to a **deprecated** object or does not resolve, drop that mapping and report
  it. Never hand-remap.
- `attack.sNNNN` (software) → the malware/tool object, a legitimate ADR-0005 §D3 feature.
- **`attack.gNNNN` (Group) tags are never mapped and never become evidence.** A rule author's actor label is
  not an observation. They are recorded as ignored in the import report.
- Tactic tags are ignored; tactics come from the technique via the KB.
- `mapping_source = "sigma"`; `mapping_basis` = Sigma rule id + title + the tag. A rule with no resolvable
  technique/software mapping is not imported (reported).
- **Limitation (stated):** a Sigma tag is the rule author's claim. The platform checks it resolves, not that
  it is semantically right. Later mitigation: fire the imported pack against technique-labelled datasets
  (e.g. OTRF Security-Datasets atomic sets) and report per-rule agreement.

### D4 — Predicate-language extension (deliberate, contract-changing)

rules.py limits the language to `equals`/`contains`/`in`/`exists`, case-sensitive, AND-only, no arrays, and
says to extend it deliberately. Faithful Sigma translation needs exactly these additions — nothing speculative:

| Addition | Why Sigma needs it | Semantics |
|---|---|---|
| `startswith`, `endswith` operators | `Image\|endswith: '\cmd.exe'` is the dominant Sigma idiom | string prefix/suffix |
| per-condition `case_insensitive: bool` (default `false`) | Sigma matching is case-insensitive by default | Unicode `casefold()` on both sides; applies to `equals`/`contains`/`startswith`/`endswith`/`in` |
| per-condition `negate: bool` (default `false`) | `selection and not filter` is in most Windows rules; dropping filters would make rules broader than their authors wrote | logical NOT of the condition; **an absent field under `negate` evaluates true** (Sigma's semantics: the positive match is false, so its negation is true) |
| `has_element` operator for array fields | scoping a rule to its Sigma `logsource` via ECS `event.category`/`event.type` (arrays the engine currently rejects) | true iff the array contains the value (exact; honours `case_insensitive`) |

- Rules remain **AND of conditions**. OR is still expressed as separate rules (the importer does this, D6).
- **Backward compatibility:** new keys default to the current behaviour; existing packs load and evaluate
  identically, and their content hashes are unchanged (regression-tested).
- `MATCH_OPERATORS` in `detection/contracts.py` and `MatchedField` gain the new operators and flags so every
  Evidence explanation still states exactly which predicate matched.

### D5 — Field and logsource mapping (source-agnostic)

- One explicit, versioned table (`sigma-field-map/1`) maps Sigma field names to our ECS-aligned
  `field_path`s (e.g. `Image` → `process.executable`, `CommandLine` → `process.command_line`,
  `DestinationIp` → `network.destination.ip`). An unmapped field ⇒ rule not imported (reported under
  "telemetry" gap, D9).
- `logsource` (`category`, e.g. `process_creation`, `network_connection`) maps to `has_element` conditions on
  `event.category` / `event.type`, **never** to Sysmon event IDs, keeping rules source-agnostic (doc 12 §D.1).
  A `logsource` with no mapping ⇒ rule not imported (telemetry gap).
- Known domain gap (fact): `ProcessRef` has `parent_name` but no parent executable path, and there are no
  registry, image-load, or script-block entities. Rules reading those fields are recorded as telemetry gaps
  until an adapter/domain extension (D10) adds them — the importer never approximates (e.g. never maps
  `ParentImage` onto `parent_name` unless the value is a bare basename that makes the match exact).

### D6 — Importer (build-time, deterministic, fail-closed)

- **pySigma (LGPL-2.1) parses Sigma YAML only** — its rule model and condition parse tree; no backend or
  query conversion. It is a **build-time tooling dependency**: the runtime loads the generated JSON pack and
  never imports pySigma. Exact pySigma version and API are pinned and verified when the importer is built.
- The condition tree is rewritten to **disjunctive normal form**; each conjunct becomes one of our rules
  (shared Sigma id, suffixed conjunct index). A rule whose DNF exceeds a fixed bound is rejected (the bound is
  a documented, reproducibility-frozen importer input).
- **Modifier support:** `contains`, `startswith`, `endswith`, `all`, `windash` (expanded to its finite
  variant set), `exists`. **Rejected, never approximated:** `re`, `cidr`, `base64`/`base64offset`,
  `utf16*`/`wide`, `lt`/`gt` family, `fieldref`, `expand` placeholders, keyword (fieldless) searches,
  Sigma correlation/aggregation rules.
- Evidence type: `behavioral` for all imported generic rules.
- Output: one generated pack JSON + import report, sorted and canonically serialized; same inputs ⇒
  byte-identical output (PYTHONHASHSEED-independent).

### D7 — Reproducibility and identity

The generated pack records: Sigma release tag + archive SHA-256, importer version, `sigma-field-map` version,
pySigma version, `attack_kb_version`, DNF bound. The pack is content-hashed like every existing pack, so any
change in any input changes the pack identity, and through it the calibration corpus identity downstream
(ADR-0006 §D12/§D13). A Sigma upgrade is a deliberate, diffed change — never a floating "latest".

### D8 — Licensing

DRL 1.1 attribution: a `NOTICE` beside the generated pack, each rule's `rule_source = "sigma:<rule id>"`,
and the Sigma `author` retained in `mapping_basis`. pySigma (LGPL-2.1) is used unmodified as a library.
Consistent with ADR-0001 D12.

### D9 — Coverage report (the full-universe measurement)

Generated with every pack, committed beside it. For **each of the 697 active techniques** (flagging the 492
Group-used ones), exactly one status:

| Status | Meaning |
|---|---|
| `covered` | ≥ 1 imported rule maps to it and its logsource/fields are produced by an adapter |
| `telemetry_gap` | a Sigma rule exists but needs an Observation kind/field no adapter produces |
| `translation_gap` | a Sigma rule exists but uses unsupported constructs (D6) |
| `no_sigma_rule` | no eligible Sigma rule maps to it |
| `not_endpoint_observable` | no ATT&CK data component, or only non-Windows platforms in v1 scope |

Plus, **per active Group**: profile size, count of profile techniques `covered`, and the list of uncovered ones.
This tells us, honestly, which Groups the platform can currently distinguish from endpoint telemetry and why the
rest cannot be — and it directs adapter work (D10) at the techniques that matter most.

### D10 — Telemetry-layer expansion is required and planned (not decided in detail here)

Full-universe coverage also needs more Observation kinds. Following doc 12 (source-agnostic adapters, Windows
first), the D9 report ranks `telemetry_gap` techniques by how many Groups use them; adapter/domain extensions
are then added in that order, each as its own small task (e.g. Sysmon image load, process access, file create,
registry, DNS; Windows Security process/logon events; PowerShell script block). Each extension changes a
source adapter and possibly a domain entity, never the attribution engine.

### D11 — Honest limits (recorded)

- **Pre-compromise techniques** (Reconnaissance, Resource Development) and non-Windows techniques are not
  observable from Windows endpoint telemetry. Groups known mainly for them cannot be distinguished from
  endpoint evidence; the engine must abstain, not guess. The D9 report makes this visible per Group.
- Sigma coverage of ATT&CK is uneven; its true extent is **unknown until D9 is run** — no figure is claimed
  here.
- Single-Observation rules only: multi-event Sigma correlation logic is out of scope (Phase-2 correlation
  already reasons across Observations).
- Imported rules carry no false-positive guarantee; the corpus measures machinery, not detection efficacy
  (ADR-0006 §D14).

## Consequences

**Positive:** evidence can name a large, measured share of ATT&CK instead of 5 techniques; detection content
becomes reproducible, licensed, and traceable to its source rule; the coverage gap becomes an explicit,
prioritised work list; the corpus v2 plan (doc 15) becomes feasible.

**Negative / costs:** a contract change to the detection layer (D4); a build-time pySigma dependency; a
translation layer to maintain; adapter work (D10) is substantial and ongoing; imported-rule noise must be
handled by the existing correlation/diagnosticity machinery, not by suppressing rules.

**Neutral:** the engine, ATT&CK loading, correlation, and calibration architecture are unchanged.

## Alternatives considered

- **Hand-written rules per technique** — does not scale to 697 techniques, and repeats "manually recreating
  existing security knowledge" (CLAUDE.md principle 8). Rejected.
- **Elastic prebuilt rules as primary** — ELv2 and EQL/ES|QL semantics beyond the single-Observation engine.
  Kept as fallback (ADR-0001 D12).
- **Import Sigma without filters / NOT** — makes rules broader than authored; unfaithful. Rejected.
- **Import only corpus-needed rules** (doc 15 original DC-1) — contradicts full-universe scope. Superseded by D1.

## Work order (implementation, each a separate reviewed task)

1. D4 predicate-language extension + regression tests (existing packs unchanged).
2. D5/D6 importer + `sigma-field-map/1` + pinned Sigma release + NOTICE + tests.
3. D9 coverage report over the generated pack.
4. D10 adapter extensions, in the order the report ranks them (ongoing).

Corpus v2 (doc 15 T5+) proceeds once steps 1–3 exist.

## Open questions for the owner

1. Accept the full-universe principle (D1) and Core++-scope generic Sigma as the source (D2), with
   Emerging-Threats deferred for circularity?
2. Accept the four predicate additions (D4), including "absent field under `negate` = true"?
3. Accept the coverage-report statuses (D9) as the way full-universe progress is measured and reported?
4. Accept that telemetry expansion (D10) is scheduled by the coverage report rather than fixed now?
