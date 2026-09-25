# ADR-0007 — Detection Content (Sigma import) & Predicate-Language Extension

- **Status:** ACCEPTED (2026-09-24)
- **Date:** 2026-09-24 (proposed) · 2026-09-24 (accepted)
- **Deciders:** project owner
- **Supersedes / superseded by:** —
- **Resolves:** open question **Q4** (detection-content strategy & conversion, [05](../05-architecture-open-questions.md)),
  deferred since Phase 0 ([13](../13-phase-0-implementation-plan.md) CL-1)
- **Related:** [ADR-0001](0001-evidence-graph-core-architecture.md) D5/D10/D12/D13 ·
  [ADR-0005](0005-attribution-engine-specification.md) §D3 · [ADR-0006](0006-calibration-corpus-and-versioning.md) §D9/§D11 ·
  [11 coverage model](../11-coverage-model.md) · [12 deployment & endpoint scope](../12-deployment-and-endpoint-scope.md) ·
  [15 corpus v2 design](../15-corpus-v2-design.md) · [research 03 detection engineering](../../research/03-detection-engineering.md)

> **ACCEPTED (2026-09-24)** by the owner, all four open questions answered yes, with the owner's condition
> restated as binding: the platform must account for **every** ATT&CK technique and **every** active Group
> in the pinned KB (D1), with coverage measured and reported (D9). Records how detection content enters the platform and how the rule predicate language grows to
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

## Implementation record

**Work-order step 1 — D4 predicate extension (2026-09-24, `6c67a05`).** Implemented as specified; existing
packs unchanged.

**Work-order step 2 — D5/D6 importer (2026-09-24).** `detection_content/sigma_import.py` +
`sigma_field_map.py` (`sigma-field-map/1`), `scripts/acquire_sigma_release.py`,
`scripts/import_sigma_rules.py`. Pinned input: SigmaHQ `r2026-07-01` `sigma_core++.zip`, 2,728,028 bytes,
SHA-256 `469d83e1d1bbdb4d7876466ff1a728550fae5a20115b91339d58d20e894e7477`, 2,842 rule files; pySigma 1.5.1
(build-time only; a test proves runtime detection never loads it); DNF bound 64. Output under
`data/detection/sigma/r2026-07-01/generated/`, regenerated byte-identically by a test.

Measured result (facts, not coverage claims beyond these counts):

| Measure | Value |
|---|---|
| Sigma rules imported fully / partially / rejected | 267 / 400 / 2,175 |
| Rejected: telemetry gap / translation gap / no ATT&CK mapping | 1,696 / 161 / 318 |
| Generated rules (DNF conjuncts) | 4,078 |
| Distinct ATT&CK ids with ≥ 1 imported rule | 209 (202 techniques, 7 software) |
| Group-used techniques with ≥ 1 imported rule | **177 of 492** (was 5) |
| Group tags ignored (never evidence) | 12 |

Largest gaps, in order: `OriginalFileName` (PE metadata), `ParentImage` (parent path — `parent_name` holds a
basename *or* a path depending on the source record, so no exact mapping exists), then whole logsources with no
adapter (`registry_set`, `ps_script`, `file_event`, Security log, `image_load`). Network-connection rules are
mostly blocked by `Initiated` (Sysmon → ECS `network.direction` mapping unverified). These feed step 3 (D9
coverage report) and step 4 (D10 adapter order).

**Findings for later tasks (recorded at step 2; both resolved 2026-09-24, see "Engine follow-up" below):**

- **Evaluation cost.** The engine evaluates every rule against every Observation: ~60 ms per Observation with
  4,078 rules (500 Observations in 30 s). Adequate for the corpus, too slow for a full-day replay (e.g. OTRF
  APT29 day 2, doc 15 S2). Indexing rules by their logsource scope is the obvious fix; it is a runtime engine
  change and needs its own task.
- **Sibling conjuncts.** Conjuncts of one Sigma rule share `rule_source`; an Observation matching two of them
  yields two Evidence items for the same technique. Decision support counts distinct features, so decisions are
  unaffected, but raw support/persistence counts could be inflated. To be handled with the evaluation-cost task.

**Work-order step 3 — D9 coverage report (2026-09-24).** `detection_content/coverage_report.py` +
`scripts/build_coverage_report.py`; outputs `generated/coverage-report.json` (every active technique and Group)
and `generated/coverage-summary.md`, both regenerated byte-identically by a test. Inputs are the runtime rule
packs (core + Sigma) and the Sigma import report; no pySigma.

| Measure (v19.0, Windows-endpoint v1 scope) | All 697 active techniques | 492 Group-used |
|---|---|---|
| `covered` | 202 | 177 |
| `telemetry_gap` | 168 | 118 |
| `translation_gap` | 3 | 3 |
| `not_endpoint_observable` | 160 | 88 |
| `no_sigma_rule` | 164 | 106 |

Groups (174 active): 157 have ≥ 2 covered techniques (the engine's necessary, not sufficient, minimum), 133
have ≥ 5, 97 have ≥ 10; 9 have none, 4 of which have no active technique in ATT&CK at all. Examples: APT29
27/66, APT28 41/93, Lazarus 53/93, APT41 52/82 profile techniques covered.

D10 adapter order from the ranking (v1-scope blockers, by Group-used techniques they block, upper bounds):
PowerShell script block `ps_script` (20), Windows Security log (16), `file_event` (12), `registry_set` (12),
`ParentImage` field (8), `Initiated` field (5), `OriginalFileName` field (4), `dns_query` (4).

**Engine follow-up — evaluation cost and sibling conjuncts (2026-09-24, T4.5).** Both step-2 findings resolved
without changing detection results:

- `DetectionRule` gains an optional `rule_family` (pack key `rule_family`; importer 1.1 sets it to
  `sigma:<id>`). `DetectionEngine` emits at most one detection per family per Observation — the first firing
  branch in rule order — so one Sigma rule matching once is one Evidence item. Rules without a family (all
  hand-authored platform rules) are unaffected; their ids and Evidence are unchanged.
- `DetectionEngine` indexes rules by a first-condition `event.category has_element` scope. Using only the
  first condition makes skipping a rule exactly equivalent to evaluating it (evaluation stops at the first
  non-match, so a skipped rule could neither fire nor raise).
- `DetectionRule.evaluate` decides with `FieldCondition.matches()` and builds `MatchedField` explanations only
  for rules that fire (same decisions, same fail-closed errors).
- Proof: a test compares the engine with a plain reference implementation (every rule in order, first firing
  rule per family) on the real core + Sigma packs; results are identical. Measured on 400 mixed process/network
  Observations: **36.6 → 8.0 ms per Observation**.


**D10 step 1 — completed process-creation telemetry (2026-09-24).** Contract change, decided here as D5
required (not assumed): `ProcessRef` gains `parent_executable`, `parent_command_line`, `working_directory`,
`integrity_level` and `pe: PeInfo` (`original_file_name`, `description`, `product`, `company`; ECS
`process.pe.*`). `parent_name` is now always a bare file name (ECS `process.parent.name`, else the basename of
the parent executable) — fixing the step-2 ambiguity where it could hold a full path. The Sysmon adapter reads
each value from Sysmon's own `winlog.event_data` (`ParentImage`, `OriginalFileName`, `IntegrityLevel`, …, the
exact names Sigma's Windows fields use) and falls back to the ECS field; `IntegrityLevel` has no ECS
equivalent. Replay fixtures and persistence carry the new fields; correlation is unaffected (it links on
entity ids, never on names).

`sigma-field-map/2` maps `ParentImage`, `ParentCommandLine`, `CurrentDirectory`, `IntegrityLevel`,
`OriginalFileName`, `Description`, `Product`, `Company`. Still unmapped, by design: `Hashes` (Sigma matches
Sysmon's combined string, mostly IMPHASH), `User` (combined `DOMAIN\user` string), `ParentUser`.

| Measure | Before | After |
|---|---|---|
| Sigma rules imported fully / partially | 267 / 400 | 819 / 42 |
| Generated rules | 4,078 | 7,830 |
| Group-used techniques covered (of 492) | 177 | 188 |
| Groups with ≥ 2 / ≥ 5 / ≥ 10 covered | 157 / 133 / 97 | 159 / 137 / 102 |
| Engine cost per Observation (400 mixed) | 8.0 ms | 13.3 ms (more rules) |

**ATT&CK v19.2 upgrade (2026-09-24).** The Sigma pack, import report and coverage report were regenerated
against `enterprise-attack-19.2` (doc 11 §0.1). Production detection content is now the Sigma pack alone;
`fixtures/phase1_core_rules.json` remains a structural fixture frozen against v19.0 (its five techniques are
all covered by Sigma). Coverage: 176 active Groups, 188 of 498 Group-used techniques covered, 161 Groups with
≥ 2 covered techniques.


**D3 amendment — Sigma software tags are not evidence unless reviewed (2026-09-25, owner-delegated).**

- *Finding (real data):* the 22 imported rules carrying an `attack.sNNNN` tag were reviewed against their
  detection logic; **12 name a tool the rule does not identify** (NirCmd, RemCom, CSExec, RunXCmd tagged PsExec;
  generic LSASS rules — WerFault, WinRM, "dump" in the image name — tagged Mimikatz; a CrackMapExec rule tagged
  cmd; a Python-ctypes rule tagged LaZagne; an HTRAN rule that also matches `lcx.exe`; an esentutl rule whose
  sensitive-path branch fires without esentutl). On the real Dumpert LSASS sample, a Mimikatz (S0002) mapping
  would have been produced for a tool that is not Mimikatz.
- *Why it matters:* software identity is strong attribution evidence (a specific tool is often used by few
  Groups, so its `D` is high). A wrong tool tag injects false high-diagnosticity evidence and biases candidates
  towards Groups known for that tool.
- *Decision:* D3's "`attack.sNNNN` → the malware/tool object" is replaced by: a software tag becomes a mapping
  **only if** the release's reviewed decision file (`data/detection/sigma/<tag>/software-tag-review.json`)
  accepts it **for that rule**; accepted only when every branch of the rule's logic identifies that specific
  tool. Unreviewed or rejected software tags are recorded per rule (`ignored_software_tags`) and ignored, like
  Group tags. Without a review file no software tag maps (safe default). Technique tags are unchanged. The
  review file's hash and accepted pairs are stamped into the pack provenance (importer 1.3).
- *Result for `r2026-07-01`:* 22 decisions (10 accept, 12 reject, each with a reason); 45 software tags ignored
  across the archive; the pack carries exactly the 10 accepted mappings; technique coverage unchanged (210 of
  498 Group-used techniques). One rule — Zeek "Default Cobalt Strike Certificate" (S0154) — lost its only
  mapping; Zeek is not supported yet, and its tag looks specific, so it is to be reviewed with Wave 2.
- *Tests:* unreviewed/rejected tags never map; acceptance is per rule; the review file fails closed (duplicate,
  bad decision, missing reason); every imported software-tagged rule has a decision; the real Dumpert sample is
  detected as T1003.001 without any Mimikatz mapping; both real LSASS dumps (comsvcs, Dumpert) are detected by
  ≥ 4 independent rules each.
