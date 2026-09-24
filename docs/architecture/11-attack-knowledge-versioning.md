# 11 — ATT&CK Knowledge-Base Versioning Strategy (resolves C0.1)

**Status: C0.1 ACCEPTED (2026-09-11).** The versioning *strategy* and the previously-deferred picks (baseline
version, vendoring approach, Terms-of-Use placement) are now decided — see **§0 Project decision**. No
application code; the actual bundle is **not** vendored yet (that is a Phase-0 implementation step), so the
SHA-256 and object fingerprint are recorded **at acquisition**, not fabricated here. Implements the
reproducibility requirements of [ADR-0001 D3/D10](adr/0001-evidence-graph-core-architecture.md) and
[ADR-0002 D12](adr/0002-attribution-scoring-and-evidence-methodology.md), and the boundaries in
[04](04-component-boundaries.md).

---

## 0. Project decision (C0.1 closed — 2026-09-11)

The following are **decided** (they resolve the §K open items and supersede the "deferred" language later in
this document, which is retained for the reasoning that led here):

1. **Baseline release: MITRE ATT&CK Enterprise `v19.0`** — pinned as the initial baseline KB. v19.0 is a
   **standard, full-scope** release (not an Agile point release), matching the §D criteria for a stable
   calibration baseline. Its tactic model (Defense Evasion split into **Stealth** + **Defense Impairment**)
   is therefore our baseline tactic set — **derived from the bundle, never hard-coded**.
2. **Source & form:** the immutable official **STIX 2.1** Enterprise bundle `enterprise-attack-19.0.json`
   from `mitre-attack/attack-stix-data` (release tag `v19.0`). Not the floating unversioned bundle; not live
   TAXII.
3. **Vendor the exact v19.0 bundle** as a version-controlled project artifact so **runtime analysis never
   touches a live MITRE service**. (Acquisition happens in Phase 0; see §J.)
4. **Record, at acquisition:** the exact **SHA-256** of the vendored file plus the ATT&CK/STIX metadata in
   §E/§F (collection id + version, object fingerprint, etc.). These are captured when the file is vendored —
   **not invented now**.
5. **Future releases (v19.1 / v19.2 / v20+) are deliberate upgrades only:** KB-diff → recompute diagnostic
   weights (`D`) → re-fit calibration → validate against the golden corpus → **explicit approval** (§G).
   Never automatic; never floating.
6. **Retain the previous bundle + its compatible `calibration_version`** so rollback is always possible (§H).
7. **No hard-coded ATT&CK vocabulary** in application logic — groups, tactics, techniques, sub-techniques,
   software, campaigns, aliases are all **derived from the pinned KB** (R2 + §A corollary).
8. **Keep `attack_kb_version` and `calibration_version` distinct** — a calibration set is valid only for the
   KB version it was fitted against (§I).
9. **No runtime/code yet** — this document is a decision record; acquisition and loading are Phase-0
   implementation steps.

**ATT&CK Terms of Use — attribution placement (resolved):** ATT&CK data is used under the **[ATT&CK Terms of
Use](https://attack.mitre.org/resources/terms-of-use/)** (permissive; attribution required). Placement:
(a) an `ATTRIBUTION`/`NOTICE` note stored **alongside the vendored bundle** naming the release, retrieval
date, source URL, and the required MITRE ATT&CK attribution statement; (b) a short attribution line in the
repository's top-level docs (e.g., README/CLAUDE context) stating the project uses MITRE ATT&CK® under its
Terms of Use; and (c) an attribution/version note surfaced in analyst-facing output that shows ATT&CK-derived
content (the same place the `attack_kb_version` is shown). No ATT&CK content is presented as our own.

> Everything below is the original strategy analysis that led to these decisions; §D/§K's "deferred"
> phrasing is now closed by §0.

---

---

## 0.1 Upgrade record — v19.0 → v19.2 (2026-09-24, owner-approved)

**Why now.** MITRE shipped two Agile releases after the v19.0 baseline: v19.1 (2026-05-12) and v19.2
(2026-08-05). The owner requires the platform to cover the Groups and techniques current in industry. No
`calibration_version` has been fitted yet, so upgrading before corpus v2 and fitting avoids a forced re-fit
(§G step 3, §I governance rule).

**What was done, per §G:**

1. **Acquire + verify** — `enterprise-attack-19.2.json` from `mitre-attack/attack-stix-data` tag `v19.2`,
   53,835,637 bytes, SHA-256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`
   (`data/attack/enterprise/v19.2/manifest.json`, with `NOTICE.md`). Stored **alongside** v19.0, which is
   retained unchanged.
2. **KB-diff report** — `scripts/diff_attack_versions.py` →
   `data/attack/enterprise/v19.2/changes-from-enterprise-attack-19.0.{json,md}` (regenerated
   byte-identically by a test). Active objects: Groups 174 → 176 (**added G1056 TeamPCP, G1057
   ShinyHunters**; none retired), techniques 697 → 697 (none added or retired; no tactic change), software
   821 → 825 (+4), campaigns 56 → 56. **No existing Group's technique profile changed.** The large
   "modified" counts are STIX `modified` timestamp changes, including metadata-only edits.
3. **Recompute `D`** — automatic: `g`/`D`, candidate universe and profile breadth are derived from the loaded
   bundle at run time, never stored. **Re-fit calibration: not applicable** — no `calibration_version`
   exists yet.
4. **A/B on the frozen corpus: not applicable** — calibration corpus v1 is frozen against v19.0 and its
   harness fails closed on a KB mismatch (doc 14 Stage 5), by design. Corpus v2 will be built on v19.2.
5. **Version bump** — `EXPECTED_ATTACK_KB_VERSION = "enterprise-attack-19.2"` in
   `attack_knowledge/verification.py`.

**Mechanism change (recorded, not silent).** `load_attack_knowledge()` previously took no argument and
could only load v19.0. It now takes an optional **version name** from a registry of vendored releases
(`VENDORED_ATTACK_ARTIFACTS`): no argument = the current pin (v19.2); a registered name loads that retained
release (needed by artifacts frozen against it). A path, an unregistered release, the floating
`enterprise-attack` bundle, or a service URL are still refused (tested). Every vendored release is
integrity-verified by the test suite, not only the current pin.

**What stays on v19.0 (frozen artifacts, loaded by name):** calibration corpus v1 and its seed, the Phase-1
structural rule pack `fixtures/phase1_core_rules.json`, and the Phase-0 scenarios
`fixtures/phase0_benign_scenarios.json`. Their tests load `enterprise-attack-19.0` explicitly.

**What moved to v19.2:** the default KB, the generated Sigma rule pack/import report (tags re-resolved
against v19.2), and the coverage report. Production detection content is now the Sigma pack alone — the five
v19.0-stamped structural rules are not production content (all five techniques are covered by Sigma).

**Effect (coverage report, Windows-endpoint v1 scope):** active Groups 176; Group-used techniques 498 (the
two new Groups use 6 techniques no other Group did); 188 covered; Groups with ≥ 2 covered techniques
159 → 161, ≥ 10 covered 102 → 104. TeamPCP and ShinyHunters are profiled mostly on cloud/SaaS/identity
platforms, so much of their profile is outside v1 endpoint scope — shown per Group in the report, not
hidden.

---

## A. Requirements (restated, with how the strategy must satisfy each)

| # | Requirement | Must be satisfied by |
|---|---|---|
| R1 | Support the **full** Enterprise KB (tactics, techniques, sub-techniques, groups, software, campaigns, relationships, aliases, methodology metadata) | Load the complete pinned STIX bundle; never a curated subset |
| R2 | Candidate generation **never** depends on a hand-maintained APT list | Groups/campaigns are read from the bundle at runtime ([07 §3](07-attribution-scoring-spec.md)) |
| R3 | **Reproducible** knowledge context (same telemetry + app version + KB version ⇒ same context) | A single **immutable, content-addressed** pinned bundle |
| R4 | Record the ATT&CK version on **every** assessment | Version + content hash in the provenance manifest ([06 §Versioning](06-evidence-model.md)) |
| R5 | **Never** silently follow floating "latest" | Forbid the unversioned bundle / live TAXII latest at runtime |
| R6 | **Deliberate** upgrades, with before/after comparison | Version bump = reviewed change + KB-diff + recalibration + A/B on the corpus |
| R7 | Prefer the **official STIX 2.1** source of truth | Use `mitre-attack/attack-stix-data` (STIX 2.1) |
| R8 | Work with Elastic **and** our evidence graph | KB loads into the evidence graph; independent of Elastic (Elastic stores telemetry, not ATT&CK) |

**Design corollary (extends R2):** *no ATT&CK vocabulary may be hard-coded* — not groups, and **not the
tactic list** either. This matters because ATT&CK v19 **split the Defense Evasion tactic into Stealth and
Defense Impairment**; any tactic-ordering / tactic-coverage logic must **derive tactics from the pinned
bundle**, so a future upgrade that changes the tactic set is absorbed by re-derivation rather than breaking a
constant.

---

## B. Current official MITRE distribution options (verified 2026-09)

**Release model (fact).** ATT&CK now has two cadences:
- **Standard releases** — biannual, full-scope (all domains, all object types). Recent: **v18** (Oct 2025),
  **v19** (Apr 2026). v19 made a structural change: **Defense Evasion → Stealth + Defense Impairment**.
- **Agile releases** — narrower, off-cycle updates to **Groups, Software, and Campaigns** when significant
  threat activity emerges. Recent: **v19.1**, **v19.2** (Aug 2026). *These touch exactly the
  attribution-relevant content (actors and their TTP mappings).*
- Enterprise scale (v19 era): ~15 tactics (post-split), 222 techniques, 475 sub-techniques, **178 groups**,
  949 software, 59 campaigns.

**Distribution mechanisms:**

1. **`mitre-attack/attack-stix-data` — versioned STIX 2.1 bundles (GitHub).** Per-release files
   `enterprise-attack-<version>.json` (e.g., `enterprise-attack-19.0.json`, `…-19.2.json`), each an immutable
   STIX 2.1 collection bundle for that release. **Plus** an unversioned `enterprise-attack.json` that
   **always tracks latest** (this is the floating dataset R5 forbids). Collection *indexes* (JSON/MD) list
   releases for programmatic discovery. **This is the STIX-2.1 source of truth (R7).**
2. **MITRE TAXII 2.1 server** — `https://attack-taxii.mitre.org` (the TAXII 2.0 server at
   `cti-taxii.mitre.org` was **retired**). A live REST endpoint serving collections; **rate-limited (10
   requests / 10 min / IP)**. It is a *network service*, not an immutable file.
3. **Floating "latest"** — the unversioned bundle, or "just query TAXII for current." A live moving target.
4. **`mitre/cti` (legacy)** — STIX **2.0**, older data model; superseded by attack-stix-data for new work.
5. **`mitreattack-python`** — not a distribution *source*; the **access library** that loads a STIX bundle
   (local file or downloaded) into queryable objects. Our reuse component ([04](04-component-boundaries.md)).

---

## C. Comparison of versioning approaches

| Approach | Reproducible (R3) | Non-floating (R5) | Offline / deterministic | Upgrade control (R6) | Official STIX 2.1 (R7) | Verdict |
|---|:--:|:--:|:--:|:--:|:--:|---|
| **Pinned versioned STIX bundle, vendored + content-hashed** | ✅ exact | ✅ | ✅ no runtime network | ✅ explicit | ✅ | **Recommended** |
| Pinned version fetched from GitHub at build (hash-verified), cached | ✅ (if hash-checked) | ✅ | ⚠️ needs network to acquire | ✅ | ✅ | Acceptable acquisition path *into* the vendored cache |
| **TAXII 2.1 endpoint, "pinned" by requesting a version** | ⚠️ endpoint can change/rate-limit | ⚠️ depends on server state | ❌ runtime network dependency | ⚠️ | ✅ | **Acquisition only, never runtime**; rate limits + availability make it unfit as the source of truth |
| Floating unversioned bundle / TAXII latest | ❌ | ❌ (violates R5) | ❌ | ❌ | ✅ | **Rejected** |
| `mitre/cti` STIX 2.0 | ⚠️ | ✅ if pinned | ✅ | ✅ | ❌ (2.0) | Rejected — older model (R7 prefers 2.1) |

**Key reasoning.** Reproducibility (R3) demands an **immutable artifact identified by content**, not a
service reply. TAXII and the unversioned bundle are moving targets and/or availability-and-rate-limit
dependent — fine for *acquiring* a version once, unacceptable as the *runtime* source of truth. The versioned
`attack-stix-data` bundle is immutable per release, is the official STIX 2.1 form, and drops straight into
`mitreattack-python` and our evidence graph.

---

## D. Recommended approach (strategy — not a version number)

**Strategy: pin one immutable, content-addressed, versioned Enterprise STIX 2.1 bundle from
`attack-stix-data`; vendor it (or a hash-verified cache of it) under version control; load only that local
bundle at runtime; and treat every version change as a deliberate, reviewed, recalibrated upgrade.**

Concretely:

1. **Source of truth:** a specific `enterprise-attack-<version>.json` from `attack-stix-data`, chosen per the
   criteria below — **never** the unversioned `enterprise-attack.json`, **never** live TAXII at runtime.
2. **Immutability:** record the bundle's **SHA-256** and the STIX **`x-mitre-collection` id + version**; the
   load fails if the hash doesn't match (guards against silent drift / corruption).
3. **Acquisition vs runtime split:** acquisition may fetch from GitHub (or TAXII) **once**, hash-verify, and
   store; runtime reads **only** the local pinned artifact (no network — R3, R8).
4. **Full load:** load the entire bundle into the evidence graph as knowledge nodes (R1); derive groups,
   software, campaigns, aliases, **and tactics** from it (R2 + corollary).
5. **Stamp everywhere:** the pinned version + hash flow into the provenance manifest and every
   `AttributionResult` (R4).

**Criteria for the version choice** (*do not pick the newest by default*): a **standard release** (full-scope)
as the initial calibration baseline; a release whose **era aligns** with our validation datasets and
detection content; **stability over recency** for v1, with Agile releases (which refresh
Groups/Software/Campaigns) handled as later deliberate upgrades (R6).

**Decision (per §0):** these criteria select **Enterprise `v19.0`** — the most recent *standard, full-scope*
release, giving a stable, current baseline while leaving v19.1/v19.2 (Agile) as deliberate upgrades. One
consequence to validate in Phase 1: some older validation datasets predate v19's technique renames/moves and
the tactic split, so **dataset↔v19.0 technique-ID alignment must be checked when the golden corpus is built**
(a mapping/labeling task, not a blocker).

---

## E. Exact reproducibility strategy

A knowledge context is reproducible iff all of these are fixed and recorded:

- **`attack_kb_version`** — e.g., `enterprise-attack-19.0` (release tag).
- **`attack_kb_sha256`** — content hash of the exact bundle file.
- **`stix_collection_id` + `collection_version`** — from the bundle's `x-mitre-collection` object.
- **`attack_domain`** — `enterprise` (Mobile/ICS out of scope for v1).
- **`stix_spec`** — `2.1`.
- **`object_fingerprint`** — counts (n groups / techniques / sub-techniques / software / campaigns /
  relationships) checked on load as a tamper/format sanity gate.

Rule: **same telemetry + same `engine_version` + same `attack_kb_version`/`sha256` + same
`calibration_version` ⇒ identical `determinism_hash`** ([06 §Versioning](06-evidence-model.md)). The KB is
loaded once from the pinned artifact; no code path may consult a live ATT&CK service during analysis.

### Baseline pinned record (v19.0)

| Field | Value | When set |
|---|---|---|
| `attack_kb_version` | `enterprise-attack-19.0` | **decided now** |
| release tag / source | `v19.0` in `mitre-attack/attack-stix-data` (file `enterprise-attack/enterprise-attack-19.0.json`) | **decided now** |
| `attack_domain` | `enterprise` | **decided now** (Mobile/ICS out of scope for v1) |
| `stix_spec` | `2.1` | **decided now** |
| `attack_kb_sha256` | *captured at acquisition (Phase 0) — not fabricated here* | at vendoring |
| `stix_collection_id` + `collection_version` | *read from the bundle's `x-mitre-collection` object* | at vendoring |
| `object_fingerprint` (counts of groups/techniques/sub-techniques/software/campaigns/relationships) | *computed on the vendored file and sanity-checked against v19.0 release notes* | at vendoring |

The three "at vendoring" rows are **deliberately empty until the file is vendored** — recording a hash or
counts we have not computed from the actual artifact would violate the reproducibility guarantee, so they are
captured by the Phase-0 acquisition step (§J) and then frozen.

---

## F. ATT&CK metadata that must be persisted with an assessment

Every `AttributionResult` (and its provenance manifest) carries:

- `attack_kb_version`, `attack_kb_sha256`, `stix_collection_id`, `collection_version`, `attack_domain`,
  `stix_spec`, `object_fingerprint` (from §E);
- **the specific ATT&CK object versions actually used** — each referenced technique/group/software/campaign
  carries ATT&CK's own object `version`/`modified` (STIX) so a conclusion is traceable to the exact object
  revision, not just the release;
- the **derived tactic set** used for ordering/coverage (since it can change across releases — v19 split);
- the **discriminating-power basis** note: that `D` was computed from *this* Group×{Technique,Software}
  matrix at *this* version (so `D` values are interpretable only against the stamped version — ADR-0002 D18).

This makes an old assessment fully interpretable later even after upgrades, and lets us explain *why* two
results differ (KB change vs. evidence change).

---

## G. Upgrade strategy (deliberate, reviewed — R6)

An ATT&CK upgrade is a **reviewed change**, never automatic:

1. Acquire and hash-verify the new versioned bundle; store it alongside (not replacing) the current one.
2. **KB-diff report:** added/removed/renamed techniques & sub-techniques; **tactic changes** (e.g., the v19
   Defense-Evasion split); new/removed/merged groups; **changed `uses` edges** (group→technique/software);
   alias-set changes. These are the changes that move candidate generation and `D`.
3. **Recompute `D`** from the new matrix; **re-run calibration** → a **new `calibration_version`** bound to
   the new `attack_kb_version` (never reuse a calibration fitted on the old KB).
4. **A/B compare** old vs new on the frozen corpus (which cases changed verdict/likelihood/confidence, and
   why) — this is the concrete realization of R6.
5. Land the upgrade as a version bump in config + a short ADR/changelog note; results generated afterward
   stamp the new version.

**Standard vs Agile upgrades:** an Agile release (Groups/Software/Campaigns only) changes actor knowledge and
therefore `D` and candidate sets, but not techniques/tactics — a lighter diff, but it **still requires
recalibration** because `D` shifts. A standard release may additionally change techniques/tactics and needs
the fuller review (feature/tactic-derivation re-check).

---

## H. Rollback strategy

Because every bundle is immutable and content-addressed and prior bundles are retained:

- **Rollback = repoint config** to the previous `attack_kb_version` + its paired `calibration_version`.
  Deterministic and instant; no data migration.
- Results generated under the old version remain valid and interpretable (they carry their own stamps), so
  rollback never orphans past assessments.
- Never delete a superseded bundle or its calibration set — they are the record that makes historical results
  reproducible.

---

## I. Impact of ATT&CK upgrades on attribution / calibration

- **`D` shifts:** new groups and new `uses` edges change technique/software group-prevalence `g(x)` → `D`
  changes → discrimination and rankings can change. **Any KB change invalidates the frozen
  `calibration_version` until re-fit** (ADR-0002 D12).
- **Candidate universe shifts:** new/removed groups change who is generated; a previously "untracked actor"
  (null-hypothesis win) may become attributable after an upgrade — a *good* outcome, but one that must be
  attributed to the KB change, not silently.
- **Tactic/feature shifts:** the v19 tactic split changes tactic-coverage and kill-chain-ordering features;
  our logic must re-derive tactics from the bundle (corollary in §A) so this is absorbed, and the derived
  tactic set is stamped (§F).
- **Alias-set shifts:** candidate collapsing changes if aliases are added/merged.
- **Governance rule:** a `calibration_version` is only ever valid for the `attack_kb_version` it was fitted
  against; the loader must refuse to run a calibration against a mismatched KB.

---

## J. Phase-0 implementation requirements (requirements only — no code now)

When Phase 0 begins (after C0.1/C0.2 are confirmed), the ATT&CK-knowledge slice must:

1. **Acquire** a specific versioned Enterprise STIX 2.1 bundle from `attack-stix-data` by release tag,
   **SHA-256-verify** it, and store it as an **immutable, version-controlled artifact** (vendored in-repo, or
   in a committed cache with the hash + a fetch script — see §K on size/licensing).
2. **Load only the local pinned bundle** via `mitreattack-python`; **no network at analysis time**.
3. **Fingerprint-check** on load (object counts, hash) and fail closed on mismatch.
4. **Derive** groups, software, campaigns, aliases, techniques/sub-techniques, relationships, **and tactics**
   from the bundle into the evidence graph — nothing hard-coded (R2 + corollary).
5. **Expose** `attack_kb_version` + `attack_kb_sha256` + collection id/version to the provenance manifest
   (R4), and make them show up in a trivial "KB loaded reproducibly" test (a Phase-0 exit criterion).
6. **Retain** the bundle + its (later) calibration set immutably to support rollback (§H).
7. **Record ATT&CK Terms of Use attribution** wherever the data or derivatives are surfaced/redistributed.

---

## K. Open questions — now resolved (see §0)

1. **Which exact version to pin.** ✅ **RESOLVED: Enterprise `v19.0`** (standard, full-scope baseline; §0.1,
   §D).
2. **Standard vs Agile baseline.** ✅ **RESOLVED: standard release baseline**; v19.1/v19.2 (Agile) are later
   deliberate upgrades (§0.5, §G).
3. **Vendored bundle vs committed-hash + fetch.** ✅ **RESOLVED: vendor the exact v19.0 file** as a
   version-controlled artifact (Git LFS if size warrants) for genuine offline reproducibility (§0.3, §J).
4. **Licensing / attribution.** ✅ **RESOLVED:** used under the **ATT&CK Terms of Use** with the three-place
   attribution scheme in §0 (NOTICE beside the bundle; repo-docs line; analyst-output version/attribution
   note).
5. **Domain scope.** Enterprise-only for v1 (Windows/endpoint-first,
   [ADR-0001 D13](adr/0001-evidence-graph-core-architecture.md)); Mobile/ICS out of scope until later.
   Confirmed by §0.1; final endpoint-scope confirmation remains part of **C0.2**, not C0.1.

**No C0.1 items remain open.** (One Phase-1 follow-up noted in §D: validate dataset↔v19.0 technique-ID
alignment when the golden corpus is built — a corpus task under C1/Q6, not a C0.1 question.)

---

## C0.1 STATUS: **ACCEPTED** (2026-09-11)

The versioning strategy **and** all previously-deferred picks are decided (§0): pin the immutable official
**STIX 2.1** Enterprise **`v19.0`** bundle from `attack-stix-data`; **vendor** it as a version-controlled
artifact; load only that local file at runtime (no MITRE network dependency); capture the **SHA-256** +
ATT&CK/STIX metadata **at acquisition**; derive all ATT&CK vocabulary from the pinned KB (nothing
hard-coded); keep `attack_kb_version` and `calibration_version` distinct; treat v19.1/v19.2/future releases
as deliberate, diffed, recalibrated, corpus-validated, explicitly-approved, reversible upgrades; and attribute
ATT&CK under its Terms of Use in the three places named in §0.

**Not done here (correctly):** the actual bundle is **not vendored yet** and no hash/counts are fabricated —
acquisition + metadata capture are the first Phase-0 implementation step (§J).

*No ADR created. No ADR statuses changed. No application code. Phase 0 not started.*
