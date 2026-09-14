# 13 — Phase 0 Implementation Plan

**Status: IN PROGRESS.** G0.0–G0.4 are **IMPLEMENTED/PASSED** (checkpointed); G0.5 and G0.6 are
**IMPLEMENTED, AWAITING REVIEW** (not yet checkpointed/committed); G0.7 onward are still planning only.
Translates the accepted architecture ([ADR-0001](adr/0001-evidence-graph-core-architecture.md),
[ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md),
[C0.1 §11](11-attack-knowledge-versioning.md), [C0.2 §12](12-deployment-and-endpoint-scope.md)) into small,
independently verifiable gates. Beyond G0.0 (repo scaffolding/CI), G0.1 (the pinned ATT&CK artifact + its
offline integrity verifier), G0.2 (the deterministic runtime knowledge loader), G0.3 (the source-agnostic
domain contracts), G0.4 (the SourceAdapter interface), G0.5 (the detection-match → Observation extraction
boundary), and G0.6 (Observation → Evidence derivation + validated ATT&CK reference), no other code exists
yet: no Dockerfiles, compose files, Elastic config, indexes, API, frontend, or dataset acquisition.

**Authoritative constraints (carried verbatim into every gate):** no hard-coded ATT&CK vocabulary (all
derived from the pinned v19.0 bundle); no live MITRE dependency at runtime; provenance on every derived
object; the Attribution Engine stays telemetry-source-agnostic; Sysmon is a v1 source, not a dependency;
Windows Event Logs and future sources enter the *same* normalization boundary; synthetic/replay uses the same
downstream path; **do not** implement the attribution scoring engine, invent weights, merge
likelihood/confidence, build the frontend, or introduce a graph database. Prefer boring, deterministic,
testable infrastructure.

---

## Pre-planning inspection — contradictions & unresolved dependencies

I checked the accepted docs against the Phase-0 scope for genuine blockers. **No hard blocker to Phase 0 was
found.** The following are *documented clarifications/dependencies* (recorded here rather than silently
decided):

- **CL-1 — "Detection execution = Elastic" ([04](04-component-boundaries.md)) vs. an Elastic-free logic
  core.** Resolved without contradiction: Phase 0 defines the **detection-match record** contract (the
  `E → L2` boundary in [04](04-component-boundaries.md)) and feeds the extractor either from a **hand-authored
  synthetic fixture** (Elastic-free unit tests) or, in the integrated slice, from a minimal Elastic
  query/rule. The architecture (detection runs in Elastic for live telemetry) is preserved; Phase 0 tests the
  *boundary* deterministically. **Real detection-content strategy (open question Q4) is deferred to Phase 1.**
- **CL-2 — Normalized-event contract (open question Q1) is unresolved.** This is **Phase-0 work, not a
  blocker**: gate **G0.3** *is* the resolution of Q1 (define the ECS→domain contract). Recorded so we don't
  treat it as pre-decided.
- **CL-3 — Validation corpus (open question Q6) not built in Phase 0.** Dataset acquisition is explicitly
  out of scope now. Phase 0 therefore validates the **plumbing, contracts, provenance, determinism, and
  source-agnosticism** using **tiny hand-authored in-repo synthetic fixtures** — **not** the external labeled
  corpus (Security-Datasets/EVTX/CALDERA), which is a later, separately-gated acquisition. **Phase 0 proves
  the pipeline is trustworthy; it does not prove attribution correctness** (that needs the corpus +
  calibration, Phase 3).
- **CL-4 — ATT&CK SHA-256 unknown until acquisition (by C0.1 design).** Not a blocker: gate **G0.1** captures
  and freezes it. Until G0.1 runs, no hash is fabricated.
- **CL-5 — Collector choice (Elastic Agent+Fleet vs Winlogbeat).** Deferred per [C0.2 §L](12-deployment-and-endpoint-scope.md);
  affects only **G0.9** (Windows ingestion), which is **off the first-slice critical path**.

**Verdict: Phase 0 may proceed as planned.** The clarifications above are constraints on *how* gates are
built, not missing decisions.

---

## Phase 0 gate catalog

Gate IDs are `G0.x`. Each gate is small and independently verifiable. "Env" = what must be running.

### G0.0 — Repository scaffolding & CI skeleton — **IMPLEMENTED / PASSED (2026-09-11)**
- **Objective:** module layout matching [ADR-0001 §"module layout"](02-recommended-architecture.md)
  (`attack_knowledge/`, `dataplane/`, `extraction/`, `domain/` contracts, `sources/` adapters, `api/`,
  `tests/`, `fixtures/`); a test runner, linter, and CI running an (initially empty) suite; a place for the
  version/provenance manifest.
- **Inputs:** the accepted architecture docs.
- **Outputs:** repo skeleton, CI config, contributor/run docs, empty test suite that passes.
- **Work:** create package structure + tooling config; wire CI to run tests + lint on every change.
- **Tests/verify:** CI green on empty suite; `import`/module-resolution smoke test.
- **Acceptance:** CI runs deterministically; structure matches the accepted module boundaries.
- **Depends:** none.
- **Env:** no Elastic, no Windows.
- **NOT yet:** no domain logic, no Dockerfiles/compose (that's G0.7), no API, no frontend.

#### Actual tooling/runtime choices (recorded at implementation)

| Decision | Choice | Why |
|---|---|---|
| Language/runtime | **Python 3.12** (`requires-python = ">=3.12,<3.13"`) | Already implied by the architecture — `mitreattack-python`, `cti-python-stix2`, and the FastAPI-family API layer ([02](02-recommended-architecture.md)) are all Python; not a new choice, just formalized. 3.12 was already installed and is current-stable. |
| Package layout | `src/attribution_platform/` (src-layout), submodules `domain/`, `attack_knowledge/`, `sources/`, `extraction/`, `dataplane/`, `api/` | Matches doc 13's G0.0 objective exactly; src-layout forces imports through the installed package (editable install), preventing accidental "works because cwd" imports. |
| Build backend | `setuptools` (PEP 621 `pyproject.toml`, no `setup.py`) | Boring, standard, zero extra concepts — G0.0 only needs an editable install for tests, not packaging/publishing. |
| Formatter + linter | **ruff** (`format` + `check`), pinned `0.8.4` | One boring tool instead of black+isort+flake8; fast; wide adoption. |
| Type checker | **mypy**, pinned `1.13.0`, `strict = true` | Strongly-typed foundation from day one, per the requirement; strict mode costs nothing now (8 nearly-empty files) and sets the bar before real logic lands. |
| Test runner | **pytest**, pinned `8.3.4` | Standard, boring, zero-config-friendly. |
| Runtime dependencies | **none** | G0.0 has no domain logic, no Elastic client, no ATT&CK loader, no API framework — so there is nothing to depend on yet. Avoids scope creep; each later gate adds exactly the dependency it needs (`mitreattack-python` in G0.1/G0.2, an ES client in G0.7/G0.8, an API framework in G0.10). |
| CI runner | GitHub Actions, `ubuntu-latest`, Python 3.12 pinned via `actions/setup-python` | No OS-specific code exists yet, so the simplest portable runner is used; Windows-specific behavior (G0.11, the native collector) will be verified separately, not by this job. Documented explicitly in the README so it isn't mistaken for "CI validates the Windows path." |
| `.env.example` | **not created** | No configuration exists to document yet (no Elastic connection, no secrets) — correctly deferred per the plan's own instruction ("only if configuration is actually required"). |
| Dependency pinning | Exact `==` pins for all dev dependencies | "Deterministic and reproducible... do not use floating dependencies unnecessarily." No lockfile tool (Poetry/PDM/uv) introduced — three exact-pinned dev dependencies don't need one; revisit if the dependency graph grows. |

#### Verification results

Run from a fresh `python -m venv .venv` + `pip install -e ".[dev]"` (Windows 11, Git Bash):

```
ruff format --check .   → 8 files already formatted
ruff check .            → All checks passed!
python -m mypy          → Success: no issues found in 8 source files
python -m pytest -v     → 3 passed (test_package_version_is_defined,
                                     test_scaffolded_submodules_import_cleanly,
                                     test_no_network_or_external_service_access)
```

CI workflow YAML (`.github/workflows/ci.yml`) parsed and validated with `yaml.safe_load` — 1 job (`checks`),
7 steps in the correct order (checkout → setup Python → install → format check → lint → type check → test).

**Deviation found and fixed during implementation:** the initial `[tool.mypy]` config had no `files`/
`packages` target, so bare `mypy` failed with "Missing target module, package, files, or command." Fixed by
adding `files = ["src", "tests"]`. Re-verified clean after the fix (all four checks above are post-fix
results).

**Windows/Git-Bash-specific note (documented in README, not a defect):** the pip-installed `mypy`/`pytest`
launcher scripts in `.venv/Scripts/` occasionally return `Permission denied` when invoked directly in Git
Bash (an MSYS/launcher quirk). Worked around with `python -m mypy` / `python -m pytest`; PowerShell and CI
(Linux) are unaffected. No project code is implicated.

### G0.1 — Pinned ATT&CK v19.0 acquisition & verification — **IMPLEMENTED / PASSED (2026-09-11)**
- **Objective:** execute the **already-accepted C0.1 decision** — **vendor** the exact official MITRE ATT&CK
  Enterprise **v19.0 STIX 2.1** bundle (`enterprise-attack-19.0.json` from `attack-stix-data`, tag v19.0) as
  an **immutable project artifact**; compute and freeze its **SHA-256**, STIX collection metadata, and object
  fingerprint at acquisition; write the ATT&CK Terms of Use NOTICE. No floating/latest bundle; no live MITRE
  dependency. (The vendoring approach is **decided, not an owner choice** — [11 §0/§K](11-attack-knowledge-versioning.md).)
- **Inputs:** attack-stix-data v19.0 release (fetched **once** at acquisition/build, hash-verified; never at
  runtime).
- **Outputs:** the **vendored immutable v19.0 bundle** (runtime loads **only** this artifact), the `attack_kb`
  manifest (`attack_kb_version`, `attack_kb_sha256`, `stix_collection_id`, `collection_version`,
  `attack_domain=enterprise`, `stix_spec=2.1`, `object_fingerprint`), and the NOTICE/ATTRIBUTION file.
- **Work:** acquisition + hashing + fingerprint capture + metadata write; a verifier that fails closed on
  hash/fingerprint mismatch.
- **Tests/verify:** recomputed hash == recorded; fingerprint sane; verifier rejects a tampered copy;
  **no runtime network** used by the verifier.
- **Acceptance:** the exact v19.0 bundle is pinned, hash-frozen, and offline-verifiable; NOTICE present.
- **Depends:** G0.0.
- **Env:** network **once** to acquire (build-time only); no Elastic, no Windows.
- **NOT yet:** no loading into a knowledge model (G0.2); **no discriminating-power / weights** (attribution,
  deferred).

#### Verification: source confirmed before acquisition

Before downloading anything, the official source was verified via the GitHub API (metadata only):
tag `v19.0` resolves to an annotated, **GPG-signed** release tag; the file
`enterprise-attack/enterprise-attack-19.0.json` exists at that tag with reported size **52,680,865 bytes**.
The tag-pinned raw URL (`.../attack-stix-data/v19.0/...`, never `master`, never the unversioned
`enterprise-attack.json`) was used for acquisition.

#### Acquired artifact

| Field | Value |
|---|---|
| Path | `data/attack/enterprise/v19.0/enterprise-attack-19.0.json` |
| Size | 52,680,865 bytes (≈ 50.2 MB) — matches the GitHub API-reported size exactly |
| SHA-256 | `df520ea0775a57db7bff760145b02fed89290802913e056b7ed5970b02f3626a` |
| STIX collection | id `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019`, name "Enterprise ATT&CK", `x_mitre_version` **19.0**, `spec_version` **2.1** |
| `attack_kb_version` | `enterprise-attack-19.0` |
| Object fingerprint (raw, unfiltered) | 25,844 total; 15 tactics; 365 techniques; 493 sub-techniques; 189 groups; 729 malware + 95 tool; 56 campaigns; 21,026 relationships; 268 mitigations |
| Sanity cross-check | active-only (excludes `revoked`/`x_mitre_deprecated`) counts: 15 tactics, **222 techniques, 475 sub-techniques, 44 mitigations — exact matches** to publicly reported v19.0 figures; 174 groups / 821 software vs. ~178/~949 estimated (small variance, expected — the estimate was a secondary-source figure, not computed from this artifact) |

**Vendoring decision (recorded):** vendored as a **plain tracked file** (not Git LFS). At ~50 MB this is
within git's technical limits; introducing LFS would add tooling every clone/CI run must have for a file
that changes only on rare, deliberate ATT&CK version upgrades — unnecessary complexity for a personal
project with no remote configured yet. Revisit if/when multiple pinned versions accumulate and repo size
becomes a real concern.

#### Deliverables

- `data/attack/enterprise/v19.0/enterprise-attack-19.0.json` — the vendored, immutable artifact.
- `data/attack/enterprise/v19.0/manifest.json` — the frozen acquisition record (attack_kb_version, domain,
  STIX spec, artifact hash/size, STIX collection metadata, object fingerprint, source reference,
  acquisition metadata).
- `data/attack/enterprise/v19.0/NOTICE.md` — ATT&CK Terms of Use attribution (place 1 of 3; place 2 is the
  new "MITRE ATT&CK® attribution" section in the top-level `README.md`; place 3, an analyst-output
  attribution note, is deferred to whichever later gate first renders ATT&CK-derived content).
- `scripts/acquire_attack_bundle.py` — the acquisition tool (network-touching; run only by a human, never
  at runtime; kept out of the installed package). Also serves as independent re-verification: re-running it
  re-downloads via a separate code path (`urllib`, vs. the initial `curl`+ad-hoc-Python check) and
  reproduced the identical SHA-256.
- `src/attribution_platform/attack_knowledge/verification.py` — offline, fail-closed artifact-integrity
  verification (`verify_artifact()` + supporting functions/dataclasses). No technique/group/software query
  API — that is G0.2. No network access anywhere in this module.
- `tests/test_attack_artifact_integrity.py` — 21 tests; combined with the 3 pre-existing G0.0 smoke tests,
  24 total (see the reconciled breakdown below).

#### Verification commands & results

```
ruff format --check .   → 11 files already formatted
ruff check .            → All checks passed!
python -m mypy          → Success: no issues found in 11 source files
python -m pytest -v     → 24 passed
```

Test breakdown (reconciled against the actual test functions — 21 in `test_attack_artifact_integrity.py` +
3 pre-existing in `test_smoke.py` = **24**, matching pytest's `collected 24 items` / `24 passed` exactly):

| Category | Count | Tests |
|---|---:|---|
| End-to-end against the **real** vendored v19.0 artifact | **8** | `test_1_…exists_at_expected_project_path`, `test_2_…sha256_matches…independently`, `test_3_…parses_successfully_as_stix`, `test_4_…collection_metadata_is_enterprise_v19_0`, `test_5_…is_not_the_floating_latest_bundle`, `test_6_…object_fingerprint_is_reproducible`, `test_full_verify_artifact_passes_end_to_end`, `test_verify_artifact_is_deterministic` |
| Fixture-baseline sanity check | **1** | `test_synthetic_fixture_baseline_is_valid` |
| Fail-closed tests, self-consistent synthetic fixtures | **11** | `test_7_fails_closed_on_{missing_artifact, missing_manifest, tampered_artifact_bytes_same_size, tampered_artifact_size, wrong_recorded_hash, wrong_attack_kb_version, floating_filename, tampered_object_fingerprint, tampered_collection_metadata, wrong_domain, wrong_stix_spec}` |
| Untrusted-JSON-input rejection | **1** | `test_load_bundle_objects_rejects_non_bundle_json` |
| Pre-existing G0.0 smoke tests | **3** | `test_package_version_is_defined`, `test_scaffolded_submodules_import_cleanly`, `test_no_network_or_external_service_access` |
| **Total** | **24** | |

(A prior draft of this report miscounted this breakdown as 9+1+12+1+3=26 — an arithmetic error in the
prose summary, not a test-run or test-design discrepancy: pytest's actual collected/passed count was 24
the whole time, and the enumerated fail-closed list above always had exactly 11 items. Corrected here.)

**Independent hash verification:** recomputed via a second, separate acquisition (re-running
`scripts/acquire_attack_bundle.py`, which uses `urllib` — a different code path from the initial `curl` +
ad-hoc Python check) — reproduced the identical SHA-256, confirming no fabrication and genuine
reproducibility.

**Network-disabled verification (not just static inspection):** ran the full test suite with
`socket.socket.connect`/`connect_ex` monkeypatched to raise `RuntimeError` on any connection attempt — all
24 tests still passed. Sanity-checked the block itself was real (not a no-op) by confirming
`scripts/acquire_attack_bundle.py`'s `download()` genuinely fails under the same block.

#### Deviations

One test-design bug found and fixed during implementation (not a `verification.py` bug): a fail-closed test
appended a byte to a fixture to test SHA-256-mismatch detection, but the size check (which correctly runs
before the costlier hash check) fired first. Split into two tests — one same-length tamper (exercises the
SHA-256 check) and one size-changing tamper (exercises the size check) — both pass.

### G0.2 — Reproducible ATT&CK knowledge loading — **IMPLEMENTED (2026-09-11, awaiting review)**
- **Objective:** load **only** the local pinned bundle via `mitreattack-python` into an in-memory,
  queryable knowledge model; **derive** tactics, techniques, sub-techniques, groups, software, campaigns,
  aliases, and relationships from the bundle (nothing hard-coded); expose version+hash.
- **Inputs:** G0.1 artifact + manifest.
- **Outputs:** a knowledge-access module (lookup technique/tactic/group/software/campaign; resolve aliases;
  traverse `uses`/`attributed-to`); version/hash surfaced for the provenance manifest.
- **Work:** loader + query accessors over the pinned STIX; tactic set derived from the bundle (absorbs the
  v19 Stealth/Defense-Impairment split).
- **Tests/verify:** object counts == fingerprint; deterministic load; known-object lookups; **guard test:
  grep/AST check that source contains no hard-coded ATT&CK IDs/tactic names** (enforces the no-hard-code
  rule); offline (no network).
- **Acceptance:** "ATT&CK v19.0 loads reproducibly and is fully queryable; nothing hard-coded" — a headline
  Phase-0 exit criterion.
- **Depends:** G0.1.
- **Env:** no Elastic, no Windows.
- **NOT yet:** no fused evidence graph, no candidate generation, no `D` computation, no graph database.

#### Scope decisions recorded (deviations from the original sketch above)

The original objective (written during planning) mentioned `mitreattack-python` and full alias/relationship
traversal. The **actual implementation gate instructions** (2026-09-11) were more specific and took
precedence where they conflicted, per the "minimal dependencies, deliberately narrow" constraints given at
implementation time:

1. **No `mitreattack-python` (or any new runtime dependency) added.** The loader is **stdlib-only**
   (`json`, `pathlib`, `dataclasses`, `types.MappingProxyType`), built directly on G0.1's `verification`
   module within the same package. Rationale: (a) the gate instructions explicitly said "keep runtime
   dependencies minimal, do not add large frameworks or unnecessary packages" and "do not invent a second
   ATT&CK schema" — `mitreattack-python`'s own object-model wrapper would itself be a second schema layer;
   (b) `mitreattack-python` pulls in `stix2`/`taxii2-client`, and `taxii2-client` exists specifically to
   talk to TAXII servers — unwanted dependency surface for a gate whose entire point is "no live MITRE
   dependency." **This is not a rejection of `mitreattack-python`** — it remains a reasonable option for a
   *later* gate if/when richer STIX object-model conveniences are actually needed; deferred, not ruled out.
2. **No alias resolution, no relationship-traversal logic** (e.g. "techniques used by group G"). Both are
   candidate-generation-adjacent machinery per ADR-0002 (candidate generation collapses aliases and walks
   `uses` edges) — the current gate's forbidden list includes "candidate generation," and building
   traversal/resolution *behavior* now would start encoding that logic prematurely. Raw `relationship`
   objects are exposed as **data** (`AttackKnowledge.relationships()`); traversal *logic* on top of them is
   deferred to whichever later gate (likely alongside G0.3 domain contracts or an attribution-adjacent
   gate) actually needs it.
3. **No re-typed per-object-type dataclasses** (e.g. no `Technique`/`Group` classes with hand-picked
   fields). Objects stay as raw, verified STIX `dict`s, indexed by id and by type — satisfying "preserve
   the authoritative STIX object fields needed by later phases" without guessing which fields matter yet.

These are recorded here per CLAUDE.md principle 12 ("architectural decisions should be documented rather
than silently changed") rather than silently diverging from the original sketch.

#### Deliverables

- `src/attribution_platform/attack_knowledge/loader.py` — `load_attack_knowledge()` (the zero-argument
  runtime entrypoint, hard-wired to the one pinned artifact directory — no path parameter, so no caller can
  redirect it), the internal path-parameterized `_load_from_dir()` (used by the entrypoint and by tests,
  mirroring G0.1's own `verify_artifact(artifact_dir)` testing pattern), and the `AttackKnowledge`
  container: `attack_kb_version`, `attack_kb_sha256`, `attack_domain`, `stix_spec`, `stix_collection`,
  `object_fingerprint`, plus `objects_by_id`/`objects_by_type` (both `MappingProxyType`-wrapped, read-only)
  and thin accessors (`tactics()`, `techniques()`, `sub_techniques()`, `groups()`, `software()`,
  `campaigns()`, `mitigations()`, `relationships()`, `get_by_id()`, `objects_of_type()`). No
  `calibration_version` field exists anywhere on it.
- `src/attribution_platform/attack_knowledge/__init__.py` — updated gate-status docstring (G0.1 and G0.2
  both implemented; domain contracts/candidate generation/attribution explicitly not yet).
- `tests/test_attack_knowledge_loader.py` — 26 tests (see below). `tests/test_attack_artifact_integrity.py`
  (G0.1) is **untouched** — confirmed via `git diff --stat`, zero changes.

#### Verification commands & results

```
ruff format --check .   → 13 files already formatted
ruff check .            → All checks passed!
python -m mypy          → Success: no issues found in 13 source files
python -m pytest -v     → 50 passed  (24 pre-existing G0.0/G0.1 + 26 G0.2)
```

G0.2 test breakdown (26 tests in `test_attack_knowledge_loader.py`):

| Category | Count | Representative tests |
|---|---:|---|
| Pinned bundle loads successfully / no path argument | 3 | `test_default_artifact_dir_resolves_…`, `test_load_attack_knowledge_succeeds`, `test_load_attack_knowledge_takes_no_path_argument` |
| Uses the expected versioned artifact | 4 | `test_loaded_knowledge_reports_the_expected_pinned_version`, `…sha256_matches_the_manifest_on_disk`, `…collection_metadata_is_enterprise_v19_0`, `…has_no_calibration_version_attribute` |
| Deterministic / repeated loading | 4 | `test_repeated_loading_produces_the_same_logical_result`, `test_accessor_counts_match_the_recorded_object_fingerprint`, `test_get_by_id_and_objects_of_type_are_consistent`, `test_loaded_containers_are_read_only` |
| **Deep immutability (added post-audit — see below)** | **7** | `test_object_returned_by_id_rejects_top_level_field_mutation`, `…returned_through_type_index_rejects_mutation`, `…by_id_and_by_type_return_the_identical_frozen_object`, `…nested_dict_fields_are_recursively_frozen`, `…nested_list_fields_are_tuples_not_lists`, `…no_plain_dict_or_list_survives_anywhere…`, `…deep_immutability_on_a_deliberately_nested_synthetic_fixture` |
| Fail-closed via the existing G0.1 verification contract | 4 | `test_loader_accepts_a_valid_self_consistent_fixture`, `test_loader_fails_closed_on_tampered_manifest_hash`, `…on_wrong_pinned_version`, `…on_missing_artifact_directory` |
| No network required | 2 | `test_loader_module_imports_no_networking_libraries`, `test_load_attack_knowledge_works_with_network_forcibly_blocked` |
| Guard: no hard-coded ATT&CK IDs/tactic names | 2 | `test_loader_source_contains_no_hard_coded_technique_or_tactic_ids`, `test_loader_derives_tactics_from_the_bundle_not_a_literal_list` |
| **Total** | **26** | matches `pytest`'s `collected 26 items` exactly (50 total with G0.0/G0.1) |

**Network-disabled verification:** re-ran the *entire* suite (all 50 tests) with `socket.connect`/
`connect_ex` monkeypatched to raise on any connection attempt — all 50 passed, confirming the immutability
fix adds no network dependency either.

#### Immutability audit (2026-09-11, post-implementation review)

A focused audit checked the `AttackKnowledge` immutability claim empirically rather than trusting the
original docstring. **Finding: the original implementation was only shallowly immutable.** The top-level
`objects_by_id`/`objects_by_type` containers were genuinely read-only (`MappingProxyType`/`tuple`), but the
individual STIX objects they contained were **plain, mutable `dict`s** — and nested lists/dicts inside those
objects were plain mutable `list`/`dict` too. Empirically confirmed before fixing:

```python
obj = kb.objects_by_id[some_id]
obj["name"] = "MUTATED"          # succeeded (BAD) — proven with the real v19.0 bundle
obj["x_mitre_contents"][0]["injected"] = "MUTATED"  # succeeded (BAD) — nested mutation too
```

**Fix:** added `_deep_freeze()` to `loader.py` — a recursive transform (`dict` → `MappingProxyType` with
every value frozen; `list` → `tuple` with every element frozen; scalars returned as-is) applied to every
STIX object before it is indexed. `_index_by_id`/`_index_by_type` were replaced by a single
`_freeze_and_index()` so both indices reference the **same** frozen instance per STIX id (no silent
fork into separately-frozen copies). The `AttackKnowledge`/`get_by_id`/`objects_of_type`/accessor type
annotations were updated to a new `FrozenStixObject` type alias (`MappingProxyType[str, Any]`, via Python
3.12's PEP 695 `type` statement) throughout. No new runtime dependency; the raw STIX field structure is
preserved semantically (field names/values unchanged — only container types become immutable, at every
depth). No second ATT&CK schema was introduced.

**Verified genuinely deeply immutable** (not just documented) by seven new tests, including: the exact
audited pattern `knowledge.objects_by_id[id]["name"] = x` (raises `TypeError`); the same on the type-index
path; that `by_id` and `by_type` return the *identical* frozen object; a recursive scanner asserting no
plain `dict`/`list` survives anywhere inside a real loaded object (scans the collection object plus one
representative object per STIX type); and a deterministic synthetic fixture with a deliberately
4-level-deep nested structure (`dict → list → dict → list → scalar`) proving every level rejects mutation,
independent of what the real bundle happens to contain.

**This is a genuine implementation fix, not a documentation change** — per the audit's explicit instruction
not to weaken the claim by editing docs alone. The module docstring was updated only to describe the
now-true guarantee.

**Sanity checks on real loaded data (not hard-coded assumptions):** `test_accessor_counts_match_the_recorded_object_fingerprint`
confirms `len(kb.tactics())`, `techniques()`, `sub_techniques()`, `groups()`, `software()`, `campaigns()`,
`mitigations()`, `relationships()` all equal the independently-computed G0.1 fingerprint fields for the
**real** vendored v19.0 bundle — proving the two categorization paths (verification's `compute_object_fingerprint`
and the loader's `objects_of_type`-based accessors) agree, without asserting anything about which specific
groups/techniques exist (no hard-coded APT actor universe).

#### Deviations

- Initial implementation: a guard test asserted the literal string `"x-mitre-tactic"` appeared in
  `AttackKnowledge.tactics()`'s source text, but `tactics()` correctly delegates to a named module constant
  (`_TYPE_TACTIC`) rather than repeating the literal inline — good design, wrong test. Fixed to check the
  constant's bound value instead.
- Immutability audit: **one genuine implementation gap found and fixed** — see "Immutability audit" above
  (not a mere test-design bug; the original code really did allow mutation below the top level).
- Immutability audit, test-design bug (not an implementation bug): the new deep-immutability fixture test
  initially expected `TypeError` from `tuple.append()`, but tuples have no `.append()` method at all, so
  Python raises `AttributeError` instead. Fixed the test's expectation (`assert not hasattr(x, "append")`
  plus a `TypeError` check on item assignment, which is the operation that actually proves immutability).

**Not yet done (correctly, per scope):** typed domain contracts (G0.3), alias resolution, relationship
traversal logic, any form of candidate generation/attribution/scoring/correlation/attack-chain
reconstruction, API endpoints, Elastic integration, source adapters, Observation/Evidence extraction,
frontend. **Not committed yet** — awaiting review.

### G0.3 — Canonical domain data contracts  *(resolves Q1)* — **IMPLEMENTED (2026-09-13, awaiting review)**
- **Objective:** define the **normalized event contract** (ECS→domain fields needed for the endpoint slice:
  host, user, process, command line, hashes, network, file, registry, timestamps) and the core domain
  schemas: `RawEventRef`, `Observation`, `Evidence`, `TechniqueAssertion`, provenance links, and the version
  manifest — the `L2/L3` contracts from [04](04-component-boundaries.md), scoped to
  **ingestion→evidence only** ([06 entities 1–4](06-evidence-model.md)).
- **Inputs:** [06 evidence model](06-evidence-model.md), G0.2 (technique refs point into the KB).
- **Outputs:** versioned schema definitions + validators; a documented field contract.
- **Work:** author schemas with mandatory `derived_from` provenance and KB-version stamps; keep the mapping
  boundary thin (OTel/OCSF-open per [01 §ECS](01-elastic-stack.md)).
- **Tests/verify:** schema validation round-trips; **guard test: `Observation`/`Evidence` schemas contain no
  source-native field names** (`sysmon.*`, `winlog.*`, collector-specific) — enforces source-agnosticism
  ([12 §D.1.3](12-deployment-and-endpoint-scope.md)); provenance fields required.
- **Acceptance:** contracts validate; source-agnosticism guard passes; Q1 recorded as resolved.
- **Depends:** G0.2.
- **Env:** no Elastic, no Windows.
- **NOT yet:** **no** attribution-side entities (BehavioralFeature, Candidate, EvidenceLink, Hypothesis,
  AttributionAssessment, AttributionResult — [06 entities 5–10](06-evidence-model.md)); those are Phase 2/3.

#### Q1 resolution — the terminology reconciliation with doc 06 (recorded per CLAUDE.md principle 12)

The original objective (above) listed `RawEventRef`, `Observation`, `Evidence`, and `TechniqueAssertion`
per [doc 06](06-evidence-model.md), which was written *before* this gate. Doc 06 framed **Observation as a
detection-rule match** atop a separate **RawEvent**, with `TechniqueAssertion` as a further derived object.
The G0.3 gate instructions (authoritative for Q1) reframe the boundary as: **Observation = normalized
telemetry that came from a source**, and **Evidence = the derived, analyst-meaningful claim** backed by
Observations. These are reconciled as follows (the reconciliation itself is the Q1 decision):

| Concept | doc 06 (earlier) | **G0.3 resolution (this gate, authoritative)** |
|---|---|---|
| raw telemetry | `RawEvent` (stored object) | **Referenced, not stored** — a `SourceRef` pointer on the Observation (`source_type` + `source_event_id` + optional `dataset_ref`/`raw_payload_ref`). Raw bytes never copied into the domain layer. |
| normalized telemetry | (implicit) | **`Observation`** — the normalized event; the source-agnostic boundary object. |
| interpreted claim | `Observation` (detection match) + `Evidence` | **`Evidence`** — a derived claim referencing ≥1 Observation, with optional ATT&CK reference. |
| technique link | `TechniqueAssertion` (separate object) | Collapsed into an **optional `AttackRef` on Evidence** ("where applicable"). A full standalone `TechniqueAssertion` object, and the doc-06 detection-`rule_ref`/`matched_fields` specifics, are **derivation-layer concerns deferred to G0.5** (extraction); `DerivationProvenance.method`/`method_version` generalizes doc 06's `rule_ref`. |

The three levels the gate requires to stay distinct — **raw (referenced) → Observation (normalized) →
Evidence (derived)** — are preserved and never collapsed into one object.

**Final Q1 contract decisions:**
- **Package:** `src/attribution_platform/domain/`, **stdlib-only** (no Pydantic/attrs/etc.).
- **Identity:** all ids are **opaque strings supplied upstream** by the source/adapter or derivation layer;
  the domain **never generates ids** and **never injects wall-clock time** (no `uuid4()`, no `datetime.now()`).
  This keeps construction deterministic (G0.3 §5).
- **Equality/ordering:** value-based (frozen dataclasses); ordering is not meaningful. Provenance
  `source_observation_ids` are canonicalized to a **sorted, de-duplicated tuple** so equality is
  order-independent and serialization deterministic.
- **Timestamps:** `datetime`, **required timezone-aware** (naive rejected fail-closed); optional
  `TimePrecision` enum for declared resolution.
- **Immutability:** **frozen dataclasses + `tuple` only** — no `dict`/`list`/`MappingProxyType` field
  anywhere, so the contracts are deeply immutable *by construction* (exceeds the G0.2 standard, which needed
  a runtime deep-freeze because it wrapped raw JSON). Proven by an exhaustive "no mutable container at any
  depth" test.
- **Raw vs normalized (G0.3 §6):** source-native/raw fields are preserved **by reference** through
  `SourceRef`, **not** via a generic `dict[str, Any]` bag and **not** via hundreds of mandatory fields. The
  Observation carries a *curated* set of optional, ECS-aligned entity groups (`HostRef`, `UserRef`,
  `ProcessRef` + parent lineage, `NetworkInfo`, `FileRef`/`HashSet`, `EventMetadata`); a genuinely new
  *normalized* concept is added by a deliberate contract extension (bump `schema_version`), not an open bag.
- **ATT&CK reference:** `AttackRef` is a pure pointer (`stix_id`, `object_type`, `attack_kb_version`,
  optional `external_id`) — validates STIX-id *shape* only, never loads the KB, never resolves/traverses.
- **Evidence quality vs attribution:** optional `EvidenceQuality` enum describes the *evidence item's own*
  trustworthiness — a closed qualitative vocabulary, **not** a number, **not** ADR-0002 attribution
  likelihood/confidence, with no combination logic. Guard test asserts no `likelihood`/`score`/`ach`/
  `candidate`/`probability`/etc. field exists on any contract.
- **Serialization:** a stdlib-only `to_serializable()` / `to_canonical_json()` (sorted-key, compact) giving
  a deterministic representation for *future* persistence/API — **no** Elastic/FastAPI/DB/Pydantic coupling,
  no API or Elastic mapping built.

#### Contracts created
`SourceRef`, `DerivationProvenance` (provenance.py); `AttackRef` (attack.py); `Observation`
(observation.py); `Evidence` (evidence.py); entity value objects `HashSet`/`FileRef`/`ProcessRef`/`HostRef`/
`UserRef`/`NetworkEndpoint`/`NetworkInfo`/`EventMetadata`/`TimeSpan` (entities.py); enums `EvidenceType`/
`EvidenceQuality`/`TimePrecision` (enums.py); `DomainContractError` + validators (errors.py); serialization
(serialization.py); re-exported from `domain/__init__.py`.

#### Verification commands & results
```
ruff format --check .   → 22 files already formatted
ruff check .            → All checks passed!
python -m mypy          → Success: no issues found in 22 source files (strict)
python -m pytest -v     → 84 passed  (50 pre-existing G0.0/G0.1/G0.2 + 34 new G0.3)
```
Network-disabled re-run (entire suite with `socket.connect`/`connect_ex` raising): **84 passed**. The 34
G0.3 tests cover valid construction of every contract, fail-closed rejection (empty/whitespace ids, naive
timestamps, empty provenance, non-enum evidence type, malformed `AttackRef` shape, reversed/naive
`TimeSpan`), Observation←Evidence provenance linkage, deterministic value-equality + canonical-JSON,
deep immutability at every exposed level (frozen-instance assignment + tuple mutation + exhaustive
"no mutable container anywhere" scan), source-agnosticism (Observation constructs with zero source-specific
fields; no field name encodes a source), and absence of attribution/scoring semantics.

**Dependencies added:** none (stdlib-only). **G0.1/G0.2 unchanged** (`attack_knowledge/`, their tests,
vendored artifact, `.gitattributes` — all confirmed untouched). **No G0.4+ implementation:** `extraction/`,
`sources/`, `dataplane/`, `api/` remain docstring-only scaffolding.

**Deferred to G0.4+ (explicitly not built here):** telemetry collectors / source adapters / normalization
implementations (G0.4); Observation & Evidence *derivation* pipelines and the standalone `TechniqueAssertion`
+ detection `rule_ref`/`matched_fields` mechanics (G0.5); persistence/Elastic mappings (G0.7/G0.8); API
(G0.10); and all attribution-side entities/logic (candidate generation, ACH, likelihood, attribution
confidence, calibration — Phase 2/3). **Not committed yet** — awaiting review.

### G0.4 — Telemetry-source abstraction (adapter interface) — **IMPLEMENTED (2026-09-13, awaiting review)**
- **Objective:** define the **`SourceAdapter` interface** (layers 1–3 → domain contract from
  [12 §D.2](12-deployment-and-endpoint-scope.md)) and the **detection-match record** contract; provide a
  trivial **synthetic-fixture adapter** as the reference implementation.
- **Inputs:** G0.3 contracts.
- **Outputs:** adapter interface; synthetic reference adapter; example fixtures (hand-authored, tiny).
- **Work:** interface for "source-native events → normalized events"; the detection-match contract that the
  extractor consumes.
- **Tests/verify:** synthetic fixture → adapter → normalized events pass schema; **guard: the domain layer
  never imports a source adapter's native types** (dependency direction enforced).
- **Acceptance:** a new source is addable purely as an adapter; nothing above the boundary changes
  ([12 §D.1.6](12-deployment-and-endpoint-scope.md)).
- **Depends:** G0.3.
- **Env:** no Elastic, no Windows.
- **NOT yet:** no real Sysmon/WEL adapters (G0.9); no Elastic.

#### Scope decision: the detection-match record contract moved to G0.5

The original objective (above) bundled the detection-match record contract into G0.4. The actual
implementation instructions (2026-09-13) scoped G0.4 to only the `SourceAdapter` interface + conversion to
`Observation`(s) + one reference adapter, explicitly forbidding "detection logic" at this gate — consistent
with G0.5's own objective ("detection-match record → `Observation`"), where that contract already belongs.
Deferred, not dropped; recorded per CLAUDE.md principle 12.

#### Contracts/deliverables
- `src/attribution_platform/sources/adapter.py` — `SourceAdapter` (a `typing.Protocol`, structural, no
  base-class inheritance required) with two members (`source_type: str`, `to_observations(raw_record) ->
  tuple[Observation, ...]`), and `convert(adapter, raw_record)` — the fail-closed boundary function every
  caller invokes an adapter through.
- `src/attribution_platform/sources/synthetic.py` — `SyntheticSourceAdapter` + `SyntheticRecord`, the
  reference implementation (no real source; proves the interface is genuinely implementable).
- `src/attribution_platform/sources/errors.py` — `SourceAdapterError` (mirrors `ArtifactIntegrityError` /
  `DomainContractError`: each layer owns its own fail-closed error type).

`convert()` enforces, in order: `source_type` present/non-empty; return value is a `tuple`; every element is
an `Observation`; every returned `Observation.raw_reference.source_type` equals the adapter's own declared
`source_type` (an adapter cannot mislabel its own provenance).

#### Verification commands & results
```
ruff format --check .   → 26 files already formatted
ruff check .            → All checks passed!
python -m mypy          → Success: no issues found in 26 source files (strict)
python -m pytest -v     → 96 passed  (84 pre-existing G0.0–G0.3 + 12 new G0.4)
```
12 G0.4 tests: reference-adapter construction/conversion/determinism/rejection of a wrong raw-record type
(5); `convert()` fail-closed on missing/empty `source_type`, non-tuple return, non-`Observation` elements,
and provenance `source_type` mismatch (5); a second, independently-defined adapter (no shared base class)
converts correctly with zero changes to `domain/` or `adapter.py` — the acceptance criterion (1); the
dependency-direction guard — AST scan confirms no `domain/*.py` module imports from `sources` (1).

**Dependencies added:** none (stdlib-only; `typing.Protocol` + `runtime_checkable`). **G0.1/G0.2/G0.3
unchanged** (confirmed via `git diff --stat`). **No G0.5+ implementation:** `extraction/`, `dataplane/`,
`api/` remain docstring-only scaffolding. **Not committed yet** — awaiting review.

### G0.5 — Normalized Observation model + extraction boundary — **IMPLEMENTED (2026-09-13, awaiting review)**
- **Objective:** implement **detection-match record → `Observation`** with provenance (source event refs,
  matched fields, rule ref, entities, time span) — [06 entity 2](06-evidence-model.md).
- **Inputs:** G0.4 (detection-match contract + fixtures).
- **Outputs:** the extraction boundary (`extraction/`) producing `Observation`s.
- **Work:** deterministic extractor over the synthetic detection-match fixtures; a placeholder/minimal
  in-process "match" for the slice (real detection content deferred — CL-1/Q4).
- **Tests/verify:** fixture match → `Observation` with correct provenance to `RawEventRef`s; deterministic;
  `Observation` carries no source-native fields.
- **Acceptance:** observations are produced deterministically with intact provenance.
- **Depends:** G0.4.
- **Env:** no Elastic, no Windows.
- **NOT yet:** no technique mapping yet (G0.6); no real detection engine.

#### Implementation notes (2026-09-13)
- **Contracts:** `src/attribution_platform/extraction/detection_match.py` — `RuleRef` (rule_id +
  rule_version), `MatchedEvent` (observation_id + G0.3 `SourceRef` + tz-aware timestamp + optional G0.3
  entity groups), and `DetectionMatchRecord` (rule_ref + non-empty `matched_events` + optional
  `matched_fields`). `extractor.py` — `extract_observations(record)` producing one `Observation` per matched
  event, in order. `errors.py` — `ExtractionError`.
- **Guarantees:** deterministic (pure function; no wall-clock/ids generated — all supplied by input);
  provenance-preserving (`Observation.raw_reference` *is* the matched event's `SourceRef`, the existing G0.3
  boundary — no new raw-data mechanism); fail-closed with a single typed error (record-level violations at
  construction; per-event `DomainContractError` wrapped as `ExtractionError` with which-event context);
  source-agnostic (generic contract + G0.3 types only).
- **Scope decision (principle 12):** the detection-match record contract sketched under G0.4 lands here in
  G0.5, alongside the extractor that consumes it (its natural home). Recorded in `detection_match.py`.
- **Verification:** `ruff format --check` clean; `ruff check` clean; `mypy` strict — 30 files, no issues;
  `pytest` — **110 passed** (96 prior G0.0–G0.4 + 14 new G0.5). No new dependencies (stdlib-only).
  G0.1–G0.4 code/tests, the vendored ATT&CK artifact, and `.gitattributes` unchanged; `dataplane/`/`api/`
  remain scaffolding (no G0.6+). **Not committed yet — awaiting review.**

### G0.6 — Evidence + ATT&CK technique reference + provenance — **IMPLEMENTED (2026-09-14, awaiting review)**
- **Objective:** **`Observation` → `Evidence`** optionally linked to a technique/sub-technique in the pinned
  KB (G0.2), with the full provenance chain and version stamping — [06 entities 3–4](06-evidence-model.md).
- **Inputs:** G0.5 observations + rule context, G0.2 knowledge, G0.3 contracts.
- **Delivered:**
  - `attack_knowledge/resolution.py` — `resolve_attack_ref(knowledge, ref)`: a bounded, deterministic KB
    lookup validating a G0.3 `AttackRef` against the loaded KB (KB-version match → id exists → resolved
    STIX `type` == `object_type`). Returns the pinned object (a pointer, **no copy/second schema**); fails
    closed with `AttackReferenceError`. No alias resolution / relationship traversal / candidate generation.
  - `extraction/evidence_derivation.py` — `derive_evidence(...)`: a pure function from supporting
    `Observation`s + `RuleRef` to one `Evidence`. Provenance retains the supporting `observation_id`s and the
    rule context (`rule_id`/`rule_version` → `DerivationProvenance.method`/`method_version`). An optional
    `AttackRef` is validated via `resolve_attack_ref` before attachment (an `attack_ref` without a `knowledge`
    to validate against fails closed). All ids/timestamps supplied by the caller — no wall-clock, no generated
    ids. `EvidenceDerivationError` for derivation-level failures and wrapped `DomainContractError`s.
- **Scope decisions (per CLAUDE.md §12):** (1) reused the existing G0.3 `Evidence`/`DerivationProvenance`/
  `AttackRef`/`EvidenceQuality` contracts unchanged — **no domain contract was extended**. (2) Doc 06's
  standalone **`TechniqueAssertion` object is not built**; the ATT&CK link is expressed as the optional G0.3
  `AttackRef` on `Evidence` (the minimal validated form), continuing the collapse recorded at G0.3. (3) The
  derivation *logic* lives in `extraction` (the interpretation step consuming Observations), while Evidence
  *contracts* remain in `domain`; the G0.0 map created no `evidence/` package.
- **Architectural finding — `resolve_attack_ref`'s type check is defence-in-depth:** a well-formed STIX id
  embeds its own type as a prefix, and G0.3 `AttackRef.__post_init__` already requires `object_type` to equal
  that prefix. So against the real KB a *normally-constructed* `AttackRef` can never reach the resolver's
  type-mismatch branch — that mismatch is caught at `AttackRef` construction (covered by G0.3's
  `test_attack_ref_invalid_shapes_rejected`). The resolver's own type check is retained as defence-in-depth
  (guarding against a KB object whose stored `type` disagrees with a truthful-looking id prefix) and is
  tested via a minimal KB stub — see `tests/test_evidence_derivation.py::test_wrong_object_type_rejected`.
- **Verify:** focused `tests/test_evidence_derivation.py` — **14 passed** (valid derivation; provenance
  preservation of observation ids + rule context; valid technique **and** sub-technique references against the
  real v19.0 KB; nonexistent-reference rejection; wrong-object-type rejection via stub; KB-version mismatch;
  determinism incl. canonical-JSON equality; fail-closed paths; no hard-coded technique/tactic ids in the
  G0.6 source). Full suite **124 passed** (110 prior + 14). `ruff format --check` + `ruff check` clean;
  **mypy strict** clean (33 files). No new dependencies (stdlib-only).
- **G0.1–G0.5 unchanged:** no prior source/test/artifact files modified; only two `__init__.py` docstrings +
  re-exports added for the new modules. **Not committed yet — awaiting review.**
- **Depends:** G0.5, G0.2, G0.3.
- **Env:** no Elastic, no Windows (this is the Elastic-free logic core).
- **NOT yet:** **no** BehavioralFeature/Candidate/ACH/scoring/likelihood/confidence/attribution; no
  correlation, attack chains, alias resolution, or relationship traversal.

### G0.7 — Reproducible local deployment (Compose)  *(platform bring-up; precedes Elastic integration)*
- **Objective:** a **Docker Compose** definition that brings up **single-node Elasticsearch + Kibana**
  (Basic tier, security on) on a WSL2/Docker-compatible runtime, per
  [C0.2 §E](12-deployment-and-endpoint-scope.md); pinned image versions; a **constrained 8 GB profile**
  variant. This gate exists **before** Elastic integration because that gate needs a running cluster. The
  Attribution Engine + API service containers are **slotted into this same compose as they land (G0.8/G0.10)**
  — ES + Kibana come up first.
- **Inputs:** G0.0 scaffolding; the accepted deployment shape ([C0.2](12-deployment-and-endpoint-scope.md)).
- **Outputs:** compose definition(s) (ES + Kibana now; app services added later), pinned versions,
  bring-up/tear-down docs.
- **Work:** author compose with security on, modest ES heap, Kibana optional; no Docker-Desktop-specific
  lock-in ([C0.2 §H](12-deployment-and-endpoint-scope.md)).
- **Tests/verify:** one-command bring-up yields a reachable, authenticated ES; reproducible across a
  compatible runtime.
- **Acceptance:** the platform stack (ES + Kibana) comes up reproducibly on the accepted deployment shape.
- **Depends:** G0.0. **(Must precede G0.8.)**
- **Env:** this gate **is** the Elastic bring-up; no Windows.
- **NOT yet:** no multi-node/HA; no frontend container (frontend not built); no paid tier; app-service
  containers added in later gates.

### G0.8 — Initial Elastic data-plane integration
- **Objective:** a thin Elastic client against the running cluster: `_bulk` write + query; deterministic
  index mappings; persist normalized events / observations / evidence / technique-refs.
- **Inputs:** G0.6 domain objects; **G0.7 (running ES + Kibana)**.
- **Outputs:** ES client module; index mapping definitions; round-trip persistence.
- **Work:** connect, create mappings idempotently, write/read domain objects; record Elastic `_index/_id` as
  provenance ([03 stage 1](03-system-data-flow.md)).
- **Tests/verify:** write→read round-trip; mappings created reproducibly; provenance ids captured; runs
  against the disposable single-node instance from G0.7.
- **Acceptance:** domain objects persist to and load from Elastic deterministically on the Basic tier.
- **Depends:** G0.6, G0.7.
- **Env:** **requires Elastic**; no Windows.
- **NOT yet:** no paid features; no detection-rule content (Q4/Phase 1); no attribution indexes.

### G0.9 — Synthetic / replay ingestion path
- **Objective:** hand-authored synthetic fixtures → **`_bulk` into Elastic** → the identical downstream
  pipeline (extraction → Observation → Evidence → technique ref → persist), per
  [03 replay mode](03-system-data-flow.md).
- **Inputs:** synthetic fixtures (G0.4), G0.8.
- **Outputs:** a replay loader; a reproducible end-to-end synthetic run.
- **Work:** dataset-relative (deterministic) ingestion; content-hash the fixture set.
- **Tests/verify:** full synthetic run is reproducible (determinism hash stable); no Windows needed; CI-able.
- **Acceptance:** the reproducible replay path works end-to-end on synthetic data.
- **Depends:** G0.8, G0.6.
- **Env:** **requires Elastic**; **validated entirely with synthetic data**; no Windows.
- **NOT yet:** **no external dataset acquisition** (Security-Datasets/EVTX/CALDERA deferred — CL-3).

### G0.10 — API boundary (read-model)
- **Objective:** a minimal **read-model API** exposing stored observations / evidence / technique-refs **with
  provenance** — the `L3 → L4` contract from [04](04-component-boundaries.md).
- **Inputs:** G0.8 persistence.
- **Outputs:** read endpoints returning JSON read models; provenance ids preserved so a consumer can drill to
  raw events.
- **Work:** thin API serving stored objects; **no computation in the API**.
- **Tests/verify:** endpoint returns a persisted evidence→technique record with full provenance; contract
  is stable and documented.
- **Acceptance:** the future frontend's data contract exists and is serveable — **rendering only, no logic**.
- **Depends:** G0.8.
- **Env:** **requires Elastic**; no Windows.
- **NOT yet:** **no attribution endpoints**; **no frontend files** ([ADR-0001 D11](adr/0001-evidence-graph-core-architecture.md)).

### G0.11 — Initial Windows telemetry ingestion path
- **Objective:** a **native Windows collector** (Sysmon + Windows Event Logs via Elastic Agent *or*
  Winlogbeat — [C0.2 §F](12-deployment-and-endpoint-scope.md)) → ECS into Elastic → the same pipeline; prove
  Windows→ES across the WSL2 boundary.
- **Inputs:** G0.8; a Windows endpoint (the dev host, benign activity only).
- **Outputs:** a documented collector setup; a Windows→Elastic ingest proof; a Windows/Sysmon source adapter
  (its specifics confined to layer 3).
- **Work:** install Sysmon + collector natively; bind ES to a WSL2-reachable address; ship a small sample of
  **benign** Windows telemetry.
- **Tests/verify:** real Windows events land as ECS and flow to Observations via the *same* extractor;
  source specifics stay in the adapter (guard).
- **Acceptance:** Windows telemetry enters through the identical normalization boundary as synthetic data.
- **Depends:** G0.8.
- **Env:** **requires Elastic + a Windows endpoint.**
- **NOT yet:** **no live adversary emulation** (isolated VM only, [C0.2 §J](12-deployment-and-endpoint-scope.md));
  not on the first-slice critical path; collector choice may be finalized here.

### G0.12 — Automated tests & validation gates (cross-cutting)
- **Objective:** the standing verification suite: **determinism** tests, **provenance-integrity** tests
  (every derived object resolves to raw refs), the **no-hard-coded-ATT&CK** guard, the
  **source-agnosticism** guard (no source-native fields above the boundary; adapter dependency direction),
  schema validation, and the **headless replay** test for the first slice.
- **Inputs:** all gates (each contributes its tests).
- **Outputs:** a CI pipeline running the Elastic-free suite always, and Elastic-dependent tests via a
  service container where feasible.
- **Work:** assemble guards + determinism harness; wire CI.
- **Tests/verify:** the suite fails loudly on a hard-coded ATT&CK id, a source-native field above the
  boundary, a broken provenance chain, or a non-deterministic result.
- **Acceptance:** all constraint-guards are enforced automatically.
- **Depends:** threads through G0.0–G0.11.
- **Env:** Elastic-free parts need nothing; integration tests require Elastic.
- **NOT yet:** no attribution-correctness metrics (needs the corpus + calibration — Phase 3).

---

## Environment matrix

| Gate | No Elastic | Requires Elastic | Requires Windows endpoint | Validatable with replay/synthetic only |
|---|:--:|:--:|:--:|:--:|
| G0.0 scaffolding | ✅ | | | ✅ |
| G0.1 ATT&CK acquire/verify | ✅ (network once) | | | ✅ |
| G0.2 ATT&CK load | ✅ | | | ✅ |
| G0.3 domain contracts | ✅ | | | ✅ |
| G0.4 source abstraction | ✅ | | | ✅ |
| G0.5 Observation/extraction | ✅ | | | ✅ |
| G0.6 Evidence + technique ref | ✅ | | | ✅ |
| G0.7 Compose deployment | | ✅ | | ✅ |
| G0.8 Elastic integration | | ✅ | | ✅ |
| G0.9 synthetic/replay ingest | | ✅ | | ✅ |
| G0.10 API read-model | | ✅ | | ✅ |
| G0.11 Windows ingest | | ✅ | ✅ | ❌ (needs Windows) |
| G0.12 tests/validation | partial ✅ | integration parts | | ✅ (except G0.11 tests) |

**Everything except G0.11 is validatable with replay/synthetic data.** Only **G0.11** requires a Windows
endpoint, and it is deliberately **off the first-slice critical path**.

---

## Dependency graph / build order

Numeric order now equals dependency/build order; the graph shows the branches and the one cross-branch
edge (Compose **G0.7** must precede Elastic integration **G0.8**):

```
G0.0 scaffolding
  ├─► G0.1 ATT&CK acquire/verify ─► G0.2 ATT&CK load ─┐
  │                                                    ▼
  ├────────────────────────────► G0.3 domain contracts   (needs G0.2 for technique refs)
  │                                └─► G0.4 source abstraction
  │                                      └─► G0.5 Observation/extraction
  │                                            └─► G0.6 Evidence + technique ref
  │                                                   ← END OF ELASTIC-FREE LOGIC CORE
  └─► G0.7 Compose (bring up ES+Kibana) ─► G0.8 Elastic integration ◄── G0.6
                                                 ├─► G0.9 synthetic/replay ingest ─┐
                                                 ├─► G0.10 API read-model          │
                                                 │                                 ▼
                                                 │   ★ FIRST VERTICAL SLICE
                                                 │     (G0.6 logic × G0.8 × G0.9 × G0.10; on the G0.7 stack)
                                                 └─► G0.11 Windows ingest  (parallel; after the slice; needs Windows)
G0.12 tests/validation                            (threads through all gates)
```

**Rule:** finish the **Elastic-free logic core (G0.0→G0.6)** and prove it deterministically **before**
standing up Elastic. **G0.7 (Compose) brings up the cluster and must precede G0.8 (Elastic integration)** —
this is the one cross-branch dependency. G0.11 (Windows) comes after the slice.

---

## First Vertical Slice

**The smallest complete, trustworthy path — and it performs NO attribution.**

```
hand-authored synthetic fixture (ECS-shaped events + a detection-match record)
  → G0.9 replay ingest (_bulk into single-node Elastic)
  → G0.5 extraction boundary (detection match → Observation, with provenance)
  → G0.6 Observation → Evidence → TechniqueAssertion (references a v19.0 ATT&CK technique)
  → provenance chain intact (Evidence → Observation → RawEventRef → Elastic _id) + version manifest
  → G0.8 persist to Elastic
  → G0.10 API returns the evidence→technique record with full provenance
```

- **Composed of:** G0.6 (logic) + G0.8 (persistence) + G0.9 (replay ingest) + G0.10 (API), with G0.2 (KB)
  supplying the technique reference and G0.12 asserting determinism/provenance/guards.
- **Requires:** Elastic (G0.7 Compose bring-up). **Does NOT require** a Windows endpoint (replay/synthetic only).
- **Explicitly excludes:** BehavioralFeature, candidate generation, ACH, likelihood, confidence, scoring,
  `D`, correlation, attack chains, the frontend, and any graph database. The slice ends at **"here is an
  evidence item that references ATT&CK technique T, and here is the exact raw event it came from."**
- **Why this slice:** it exercises every architectural boundary (source→normalization→Observation→Evidence→
  technique ref→persistence→API) end-to-end while remaining deterministic and attribution-free — the minimum
  trustworthy foundation the accepted architecture demands, and the concrete antidote to the previous
  version's "disconnected/hard-coded" failure.

---

## What must NOT be implemented in Phase 0 (global)

- The **attribution engine**: no BehavioralFeature, Candidate generation, ACH, `EvidenceLink` support/
  contradiction, Hypothesis, `AttributionAssessment`, `AttributionResult`, `D`/discriminating power,
  likelihood, or confidence. (These are Phase 2/3, and only after the scoring spec's calibration prerequisites.)
- **No arbitrary weights**; **no merging of likelihood and confidence** (they don't exist yet).
- **No correlation or attack-chain reconstruction** (Phase 2).
- **No graph database** (embedded-first per [ADR-0001 D9](adr/0001-evidence-graph-core-architecture.md); Phase 0
  needs only in-memory KB + persisted domain objects).
- **No frontend** ([ADR-0001 D11](adr/0001-evidence-graph-core-architecture.md)).
- **No external dataset acquisition** (CL-3) and **no live adversary emulation** ([C0.2 §J](12-deployment-and-endpoint-scope.md)).
- **No enrichment/TI** integrations (Phase 4).
- **No paid Elastic features.**

---

## Phase 0 exit criteria

Phase 0 is complete when: (1) ATT&CK v19.0 loads reproducibly with nothing hard-coded (G0.2); (2) the
domain contracts + source-agnostic boundary exist and their guards pass (G0.3/G0.4); (3) the Elastic-free
logic core produces a provenance-complete, deterministic evidence→technique reference (G0.6); (4)
reproducible local deployment works (G0.7); (5) the **first vertical slice runs end-to-end on synthetic data
through Elastic and the read-model API** (G0.8/G0.9/G0.10); (6) the full guard/determinism suite is green in
CI (G0.12). G0.11 (Windows ingest) may trail the slice but should complete before Phase 1 relies on live
Windows telemetry.

---

## PHASE 0 STATUS: PLANNED — FINAL PLAN REVIEWED

*(Implementation still not started. Corrections applied: C0.1 vendoring recorded as decided — executed by
G0.1, not an owner choice; gate numbering now runs in dependency order, with the Compose bring-up (G0.7)
preceding Elastic integration (G0.8) made explicit in the dependency graph.)*

### 1. Phase 0 gates in order
Gate numbers now run in dependency/build order:
G0.0 scaffolding → **G0.1 ATT&CK acquire/verify** → G0.2 ATT&CK load → G0.3 domain contracts → G0.4 source
abstraction → G0.5 Observation/extraction → G0.6 Evidence + technique ref *(end of Elastic-free logic core)*
→ G0.7 Compose deployment (brings up ES+Kibana) → G0.8 Elastic integration → G0.9 synthetic/replay ingest →
G0.10 API read-model *(G0.8+G0.9+G0.10 = FIRST VERTICAL SLICE, on the G0.7 stack)* → G0.11 Windows ingest
*(parallel/after; only gate needing a Windows endpoint)*; G0.12 tests/validation threads throughout.

### 2. First implementation gate
**G0.0 — repository scaffolding & CI skeleton** (the mechanical prerequisite), immediately followed by
**G0.1 — pinned ATT&CK v19.0 acquisition & verification** (the first *substantive* domain gate). Both are
Elastic-free and Windows-free.

### 3. Remaining blockers
**None hard.** Documented dependencies to respect (not blockers): CL-1 (Phase-0 detection is a fixture-fed
boundary; real content is Phase 1/Q4), CL-2 (Q1 is resolved *by* G0.3), CL-3 (external corpus + attribution
correctness are out of Phase 0), CL-4 (ATT&CK hash captured at G0.1), CL-5 (collector choice deferred to
G0.11). **ATT&CK vendoring is NOT a blocker or an owner decision — it is the accepted C0.1 decision that
G0.1 executes.**

### 4. Recommended model for the first implementation gate
For **G0.0** (mechanical scaffolding + CI) and **G0.1** (scripted acquisition/hashing) — deterministic,
low-ambiguity work — a **fast, capable general model (Sonnet-class)** is the right fit. Reserve a
**deeper-reasoning model (Opus-class)** for the **contract/boundary-design gates G0.3, G0.4, and G0.6**,
where getting the domain schema, source-agnostic boundary, and provenance model right has the highest
long-term leverage.

*No application code, Dockerfiles, compose files, Elastic config, indexes, API, or frontend were created. No
ADR created or changed. C0.1/C0.2 unchanged. ATT&CK bundle not vendored; no datasets acquired.*

---

## Progress update (2026-09-13): G0.0–G0.2 checkpointed; G0.3 implemented, awaiting review

The section above is the historical planning-review snapshot from before implementation began; it is left
as-is for the record. Since then:

- **G0.0 IMPLEMENTED/PASSED** (checkpointed at commit `c6d31a3`) — see the G0.0 entry above.
- **G0.1 IMPLEMENTED/PASSED** (checkpointed at commit `2eea5f3`) — see the G0.1 entry above: the pinned
  MITRE ATT&CK Enterprise v19.0 STIX 2.1 bundle is vendored, hash-verified, offline-verifiable, and
  attributed.
- **G0.2 IMPLEMENTED/PASSED** (checkpointed at commit `f649e1f`) — see the G0.2 entry above: the
  deterministic runtime loader (`load_attack_knowledge()`), deeply immutable, built on the verified G0.1
  artifact.
- **G0.3 IMPLEMENTED, AWAITING REVIEW (not yet checkpointed/committed)** — see the G0.3 entry above: the
  source-agnostic domain contracts (`Observation`, `Evidence`, `SourceRef`/`DerivationProvenance`,
  `AttackRef`, entity value objects, enums, serialization), resolving Q1. **Not marked PASSED** until
  reviewed and accepted, per this gate's explicit instruction.
- **Next gate (after G0.3 review): G0.4 — telemetry-source abstraction (adapter interface).**
- All other Phase-0 gates (G0.4–G0.12) remain **not started**. No Dockerfiles, compose files, Elastic
  config, indexes, API, source adapters, or frontend exist. No ADR created or changed; C0.1/C0.2 unchanged.
