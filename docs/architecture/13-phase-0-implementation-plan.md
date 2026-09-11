# 13 — Phase 0 Implementation Plan

**Status: PLANNED — implementation NOT started.** Translates the accepted architecture
([ADR-0001](adr/0001-evidence-graph-core-architecture.md),
[ADR-0002](adr/0002-attribution-scoring-and-evidence-methodology.md),
[C0.1 §11](11-attack-knowledge-versioning.md), [C0.2 §12](12-deployment-and-endpoint-scope.md)) into small,
independently verifiable gates. This document is **planning only**: no code, Dockerfiles, compose files,
Elastic config, indexes, API, frontend, dataset acquisition, or ATT&CK vendoring were created.

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

### G0.1 — Pinned ATT&CK v19.0 acquisition & verification
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

### G0.2 — Reproducible ATT&CK knowledge loading
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

### G0.3 — Canonical domain data contracts  *(resolves Q1)*
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

### G0.4 — Telemetry-source abstraction (adapter interface)
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

### G0.5 — Normalized Observation model + extraction boundary
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

### G0.6 — Evidence + TechniqueAssertion + provenance  *(logic core of the first slice)*
- **Objective:** **`Observation` → `Evidence` → `TechniqueAssertion`** that references a technique in the
  pinned KB (G0.2), with the full provenance chain and version stamping — [06 entities 3–4](06-evidence-model.md).
- **Inputs:** G0.5 observations, G0.2 knowledge.
- **Outputs:** evidence + technique-assertion objects; a `determinism_hash` over the canonical result.
- **Work:** deterministic mapping from an observation to an evidence item and a **referenced** ATT&CK
  technique (reference only — **no scoring, no diagnosticity, no weights**); assemble the provenance manifest.
- **Tests/verify:** synthetic fixture → Observation → Evidence → TechniqueAssertion resolving a real v19.0
  technique; **provenance walks back to the raw event ref**; same inputs+versions ⇒ identical
  `determinism_hash`.
- **Acceptance:** an evidence→technique reference exists, is fully traceable, and is reproducible — **with no
  attribution performed**.
- **Depends:** G0.5, G0.2, G0.3.
- **Env:** no Elastic, no Windows (this is the Elastic-free logic core).
- **NOT yet:** **no** BehavioralFeature/Candidate/ACH/scoring/likelihood/confidence.

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
