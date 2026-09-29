# ADR-0009 — Read-model API v1: investigations, attribution units and uncalibrated attribution analysis

- **Status:** ACCEPTED (2026-09-29, owner delegation "go ahead" on the recommended API task)
- **Builds on:** ADR-0001 D11 (the API performs no computation), doc 02 / doc 04 (read-model API between the
  engine and the analyst frontend), G0.10 (the Phase-0 read-model server: `GET /observations/{id}`,
  `GET /evidence/{id}`), ADR-0003/0004 (correlation groups, behavioral sequences), ADR-0005 (candidates, ACH,
  comparative evidence), ADR-0006 (calibration — not yet available).

## Context

The engine now turns real recordings into attribution units (correlation groups + behavioral sequences) and runs
the Gate 3.3–3.5 attribution stages on them. Only Observations, Evidence, links, groups and sequences are persisted;
candidates, the ACH matrix and the comparative evidence are computed in memory and lost. Calibration (ADR-0006) is
blocked on corpus size, so no likelihood, confidence, WEP band or abstention verdict exists. The frontend and any
analyst need a stable read model of what *is* real and validated — without any number the methodology cannot yet
justify.

## Decisions

**D1 — The API stays a pure read model.** It reads persisted objects and returns them; it computes nothing
(ADR-0001 D11). Everything it serves is produced and persisted by the engine.

**D2 — Investigations are engine runs.** `investigation/` runs the unmodified pipeline over one source (a pinned
recording or a replay fixture) and persists every result: the Evidence and their Observations, all structural and
contextual links, every correlation group, every behavioral sequence, one **attribution analysis** per group, and
one **Investigation** record: id, source (id, kind, SHA-256), the pinned versions used (ATT&CK KB, Sigma pack
content hash, method versions), counts, and the unit (group) ids. The investigation id is a deterministic hash of
the source digest and the versions, so re-running the same inputs overwrites the same records (idempotent).
Context Observations (no Evidence) are not persisted — the recording archive itself remains the reference.

**D3 — Attribution analysis read model, explicitly uncalibrated.** Per unit: every candidate (Group or Campaign
id, name, generation basis), and per hypothesis its supporting contributions exactly as ADR-0005 computes them
(feature technique ids, diagnosticity outcome, `g`, `D`, contribution value, grounding ACH assessment ids), its
support value and profile breadth; the unit's observed decision features and the candidate-independent
`Unattributed` baseline (Amendment B §B2). Every analysis carries a mandatory
`calibration = {status: "uncalibrated", calibration_version: null, note}` block. **No likelihood, confidence, WEP
band, abstention verdict or rank is emitted**; hypotheses are listed in id order, not by support, so no ordering
implies a verdict. When a `calibration_version` exists (ADR-0006), a later amendment adds the calibrated decision.

**D4 — Transport: the Phase-0 stdlib server, extended.** Read-only JSON over `GET`, bound to `127.0.0.1` by
default, no new dependency (FastAPI stays a reasonable later transport; the read-model functions are
transport-independent). v1 routes:

| Route | Returns |
|---|---|
| `GET /health` | service and backend status |
| `GET /investigations` | investigation summaries |
| `GET /investigations/{id}` | one Investigation record |
| `GET /units/{group_id}` | the unit: correlation group, its behavioral sequence and its attribution analysis |
| `GET /observations/{id}`, `GET /evidence/{id}` | unchanged (G0.10) |

**D5 — Errors and safety.** The G0.10 typed errors (400 invalid id, 404 not found, 502 backend) apply to every
route; no mutation routes exist; no authentication in v1 because the server binds to localhost only (a remote
deployment requires an authentication amendment first).

## Consequences

- Every value an analyst or the frontend sees is traceable to a persisted engine object and its provenance.
- The UI cannot show an uncalibrated confidence by construction: the field does not exist.
- Persisting a large recording's units (e.g. a 9,000-step CALDERA agent chain) is bounded by what the engine already
  computes; context Observations are deliberately not duplicated into Elasticsearch.

## Implementation record (2026-09-29)

- `investigation/` — `run_investigation(source, …)` (recording or fixture) persists Evidence + Observations, all
  links, groups, sequences, one `AttributionAnalysisRecord` per unit and the `InvestigationRecord`; ids are
  deterministic (source digest + ATT&CK KB + detection-pack hash + method versions). New indices
  `attribution-platform-investigations-v1`, `attribution-platform-attribution-analyses-v1`.
- `api/` — `GET /health`, `/investigations`, `/investigations/{id}`, `/units/{group_id}` added to the G0.10 routes
  (stdlib server, localhost, GET only; `POST` → 501). Read-model functions return persisted data unchanged.
- *Guarantee tested:* no key containing likelihood / confidence / wep / verdict / rank / probability exists in any
  served analysis; hypotheses are in id order; `D = 1 − g` on every contribution; re-runs give the same id.
- *Real data:* OTRF APT3 Empire investigated in ≈2 min (4 units, 33 Evidence) and served through the live API — the
  main unit is a 12-step chain (T1033, T1202, T1059, T1059.001, T1685) whose 130 candidates include APT3, each with
  its contribution breakdown, all marked uncalibrated.
- 8 new tests (engine run, determinism, fixture sources, HTTP routes, typed errors); 1,792 tests pass.
