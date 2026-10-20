# ADR-0016 — The analyst frontend: a reader over the read-model API

- **Status:** ACCEPTED (2026-10-11, owner instruction: build the frontend from the Stitch designs; "your job
  is connecting everything properly … most important the site should be working and providing solutions
  correctly").
- **Builds on:** ADR-0001 D11 (the frontend renders what the API returns and computes nothing), ADR-0009 (read-model
  API v1, uncalibrated analyses, the dossier), ADR-0005 (g, D, the unattributed baseline, collection guidance),
  ADR-0007 / ADR-0015 (detection content and its coverage report), ADR-0013 (indicators are context),
  CLAUDE.md ("frontend functionality must connect to real backend functionality"; "visual polish must never take
  priority over correctness"; "never hard-code attribution results").

## Context

The previous version of this project had a polished frontend over simulated results. This one was built in the
opposite order: the backend is complete and measured, and the frontend arrives last, as a reader.

The visual design came from Google Stitch (seven screens; prompt in `docs/frontend/stitch-prompt.md`). Stitch
produces static HTML with invented content. Kept: the layout, the type scale, the colour tokens, the component
shapes. **Removed, because nothing in the backend states it:** every confidence/likelihood/score label
("Actor Confidence: High", "Confirmed attribution", "94.2 % verified", "Coverage score", "Ranked by information
gain"), every action the backend does not have (re-evaluate, ingest, export STIX/PDF, notifications, settings, a
user profile), every invented version string, latency, throughput number, host address, investigation, actor,
blocker and narrative sentence, and the coverage figures (Stitch drew 92/41/33/18; the committed report says
314/17/4/100/63 for group-used techniques).

## Decisions

### D1 — The frontend computes nothing the backend did not

It joins and groups records for display (`frontend/src/lib/derive.ts`, unit-tested) and nothing else. The only
arithmetic on attribution data is `n of m` and `g = groups_using / active_groups`, `D = 1 − g` for a technique —
the dossier's own formula over the same catalogue numbers. There is no type for a likelihood, confidence or rank in
`frontend/src/lib/api.ts` because the API has no such field to mirror.

### D2 — The uncalibrated rule is structural, not a label

- Candidates are ordered by name, in one function (`candidateRows`), with a test that they are not ordered by
  support. No control in the UI sorts them otherwise; filters (kind, "uses technique X", name) only narrow.
- A candidate's `support_value` and per-feature contributions are shown only inside an expanded row, beside the
  text that they are ADR-0005's uncalibrated quantities, not probabilities, and never an ordering.
- The matrix states one fact per cell: ATT&CK records this candidate using this observed technique, or does not.
- "UNCALIBRATED — explainable facts only" is in the top bar and sidebar on every page; the unit header repeats it,
  and the stored `calibration_note` is shown verbatim.
- Collection-guidance questions are shown in the stored order (ADR-0005 Amendment E: by `split`), described as
  such; that orders *evidence to look for*, not actors.
- Indicator matches are a separate tab headed "Context only — not part of attribution", with the publisher's
  sentence quoted and the validity window stated.

### D3 — Four reference reads are added to the API (all read-only)

The stored records lack three things the screens need. Each comes from a pinned artefact already in the
repository; none is computed for the UI.

| Route | Returns | Source |
|---|---|---|
| `GET /units/{id}/evidence` | the unit's Evidence (time order), the Observations they are grounded in, and for each rule its origin (Sigma / Elastic), title, upstream URL, content tier, log sources, whole/partial translation | stored records + the two import reports |
| `GET /investigations/{id}/dossier` | `{markdown, dossier_version}` — `render_dossier`, unchanged | stored records + ATT&CK KB |
| `GET /coverage` | the committed coverage report (per-Group "uncovered" lists dropped: they repeat the technique rows), each content source's import summary and most frequent non-translation reasons, translated-rule counts per log source | `coverage-report.json` + the two import reports |
| `GET /attack/techniques` | active techniques with tactics (matrix order), platforms and the number of active Groups using each | pinned ATT&CK KB |

`api/context.py` reads these once into an `ApiContext` passed to `create_server(..., context=)`. A server without
a context is exactly the previous API; the reference routes then answer 404 "not available". A rule the import
reports do not list is absent from `rules` — never guessed. An import-report row states its content tier only
when it is not the importer's default (`core`), and the context applies that same default.

### D4 — One address serves both; the frontend routes by URL fragment

Every route also answers under `/api`. With a built frontend (`frontend/dist`), the same stdlib server returns
`/`, `/index.html`, `/assets/*` as files — resolved inside the directory or refused (tests cover traversal
forms). The frontend routes by fragment (`#/units/<id>/evidence`), so no page path can collide with a JSON route,
identifiers containing `:` and `/` are just percent-encoded segments, and no SPA fallback rule is needed. In
development Vite serves the frontend and proxies `/api` to the Python server.

### D5 — Stack

React 18, TypeScript (strict, `noUncheckedIndexedAccess`), Vite, Tailwind CSS 4 with the Stitch tokens as
`@theme` variables, `lucide-react` icons, `react-markdown` + `remark-gfm` for the dossier, Geist and JetBrains
Mono self-hosted via `@fontsource` (no request leaves the machine). No router, state or data-fetching library:
a 60-line fragment router and one cached `useApi` hook are enough for seven read-only pages. `npm audit`: 0
findings at the time of writing. Dark theme only (the design has no light variant).

### D6 — States are part of the product

Every read has four outcomes and each has a screen: loading (skeleton), empty ("No units — no detection matched
this recording" is a result, and says so), not found (the API's own message, and that in-memory sessions end with
the server), and failure (the API's message verbatim; when the API does not answer at all, the command that
starts it). The health indicator polls `GET /health` and reports the API and its store separately.

## Screens and what backs them

| Screen | Reads |
|---|---|
| Investigations | `/investigations` |
| Investigation (metadata, host timeline, units table) | `/investigations/{id}`, `/investigations/{id}/units` |
| Unit workspace — Overview, Attack sequence, Evidence, Techniques, Candidate actors, What evidence would help, Indicator context, Provenance | `/units/{id}`, `/units/{id}/evidence`, `/attack/techniques`, `/investigations/{id}` |
| Units search | `/units?investigation=&technique=&host=&candidate=` (filtering is done by the API) |
| Detection coverage | `/coverage`, `/attack/techniques` |
| Attribution dossier (rendered / Markdown, contents, copy, download, print) | `/investigations/{id}/dossier` |
| About & provenance | `/coverage` (provenance), `/attack/techniques`, `/health` |
| Global search (Ctrl+K) | `/investigations`, `/attack/techniques`; opens Units search with an exact filter |

## Consequences

- The CLI accepts several recordings in one session (`investigation a b c --serve`); the pinned content is loaded
  once (`load_workbench`).
- The frontend has a build step and a `node_modules` tree; neither is needed to run investigations or the API.
  `frontend/dist` and `node_modules` are git-ignored; the lockfile is tracked.
- Not built, deliberately: authentication (the server binds to localhost and is read-only), any mutation, any
  export the backend does not produce, a light theme, phone layouts.

## Verification

- Python: `tests/test_frontend_api.py` — the catalogue and coverage bodies equal their pinned artefacts; evidence
  joins are complete and time-ordered; the dossier route returns `render_dossier` byte for byte; `/api` aliases
  every route; static serving refuses traversal; reference routes need a context; no decision-field key appears.
- Frontend: `npm run typecheck`, `npm test` (view shaping: alphabetical candidates, feature/context split,
  sequence layering, timeline lanes, fragment round-trip of awkward identifiers), `npm run build`.
- `scripts/audit_served_read_model.py` against the running server (ADR-0009 Amendment D4).
- In the browser against real investigations of pinned OTRF recordings — see the implementation record below.

## Implementation record (2026-10-11)

One session serving four pinned recordings (`otrf-lsass-01-logonpasswords`, `otrf-lsass-03-comsvcs`,
`otrf-apt29-day1`, `otrf-apt3-empire`): 4 investigations, 148 units, 2,900 Evidence items (2,413 in units).

- **Served statements, recomputed independently:** 40,848 checks, all passing — every in-unit Evidence's rule
  re-evaluated on its served Observation (2,413), every technique's g against the knowledge base, every unit's
  candidate set and every matrix cell against ATT&CK `uses` relationships, collection-guidance users and splits,
  unit summaries, search filters, sequence integrity, coverage counts.
- **Rendered pages against the API:** 1,184 pages (every unit × every tab) driven in the browser, comparing
  rendered rows, candidate order, matrix dots, steps, technique cards and guidance cards with the API responses;
  no script error, no mismatch, slowest page 0.9 s.
- **What the audit changed** (it is why these are listed here and not assumed): Evidence outside units was
  uncounted and the dossier misstated it; a technique with core Evidence that no Group or Campaign uses was not a
  decision feature and would have been labelled "context"; lineage edges can run against timestamp order and are
  now drawn and described as such; the Empire recording could not be investigated at all; raw telemetry restyled
  the rendered dossier; a 541-step unit has 24,688 ordering edges, so sequences beyond 60 steps or 400 lines are
  listed in time order instead of drawn. Backend parts are ADR-0009 Amendment D.
- **Removed as not earning their place:** a second "uncalibrated" badge in the top bar, an animated health pulse,
  a "Pages" group in search, a stat card repeating the ATT&CK version, a stat row repeating the unit header,
  decorative grid backgrounds, "read model" eyebrow labels.
- **Measured cost:** largest unit payload 2.9 MB (542 Evidence) in 70 ms; APT29 dossier 17 s → 1.0 s after the
  index fix; full Python suite 19 min → 7 min. Investigating is the slow part and is unchanged in kind: about
  2.5 min for a small recording, 11.5 min for APT29 day 1, 18 min for Empire on the development machine — rule
  evaluation over every record, and for Empire the exact comparison search near its bound.

Known limits, stated in the UI where they apply: two Empire units (21 and 13 decision features) have no
per-candidate quantities (ADR-0009 D1); low-level Evidence outside units is counted but not listed; in-memory
sessions end with the server.

## Amendment (2026-10-20) — every backend capability is reachable, and nothing on screen is unbacked

The owner's direction for the frontend phase: the console must connect to and match everything the backend does.
An inventory of the API routes against the console's calls found three gaps, now closed:

- **Live mode** (ADR-0028) had no page. *Live Monitoring* reads `GET /api/live` every 5 s: the session's sources
  (bytes or documents read, partial and undecodable lines), the latest analysed window (verdict, counted
  techniques, link to its investigation) and every cycle (state and its meaning, snapshot lines and hash, time,
  what changed — techniques newly counted or gone from the window, verdict, named actors). Cycles where nothing
  new arrived are collapsed behind a count. Without a live session it says so and shows how to start one.
- **Declared versus established** (ADR-0025) was shown in the activity views but not in a unit's Evidence tab,
  where an uncounted technique looked like a counted one. Each Evidence row now marks *Declared only* or *Counts
  once linked*, and the rule detail shows the recorded review — what every match establishes and why, each
  per-match clause, and which clause this match satisfied — or why the rule was left ambiguous. The rule index
  served beside Evidence now carries each rule's review (`review`).
- **The measurements** were in the repository but not served. `GET /api/validation/measurements` serves the stored
  reports (authors'-technique comparison on the LSASS tool runs; the unseen test's first run and its re-run)
  without their per-recording rows, and *Methodology* shows them, with the first run's figures marked as first
  measured.

The shell is also usable on a phone now: below desktop width the sidebar is a slide-in menu, content uses the
full width and wide tables scroll inside their card, never the page (checked at 375 px; desktop unchanged).
