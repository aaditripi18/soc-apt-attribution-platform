# ADR-0028 — Live mode: rolling capture, analysed as a sequence of reproducible snapshots

- **Status:** ACCEPTED (2026-10-19, owner delegation: "go ahead with the recommended step, you have permission").
- **Builds on:** ADR-0020 (an upload runs exactly what the command line runs), ADR-0008 (source formats; the
  intake standard), ADR-0023 (Wazuh alerts), ADR-0009 (read model), ADR-0025 / 0026 (what is counted).

## Context

Every investigation so far is over a finished recording: a file in, a result out. A SOC watches telemetry as it
arrives. "Live mode" must add that without weakening what makes a result trustworthy here: the same pipeline,
every conclusion traceable to the exact records and the exact rule, review and ATT&CK versions that produced it.

Three facts shape the design.

1. **The analysis is a whole-window computation.** Structural correlation, the ancestry walk, two-stage sequences,
   new-terms and threshold rules all read a set of records together. A per-event streaming engine would be a
   second implementation of each — the drift this project has avoided everywhere else (one pipeline for command
   line and upload, ADR-0020).
2. **Reproducibility is per input.** A result is reproducible when its input is a fixed, hashed set of records.
   A stream has no such set unless one is cut from it.
3. **The telemetry already lands somewhere.** Elastic Agent / Winlogbeat write Windows event logs (including
   Sysmon) to Elasticsearch in the `winlog.*` shape the existing adapters read; Wazuh writes `alerts.json`; Zeek and
   auditd write files. Live mode reads where telemetry already is; it installs nothing on hosts.

## Decisions

### D1 — Capture: append raw records to a rolling store, from files or from Elasticsearch

A *live source* is one of:

- **follow a file** (NDJSON/JSON lines in a shape the pipeline reads: Winlogbeat/Elastic Agent event logs,
  Wazuh `alerts.json`, Zeek JSON logs, raw `audit.log`), reading only appended bytes and surviving rotation;
- **poll Elasticsearch** data streams that hold such records (`logs-windows.sysmon_operational-*`,
  `logs-system.security-*`, `logs-windows.powershell*`, `winlogbeat-*`), with a `search_after` checkpoint on
  `@timestamp` and document id, read-only credentials from the environment.

Records are appended unchanged to time-partitioned capture files with a per-source checkpoint. Capture never
interprets; the adapters do, exactly as for a recording.

### D2 — Analysis: every cycle investigates a frozen snapshot of the window

On a fixed interval (default 60 s), the analyser cuts the **window** (default the last 24 h of capture) into an
immutable snapshot file with its SHA-256 and runs `analyze_recording` on it — the function the command line and
upload use, with the same pinned packs, review and ATT&CK version. The result is stored as an ordinary
investigation whose source is `live:<name>@<window end>`. A snapshot whose content hash equals the previous one is
not re-analysed. Snapshots are kept for a bounded retention so any live result can be re-run byte-for-byte.

### D3 — What changed is computed from two stored investigations, never inferred

Each cycle records its difference from the previous one: units new or grown, techniques newly counted, a verdict
or identified actor that changed. This is a comparison of two stored records, served by the read model; it adds
no scoring and no alert logic of its own.

### D4 — Latency is the cycle interval, stated

Live mode is near-real-time by design: a detection is visible within one cycle plus analysis time, and that bound
is shown, measured on the real window size. Analysis cost is measured before the default window is fixed; if a
24 h window cannot be analysed within the interval, the window shrinks, never the analysis.

### D5 — Bounds

Loopback-only API, as for uploads. Read-only access to sources. A size cap per snapshot (oldest capture outside
the window is not read). Capture and snapshot directories are git-ignored and contain no credentials. Stopping
live mode stops capture; nothing it stored is changed afterwards.

## Alternatives rejected

- **Incremental (per-event) correlation.** Lower latency, but a second implementation of every whole-window
  method, and results that depend on arrival order. Rejected for drift and reproducibility.
- **Elastic detection engine alerts as the only input.** Kibana alerts are useful (and Wazuh alerts are already
  read, ADR-0023), but the platform's own explanation needs the underlying records.
- **An agent on endpoints.** Out of scope; collection belongs to Elastic Agent, Winlogbeat, Sysmon, Wazuh, Zeek.

## Implementation order

1. Capture from a followed file and the snapshot/analyse cycle, with D3, tested on a recording replayed into a
   file at its own pace (a real recording, written incrementally — not synthetic events).
2. Polling Elasticsearch, tested against the project's local Elasticsearch with a recording indexed into a
   Winlogbeat-shaped data stream.
3. The console view of a live source (frontend last, ADR-0016).

## Implementation record (2026-10-19) — steps 1 and 2

- `live/capture.py`: `FileFollower` (only complete lines; restarts on rotation or truncation, dropping and
  counting a partial line of the old file; undecodable lines counted, never guessed) and `CaptureStore`
  (capture files by arrival hour; a snapshot is the window's files concatenated, with its SHA-256; bounded
  snapshot retention).
- `live/elastic_source.py`: `ElasticsearchSource` polls an index pattern read-only through the new
  `ElasticsearchHttpClient.search_hits` (a bounded `_search` that keeps each hit's id). The checkpoint is the last
  time read plus the ids read at that time, which the next query excludes - so documents sharing a timestamp are
  read once however many there are (found by the first unit test: a version that only skipped them could not move
  past a full page of one timestamp). Time field `event.ingested` by default; with an event-time field such as
  `@timestamp`, a document arriving after newer ones were read is missed - stated in the module and the status.
- `live/session.py`: `LiveSession.cycle()` - append, snapshot, skip an unchanged snapshot, intake check, the
  shared `investigation_runner` (now also behind uploads), a stored-summary comparison (`changes_between`: newly
  counted techniques, techniques that left the window, unit count, verdict, named actors).
- `python -m attribution_platform.live --follow <file> [--elasticsearch-index <pattern>] [--serve]`;
  `GET /api/live` reports sources and recent cycles (`{"enabled": false}` on a server without live mode).
- **Checks.** `tests/test_live.py`: follower and store behaviour; a real recording (OTRF comsvcs LSASS dump)
  written into a followed file in two parts - the second cycle's snapshot hash, evidence, units, counted
  techniques and verdict equal the recording run of the same records, LSASS Memory counted; an unchanged window
  is not re-analysed; the status and the cycle's investigations are served. Polling: same-timestamp documents
  read once; `search_hits` request shape and refusal of malformed hits. `tests/test_live_elasticsearch_poll.py`
  (opt-in) against the project's Elasticsearch 8.15.3: the recording indexed in two parts, every document polled
  once and unchanged, and a live cycle over them equal to the recording run.
- **Not yet:** the console view (step 3) waits for the frontend phase.

## Amendment A (2026-10-19) — D4 measured: per-record detection is reused between cycles

**Measured.** Analysis cost on real recordings (one process, while other investigations were loading, so upper
bounds): the lab credential-dumping recording, 42,482 records, 270 s; LSASS tool run 01, 53,698 records, 356 s;
APT3 Empire, 121,659 records, 629 s - about 6 ms a record. Profiled on the first: **877.9 s of 878.0 s** is
single-event detection (`DetectionEngine.evaluate_split`, about 560 candidate rules a record); correlation,
sequences and attribution are negligible. A 60 s cycle re-analysing a full day of a busy host could not keep up.

**Decision.** Single-event detection is a function of the Observation and the engine alone, so a live session
keeps each Observation's result (`DetectionMemo`) and reuses it in later cycles **only for an Observation equal to
the one it was computed for, by the same engine**; anything else is evaluated afresh, so a cycle's result is
identical to evaluating everything. Multi-event rules, correlation and attribution still run over the whole
window every cycle. Entries that leave the window are dropped. The memo is not part of any result or version: an
investigation with it equals one without it (tested).

**Result.** The same 42,482-record recording analysed twice with the memo: 278.2 s, then **5.4 s**, with the same
112 Evidence and 7 units (35,559 Observations reused). A steady-state cycle costs roughly that fixed part plus
about 7 ms for each new record, so the 60 s default keeps up with several thousand new records a minute; above
that, D4 applies - the interval grows, the analysis is never cut.
