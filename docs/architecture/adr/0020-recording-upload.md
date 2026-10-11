# ADR-0020 — Recording upload: the one route that accepts input

- **Status:** ACCEPTED (2026-10-11, owner instruction: "i want the upload option" — an analyst uploads logs in
  the console and gets the investigation).
- **Builds on:** ADR-0009 (read model; a read-only API by decision), ADR-0016 (console), ADR-0008 (source formats
  and the intake standard), `replay/recording_check.py` (intake check), ADR-0017/0018 (what a verdict may say).
- **Changes:** ADR-0009's "no mutation endpoint exists" becomes "no stored record can be changed; one route hands
  the server a new recording".

## Context

A recording reached the platform only through the command line. A reviewer or analyst using the console could
read investigations but not start one. The owner wants the console to take a log archive and show its result.

Two things must not change: the analysis (an upload must run exactly what the command line runs) and the
read model's guarantees (no route edits or deletes a stored record).

## Decisions

### D1 — One input route, three reads

| Route | Meaning |
|---|---|
| `POST /api/uploads?name=<file name>` | the archive as the raw request body; answers `202` with the job |
| `GET /api/uploads` | whether uploading is on, its limits, and this session's jobs (newest first) |
| `GET /api/uploads/<job_id>` | one job |

The body is the file itself (`application/octet-stream`), not a multipart form: nothing to parse, and a browser
on another site cannot send that content type to this server without a pre-flight request, which the server does
not answer.

Every other `POST`, and every `PUT` / `PATCH` / `DELETE`, is refused with `501` as before. A server created without
an upload service (`create_server(..., uploads=None)`, `python -m attribution_platform.api`, `--no-upload`) refuses
the upload route too and reports `enabled: false`.

### D2 — Bounds, enforced before the file is used

| Bound | Rule |
|---|---|
| Who | the client address must be a loopback address; a browser `Origin` must be this server's own |
| Size | `Content-Length` is required and at most 1 GiB; a body shorter than declared is refused |
| Name | reduced to a base name in `[A-Za-z0-9._-]` with a supported extension (`.zip`, `.tar.gz`, `.log`, `.json`, `.jsonl`); it names the recording and is never used as a path |
| Storage | `data/cache/uploads/<sha256 prefix>-<name>` (git-ignored); written under a temporary name, renamed when complete |
| Expansion | a `.zip` whose members declare more than 16 GiB is refused; recordings are read as streams and never extracted to disk, so no member name can write a file |

The console is a local tool bound to `127.0.0.1`. This ADR does not make it a service: there are no accounts, and
exposing the port to a network is out of scope and guarded against only by the loopback check.

### D3 — A job runs the command line's own check and investigation

A job is: store → **intake check** (`check_recording`, the function behind `scripts/check_recording.py`) → if it
has problems, the job is `refused` with those problems and nothing is investigated → **investigation**
(`run_investigation` with the session's pinned workbench) → `done` with the investigation id.

States: `queued`, `checking`, `analysing`, `done`, `refused`, `failed`. A failure of the run is a job state with
the error's text; it never stops the worker.

The recording's SHA-256 and source declaration come from the intake check, as for a path given on the command
line. The investigation id is the same hash of the source digest and every pinned version, so an uploaded
recording and the same file run from the command line are the same investigation.

Uploading the same bytes again returns the existing job (it is keyed by content) unless that job was refused or
failed, in which case it is tried again.

### D4 — One investigation at a time, published whole

The detection engine is CPU-bound; two concurrent runs would only slow both. One worker thread takes jobs in
arrival order.

Requests are served while a run is in progress. With the in-memory store (`SharedMemoryClient`, a locked
`FakeElasticClient`), a run writes into a private store that is copied into the shared one in a single locked step
when it finishes: a reader sees none of an investigation or all of it. With `--elasticsearch` the run writes to the
cluster directly, as the command line does.

Jobs are session state: they are not persisted, and a restart forgets them. Finished investigations persist as
far as the store does (in memory: for the session; Elasticsearch: until deleted there).

### D5 — What the console says about an upload

The upload page states, next to the control, what an upload yields: techniques with their evidence, the consistent
actors and a verdict with reasons — and that a Group is named only on evidence specific to it, that most recordings
therefore end in "no actor can be singled out", and that no confidence percentage exists. Progress is reported as
the job's state and elapsed time; the page does not show a percentage it cannot measure.

## Consequences

- `python -m attribution_platform.investigation --serve` alone starts an empty console to upload into.
- No emulation report can be attached to an upload yet (ADR-0019 remains a command-line option).
- Uploaded files accumulate in `data/cache/uploads` until removed by hand.
- An investigation still takes minutes; the upload makes that visible rather than faster.

## Checks

`tests/test_uploads.py`: name reduction and refusal; loopback and origin rules; accepted, refused and failed jobs;
one job per content; every size bound; an over-expanding and an unreadable zip; whole-investigation publishing;
the HTTP route and its refusals; that every other mutation is still `501`; that a server without the service is
unchanged; and one upload through the real intake check and investigation, read back from the API.
