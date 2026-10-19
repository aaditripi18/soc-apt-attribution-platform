# ADR-0027 — An unseen test: 105 OTRF atomic recordings, run once on a frozen build

- **Status:** RUN (2026-10-19). Pre-registered, with its selection, before any recording was downloaded; run once
  on the frozen build `9733a74` (clean working tree). Results below, as measured.
- **Context:** ADR-0025 Amendment J used up the last held-out recordings: all 11 recordings the project had run
  now inform development. Whether the platform generalises needs recordings it has never seen.

## What is tested, and what is not

The OTRF Security-Datasets repository (MIT) holds, at the commit the project already pins
(`d9d40ef1`), 112 Windows *atomic* recordings — one procedure each, run by the dataset authors in a lab, with a
metadata file listing the ATT&CK techniques the procedure performs (`attack_mappings`, the authors' own). The
project has used 7 of them (`data/telemetry-samples/otrf/manifest.json`). The other **105** are the test set
(`data/validation/unseen-otrf-atomic/selection.json`: path, size, git blob id, metadata blob id, the authors'
techniques). The selection rule is mechanical — every such recording, minus those already used — and nothing
was excluded for any other reason.

- **Tested:** technique detection on unseen recordings, against the authors' mappings; that no recording is
  given an actor's name; that the served read model passes its audit.
- **Not tested:** group identification. Atomic recordings are single procedures, not a group's operation, so the
  only correct verdict is that no actor is identified; a named actor is counted as wrong.
- **Contamination that cannot be ruled out:** this project developed nothing on these recordings, but external
  rule authors (Sigma, Elastic) may have written or tested rules against this public dataset. A detection here
  shows that the content works on this data, not that it would on a new environment.

## Protocol

1. The build is frozen at the commit that adds this ADR's acquisition and measurement scripts; no rule, review
   decision or code changes until the results are recorded.
2. `scripts/acquire_unseen_atomic.py` downloads the 105 host recordings into the git-ignored cache, verifying each
   against its size and git blob id at the pinned commit, and lists archive members as data only (nothing
   extracted, nothing executed); the tracked manifest records what was fetched.
3. `scripts/run_unseen_atomic.py` investigates each recording on its own, unchanged, with the intake check and
   pipeline of the command line, in one served run; a refusal or failure is recorded as that recording's result
   (`run.json`, with the build commit and whether the working tree was clean).
4. `scripts/measure_unseen_atomic.py` reads the served investigations and writes
   `data/validation/unseen-otrf-atomic/results.json`, with the same definitions as ADR-0025 Amendment E:
   - *found exactly* / *found as parent or sub-technique* / *missed*, per authors' technique;
   - *shown*: an authors' technique present among the recording's detections at all, counted or not
     (declared only, or low-level context) — separates "the content saw it" from "the platform counted it";
   - *counted but not listed by the authors*: a list to examine, not false positives by that fact;
   - verdicts, and any named actor.
5. Results are reported as measured, including unfavourable ones. Anything fixed afterwards is development; these
   recordings then become development data, and that is recorded.

## Results (2026-10-19, build `9733a74`)

Files: `run.json` (each recording's outcome), `results.json` (per-recording comparison). Served audit on the 61
investigations: 190,501 checks, all passing.

**1. 44 of the 105 recordings never reached detection: the intake refused them.**

| Refusal | Occurrences | What it is |
|---|---|---|
| "host … has no Sysmon records" | 38 | mostly the domain controller of a two-host recording, logging only the Security channel |
| "… line(s) are not JSON objects" | 16 | one line that is not a JSON record refuses the whole recording |
| "the archive contains no JSON records" | 2 | two files listed as *host* in the authors' metadata are network packet captures (a metadata error; the intake is right to refuse them) |

The first two are the platform's own rules: the intake was written for the calibration corpus, whose lab
recordings must have Sysmon on every host, and it refuses a recording for one unreadable line. A real SOC has
domain controllers that send only Security logs. These refusals hold 44 of the 109 authors' techniques. **This is
the main finding of the test, and it is about intake, not detection.**

**2. On the 61 investigated recordings** (65 authors' techniques):

| | Count |
|---|---|
| found exactly | 26 |
| found as parent or sub-technique | 4 |
| **found in total** | **30 of 65 (46%)** |
| missed | 35 — of which 7 were shown (declared only, or low-level context) but not counted |
| recordings with at least one authors' technique counted | 28 of 61 |
| recordings with no Evidence at all | 10 |
| counted but not listed by the authors | 74 (most often PowerShell, 11; Process Injection, 6 — to examine, not errors by that fact) |
| recordings naming an actor | **0** (42 "not distinguishable", 19 "no decision features") |

Most often missed: SMB / Windows Admin Shares (T1021.002, 5), Disable Windows Event Logging (T1562.002, 3),
Process Injection (2), Modify Registry (2), Distributed COM (2), Registry Run Keys (2).

**Reading it.** On the recordings it read, the platform counted about half of what the authors performed — in line
with what was measured on development data (ADR-0025 Amendment E: about a third on the LSASS tool runs, 22 of 45
after later work), so detection did not collapse on unseen data, and it named no actor on any of 61 single
procedures. Across all 105 recordings the figure is 30 of 109 (28%), because of the intake.

**What happens next is development.** Relaxing the intake (a host with only Security logs; a recording with one
unreadable line) is a change made *after* seeing these results; once it is made and these recordings are re-run,
they are development data, and that will be recorded here.

## Development after the test (2026-10-20) — the recordings are development data from here

Three faults the test exposed were fixed, each with a regression test (first-run files kept in `first-run/`):

1. **Intake** (ADR-0008 amendment): a Windows host with Security logs but no Sysmon is accepted with a warning;
   macOS archive-metadata members are skipped; a "host" named only by records of channels that are not read (the
   legacy *Windows PowerShell* log names a computer by its short name — `WORKSTATION6` beside
   `WORKSTATION6.theshire.local`) declares nothing and is reported, not refused.
2. **In-memory store** (`FakeElasticClient` / `SharedMemoryClient`, the default store of the console, uploads and
   live mode): it ignored the query and capped first, so once it held more than 1,000 unit summaries, units fell
   out of their investigation's listing (found when the re-run's audit failed with 1,240 units). It now evaluates
   the query subset the read model sends (`match_all`, `term` filters) before the cap and refuses any other query.
   The investigation list's cap rose from 100 to 10,000 (a live session adds one investigation per cycle).
3. **The audit** builds its unit list from each investigation's own listing, and accepts a global search past one
   page only as a full, flagged page of true matches.

**Re-run** (build `1319109` plus these fixes; served audit 904,111 checks over 103 investigations and 1,702 units,
all passing):

| | First run | Re-run |
|---|---|---|
| recordings read | 61 of 105 | **103 of 105** (the two refused are network captures) |
| authors' techniques counted | 30 of 65 (46%) | **41 of 107 (38%)** — exactly 35, as parent / sub 6 |
| the same 61 recordings | 30 | 30 (unchanged) |
| the 42 newly read | — | 11 of 42 |
| missed but shown (declared only or context) | 7 | 13 |
| recordings naming an actor | 0 | **0** (72 not distinguishable, 31 no decision features) |

By tactic (re-run): credential access 10 of 18, lateral movement 11 of 28, defense evasion 9 of 38, discovery 1 of 9,
persistence 3 of 6.

**What the re-run shows.** The newly read recordings are mostly domain controllers with Security logs only, where
detection is weaker (no process GUIDs, fewer rules apply): 11 of 42. The largest single gap is **Disable Windows
Event Logging (T1562.002), missed in 17 recordings** — the event-log tampering family (service start type, the
MiniNT key, the log path, stopping the service). That is the clearest next detection work, measured, on what are
now development recordings.

### Correction (2026-10-20) — the authors' labels are resolved through the pinned ATT&CK version

The figures above compared the authors' labels as written. Several predate ATT&CK v19's renumbering — Disable
Windows Event Logging, T1562.002, is **T1685.001** in the pinned v19.2 — so a correct detection could count as a
miss. `measure_unseen_atomic.py` now resolves each label through the knowledge base's `revoked-by` relationships
(as the Linux report always did) and keeps the label as written beside it (`results.json` version 2, which also
records each recording's counted ids). The first run is rescored from its stored sets
(`--rescore-first-run`). The LSASS ground truth of ADR-0025 Amendment E has no renumbered label (checked).

| | As first reported | Labels resolved |
|---|---|---|
| first run (61 read) | 30 of 65 (46%) | **32 of 65 (49%)** |
| re-run (103 read) | 41 of 107 (38%) | **44 of 107 (41%)**; missed but shown 19 |

Most of the remaining event-log-tampering "misses" are now *shown but not counted*: the rules that fire declare
both Disable Windows Event Logging and Modify Registry, which ADR-0025 treats as alternatives until the rule is read.
Reading those rules is the next step.
