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
