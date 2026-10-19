# ADR-0027 — An unseen test: 105 OTRF atomic recordings, run once on a frozen build

- **Status:** PRE-REGISTERED (2026-10-19). Written, with its selection, before any of the recordings was
  downloaded. Results are added below once, without changing this protocol.
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

## Results

(To be added once, after the run.)
