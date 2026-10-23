# ADR-0029 — A second unseen test: 169 Splunk attack_data Windows recordings, before and after

- **Status:** PRE-REGISTERED (2026-10-23). The selection and this protocol are committed before any recording's
  content was downloaded; only Git LFS pointers (hash and size) and the dataset descriptors were read.
- **Context:** ADR-0027's 105 OTRF recordings became development data once their results were used (its
  "Development after the test"). Since then there has been no held-out data, so no change to detection can be
  shown to generalise. The README's figure, 54 of 107 of the authors' techniques counted, is now a development
  figure. The next step on the recommended path is closing the largest measured gaps (ADR-0026 Amendment C and
  later), and that work needs a test it cannot have been tuned on.

## What is tested, and what is not

`splunk/attack_data` (Apache-2.0), at the commit the project already pins (`a28608b5`), holds Windows Sysmon
recordings made in Splunk's Attack Range lab, each in a directory named after the ATT&CK technique it was made for,
with a YAML descriptor whose `mitre_technique` field is the authors' own label. The project has used none of its
Windows recordings (its Linux, cloud and macOS sets are listed in `data/telemetry-samples/splunk-attack-data*/`).

- **Tested:** technique detection on recordings never used, against the authors' labels; that no actor is named
  where the recording is not of an actor's tooling; whether the changes made after this registration help on data
  they were not written for.
- **Not tested:** group identification as such. Most recordings are atomic tests of one technique. A few
  directories are named after a group's malware or campaign (for example `lotus_blossom_chrysalis`); an actor
  named there is reported with the recording and judged by its descriptor (below), not counted as a success of
  the attribution method.
- **Different from ADR-0027, on purpose:** another lab, another collection pipeline (Splunk's XML event export
  instead of OTRF's JSON), Sysmon only. The Security, System and PowerShell logs that some directories also hold
  are not part of the test: this is a test of the platform reading Sysmon, stated here so the result is not read
  as covering Security-log detection.
- **Contamination that cannot be ruled out:** Splunk built these recordings to test its own detections, and other
  rule authors may have used them. A detection here shows the content works on this data, not on a new
  environment. The authors' label names one technique per recording; an atomic test that ran but failed, or that
  also performed other techniques, is not visible in the label. "Counted but not listed" is reported as a list to
  examine, never as false positives by that fact.

## Selection (mechanical, recorded in `data/validation/unseen-splunk-windows/selection.json`)

`scripts/select_unseen_splunk_windows.py`: every `datasets/attack_techniques/<technique>/[<dir>/]windows-sysmon.log`
at the pinned commit that the project has not used, whose Git LFS pointer states **at most 50 MB**. The size bound
exists only to keep two full runs within a working day on a laptop; it was chosen from the pointers' sizes alone,
before any content was fetched. Each entry records the path, git blob id, LFS SHA-256 and size, its descriptors,
and the authors' techniques (the union of `mitre_technique` in the descriptors in the recording's own directory).

| | Recordings | Size |
|---|--:|--:|
| Windows Sysmon recordings at the commit | 179 | 2.59 GB |
| Larger than 50 MB (excluded, listed with sizes) | 10 | 1.12 GB |
| **Selected** | **169** | **1.48 GB** |

All 169 have a descriptor; each names exactly one technique, the same as its directory: 169 labels, 104 distinct
techniques.

## Protocol

1. **Registration.** This ADR, the selection and the scripts are committed together. That commit changes no
   detection, correlation or attribution code. Nothing in the selected recordings has been read.
2. **Baseline build = the registration commit.** It is code-identical to the published state (`f5029b3`) and to
   the state ADR-0027's development ended in. `scripts/acquire_linux_telemetry.py --set windows-unseen` downloads
   the recordings (each verified against its LFS pointer's SHA-256 and size; text only, nothing executed);
   `scripts/run_unseen_atomic.py --set splunk-windows --run run-baseline.json` investigates each on its own, from a
   clean checkout of that commit; `scripts/measure_unseen_atomic.py --set splunk-windows --run run-baseline.json
   --out results-baseline.json --quiet` stores the comparison **without printing it**. The baseline results are not
   read until step 4.
3. **Development continues on development data only** (the OTRF recordings, the corpus, the tool runs), recorded
   in ADRs as before. Nothing is changed in response to the Splunk recordings, whose content is not opened.
4. **The improved build is frozen** at a commit recorded in `run-improved.json` (clean working tree). The same
   two scripts run it (`--run run-improved.json`, `--out results-improved.json`). Then both result files are
   read, compared and reported here, including unfavourable results: lower recall, recordings refused, new
   "counted but not listed" techniques.
5. **Afterwards these recordings are development data,** as ADR-0027's became. Any later fix is development and
   is recorded as such; the figures in this ADR are not updated by it.

## Measures (as ADR-0027, ADR-0025 Amendment E)

Per authors' technique: *found exactly*, *found as parent or sub-technique*, *missed*, and *missed but shown* (the
technique is among the recording's detections at all — declared only, or low-level context); per recording:
*counted but not listed by the authors*, the verdict, and any named actor. Labels are resolved through the pinned
ATT&CK version's `revoked-by` relationships (ADR-0027 Correction). Results are grouped by technique directory.

A **named actor** is correct only if the recording's descriptor names that Group, or software ATT&CK records for
that Group alone; otherwise it is counted as wrong. A recording the intake refuses, or that fails, is reported with
its reason; its labels stay in the denominator of "selected" figures and are reported separately, as in ADR-0027.

## Results

Not yet run.
