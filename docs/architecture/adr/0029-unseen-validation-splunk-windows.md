# ADR-0029 — A second unseen test: 169 Splunk attack_data Windows recordings, before and after

- **Status:** RUN (2026-10-23/25). Pre-registered (`4de512a`, pushed) before any recording's content was
  downloaded; only Git LFS pointers (hash and size) and the dataset descriptors were read. Baseline run on
  `4de512a`; improved build frozen and pushed at `8d81d46` before either result was read; both from clean
  checkouts. Results below, as measured.
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

## Results (baseline `4de512a`, improved `8d81d46`; run 2026-10-23, read 2026-10-25)

Files in `data/validation/unseen-splunk-windows/`: `run-baseline.json`, `run-improved.json` (each recording's
outcome, the build commit, clean working tree), `results-baseline.json`, `results-improved.json` (per-recording
comparison, same definitions as ADR-0027).

| | Baseline | Improved |
|---|--:|--:|
| Recordings read (of 169) | 164 | 164 |
| Authors' techniques counted (of 164) | **74 (45%)** — 63 exactly, 11 as parent or sub-technique | **74 (45%)** — same |
| Missed but shown (detected, not counted) | 35 | 35 |
| Counted but not listed by the authors | 720 | 723 |
| Recordings naming an actor | 0 | 0 |

**1. The changes made after registration did not change recall on this data.** That is the result, and it is the
reason the test was registered first. Why, from the recordings (read only after both runs were stored):

- *The Event Log rules (ADR-0026 Amendment C)* had nothing to act on: no recording in this set is labelled
  T1685.001 (or T1562.002).
- *The sequence rules (ADR-0015 Amendment E)*: one of the 17 fired here — "Mshta Making Network Connections", on 3
  recordings, adding T1218 / T1218.005 where the label was already found or is another technique. The
  lateral-movement sequences did not fire, and in the two recordings examined the cause is the data, not the
  translation:
  - `T1047/lateral_movement`: stage 1 **matched** four times (`svchost.exe` accepting RPC on port 135 from
    10.0.1.14 — the new `network.direction` and `source.ip` fields working on unseen data); stage 2 needs a
    process started by `WmiPrvSE.exe` on the target, and the recording holds none — the attacker's
    `Invoke-WmiMethod` is there, the process it asked for is not.
  - `T1021.003/lateral_movement`: stage 2 **matched** (`calc.exe` started by `mmc.exe`); stage 1 needs an incoming
    connection *by `mmc.exe`*, and Sysmon logged the matching inbound connection with the image
    `<unknown process>`. Elastic's own engine would not fire on this data either.

**2. A measurement effect, stated so the figure is not misread.** "Counted" means compared with group profiles.
14 of the 164 labels are techniques that **no Group or Campaign in ATT&CK v19.2 is recorded using** (for example
T1021.003, Distributed Component Object Model: three software entries, no Group). Such a technique can be detected
but never counted. 13 of them were missed, and **11 of those 13 were detected** — `T1021.003/lateral_movement` has
Sigma's "MMC20 Lateral Movement" established on the target's `mmc.exe -Embedding`, inside a unit. On the 150 labels
a Group does use: **73 counted (49%)**, both builds. The definition is not changed after the fact; both figures are
reported.

**3. Five recordings never reached detection**, all the platform's own intake limits (labels 5, kept in the
"selected" denominator):

| Recording | Refusal | What it is |
|---|---|---|
| `T1059.005/lotus_blossom_chrysalis`, `T1574.002/lotus_blossom_chrysalis` | no record converted | Splunk's own JSON export shape (`EventCode`, `EventData_Xml`), not a Sysmon record shape the adapters read |
| `T1014` | no record converted | only Sysmon event 6 (driver loaded), an event the platform does not model |
| `T1048.003/nslookup_exfil`, `T1562.004/atomic_red_team` | lines not readable | lines that are neither JSON nor one-line XML events |

The two `lotus_blossom_chrysalis` recordings were the only ones named after a Group's campaign, so the actor
question of this test went **untested**, not answered.

**4. Against ADR-0027.** A different lab, collector and export: 45% of all labels (49% of group-used labels)
here, against 49% on ADR-0027's first run and 50% after its fixes. The platform counts about half of what
single-procedure recordings perform, on two independent public sources. No actor was named on either.

**What follows.** Both changes stay: each is exact against its source and tested, and the stage matches above
show the translation working on unseen data. But no recall improvement is claimed for them; the README reports
this test's figure. The improvements this result points at, for a later registered test: (a) the intake reading
Splunk's JSON export and multi-line events; (b) whether "counted" should also report detected techniques that no
Group uses — a presentation question, recorded here, not decided by this result. From here these 169 recordings
are development data.
