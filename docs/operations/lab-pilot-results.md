# Lab pilot — a recording made in a self-built lab, and what the platform found in it

**Date:** 2026-10-11/12. **Purpose:** prove that a lab built to `lab-recording-guide.md` produces recordings the
platform accepts and can analyse end to end, and compare what was run with what was detected. This is a logging
pilot, not an actor emulation: it is not calibration data and says nothing about any threat group.

## The lab

| Piece | Detail |
|---|---|
| Hypervisor | VirtualBox, two VMs on an internal network with no route to the internet or the host LAN |
| Controller | Kali Linux running MITRE CALDERA |
| Recorded host | Windows 11 (`micky`), a disposable clone restored to a clean snapshot after each run |
| Telemetry | Sysmon 15.22 with OTRF Blacksmith's `sysmon.xml` (SHA-256 `73277a43…35aaa`); Windows Security auditing (process creation with command line, logon, file share, object access); PowerShell module and script-block logging |
| Collection | Winlogbeat 8.17.0 writing JSON lines to a local file |
| What left the lab | Text only: the log archive, CALDERA's operation report and a run sheet |

The recordings stay in the git-ignored `data/cache/lab/pilot/`; they are identified here by SHA-256.

## The runs

| Run | What ran | Recording SHA-256 | Records | Intake check |
|---|---|---|---|---|
| `pilot-01` | CALDERA's built-in *Discovery* profile, stopped after one step | `a5e188f9…757a82` | 178,846 | accepted |
| `pilot-02` | The same profile to completion: 8 steps, 6 succeeded, 2 failed | `1a9174a5…2de9a0` | 192,639 | accepted |

Intake (`scripts/check_recording.py`) on `pilot-02`: Sysmon 190,734, Windows Security 532 and PowerShell 382 records
converted; 991 (0.5 %) refused as event types the platform does not model. Every event lies inside the 24-minute
run window written on the run sheet.

## `pilot-02`: what was run against what was found

CALDERA's report lists each step with its ATT&CK technique, host, times and process id. The platform was given the
recording only. The comparison below is the stored ran-versus-detected record (ADR-0019,
`--emulation-report`): a step's own Evidence is Evidence grounded in the step's process (its process id or a
child of it) on its host inside its time window ± 10 s.

| # | Step (from CALDERA's report) | Technique named | Lab result | Evidence from the step's own process | Named technique among it | Named technique anywhere (core · context) |
|---|---|---|---|---|---|---|
| 1 | Identify active user | T1033 | ran | 3 (in no unit) | **yes** | 0 · 1 |
| 2 | Identify local users | T1087.001 | ran | 4 | no | none |
| 3 | Find user processes | T1057 | ran | 5 | **yes** | 0 · 3 |
| 4 | View admin shares | T1135 | ran | 120 | no | none |
| 5 | Discover domain controller | T1018 | failed (no domain) | 11 | **yes** | 0 · 2 |
| 6 | Discover antivirus programs | T1518.001 | failed | 4 | no | none |
| 7 | Permission Groups Discovery | T1069.001 | ran | 5 | no | 0 · 115 |
| 8 | Identify Firewalls | T1518.001 | ran | 4 | no | none |

- **Every step left Evidence** (8 of 8): each was launched through a hidden interpreter window, which the pinned
  rules recognise (T1059, T1059.001, T1564).
- **The technique the report names was detected in its own step for 3 of 8 steps** (T1033, T1057, T1018), each time
  at the low-level (context) tier only.
- **4 of the 7 distinct techniques have Evidence somewhere in the investigation; 3 have none** (T1087.001, T1135,
  T1518.001).
- **T1069.001 was detected, but not where the plan ran it.** All 115 items are PowerShell module and script-block
  records of step 4's process ("View admin shares", 14:59:23–14:59:25 UTC); step 7, which the report labels
  T1069.001, produced none. Matching by technique name alone would have credited step 7.

> **Correction (2026-10-11).** The first version of this table was compiled by hand from the units' technique
> lists. It reported T1033 as not detected (its one Evidence item is low-level and in no unit, so the units did not
> show it), counted "3 of 7" techniques, and credited the 115 T1069.001 items to step 7 by name. The stored
> comparison above replaces it.

The steps were issued through PowerShell, and rules that read PowerShell script-block text are a documented gap
(ADR-0015: "PowerShell script-block text" not offered), which is the likely reason for the misses — not yet
confirmed rule by rule.

What the platform did find, beyond the plan's own technique labels (224 Evidence items, 2 attribution units):

| Technique | Evidence | What it corresponds to |
|---|---|---|
| T1036 / T1036.005 Masquerading: Match Legitimate Resource Name or Location | 25 core | the agent binary, saved under another product's name in a public folder |
| T1564 Hide Artifacts, T1059 Command and Scripting Interpreter | 8 + 10 core | each step being launched through a hidden interpreter window |
| T1059.001 PowerShell | 1 core, 17 context | the same launches |
| T1482 Domain Trust Discovery, T1016 System Network Configuration Discovery | core + context | around the domain-controller step |
| T1070.003 / T1070.005 Indicator Removal | 3 core | clean-up commands attached to steps |

**Assessment stored for the investigation:** "No actor can be singled out from this evidence." 165 Groups and
Campaigns have at least one of the 11 decision features in their recorded profile; 3 have at least half; none has
all. That is the correct answer: a generic discovery profile was run, and no actor was being emulated. No
actor-specific rule fired.

## What this establishes, and what it does not

- A lab built from the guide yields recordings that pass intake and run through detection, correlation, the unit
  analyses, the investigation assessment and the dossier without manual editing.
- The platform recognised the *way* the activity was carried out (a masquerading agent, hidden interpreter
  launches) more reliably than the individual discovery techniques: it detected the named technique in 3 of 8 steps and
  has no Evidence at all for 3 of the 7 techniques.
- It does **not** measure detection recall in general: one host, one profile, eight steps.
- It is **not** calibration data. Calibration would need recordings of several named actors' published plans
  (`lab-recording-guide.md` §4); the owner decided on 2026-10-11 not to record them.
