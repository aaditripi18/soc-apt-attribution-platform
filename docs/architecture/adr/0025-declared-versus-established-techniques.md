# ADR-0025 — Declared versus established techniques

- **Status:** ACCEPTED (2026-10-12, owner specification: preserve every declared technique; count a technique as
  attribution evidence only when the detection establishes it; mark what cannot be decided as ambiguous and keep it
  out of the overlap; allow corroboration and rule-specific adjudication; do not redefine the 404 / 697 figure;
  preserve previous results and report what changes).
- **Builds on:** ADR-0003 Amendment H (enrich tier), ADR-0005 (features), ADR-0007 / ADR-0015 (rule import),
  ADR-0021 (profile match). Changes the features of every investigation: `INVESTIGATION_METHOD_VERSION` 1.9.

## The defect

A rule's ATT&CK tags describe the rule, not the match. The platform mapped every firing to **all** the techniques
its rule declares. Found on an uploaded recording of one credential-dumping tool run: a rule that fires when a
file named after the tool is written declared five credential-dumping sub-techniques, and all five were reported
as observed; a rule covering several dumping methods fired on one and Rundll32 was reported as observed. Of the
source rules, 450 of 1,991 (Sigma) and 435 of 514 (Elastic) declare more than one technique.

## Decisions

### D1 — Declared, established, ambiguous

Every declared technique is still recorded as Evidence, with the rule and its source. Each Evidence item now
states whether its technique is **established** by the match or only **declared** (`Evidence.technique_ambiguous`,
stored; `declared_only` on the activity route; stated in the claim and the report).

What one firing establishes, without reading the rule (`detection/evidence.py::ambiguous_technique_ids`):

| The rule declares | Established | Declared only |
|---|---|---|
| one technique | it | — |
| a technique and its own sub-technique | both (the sub-technique implies its parent) | — |
| several sub-techniques of one parent | the parent, if declared | each sub-technique |
| techniques of different parents | — | all of them |

Mappings to software or Groups are not techniques and are unaffected.

This is a **structural** rule. The platform does not read a rule's logic to decide which tag a match supports;
nothing in a rule says so. The last row is deliberately conservative: some of those rules do establish several
techniques at once, and D2 is how they get that back.

### D2 — Rule-specific adjudication

`data/detection/technique-support-review.json` records, for a source rule a reviewer has read, the techniques
every match of it establishes, with the rule's name, what it declares and a reason. A decision can only name
techniques the rule declares (tested against the packs). The file's SHA-256 is part of every investigation's
recorded versions, so a result is tied to the decisions it was computed with. Four rules are adjudicated so far —
the ones inspected in the recording that exposed the defect. Reviewing all multi-technique rules is not a
prerequisite and has not been done.

### D3 — Corroboration

A declared-only technique counts for comparison only if **another** detection establishes it: a rule that declares
it alone (or with its parent), or an adjudicated rule. Two rules that both merely declare it do not corroborate
each other — a shared tag is not independent evidence. This falls out of D1: only established Evidence becomes a
feature (`correlation/sequence_engine.py`).

### D4 — Attribution

Group comparison, candidates, overlap and the verdict are computed from established techniques only. The
unattributed outcomes are unchanged. Group-specific evidence (ADR-0018) maps to Groups, not techniques, and is
unaffected.

### D5 — Three coverage figures, none redefined

- **Declared coverage** — a usable rule declares the technique. This is the existing 404 of 697 and is unchanged.
- **Established coverage** — at least one core rule establishes the technique when it fires
  (`scripts/build_technique_support_report.py` → `data/validation/technique-support-coverage.json`): of the 384
  techniques core rules declare, **294 are established by some rule and 90 are declared only**.
- **Validated coverage** — the technique was established in an activity cluster of a recording. Measured on the
  reference recordings only; see Results.

## Results of re-running the investigations

Previous results are kept in `data/validation/history/known-answer-checks.before-adr-0025.json`; the new ones are
`data/validation/known-answer-checks.json`. The served-model audit passes on the re-run (44,989 checks, five
investigations, 160 units) after two of its checks were updated to the new definition of a counted technique.

| Recording | Verdict before -> after | Techniques counted | Candidates | Known actor's techniques seen |
|---|---|---|---|---|
| APT29 emulation | APT29 identified -> APT29 identified | 59 -> 29 | 206 -> 193 | 11 -> 6 |
| APT3 emulation | not distinguishable -> same | 26 -> 8 | 196 -> 138 | 8 -> 4 |
| LSASS tool run 01 | not distinguishable -> same | 10 -> 8 | 120 -> 120 | no actor |
| LSASS tool run 03 | not distinguishable -> same | 15 -> 9 | 141 -> 125 | no actor |
| Uploaded tool run (procdump) | not distinguishable -> same | 16 -> 8 | 167 -> 157 | no actor |

- **No verdict changed.** APT29 is still identified, and on the same evidence as before: one match of one rule
  written from reporting on that Group's tooling (ADR-0018), which maps to the Group and not to a technique, so this
  change does not touch it. Its behavioural overlap is 17% (6 techniques); it was never what identified it.
- **Still no wrong name**, and the known actor is still never first by overlap (positions 10-116; before, 15-125).
- **On the uploaded recording** the five credential-dumping sub-techniques and Rundll32 that exposed the defect are
  no longer counted: four sub-techniques, Masquerading, Native API, System Binary Proxy Execution and Rundll32 are
  shown as declared only. LSASS Memory is still counted, through the adjudicated rules.

**A weakness this exposed.** The top overlap percentages went **up**, not down (uploaded recording: APT32 56% ->
85%; APT3 emulation: top profile 85%). Overlap is the matched share of what was counted, and with only eight
techniques counted a profile that contains most of them scores high. A high percentage on a small set is weak
evidence, and the figure does not show that by itself. Nothing here names a group on overlap, so no verdict is
affected, but the display should state how many techniques a percentage rests on. Not changed in this ADR.

**Still counted and probably ordinary activity:** a browser writing a download marker (NTFS File Attributes) and a
built-in Windows script. Single-technique rules, firing as written; see Consequences.

## Consequences

- Fewer techniques count for comparison, so candidate lists and overlap figures change; the size of the change is
  reported above, not assumed.
- A rule that genuinely establishes several unrelated techniques contributes none until it is adjudicated. That
  loses real evidence in exchange for never counting false evidence; the adjudication file is how it is recovered.
- Noisy single-technique rules (a browser writing a download marker, a built-in script) are **not** addressed here:
  the rule fires as its author wrote it. That is a validation question (how often a rule fires on ordinary
  activity), left open.

## Checks

`tests/test_technique_support.py`: what one match establishes, case by case; declared techniques kept and marked;
a review establishes exactly what it names; the tracked review names only existing rules and declared techniques;
malformed reviews refused; end to end, a tool seen only by name establishes neither of the techniques its rules
declare, and the same tool seen dumping memory establishes that technique through an adjudicated rule while the
other declared technique still counts for nothing.

## Amendment A (2026-10-12) — two detections that looked like ordinary activity, inspected

After the re-run, two kinds of detection on the uploaded recording were suspected of being ordinary activity. The
events were read before anything was changed. Neither was what it had been assumed to be.

**1. "Hidden Executable In NTFS Alternate Data Stream" on the browser.** The events are the browser saving a
downloaded executable with a double extension — in this lab scenario, the delivery of the payload. So the event is
relevant, not noise. What is wrong is the technique: the events name the file, no alternate stream and no stream
contents, and the rule's logic (a stream-creation event whose file has an import hash) never tests for a named
stream. **Change:** a review may now record that a rule establishes **nothing** (`"establishes": []`), and a review
is authoritative — exactly what it names is established. This rule is recorded so, with the reason. Its
detections are still raised and shown, as declared only; NTFS File Attributes is no longer counted from it
(uploaded recording: 8 counted techniques -> 7; verdict unchanged). The rule is not suppressed and no event is
excluded.

**2. A built-in Windows script (script host, registry values, group-policy query).** The parent process is
`netsh trace stop`, which runs that script itself: it is a side effect of stopping a network trace — here, almost
certainly the recording harness. The detections are true to the rules (a script host did run a Visual Basic
script; registry values were set). **No change.** Starting a network trace is itself something an attacker may do,
so the lineage cannot be declared benign by rule, and the platform has no baseline of normal activity to decide
with. Recorded as a known source of ordinary-activity detections for the validation work.

**What this says about the earlier guess.** One of the two "ordinary" detections was the payload download with
the wrong technique attached. Reading the events first, as the review of this step asked, changed the fix.

## Amendment B (2026-10-12) — first adjudication batch, by measured contribution

**Selection.** Rules were ranked by the declared-only evidence they contribute across the five investigations.
Only 28 rules contribute any, so all were read (five had been reviewed before). Each decision was made from the
rule's logic in the pinned Sigma / Elastic source before its effect on any result was looked at.

**Decisions** (`data/detection/technique-support-review.json`, 23 in total): 6 rules establish several of the
techniques they declare, 11 establish part, 6 establish nothing; 6 more were read and **left ambiguous**
(`left_ambiguous_after_reading`, with the reason — for two of them, that the rule text was not read in full).
Established coverage of the packs: 294 -> 297 of 384 declared techniques.

**One decision was wrong and was corrected by the events.** "Microsoft Windows Defender Tampering" was recorded,
from its logic, as establishing Modify Registry and the defence-impairment technique. The event it matched in the
APT29 recording was Defender's own engine setting its own value. The decision is now "establishes nothing", and
its reason records the correction. Reading the logic is not sufficient; the matched events of the other newly
counted techniques were checked at the level of the rule and process behind each (an archiver, PowerShell script
blocks, a shell started by the service manager, a decode call) and are consistent — a light check, not a review of
each full event.

**Results** (before: `data/validation/history/investigations.before-review-batch-1.json`; after:
`...after-review-batch-1.json`; audit 45,955 checks, all passing):

| Recording | Verdict | Counted | Gained / lost | Top profile after |
|---|---|---|---|---|
| APT29 emulation | APT29 identified (unchanged) | 29 -> 32 | + Input Capture, Deobfuscate/Decode, Archive Collected Data | Kimsuky 46% (16 of 32) |
| APT3 emulation | not distinguishable (unchanged) | 8 -> 11 | + Command and Scripting Interpreter, Clipboard Data, Service Execution | APT41 69% (8 of 11) |
| LSASS run 01 | not distinguishable (unchanged) | 8 -> 7 | - NTFS File Attributes | Magic Hound 68% (5 of 7) |
| LSASS run 03 | not distinguishable (unchanged) | 9 -> 8 | - NTFS File Attributes | Kimsuky 72% (6 of 8) |
| Uploaded tool run | not distinguishable (unchanged) | 8 -> 7 | - NTFS File Attributes | APT32 82% (6 of 7) |

- No verdict changed; no wrong name.
- **The true actors became less similar, not more:** APT3 on its own emulation 46% (4 of 8) -> 32% (4 of 11); APT29
  on its own 17% -> 15%. By overlap the known actor is now at positions 14-124 (before this batch 10-116). The
  recovered evidence is real behaviour that those groups' public profiles do not list. Nothing was adjusted for it.
- The browser stream rule had also been counted in both LSASS runs; it no longer is.

## Amendment C (2026-10-12) — the two rules left unread, read in full with their events

- **"Mounting Hidden or WebDav Remote Shares"** (the largest contributor: 47 events, counted once per declared
  technique, 329 Evidence items). Establishes **nothing** at rule level: its three kinds of target (hidden share,
  WebDAV over SSL, http) are alternatives that the translated branches do not separate, and the rule observes
  neither the account used nor any account discovery. The 47 matched events were all mounts of another host's
  administrative share with supplied credentials — SMB/Windows Admin Shares in fact, which the rule cannot establish
  for every match. In that recording another rule establishes the technique, so nothing is lost there.
  **Limitation recorded:** a decision is per rule and cannot depend on the matched event; an event-conditioned
  decision would recover such evidence in general and is not supported.
- **"Potential Meterpreter/CobaltStrike Activity"**. Establishes **Token Impersonation/Theft**: both branches are
  the published named-pipe impersonation methods of one command, and the matched events (two recordings) are the
  second branch exactly. Creating a process with the token is not observed and stays declared only.

25 decisions; 4 rules remain read and left ambiguous. Re-run (audit 46,048 checks, all passing; snapshot
`data/validation/history/investigations.after-review-batch-2.json`): the two LSASS tool runs each count one more
technique (Token Impersonation/Theft: 7 -> 8 and 8 -> 9); the two emulations and the uploaded recording are
unchanged; no verdict, candidate count or known-actor position changed (positions 14-124). The outcome matched
what was predicted before the re-run.

## Amendment D (2026-10-13) — six further recordings, run unchanged

**What this is, and is not.** The six catalogued recordings not among the five above were run on the committed
build (`158a60f`) with no change to rules or decisions. They are held out from this ADR: none informed the
declared / established rule, the 25 decisions or the overlap display. They are **not** unseen by the project:
four have annotation files from the earlier calibration work, all were included when group-specific rule firings
were measured, and two test files reference some of them. So this measures whether ADR-0025 generalises, not the
platform as a whole. Snapshot: `data/validation/history/investigations.held-out-from-adr-0025.json`. The
served-model audit passes on them (161,659 checks, 6 investigations, 71 units).

| Recording | Known actor | Verdict | Counted | Declared only | Top profile | Known actor by overlap |
|---|---|---|---|---|---|---|
| LSASS tool run 04 | none | not distinguishable | 4 | 3 | two groups at 100% (4 of 4) | — |
| LSASS tool run 05 | none | not distinguishable | 6 | 2 | 80% (5 of 6) | — |
| LSASS tool run 06 | none | not distinguishable | 3 | 3 | two groups at 100% (3 of 3) | — |
| LSASS tool run 07 | none | not distinguishable | 3 | 1 | two groups at 100% (3 of 3) | — |
| APT3 emulation (CALDERA) | APT3 | not distinguishable | 14 | 40 | OilRig 59% (9 of 14) | APT3 16% (3 of 14), position 55 of 166 |
| APT29 emulation, day 2 | APT29 | not distinguishable | 27 | 48 | Kimsuky 42% (12 of 27) | APT29 19% (6 of 27), position 35 of 188 |

**Attribution.** No group was named on any of the six. For the four tool runs that is the right answer. For the
two emulations it is a miss: the known actor was not identified (and was nowhere near the top by overlap). No
wrong name. Across all eleven recordings: of four emulations one is identified (APT29 day 1, one rule match) and
three are not; of seven tool runs none is given a name. Identification rests on a single artefact in a single
recording — a demonstration that the path works, not evidence that it generalises.

**Detection.** Each tool run yields three to six counted techniques. Whether those are the right techniques was
not checked against ground truth here; that needs the recordings' own annotations and is a separate measurement.

**What generalised and what did not.**
- The declared / established rule did: nothing over-claimed was counted, and the audit holds.
- The recovered evidence did not: the 25 decisions were made for the rules that mattered in five recordings. On
  the two new emulations far more evidence is declared only than counted (40 against 14, 48 against 27), from 14
  rules that have no decision. A review set built from some recordings under-recovers on others.
- The small-denominator weakness is plain here: three tool runs show two groups at 100% overlap, resting on three
  or four techniques. The count beside the percentage (ADR-0021 Amendment A) is what makes that readable; without
  it these would look like strong matches.

**Not done in this step, deliberately:** no rule was adjudicated and nothing was tuned on these six. The 14
unreviewed rules are a candidate second batch; adjudicating them makes these recordings development data too.

## Amendment E (2026-10-13) — counted techniques against the dataset authors' own mappings

The measurement Amendment D left open. For the seven single-tool recordings the dataset's metadata lists the
techniques its authors performed. `scripts/measure_technique_ground_truth.py` compares those with the techniques
the platform counted, from the stored snapshots — nothing is run and nothing is tuned
(`data/validation/technique-ground-truth.json`). Techniques of the Resource Development tactic are set apart: the
authors state the recordings do not include the preparation of the files.

| | Authors' techniques in the recordings | Counted exactly | Counted as parent / sub | Not counted |
|---|---|---|---|---|
| All seven | 45 | 15 | 1 | 29 |
| Three whose results informed development | 21 | 7 | 1 | 13 |
| Four held out from this ADR | 24 | 8 | 0 | 16 |

**About a third of what the authors performed is counted** (16 of 45; 8 of 24 on the held-out four). The two
figures are close, so this is not an effect of tuning; it is what the detection content sees.

- **Counted every time:** LSASS Memory and System Owner/User Discovery — the core of each simulation.
- **Never counted:**
  - User Execution: Malicious File (the payload being run) — no rule recognises it; the same gap as the
    double-extension download recorded in Amendment A.
  - System Information Discovery — detected in the three recordings checked, but only by low-level (enrich)
    rules, which are shown and never compared.
  - Exfiltration Over C2 Channel and Ingress Tool Transfer — network behaviour; the host logs analysed here do
    not show it, and the recordings' network captures were not part of these runs.
  - Process Discovery, Process Injection, Windows Service, Query Registry — not detected in the recordings where
    the authors list them.
- **Counted but not listed by the authors:** 17 across the seven (4 on the held-out four). Not false positives by
  that fact alone — the authors list the simulation's steps, not everything on the host — but they include the
  side effects of the recording setup found in Amendment A (a built-in script and its registry writes).

**What this changes.** "Coverage" in this project has meant that a rule exists (declared), then that a rule can
establish the technique. This is the first figure for what is actually counted on real recordings of known
content, and it is about one third. It says where detection work would pay: execution of a delivered file, the
enrich-only discovery techniques, and network telemetry — not more rule imports for techniques already covered.

**Limits.** Seven recordings of one family (credential dumping with different tools), one host each; the authors'
lists are coarse (no times, no events), so a "found" technique was not checked to be found on the right event.

## Amendment F (2026-10-13) — the tool runs again, with their network logs: no change

**Question.** Amendment E found network behaviour (exfiltration over the command channel, tool transfer) never
counted, and the recordings' network logs had not been part of the runs. Would including them close that gap?

**What was done.** Each of the seven tool runs comes with Zeek logs (connections, DNS, HTTP, file transfers,
Kerberos, SMB). They were added to the host logs and the seven were re-run with nothing else changed
(snapshot `data/validation/history/investigations.tool-runs-with-network.json`; audit 12,050 checks, all passing).
No parser was needed: the existing Zeek reader recognises the files.

**Result: nothing changed.** In all seven, the counted techniques, candidates, top profiles and verdicts are
identical to the runs without network logs; no network Evidence is in any activity cluster; still 16 of 45.

**Why.** The telemetry is read — one tool run yields 247 network Observations (116 connections, 121 DNS queries,
4 file transfers, 4 HTTP requests, 1 Kerberos, 1 SMB mapping). 78 rules in the engine read Zeek data. **None of
them fires on any of those Observations.** The gap is detection content, not ingestion: the pinned Zeek rules
look for specific protocol abuse (remote administration over DCE/RPC, SMB file patterns and the like), not for a
payload fetched over HTTP or a command channel that looks like an ordinary connection. One relevant log is not
read at all: Zeek's executable-file log (`pe`), refused by the reader as "not a traffic log read here" — together
with the file-transfer log it is the direct evidence of an executable arriving over the network.

**Consequence for the plan.** Including network logs is necessary and not sufficient. The measured gaps are
detection-engineering tasks: a transfer of an executable over HTTP (file-transfer and executable-file logs), then
the delivered file being written and run (host logs), correlated — not more telemetry and not more rule imports.

## Amendment G (2026-10-18) — low-level discovery detections: inspected, nothing promoted

**Question.** Amendment E found System Information Discovery, listed by the authors in every tool run, detected
only by low-level (enrich) rules, which are shown and never compared. Should those detections be promoted?

**Survey** (`data/validation/history/low-level-detections.tool-runs.json`): every low-level detection in the seven
tool runs, by rule and technique. Of all of them, one rule bears on a technique the authors list and the platform
does not count: Elastic's command-shell discovery rule, System Information Discovery, in four recordings.

**The events.** Every one is `cmd.exe /c set processor >> config\osinfo.txt` (or `set u`), started by `cscript.exe`
— the built-in network-diagnostics script that `netsh trace stop` runs (Amendment A): a side effect of how the
recordings were made, not the attacker's discovery. Promoting this rule would have raised the measured figure by
counting the recording harness. **Nothing was promoted.**

**What the authors' discovery was.** Their simulation ran discovery from inside the delivered payload (a
command-and-control implant). Such discovery is API calls inside one process, with no child process and no
command line, so process-creation logs do not show it. Detecting it needs other telemetry (API or script-content
logging from inside the implant), not a different reading of the events here.

**Measurement after this step:** unchanged, 17 of 45. Steps 3 and 4 of the reviewer's plan are complete; step 4's
repeat measurement records no change, and the reason.

## Amendment H (2026-10-18) — correction to Amendment G: the attacker's discovery *was* recorded

Amendment G said the authors' System Information Discovery ran inside the implant and left no process to detect.
**That was wrong.** Its survey read only the Evidence inside activity clusters. The context view added in
ADR-0026 Amendment B lists the Evidence outside them, and there it is: `systeminfo.exe`, detected by a low-level
Sigma rule, in each tool run checked (four of four). Its ancestry in the uploaded recording:
`systeminfo.exe` <- `cmd.exe` <- `winx64_payload.exe` (the implant) <- `happy_image.jpeg.exe` (the delivered
file). It is the attacker's discovery.

**Why it is not counted.** The rule is low-level (enrich): shown, never compared. And it is outside every cluster:
the `cmd.exe` between it and the implant matched no rule, so no Evidence sits on it, and structural correlation
links Evidence to Evidence. A chain through an undetected process is broken.

**What the harness finding still holds.** The `set processor >> osinfo.txt` detections of Amendment G are the
recording harness; that stands. What does not stand is "no process to detect".

**Consequence.** The gap is in correlation, not telemetry: linking a low-level detection to a cluster through the
process ancestry, across processes that matched no rule. Recorded as the next step (ADR-0003 is the decision to
amend); the measured figure is unchanged until then.

## Amendment I (2026-10-18) — a reviewed low-level rule may count once linked into a cluster

**Decision.** A review may mark a low-level rule `"counts_when_linked": true`. Its Evidence stays low-level (it
never forms a unit, ADR-0003 Amendment H), but once it is in a unit its technique is a feature of that unit
(`Evidence.counted_when_linked`). Joining a unit requires a structural link to core Evidence — with ADR-0003
Amendment I, through the process ancestry. So the technique counts only where the detection sits in an attack's
process chain, never where the same command was run anywhere else.

**First decision:** "Suspicious Execution of Systeminfo" (Sigma, low): every match is System Information
Discovery; low-level because administrators run it routinely.

**Measured** (seven tool runs; snapshot `data/validation/history/investigations.tool-runs-with-ancestry.json`;
audit 14,205 checks, all passing after its feature check learnt this rule):

| Tool run | Counted before -> after | Authors' techniques counted |
|---|---|---|
| 01 | 8 -> 9 (+ System Information Discovery) | 3 -> 4 of 7 |
| 02 | 9 -> 10 (+ the same) | 3 -> 4 of 6 |
| 03 | 9 -> 10 (+ the same) | 3 -> 4 of 8 |
| 04 | 4 -> 4 | 2 of 5 |
| 05 | 6 -> 7 (+ the same) | 2 -> 3 of 7 |
| 06 | 3 -> 4 (+ the same) | 2 -> 3 of 6 |
| 07 | 3 -> 3 | 2 of 6 |

**17 -> 22 of 45.** No verdict changed. In tool runs 04 and 07 `systeminfo` was also started by a shell, but no
ancestor within three steps has Evidence of its own (the delivery there matched no rule), so it stays context — the
bound doing its job, reported rather than relaxed.

**Reference investigations** (main site, snapshot `data/validation/history/investigations.after-ancestry.json`,
compared with `investigations.after-platform-rules.json`; served audit 49,079 checks over 6 investigations, all
passing): System Information Discovery is now counted in lsass-01, lsass-03 and the lab credential-dumping
recording (8 -> 9, 9 -> 10, 9 -> 10 techniques). Verdicts unchanged everywhere; APT29 day 1 and APT3 Empire
unchanged; known-actor positions in `data/validation/known-answer-checks.json` unchanged (best 14, worst 124; no
wrong name). The orderings on tool tests now name different groups at the top (e.g. Sowbug), as expected when a
broadly used technique is added: they remain orderings, not verdicts.

## Amendment J (2026-10-19) — the rules the held-out emulations exposed, read with their events

**What this uses up.** Amendment D left 14 rules with declared-only evidence on the two held-out emulations
(APT3 CALDERA, APT29 day 2) unread; one (Defender tampering) was decided since. The other 13 are decided here, so
those two recordings are now development data for the review, not held-out data.

**Method.** As before: a rule establishes a technique only if every match of its logic does. New in this batch,
each rule's matched events were read in the recordings before deciding (script blocks and process starts), and what
they showed is in each reason. That reading changed the picture for PowerShell script-block rules: most matches
were **fragments of attack-tool modules being loaded** (a credential-dumping module, a reflective loader, a
reconnaissance module) — the code was present and compiled, but the specific function was not shown to run. A
rule whose branch is satisfied by a function name or a definition therefore establishes PowerShell, not the
function's technique.

| Rule | Establishes | Why, in short |
|---|---|---|
| PowerShell Script with Token Impersonation Capabilities | T1059, T1059.001 | one branch only enables a privilege on the script's own token; matches were a loader doing that |
| Suspicious .NET Reflection via PowerShell | T1059, T1059.001 | assembly-load also loads by name; reflective loading not shown by every match |
| Suspicious Portable Executable Encoded in PowerShell Script | T1027, T1027.013, T1059, T1059.001 | every match carries a base64-encoded executable |
| PowerShell Share Enumeration Script | T1059, T1059.001 | matched a function name in a module's alias list |
| Potential WinAPI Calls Via PowerShell Scripts (Sigma) | T1059.001 | function names together; calls not observed (as PSReflect) |
| PowerShell Mailbox Collection Script | T1059, T1059.001, T1114 | every branch builds a mail client object and reads a folder; local or remote differs |
| PowerShell Script with Encryption/Decryption Capabilities | nothing | matches were the implant's channel encryption; no declared technique follows |
| Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell (Sigma) | T1047, T1059.001 | PowerShell started by the WMI provider host; remote use not observed |
| NTFS Alternate Data Stream (Sigma) | T1059.001 | the two strings need not be together; matches were PowerShell's own module code |

Left ambiguous after reading (alternatives by branch): Potential Invoke-Mimikatz PowerShell Script, HackTool -
Mimikatz Execution, Suspicious CertUtil Commands, Potentially Suspicious Execution From Parent Process In Public
Folder. 36 decisions, 8 rules read and left ambiguous.

**Predicted before the re-run:** CALDERA +2 (T1027, T1027.013), day 2 +2 (T1047, T1114), no verdict change.

**Measured** (snapshots `investigations.before-review-batch-3.json` / `.after-review-batch-3.json`; audit 157,123
checks over the two, all passing; 2,915 tests passing):

| Recording | Counted | Added | Verdict | Known actor by overlap |
|---|---|---|---|---|
| APT3 emulation (CALDERA) | 15 -> 17 | T1027, T1027.013 | not distinguishable | APT3 4 -> 5 of 17 |
| APT29 emulation, day 2 | 27 -> 29 | T1047, T1114 | not distinguishable | APT29 6 -> 7 of 29 |

As predicted. The six reference investigations are identical (snapshot
`investigations.after-review-batch-3-reference.json`; audit 49,079 checks; `known-answer-checks.json` summary and
every known-actor position unchanged).

**What this does not fix.** 38 (CALDERA) and 46 (day 2) techniques remain declared only, mostly from the two
large function-name rules (HackTool function names, Invoke-Mimikatz) whose branches are alternatives. Reading more
rules will not recover them; a rule whose match names one function — a decision per branch, conditioned on the
matched event — would, and is not decided here (it is the "event-conditioned decision" left open above). Neither
emulation is identified; adjudication adds established techniques but no group-specific evidence.

## Amendment K (2026-10-19) — decisions conditioned on the matched event

**Problem.** A decision said what *every* match of a rule establishes. For a rule whose branches are
alternatives, that is often nothing — although each individual match shows which branch ran: certutil was given
`-decode` or a URL, a credential tool was given `lsadump::sam` or `sekurlsa::logonpasswords`. Four rules were left
ambiguous for exactly that reason.

**Decision.** A decision may carry `when` clauses (review file `technique-support-review/2`). Each clause is one
detection-engine field condition — the engine's own `FieldCondition`, case-insensitive, with its exact semantics —
evaluated on the Observation the rule matched; the techniques it names are established for the matches that
satisfy it, in addition to what every match establishes. Clauses name only techniques the rule declares (tested
against the packs), each with a reason. A clause **may not read PowerShell script-block text** (refused by the
loader): Amendment J found script blocks are mostly tool code being loaded, so text in a block is code that was
compiled, not code shown to run. Clauses therefore apply to process starts, where the command line is what ran.

| Rule | Clause → establishes |
|---|---|
| Suspicious CertUtil Commands | URL-cache verb with a URL → T1105; decode verbs → T1140; PFX export → T1552, T1552.004 |
| HackTool - Mimikatz Execution | `sekurlsa::` credential commands → T1003.001; `lsadump::sam` → .002; `::secrets` → .004; `::cache` → .005; `::dcsync` → .006 |
| Potential Credential Access via Windows Utilities | procdump `-ma lsass` → T1003, T1003.001; ntdsutil → T1003, T1003.003; rundll32 → T1218, T1218.011 |
| Potentially Suspicious Execution From Parent Process In Public Folder | child is cmd / PowerShell / cscript / wscript → T1059 |

Found while predicting: a first draft of the LSASS clause read "command line contains lsass", which a dump *file*
named after LSASS also satisfies. It was narrowed to procdump's target argument before any result was read.

Limit: a command line that only mentions a command (for example printing it) would be over-claimed; the same limit
applies to every command-line decision since Amendment B. 40 decisions; 4 rules remain read and left ambiguous
(the two PowerShell script-block rules, Invoke-Mimikatz and HackTool function names, among them — correctly).

**Predicted before the re-run** (recorded 2026-10-19T15:13Z): CALDERA 17 → 18 (+T1003.002, the SAM dump in the
command PowerShell ran); APT29 day 2 unchanged (its certutil decode and credential commands are already counted
by other evidence); LSASS run 03 + T1218, T1218.011 (comsvcs through rundll32); others unchanged; no verdict
change.

**Measured — as predicted** (snapshots `investigations.after-amendment-k.json` and
`investigations.after-amendment-k-reference.json`, compared with the Amendment J snapshots):

| Recording | Counted | Added | Verdict |
|---|---|---|---|
| APT3 emulation (CALDERA) | 17 -> 18 | T1003.002 (Security Account Manager) | not distinguishable |
| LSASS tool run 03 | 10 -> 12 | T1218, T1218.011 (Rundll32) | not distinguishable |
| APT29 day 2, APT29 day 1, APT3 Empire, LSASS 01 and 04, lab recording | unchanged | — | unchanged; APT29 day 1 still identified |

Served audit: 157,129 checks (the two emulations) and 49,143 (the six reference investigations), all passing.
`known-answer-checks.json` regenerated against the served reference investigations: summary and every known-actor
position unchanged (best 14, worst 124; no wrong name).

**Correction to Amendment J.** Its statement that `known-answer-checks.json` was regenerated and unchanged rested
on a command that was given without the server address: the script printed its usage and wrote nothing, so the
file compared equal because it was not rewritten. The conclusion held for another reason — the six reference
investigations counted exactly the same techniques before and after Amendment J (snapshot), and the orderings are
computed from those — but the file was not regenerated then. It is regenerated here against the served
investigations.
