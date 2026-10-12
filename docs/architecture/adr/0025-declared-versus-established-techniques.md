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
