# ADR-0010 — Linux telemetry (ADR-0008 Wave 2, first format)

- **Status:** ACCEPTED (2026-10-01, owner delegation "go ahead" on the recommended Wave 2 order: Linux first).
  Implementation is gated on the data download in D6, which needs the owner's explicit approval.
- **Builds on:** ADR-0008 (per-format acceptance standard D2, one authoritative source per observation kind D3,
  record shapes D4, domain additions D5), ADR-0007 (Sigma import, field map, false-coverage guards), ADR-0003
  (structural correlation; Amendment B pid-only identity; Amendments E/F), ADR-0005/0006 (attribution and
  calibration are format-agnostic).

## Context — measured, not assumed

Wave 2 order was chosen by measuring what each format adds through the pinned Sigma release (r2026-07-01, Core++):
Linux has the largest uncovered share — **27 ATT&CK techniques** not covered by any imported rule, out of 132
rejected Linux rules. Their logsources split cleanly:

| Sigma logsource | Rules | New techniques | Fields read |
|---|---|---|---|
| `linux / process_creation` | 78 | 16 | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `LogonId`, `CurrentDirectory` |
| `linux / auditd` | 26 | 13 | raw audit record fields: `type`, `SYSCALL`, `a0`–`a3`, `exe`, `name` |
| `linux / file_event` | 5 | 3 | `TargetFilename`, `Image` |
| `linux / network_connection` | 5 | 2 | `Image`, `Initiated` |
| other services (syslog, cron, sshd, clamav, …) | 18 | ≤ 4 | free-text / keyword rules |

The 27 include T1014 (rootkit), T1053.003 (cron), T1059.004 (Unix shell), T1543.002 (systemd service),
T1546.004 (shell configuration), T1547.006 (kernel modules), T1548.003 (sudo), T1552.003 (shell history),
T1574.006 (dynamic linker hijacking).

**Sources examined (facts verified at the source on 2026-10-01).**
- **Sysmon for Linux** (`microsoft/SysmonForLinux`, MIT, maintained): the Sysinternals schema on Linux, written to
  syslog as one XML `<Event>` per line (channel `Linux-Sysmon/Operational`). Its integration tests cover event IDs
  1 (process create), 2, 3 (network connect), 4, 5 (process terminate), 9, 10 (process access), 11 (file create),
  16, 22 (DNS), 23 / 26 (file delete). It carries `ProcessGuid` / `ParentProcessGuid`, so ADR-0003 structural
  correlation works exactly as on Windows. Sigma's `linux/process_creation` field names are its field names.
- **auditd** (the Linux Audit framework, raw `audit.log`): one event is several records (`SYSCALL`, `EXECVE`,
  `PROCTITLE`, `PATH`, `CWD`, …) sharing an event serial `msg=audit(<time>:<serial>)`; `EXECVE` arguments may be
  hex-encoded; there is no process GUID (pid / ppid only). Sigma's `linux/auditd` rules match individual records
  by `type`.
- **Elastic Auditbeat / Elastic Agent** (ECS-normalized auditd) — the Elastic-native path; not needed to consume
  the available real data, which is raw. Kept as a later record shape (ADR-0008 D4), not a new source.
- **Real data:** `splunk/attack_data` (Apache-2.0, maintained) holds **59 Sysmon for Linux logs (677 MiB)** and
  **102 auditd logs (1.5 MiB)** from Atomic Red Team / attack-range runs, each labelled by ATT&CK technique in a YAML
  descriptor, across 17 + 30 techniques; and Linux **malware detonations**: AcidRain (S1125) and Cyclops Blink
  (S0687) — both attributed to **Sandworm Team (G0034)** in the pinned ATT&CK v19.2 — and AwfulShred (not in ATT&CK).
  No OTRF Linux compound dataset was found.

## Decisions

**D1 — Sysmon for Linux first, through the existing Sysmon adapter.** A new record shape (ADR-0008 D4): a syslog
line carrying a Sysmon `<Event>` XML document is parsed into the same `EventData` mapping the Windows path uses,
then built by the **same** per-event builders — so the Linux and Windows field semantics cannot drift. Supported
first: 1, 3, 5, 11, 23 (the IDs the Sigma Linux content reads, plus process terminate for identity proofs); 10 and
22 when a real sample exists. The XML is parsed with a hardened parser (no DTDs, no entity expansion); any line that
is not a well-formed Sysmon event fails closed. Event time is Sysmon's own `UtcTime` (as on Windows).

**D2 — Operating system becomes an explicit scope (contract change).** `HostRef` gains `os_type` (ECS
`host.os.type`: `windows` / `linux` / `macos`), set by every adapter from facts it reads (the channel / provider
proves the platform). Sigma logsources are product-scoped: `linux/*` rules require `host.os.type equals linux`;
`windows/*` rules require it **not** to be `linux` or `macos` (so fixture and synthetic Windows observations,
which predate the field, keep matching). Without this, a Windows rule matching `CommandLine contains whoami` would
fire on a Linux process — false coverage of exactly the kind ADR-0007's guards exist to prevent. The field map
moves to `sigma-field-map/10`; every rule's content hash changes once (recorded, expected).

**D3 — Linux field semantics are exact, never Windows-normalized.** Paths stay POSIX (`/usr/bin/bash`; the bare
name is the last `/` segment); `User` is the account name as logged (no `DOMAIN\` split); `LogonId` is Sysmon's
value. Case-sensitivity follows Sigma (case-insensitive unless the rule says `|cased`); POSIX paths are never
case-folded by the adapter.

**D4 — auditd second, one Observation per audit record.** Sigma's auditd rules match single records (`type:
EXECVE` with `a0` …), so each record becomes one Observation carrying its raw fields under a new `audit` entity
group (record type, syscall, `a0`–`aN` decoded from hex only when the record marks them hex, `exe`, `comm`,
`name`, `key`, `pid`, `ppid`, `auid`, `ses`), with the event serial as `audit.event_id`. Records of one audit event
are one instance of execution: a new structural dimension `SAME_AUDIT_EVENT` (same host + same serial) would be
proposed as an ADR-0003 amendment *with* this batch, not assumed now. Process identity is pid-only (Amendment B;
the B3 principal rule uses `auid`), so auditd evidence joins Sysmon for Linux process chains only where both are
collected and the proof rule holds.

**D5 — No overlap without a precedence rule.** Where a host runs both Sysmon for Linux and auditd, process starts
are double-counted (as Sysmon 1 vs Security 4688 on Windows). ADR-0008 D3 extends: `process_start: [sysmon,
auditd]` (Sysmon first: it has GUIDs). Implemented in the auditd batch with real-data proof, as 4688 was.

**D6 — Data: a pinned, verified subset of `splunk/attack_data` (download requires owner approval).**
Proposed: all 102 auditd logs (1.5 MiB); the 47 Sysmon for Linux logs ≤ 20 MiB (160 MiB); and the two
Sandworm-attributed malware detonations, AcidRain (14.1 MiB) and Cyclops Blink (76.5 MiB) — about **252 MiB**
in total, fetched from Git LFS at a pinned commit, each file's SHA-256 recorded in a manifest (the LFS pointer
oid), cache git-ignored, a small golden-record file vendored with the Apache-2.0 notice. The ten large technique
captures (22–57 MiB each, 425 MiB) and AwfulShred are not needed for golden tests and are left out.

**D7 — Validation per ADR-0008 D2.** Golden tests on real records of every supported event and shape;
fail-closed tests; a parity test for the OS scope (no Windows rule ever fires on a Linux Observation, and vice
versa, proven on the real data); technique-level detection checks against each dataset's own ATT&CK label
(documented, not derived from our detections); coverage re-measured. The Sandworm detonations are **not** added to
the calibration corpus by this ADR: a malware detonation documents the malware, not an intrusion, and whether it
may label a Sandworm family is a labelling-rule decision for ADR-0006 / doc 15, taken separately.

## Consequences

- Linux becomes a first-class platform with the same quality bar as Windows; up to 27 techniques become
  detectable (measured after implementation, not claimed now).
- The OS scope (D2) is a one-time change to every rule's hash and closes a latent cross-platform false-coverage
  path before it can occur.
- auditd adds a correlation question (D4) that is answered by an ADR-0003 amendment with real-data evidence, not
  by assumption.

## Alternatives rejected

- **auditd first.** Smaller data, but no process GUIDs (weaker correlation), multi-record reassembly, and fewer
  new techniques (13 vs 16 for process creation alone).
- **A separate Linux Sysmon adapter.** Duplicates builders whose semantics must stay identical across platforms.
- **Auditbeat as the source of truth.** The real data available is raw; Auditbeat is a record shape to add later,
  not a reason to discard raw-auditd support.
- **Synthetic Linux telemetry.** Rejected project-wide (ADR-0008): adapters are validated on real recordings.

## Implementation record — Sysmon for Linux (2026-10-01)

- *Data (D6):* owner-approved; 264 files (149 logs + 115 descriptors, 249,116,616 bytes) from `splunk/attack_data`
  at `a28608b5`, every log verified against its Git LFS pointer's SHA-256 and size
  (`scripts/acquire_linux_telemetry.py`, tracked `manifest.json` / `selection.txt`, cache git-ignored). The
  selection came to ~238 MiB of logs, below the approved ~252 MiB (the ≤ 20 MiB bucket already held AcidRain).
- *Record shape (D1):* `sources/sysmon_xml.py` parses one `<Event>` into the collector shape the existing Sysmon
  builders read; DTD / entity declarations are refused before parsing; malformed, duplicate-`Data`, non-`Event`
  and foreign-channel input fails closed. The channel `Linux-Sysmon/Operational` sets `host.os_type = linux`.
- *Real-data finding — events span lines:* Sysmon for Linux writes a command line's own newlines verbatim (e.g.
  a 17-line `sh -c` in the cron dataset, a multi-line `perl -e` in AcidRain). A line-based reader would have cut
  those events and corrupted exactly the field detection reads. `iter_recording_records` now reassembles an XML
  event from `<Event` to `</Event>` over raw lines (blank lines kept); an unterminated event is refused, never
  cut. Plain `.log` / `.json` / `.jsonl` recordings are read directly.
- *OS scope (D2):* `HostRef.os_type`; all Windows adapters set `windows` from their channel;
  `PRODUCT_OS_SCOPES` adds the OS conditions after the indexed logsource scope (importer 1.7,
  `sigma-field-map/10`). Proven three ways: unit-level (both products' rules carry their scope), real-record
  level (the production pack's 4661 detection stops firing when the same Observation is labelled Linux), and
  whole-cache level (only Linux rules fire on 246,717 Linux Observations).
- *Coverage:* Linux rules imported 0 → **73** (67 process creation, 5 file, 1 network); pack 1,466 → 1,539;
  ATT&CK ids with an imported rule 275 → 291 (+16, e.g. T1014, T1053.003, T1059.004, T1222.002, T1548.003);
  group-used techniques **225 → 238 of 498**; every Windows rule's status unchanged. Remaining Linux
  process-creation rejections are translation limits (DNF bound 5, regex 4) and `LogonId` (2, not captured).
- *Real-data results* (`scripts/report_linux_telemetry.py` → tracked `conversion-report.json`; the test pins it
  to the current manifest and pack): **246,717** Observations (unique ids; 157 events appear in two dataset
  files); the only refusals are 52 Event 9 (raw access read, unsupported). 13 detections by 6 Linux rules
  (sudoers access, chmod on sensitive directories, doas configuration, shell via find / apt / awk).
  **Technique-level recall against the datasets' own labels is 1 of 45** (doas → T1548.003). Checked rather than
  assumed: the misses are content gaps — no imported Linux rule targets T1003.008, T1016, T1068, T1485, T1489 or
  T1547.006, and where one exists it targets other procedures (the cron rule requires a crontab loaded from
  `/tmp/`, the dataset loads `/var/log/tasks`; the rootkit rule is for Triple Cross, the data is Medusa). The two
  Sandworm-attributed detonations (AcidRain, Cyclops Blink) trigger **no** Sigma Linux rule.
- *Consequence:* the Linux pipeline is exact and validated; Linux *detection content* is now the bottleneck, not
  telemetry. Raising it means more content (the Sigma rules above the Core++ policy line, or reviewed local
  rules), which is a content decision under ADR-0007, measured the same way.
- *Acceptance (ADR-0008 D2):* exact mapping ✓, fail-closed ✓, real-sample golden tests ✓ (8 records, 25 tests),
  source-agnostic ✓ (same builders, OS from facts), correlation facts ✓ (process GUIDs), Sigma wiring ✓, evidence
  type ✓; auditd (D4) remains the next batch — its available real logs are `ausearch -i` output whose event time
  has no zone, so a trustworthy event time must be established first or those records refused.

## Implementation record — auditd (2026-10-01)

- *Adapter (D4):* `sources/auditd.py` — one Observation per raw `audit.log` record, `node=` optional, the
  ENRICHED format's interpreted suffix (after the `\x1d` group separator) read for the syscall *name* and account
  names only. Event time = `msg=audit(<epoch>.<ms>:…)`, UTC, millisecond precision. auditd's untrusted-string
  encoding undone exactly (quoted literal / unquoted hex / `(null)`); split `aN_len` / `aN[i]` arguments,
  duplicates, non-UTF-8 hex and non-records fail closed. Nested `msg='…'` (SERVICE_STOP, ADD_USER, …) is parsed;
  a bare value there runs to the next `key=` — **found by the golden test:** auditd writes `op=adding user`
  unquoted, which a whitespace tokenizer truncated to `op=adding`.
- *Host:* the records name no host (no `node=`), and a host is never guessed. The pipeline gives the adapter the
  host the recording's **source declaration** states for `auditd` (only when exactly one host declares it);
  the report declares each dataset directory (one attack-range host) by its dataset path as `HostRef.id`.
- *Time — real-data finding:* of 7,187 audit records in the cache, **6,348 are `ausearch -i` output**
  (`msg=audit(MM/DD/YYYY hh:mm:ss.mmm:serial) :`): local time with **no zone**, so no trustworthy event time
  exists — refused, as the zone-less round-1 Windows exports were. 2 records with bare unencoded arguments
  (`a0=xclip`, which auditd never writes — a post-processed file) are refused. **837** raw records remain
  (839 lines; one record appears twice in its dataset).
- *Correlation:* ADR-0003 Amendment G — `SAME_AUDIT_EVENT` (structural; same host scope + event serial).
- *Detection:* `linux/auditd` scoped by `event.dataset equals auditd.log` + the Linux OS scope
  (`sigma-field-map/11`). auditd rules imported 0 → **19** (+2 partial; 5 free-text keyword rules and 2
  empty-value rules stay translation gaps). Pack 1,539 → 1,558; ATT&CK ids with an imported rule 291 → 297;
  group-used techniques **238 → 242 of 498**.
- *Dataset labels:* Splunk's labels predate ATT&CK v19's renumbering (e.g. `T1562.004`, revoked by `T1686`).
  `attack_knowledge/external_ids.py` (`ExternalIdResolver`) now holds the importer's `revoked-by` resolution
  (moved, not copied — the import output is byte-identical) and the report resolves labels through it.
- *Real-data results (report v2):* only Linux rules fire on either source. auditd: 8 detections by 4 rules
  (kernel module via insmod, `ld.so.preload` modification, user creation, firewall disable); **4 of 48** labelled
  datasets have their documented technique detected. Sysmon for Linux unchanged: 1 of 45. As before, the misses
  are content gaps, and most auditd datasets hold only refused `ausearch -i` records.
- *Acceptance (ADR-0008 D2):* exact mapping ✓, fail-closed ✓, real-sample golden tests ✓ (9 auditd records,
  21 tests), source-agnostic ✓, correlation facts ✓ (`SAME_AUDIT_EVENT`; Sysmon ↔ auditd pid resolution only
  where one host records both — not in the available data), Sigma wiring ✓, evidence type ✓. D5 (Sysmon-over-
  auditd precedence) is not needed: auditd records are not classified as process starts, so no observation kind
  is double-counted; it will be revisited if a process-start mapping is added.

## Amendment A (2026-10-19) — the remaining Linux audit work, measured: nothing to build on the available data

The roadmap listed "a Linux audit reader". The reader exists (implementation record above); two extensions were
open. Both were measured before building anything.

**1. Recovering the refused `ausearch -i` records (6,348 of 7,187).** Their time has no zone. A zone could be
*established* (not assumed) only where the same audit event appears both raw (UTC epoch) and interpreted (local
time), matched by event serial. Measured over the 48 datasets that hold interpreted records: serials are shared
in two datasets only, and the implied offsets are about 196 days — serial reuse across different sessions, not
the same events. No dataset establishes a zone, so the records stay refused. Assuming UTC would put a wrong
time on evidence that correlation and sequences depend on.

**2. Elastic's Linux rules on raw audit records.** 172 production Elastic rules name `logs-auditd_manager.auditd-*`
or `auditbeat-*`. They read Auditbeat's *normalised* event (one event per kernel event, with derived
`event.action` values such as `executed`, and `process.args` reassembled from `EXECVE`), not raw records.
Running them exactly would need Auditbeat's normalisation (go-libaudit's coalescing and its normalisation table)
ported and verified. Of the 172, 132 also read fields Auditbeat cannot supply from raw audit
(`process.parent.name` / `.executable` / `.args`, `process.command_line`) and would stay undetermined; about 40 could
apply at most. The available data to validate against is 837 raw records. A large exact-translation subsystem
validated on that little data is not justified now.

**Decision.** Linux audit reading is complete for the data available. The extension in (2) is deferred until
real Linux recordings exist (the owner's lab, or Elastic Agent output, which would carry the normalised shape
directly and need no port). The Linux detection gap remains the content gap measured above (Sysmon for Linux 5 of
45, auditd 5 of 48 labelled datasets), documented rather than hidden.
