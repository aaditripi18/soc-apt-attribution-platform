# ADR-0008 — Telemetry Source Formats: Acceptance Standard, Overlap Policy, and Order

- **Status:** ACCEPTED (2026-09-24)
- **Date:** 2026-09-24 (proposed) · 2026-09-24 (accepted)
- **Deciders:** project owner
- **Supersedes / superseded by:** — (extends doc 12 C0.2 §D.1/§D.2 and ADR-0007 D10)
- **Related:** [ADR-0003](0003-correlation-and-behavioral-chain-layer.md) (structural correlation) ·
  [ADR-0006](0006-calibration-corpus-and-versioning.md) · [ADR-0007](0007-detection-content-and-predicate-language.md)
  D5/D9/D10 · [12 deployment & endpoint scope](../12-deployment-and-endpoint-scope.md) ·
  [11 coverage model](../11-coverage-model.md) · [15 corpus v2 design](../15-corpus-v2-design.md)

> **ACCEPTED (2026-09-24)** by the owner: acceptance standard (D2), overlap policy (D3) and Wave-1 order
> (D1) all accepted as proposed. Decides how new telemetry formats enter the platform without degrading attribution quality: one
> acceptance standard every format must pass, a policy for sources that observe the same activity, a reusable
> adapter pattern for ECS-normalized input, and the build order. Creates no code. The owner chose **Option A**
> on 2026-09-24: complete Windows endpoint telemetry first; network, Linux, macOS and cloud as a second wave.

## Context

**Facts (2026-09-24).** The platform ingests one real telemetry format — Sysmon, event IDs 1 (process
create) and 3 (network connection) — plus hand-authored replay fixtures and Elastic Security alerts (as
detections). Measured against the imported Sigma rules (ADR-0007), the formats not yet supported carry most
of the reachable detection content:

| Format | Sigma rules | Group-used techniques not yet covered it could add (upper bound) |
|---|---|---|
| Sysmon — remaining event types | 551 | 23 |
| Windows Event Logs (Security, System, Defender, …) | 236 | 18 |
| PowerShell logging (4103/4104) | 162 | 20 |
| Linux (auditd, Sysmon for Linux) | 132 | 24 |
| Cloud/SaaS (Azure, AWS, M365, GCP, Okta, GitHub, …) | ~200 | ~40 |
| macOS | 43 | 13 |
| Zeek | 16 | 2 |
| Proxy / DNS / firewall / web server | ~50 | ~8 |

**The quality risk.** More formats only help attribution if each one is ingested exactly and does not distort
the evidence. Four concrete ways a new format can make attribution *worse*:

1. **Overlap.** Different sources can record the same action. Sysmon event 1 and Windows Security event 4688
   both record a process start. ADR-0003 correlates only structurally (same `Observation`, same
   `process.entity_id`, or parent→child `entity_id` lineage). Sysmon supplies a process GUID; 4688 is not
   known to supply an equivalent (to be verified on real samples). The same process seen by both would then
   produce a second, *unlinked* observation: its evidence could not join the attribution unit, and the one
   action would be split across units — silently fragmenting evidence (or, if it were linked, double-counting
   it in raw support/persistence).
2. **Approximate mappings.** A field mapped "close enough" makes rules fire on the wrong things.
3. **Unproven parsers.** A parser tested only on hand-written records can fail on real collector output.
4. **Format leakage.** Format-specific logic above the adapter boundary breaks source-agnosticism (doc 12).

## Decisions

### D1 — Build order (owner decision, Option A)

**Wave 1 — complete Windows endpoint (v1 scope):**

1. **PowerShell logging** — event 4104 (script block) and 4103 (module/pipeline).
2. **Sysmon — remaining event types**, in coverage-report order: registry (12/13/14), file (11, 23/26),
   image load (7), process access (10), remote thread (8), DNS query (22), pipes (17/18), driver load (6),
   WMI (19/20/21), process tampering (25), file stream hash (15).
3. **Windows Event Logs** — Security (e.g. 4688, 4624/4625, 4698, 4720, 1102), System (e.g. 7045),
   Defender — subject to the D3 overlap policy.

**Wave 2 (after corpus v2 and calibration are on solid ground):** network (Zeek, Suricata EVE), Linux
(auditd, Sysmon for Linux), cloud/identity (AWS CloudTrail, Entra/Azure, M365, Okta, GCP, GitHub), macOS.
Wave 2 changes doc 12's "Linux architecture-only in v1" scope and is decided then, not now. Cloud formats
matter specifically for cloud-profiled Groups (e.g. v19.2's ShinyHunters, TeamPCP); this is recorded so the
deferral is visible, not forgotten.

**Network formats need more than rules.** Zeek/Suricata's attribution value is mainly infrastructure evidence
(C2 endpoints, DNS, TLS). Using it for attribution requires the threat-intelligence/IOC layer (research doc
04), which is not built. Wave 2 network work therefore includes that layer's design; it is not "add an
adapter and done".

### D2 — Format acceptance standard (every format, no exceptions)

A format is supported only when all of these hold; otherwise it is not listed as supported:

1. **Exact mapping or recorded gap.** Every field it populates has one exact normalized home; anything else
   is left unmapped and appears in the coverage report — never approximated (ADR-0007 D5 rule, extended to
   adapters).
2. **Fail closed.** Unknown event types, malformed records and wrong-typed fields raise; nothing is silently
   dropped or guessed (the Sysmon adapter's existing contract).
3. **Real-sample tests.** Golden tests on **real, licensed** sample logs of the format (e.g. OTRF
   Security-Datasets, MIT), in addition to hand-written edge cases. Samples are vendored or hash-pinned with
   provenance, like other data.
4. **Source-agnostic output.** Only neutral `Observation` fields leave the adapter; no format name, event ID
   or native field name above the boundary (guard test, as for Sysmon).
5. **Correlation proof.** A test shows the format's observations link structurally where the source asserts
   identity or lineage, and that its known overlaps follow D3.
6. **Detection wiring.** The Sigma logsource(s) it serves are mapped in the field map only for fields it
   exactly produces; the Sigma pack and the coverage report are regenerated and the gain recorded.
7. **Evidence type honesty.** Evidence carries the right `EvidenceType` (e.g. infrastructure indicators are
   evidentiary, not behavioral).
8. **Performance check.** Engine cost per Observation is measured and recorded.

### D3 — Overlap policy: one authoritative source per observation kind

For activity recorded by more than one source, the platform does **not** try to merge two observations after
the fact (merging without a shared identifier would be a guess). Instead:

- Each observation kind (process start, network connection, file create, …) has an ordered **source
  precedence** per host, declared in the deployment's coverage declaration (doc 11 coverage model), e.g.
  `process_start: [sysmon, windows_security]`.
- On a host where the higher-precedence source is declared present, the lower one's observations of that
  kind are **not ingested** (recorded as suppressed-by-precedence, counted, never silently lost). On a host
  without it, the lower-precedence source is used, and its weaker correlation (e.g. no process GUID) is a
  recorded limitation that lowers confidence through the existing coverage mechanism, not likelihood.
- Default precedences favour the source with the stronger identity fields (Sysmon over Security for process
  starts).

This keeps each action as exactly one observation, preserving ADR-0003's structural correlation and the
distinct-feature decision basis, and it is explainable (the suppressed count is visible).

### D4 — ECS-normalized input pattern

Much Windows telemetry arrives already normalized to ECS by Elastic Agent (Windows integration: Sysmon,
PowerShell; System integration: Security/System/Application channels). Adapters therefore follow the pattern
the Sysmon adapter already established: read the collector's ECS fields, and where the source's native field
names are what detection content is written against (Sysmon/Windows EventData, e.g. `ParentImage`,
`ScriptBlockText`), prefer the raw `winlog.event_data` value with an ECS fallback. One adapter per source
family, each dispatching on the source's event identifier and failing closed on unknown ones. Exact dataset
names and field mappings are verified against real samples during implementation, not assumed here.

### D5 — Domain additions are deliberate

New observation kinds need new neutral entity groups (e.g. registry key/value, script block, image load,
target process for process access, DNS query). Each is added only when its format is implemented, recorded in
this ADR's implementation record, and kept ECS-aligned — never speculatively.

## Consequences

**Positive:** a clear, testable bar for "supported"; the overlap failure mode is prevented by design; format
work is ordered by measured attribution value; the coverage report tracks progress honestly.

**Negative / costs:** each format needs real sample data and golden tests (slower than writing parsers alone);
the precedence declaration adds a deployment configuration step; Wave 2 is explicitly deferred.

**Neutral:** the attribution engine is unchanged — it only ever sees neutral observations.

## Alternatives considered

- **Add many adapters quickly, fix quality later** — rejected: repeats the prior version's failure
  (features without correct substance).
- **Merge overlapping observations heuristically (same host + pid + time window)** — rejected: pid reuse and
  clock skew make it a guess; a wrong merge invents a relationship. Precedence is exact and explainable.
- **Ingest everything and let correlation sort it out** — rejected: correlation cannot link observations
  that share no identifier; evidence would fragment silently.

## Open questions for the owner

1. Accept the acceptance standard (D2) as the definition of "supported format"?
2. Accept the overlap policy (D3): one authoritative source per observation kind per host, with visible
   suppression counts?
3. Accept the Wave-1 order (D1): PowerShell → remaining Sysmon event types → Windows Event Logs?

## Implementation record

**Wave-1 order change (owner, 2026-09-24).** The first real samples acquired for PowerShell
(`data/telemetry-samples/otrf`, OTRF Security-Datasets, MIT, commit `d9d40ef1`) turned out to contain no
PowerShell/Operational events. The owner chose to do **remaining Sysmon event types first** (samples in hand)
and PowerShell after real 4103/4104 samples are found. D1's list is otherwise unchanged.

**Batch A — Sysmon flat format + event IDs 7, 11, 12, 13 (2026-09-24).**

- *Real-sample facts that shaped the design (D2.3):* OTRF records are **flat Windows EventData JSON**
  (`EventID`, `Channel`, `Image`, `ProcessGuid` … at top level), not ECS; they carry **no record id**; and the
  collector's `@timestamp`/`TimeCreated` disagree with Sysmon's own `UtcTime` by 5 h and 16 h in the two files.
  The same process start appears as Sysmon 1 (GUID `{39e4a257-e321-…}`, pid 3440) and Security 4688 (pid
  `0xd70`, no GUID) — the D3 overlap case, confirmed on real data. Sysmon reports integrity `High` where 4688
  reports `S-1-16-12288`.
- *Adapter:* `SysmonSourceAdapter` accepts both collector (ECS + `winlog`) and flat records; a flat record is
  re-enveloped so one code path reads every field "raw Sysmon EventData name first, ECS fallback". Flat
  records: channel must be Sysmon's (else refused); time = `UtcTime`; record id = `EventRecordID` or a
  deterministic content address `sha256:<hex>`. New event types: 7 image load → `dll` (path, name, PE info,
  code signature — of the **loaded library**, not the process), 11 file create → `file`, 12/13 registry →
  `registry` with Sysmon's `EventType` as `event.action` and `event.type` creation/deletion/change (unknown or
  mismatched `EventType` refused). Supported IDs: 1, 3, 7, 11, 12, 13; anything else refused with its ID.
- *Domain (D5):* `DllRef`, `CodeSignature`, `RegistryRef` (ECS `dll.*`, `registry.*`) added to
  `Observation`, extraction, replay fixtures, persistence and index mappings.
- *Known limitation (recorded):* flat records without a record id cannot distinguish a genuine same-millisecond
  repeat from a collector duplicate; byte-identical records share one id and are one observation. In the OTRF
  samples this is 21 of 253 supported records (all Sysmon 12 `CreateKey`). Decision support counts distinct
  features, so this never changes a decision; it can only lower raw repetition counts.
- *Detection wiring (D2.6):* `sigma-field-map/3` adds `image_load`, `file_event`, `registry_add`,
  `registry_delete`, `registry_set`, `registry_event`. Sigma import: 1,193 fully + 53 partially imported
  (was 819 + 42), 9,955 rules; coverage: **207 of 498 Group-used techniques** (was 188), 105 Groups with
  ≥ 10 covered.
- *Real-data result:* on the mavinject sample the production Sigma pack raises exactly two detections, both on
  the mavinject process start, mapping to **T1218.013** and **T1055.001** — the documented behaviour; one of
  them ("Renamed Mavinject.EXE Execution") fires because Windows 10's `mavinject.exe` embeds the original name
  `mavinject64.exe`, which is that community rule's own logic, faithfully translated. The HTTP-listener sample
  raises nothing (its PowerShell activity was not logged).
- *Acceptance checklist (D2):* exact mapping ✓, fail-closed ✓, real-sample golden tests ✓ (25 tests),
  source-agnostic output ✓, correlation facts ✓ (the DLL-writing PowerShell process is the parent entity of the
  mavinject process), Sigma wiring ✓, evidence type (behavioral) ✓, performance ✓ (2.0 ms/observation on the
  real samples; 16.7 ms on the process/network benchmark with 9,955 rules — to watch as rules grow).
- *Not yet supported, refused explicitly:* Sysmon 8, 9, 10, 22, 24 in the samples (next batch), and all
  Security/System records (D1 item 3).

**Batch B — Sysmon 8 (remote thread), 10 (process access), 22 (DNS) (2026-09-25).**

- *Scope rule applied:* only event types with **both** real samples and detection content. Samples in hand
  cover 8 (1 record), 10 (309), 22 (3); Sigma has 11, 22 and 18 rules for them. Sysmon 9 (raw disk read) and
  24 (clipboard) have samples but no detection content and stay unsupported; 6, 15, 17/18, 19–21, 23/26, 25
  have no samples yet and stay unsupported until they do.
- *Domain (D5):* `target_process: ProcessRef` (the process **acted upon**; `process` stays the actor),
  `ProcessAccessRef` (granted access, call trace), `RemoteThreadRef` (start address/module/function),
  `DnsRef` (question name, query status, results). Carried through extraction, replay fixtures, persistence and
  index mappings.
- *Real-data quirks handled exactly:* for 8 and 10 the actor is `Source*`, not `Image`; Sysmon spells the GUID
  field `SourceProcessGuid` in event 8 but `SourceProcessGUID` in event 10 — each event reads its own spelling.
  DNS events carry no `connection` type, so network-connection content never applies to a lookup.
- *Detection wiring:* `sigma-field-map/4` adds `process_access`, `create_remote_thread`, `dns_query`; scopes
  are now `(field, operator, value)` triples and `create_remote_thread` also requires an exact `event.action`
  (importer 1.2). Sigma import 1,229 + 54 partial (was 1,193 + 53), 10,118 rules; coverage **210 of 498
  Group-used techniques** (was 207).
- *Real-data results:* the injection chain is fully identified — mavinject's process start (`…d310…`) is the
  remote thread's source and Notepad's start (`…d210…`) its target, starting at `KERNEL32!LoadLibraryW`; DNS
  shows the dataset fetching from `github.com` / `raw.githubusercontent.com`. The production pack still raises
  exactly the two mavinject detections; the 309 process-access events add no false positives.
- *Gap stated:* the samples contain **no LSASS access**, so credential-access detection (T1003.001) is proven
  only on a hand-built record (rundll32 + `comsvcs.dll` MiniDump → "Lsass Memory Dump via Comsvcs DLL"), not on
  real telemetry yet. A real LSASS-access sample is wanted.
- *Performance (D2.8):* process-access events share the `process` category with ~3,900 process-creation rules;
  the engine index now also filters on a second-condition `event.type has_element` (exact for the same reason
  as the category index: membership tests on tuple fields never raise). Real samples: 14 → **1.1 ms/obs**; the
  all-process-start benchmark stays ~17.7 ms/obs (genuine rule cost; field-level indexing is the future lever).
- *Finding for the correlation layer (not changed here):* a remote thread or process access is a
  collector-asserted interaction between two process instances, but ADR-0003's structural dimensions (same
  observation, same process entity, parent→child lineage) do not include "acted upon". So the injected Notepad's
  own events are not linked to the injector's group through this event. Whether to add a process-interaction
  structural dimension is an ADR-0003 amendment for the owner to decide — recorded here so it is not lost.

**Batch C — Sysmon 15, 17/18, 19/20/21, 23 (2026-09-25).**

- *Samples:* round-2 OTRF files (commit `d9d40ef1`): Empire SMBExec, Empire Mimikatz, Empire WMI persistence.
  They are a **third record shape**, the NXLog/Logstash flat variant: extra pipeline fields (`RecordNumber`,
  `EventTime`, `EventReceivedTime`, `EventTypeOrignal`, `tags: ['mordorDataset']`, …), plus Sysmon's own
  `UtcTime`, `Channel`, `Hostname`. Here the collector time agrees with `UtcTime`.
- *Adapter:* pipeline fields are envelope and never reach an Observation; **`RecordNumber` (the Windows event
  record number) is now the record id**, so these exports no longer rely on content hashes (no collapse). New
  events: 15 → `file` + `FileStreamRef` (contents, hash string); 17/18 → `PipeRef` (create vs connect from the
  event ID — real `System`-process connects lack `EventType` and `ProcessId`); 19/20/21 → `WmiRef` (filter /
  consumer / binding, `Operation` → created/deleted, anything else refused; values kept exactly as reported);
  23 → `file` (deletion).
- *Real-data quirks (recorded, handled exactly):* the SMBExec export **dropped Sysmon's `EventType`** from all
  1,140 registry events. Event 13 is by Sysmon's definition always `SetValue`, so its operation follows from the
  event ID; event 12 (create/delete) cannot be recovered and its 680 records stay refused rather than risk a
  wrong operation. Pipe names are HTML-escaped by the export (`&lt;Anonymous Pipe&gt;`) and are kept as
  exported, not guessed back.
- *Scope separation:* Sysmon 11 and 15 are both ECS file creations, so `file_event` now also requires the exact
  `file_create` action; stream hash uses `file_stream_create`, file delete `file_delete`, pipes and WMI match on
  `pipe_` / `wmi_` action prefixes. A test proves `file_event` content never fires on a stream event.
- *Detection wiring:* `sigma-field-map/5` adds `create_stream_hash`, `file_delete`, `pipe_created`, `wmi_event`
  (importer 1.4). Sigma import 1,256 + 55 partial (was 1,229 + 54). Group-used technique coverage is unchanged
  at 210 — these event types add independent ways to see techniques already covered, not new techniques.
- *Software-tag review extended (ADR-0007 D3 amendment):* two newly importable rules were reviewed. **Rejected**
  "Hidden Executable In NTFS Alternate Data Stream" tagged S0139 **PowerDuke — software used by exactly one
  Group, APT29**; the rule fires on any executable in an alternate data stream, so trusting the tag would have
  made a common technique near-maximum-diagnosticity evidence for APT29. **Accepted** the `\PSEXESVC` pipe rule
  (PsExec). The completeness test caught both automatically.
- *Real-data results:* WMI persistence detected on the WMI events themselves ("Suspicious Scripting in a WMI
  Consumer", T1059.005) and as **T1546.003** (WMI Event Subscription); SMBExec yields Empire PowerShell launch,
  PowerShell-as-a-service and Base64 PowerShell (T1059.001, T1569.002). "HackTool - SysmonEnte Execution"
  fires 46 times — verified as the community rule's own false positive on Azure guest agents
  (`WaAppAgent.exe`, `AntimalwareConfig.exe` opening `Sysmon.exe`; the lab runs in Azure), faithfully translated;
  such single-technique noise is for the attribution layer's single-technique guard and null baseline to reject
  (to be verified in G3.6 validation). The Empire Mimikatz sample raises nothing: that credential theft runs in
  PowerShell memory and needs PowerShell script logging (next task).
- *Acceptance (D2):* exact mapping ✓, fail-closed ✓, real-sample golden tests ✓ (20 tests), source-agnostic ✓,
  correlation facts ✓, Sigma wiring ✓, evidence type ✓, performance ✓ (≈1–2 ms/observation on all seven real
  samples, including the 64,000-event WMI file).
- *Still unsupported:* Sysmon 2, 4, 5, 6, 9, 14, 24, 25, 26, 255 (no detection content, or no real samples yet).
