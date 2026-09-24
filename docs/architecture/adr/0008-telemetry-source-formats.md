# ADR-0008 — Telemetry Source Formats: Acceptance Standard, Overlap Policy, and Order

- **Status:** PROPOSED (2026-09-24)
- **Date:** 2026-09-24 (proposed)
- **Deciders:** project owner
- **Supersedes / superseded by:** — (extends doc 12 C0.2 §D.1/§D.2 and ADR-0007 D10)
- **Related:** [ADR-0003](0003-correlation-and-behavioral-chain-layer.md) (structural correlation) ·
  [ADR-0006](0006-calibration-corpus-and-versioning.md) · [ADR-0007](0007-detection-content-and-predicate-language.md)
  D5/D9/D10 · [12 deployment & endpoint scope](../12-deployment-and-endpoint-scope.md) ·
  [11 coverage model](../11-coverage-model.md) · [15 corpus v2 design](../15-corpus-v2-design.md)

> PROPOSED. Decides how new telemetry formats enter the platform without degrading attribution quality: one
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
