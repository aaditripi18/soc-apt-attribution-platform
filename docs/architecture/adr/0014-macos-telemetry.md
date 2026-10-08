# ADR-0014 — macOS telemetry: Endpoint Security process events via osquery (ADR-0008 Wave 2, last family)

- **Status:** ACCEPTED (2026-10-08, owner standing instruction: proceed on the recommended path; Wave 2 order
  Linux → cloud → network → macOS). Data acquired under the same instruction (D5), recorded in a manifest.
- **Builds on:** ADR-0008 (acceptance standard D2), ADR-0010 D2 (product / OS scopes — Windows rules already
  exclude `host.os_type = macos`), ADR-0007 (field map, false-coverage guards), ADR-0003 Amendment B (pid-only
  process identities).

## Context — measured, not assumed

- **Detection content.** The pinned Sigma release holds 43 eligible macOS rules: `macos/process_creation` 42,
  `macos/file_event` 1. They read `CommandLine` (71 uses), `Image` (39), `ParentImage` (10), `TargetFilename`,
  `OriginalFileName`. They would add **9 ATT&CK ids** no imported rule covers: T1027.001, T1059.002 (AppleScript),
  T1189, T1543.001 (Launch Agent), T1543.004 (Launch Daemon), T1546.014, T1552.003, T1555.001 (Keychain), T1569.001
  (Launchctl).
- **Real data.** `splunk/attack_data` at the pinned commit (`a28608b5`, Apache-2.0) holds five macOS datasets:
  four are **osquery** results of the `es_process_events` table (Apple **Endpoint Security** exec events), one is
  Cisco NVM flow data (not a macOS host log — not taken). 9 files, 38,481 bytes, **25 records** (network
  discovery and firewall listing, Gatekeeper bypass via `xattr` / `PlistBuddy`, LOLBin use). No public macOS
  dataset with an APT emulation exists in the sources already pinned.
- **Record shape (observed).** osquery's results-log JSON: `name` (the *configured query name* — `log_processes`,
  `es_process_events`, …), `hostIdentifier`, `unixTime` (when the query ran), `columns` (the table row: `path`,
  `cmdline`, `cmdline_count`, `pid`, `parent`, `cwd`, `uid`, `username`, `event_type`, `time`, `global_seq_num`,
  `signing_id`, `cdhash`, …), `action`. Every `cmdline` ends with exactly one space: osquery appends a separator
  after each argument.

## Decisions

**D1 — Source.** osquery `es_process_events` rows. A row is recognised by the table's own columns, never by the
query name (operator-chosen). Only `event_type = exec` rows are process starts; others are refused and counted.

**D2 — Exact values.** `process.executable` = `path`; `process.command_line` = `cmdline` minus osquery's one
trailing separator (a non-empty `cmdline` without it is refused — the transformation is exact or not applied);
`pid` / `parent` / `cwd` / `uid` / `username` as logged; `host.name` = `hostIdentifier`, `host.os_type` = `macos`
(the table exists only on macOS — a fact of the source, not an inference). Sigma `ParentImage` is **not** mapped:
the row carries only the parent's pid; resolving it to an executable would need another event (correlation's
pid resolution, ADR-0003 Amendment B), not a guess in the field map. `OriginalFileName` (a PE field) has no
macOS meaning.

**D3 — Event time.** The row's `time` (Endpoint Security event time, epoch seconds, UTC), not `unixTime` (the
query's run time). Second precision.

**D4 — Scope.** `macos/process_creation` uses the same ECS process-start scope as the other endpoint OSes, plus
the macOS product scope `host.os_type = macos` (and, like the other endpoint products, no cloud account and no
network observer). Windows rules already exclude macOS hosts (ADR-0010 D2); Linux rules require Linux. Proven
on all the real data in the tests. `macos/file_event` stays a telemetry gap (no file-event source in the data).

**D5 — Data and validation.** Acquired by `scripts/acquire_linux_telemetry.py --set macos` (commit-pinned, every
file verified against its LFS pointer or git blob id). The set is small enough that the golden file holds
**every** record, so the tests run the whole real dataset; detection is measured against each dataset's own
ATT&CK label, and rules are proven on real records with one labelled change.

## Consequences

- Up to 9 more ATT&CK ids become detectable on macOS hosts; macOS process starts take part in correlation like
  Linux ones (pid-only identities, Amendment B).
- The real macOS data is a handful of atomic tests: it validates parsing, scope and rules, not attribution.

## Record — implementation (2026-10-08)

- *Adapter:* `sources/osquery_es.py`, routed by the table's columns (`OSQUERY_ES_CHANNEL`); all **25** real rows
  convert (the query names in the data are `es_process_events` and `log_processes` — the same table, as the
  columns show). Field map `sigma-field-map/14`: `macos/process_creation` (`Image`, `CommandLine`,
  `CurrentDirectory`) with the macOS product scope.
- *Enrich tier extended to macOS (ADR-0007 Amendment A).* SigmaHQ's macOS discovery and Gatekeeper rules are
  `low` / `informational`, so they live in the tree, not the release package. The enrich archive's selection now
  includes `rules/macos/` (21 rules, each verified against its git blob id): 224 → **245** rules, no existing row
  changed. Cloud and network low-level rules are not taken: their Evidence forms single-Evidence units without
  structural links, so low-level Evidence there could never join a unit.
- *Software tags:* the Core++ rule *Payload Decoded and Decrypted via Built-in Utilities* tags Bundlore (S0482) and
  OSX/Shlayer (S0402); both **rejected** in the review — the rule matches a generic `openssl` decode from a mounted
  DMG, which its own description calls only "consistent with" those families.
- *Pack:* 1,836 → **1,883** imported rules (75 partial); ATT&CK ids with an imported rule 336 → **344** (Core++ adds T1027.001, T1059.002
  (AppleScript), T1543.001 / T1543.004 (Launch Agent / Daemon), T1552.003, T1555.001 (Keychain), T1569.001
  (Launchctl); the macOS enrich rules add one more). Active techniques covered 328 → **336**; group-used techniques
  covered 273 → **276 of 498**; Groups with no covered technique 7 → 6. Six Core++
  rules stay `ParentImage` gaps (D2) and one is a DNF-bound translation gap.
- *Real data:* only macOS rules fire on macOS records, and Windows / Linux hosts never match a macOS rule (tested
  in every direction). Documented-label result on the four datasets: Gatekeeper bypass via `xattr` **detected**
  (T1553.001); network discovery labelled T1016 → T1018 / T1049 detected (`arp`, `netstat`; the T1016 rule needs
  `ParentImage`); the PlistBuddy quarantine change — no rule; the LOLBin set is unlabelled (T1083, T1113
  detected). **Every one of these detections is low-level**: the real macOS data contains no Core++ match, so —
  by ADR-0003 Amendment H — it forms no attribution unit. That is the honest state of public macOS data; the
  rules and scope are proven, attribution on macOS waits for richer recordings.
