# ADR-0015 — Elastic prebuilt detection rules as a second content source

- **Status:** ACCEPTED (2026-10-09, owner request: "add elastic prebuilt rules to increase coverage").
- **Builds on:** ADR-0007 (detection content: pinned, translated exactly, false-coverage guards, per-rule gap
  report), ADR-0008 / 0010 / 0011 / 0012 / 0014 (the sources and their field maps), ADR-0003 Amendment H (content
  tiers), CLAUDE.md ("prefer authoritative sources and mature components"; "never fabricate functionality").

## Context — measured, not assumed

- **Source.** `elastic/detection-rules`, Elastic License 2.0. Tagged releases stop at v8.6.0 (2023); current content
  is on `main`, so commit `195f15c0` (2026-10-09) is pinned. 2,215 non-deprecated rule files (17.5 MB), each verified
  against its git blob id (`scripts/acquire_elastic_rules.py`; cache git-ignored, manifest tracked).
- **Rule types (production maturity).** EQL 1,045 · KQL query 487 · ES|QL 286 · new_terms 256 · machine learning
  106 · threshold 29 · threat match 6.
- **What could be gained.** Elastic rules map to **156** ATT&CK techniques the Sigma pack does not cover (**94**
  used by active Groups). Restricted to what this engine can evaluate exactly — single-event EQL (no `sequence` /
  `sample`) and KQL query rules — written for a data source this platform ingests (by the rule's index patterns),
  the upper bound is **110 techniques (72 group-used)** from **947 rules**.
- **Fields those rules read (top).** `process.args` 739, `process.name` 671, `host.os.type` 558, `event.action` 480,
  `event.type` 460, `data_stream.dataset` 357, `process.parent.name` 243, `event.outcome` 219,
  `process.executable` 203, `event.provider` 159, `process.command_line` 155, …
- **Parser finding.** Elastic's Python EQL package (`eql` 1.0.1) **discards case-sensitivity**: `like` (sensitive),
  `like~` and `:` (insensitive) all become one `wildcard()` node; `in` / `in~` and `startsWith` / `startsWith~` are
  likewise merged. Translating its AST would silently change some rules' meaning. It is also **AGPLv3**.

## Decisions

**D1 — Translate exactly, or not at all.** Elastic rules go through the same contract as Sigma (ADR-0007): a rule
imports only if every condition has an exact equivalent; otherwise it is rejected with a named reason
(unsupported rule type, unsupported construct, unmapped field, value semantics differ). Partial import of an
`or`-branch follows the Sigma importer's DNF rule.

**D2 — Own parsers for the needed subset, from Elastic's documented syntax.** A `lark` grammar (MIT) for
single-event EQL (`<category> where <expr>`: `and` / `or` / `not`, `==` `!=` `:` `like` `like~` `in` `in~`
`regex` `regex~`, `startsWith` / `endsWith` / `stringContains` and their `~` forms, `?` optional fields) and one for
KQL (`field:value`, quoted values, value lists, wildcards, `and` / `or` / `not`, existence). Each operator keeps its
documented case semantics (EQL: `==`, `like`, `in`, plain functions case-sensitive; `:`, `~` forms insensitive;
KQL on ECS keyword fields: case-sensitive). Anything else is a translation gap. `eql` is not a dependency.

**D3 — Scope by source.** A rule is considered only if its index patterns include a source this platform reads;
`host.os.type == "<os>"` is the product scope this project already uses (ADR-0010 D2); `data_stream.dataset` /
`event.dataset` values are matched to the adapters' own dataset names, which follow Elastic's (ADR-0011 D4).

**D4 — A separate pack and report.** Output: `data/detection/elastic/<commit>/generated/elastic-<commit>.rules.json`
plus an import report listing every rule with its status and reasons, and a coverage report counting both packs.
Elastic content is provenance-tagged (`rule_source = elastic`) and keeps Elastic's rule id, name and licence.

**D5 — Measure before claiming.** Coverage, real-data detections and corpus effects are measured and recorded here;
nothing is claimed from the upper bound.

## Implementation record (2026-10-09)

**First data stream: Windows Sysmon.** A rule applies to this platform's Sysmon telemetry iff one of
its index patterns matches `logs-windows.sysmon_operational-default`, the data stream Elastic's Windows
integration writes Sysmon events to (`detection_content/elastic_field_map.py`). Rules for a stream that
is not modelled are reported as `index:no_supported_data_stream` (Windows Security and the cloud audit
streams were added next — Amendment A below).

**What a rule condition reads — verified, not assumed.** Elastic rules read ECS fields that Elastic's
*ingest pipeline* computes. For each, `detection/derived_fields.py` reproduces the pinned pipeline
(`elastic/integrations` @ `ff5328128a30`, `sysmon_operational.yml`) and exposes it to the engine as
`elastic_sysmon.<ECS field>`:

| ECS field(s) | Pipeline semantics reproduced |
|---|---|
| `process.args`, `process.parent.args` | its "Windows-like SplitCommandLine" (Go's pre-2008 argv rules) |
| `process.name`, `process.parent.name` | text after the last `\` of the image path, only if non-empty |
| `file.name` / `directory` / `extension` | its path split (`file.extension` = after the last `.` of the *whole path*, bug-compatible) |
| `registry.hive` / `key` / `value` / `data.strings` / `data.type` | its registry script, incl. `DWORD (0x…)` → decimal and Java `split` semantics |
| `process.executable` | `Image` / `SourceImage`, or a WMI consumer's `Destination` (event 20) |
| `winlog.event_data.*` | event data the pipeline leaves in place (`IntegrityLevel`, `GrantedAccess`, `CallTrace`, `TargetImage`, WMI fields, …) |
| every field | the pipeline's first step drops `""`, `"-"` and the null GUID; ECS 8.17 `keyword` fields have `ignore_above: 1024`, so longer values are not queryable |

`tests/test_elastic_sysmon_conformance.py` runs Elastic's **own pipeline test fixtures** (221 raw
events and the ECS documents the pipeline must produce, vendored with their git blob ids) through the
Sysmon adapter and compares every view: all equal, except one documented case — a fixture
process-creation event with no `Image`, `ProcessId` or `ProcessGuid`, for which the adapter records no
process while the pipeline still copies PE / integrity fields.

**Constant fields are decided at import.** For each supported Sysmon event, a profile holds the values
Elastic gives it (`event.category` / `type` / `action` from the pipeline's table — e.g. image load is
category `[process, library]`, type `[change, start]` — `event.dataset`, `event.module`,
`data_stream.dataset` from the data stream's `constant_keyword`s, `event.provider` / `event.kind` as
the fixtures show, `host.os.type = windows`). A rule is partially evaluated per profile; a branch that
needs Elastic Defend's `event.action == "exec"` or `process.code_signature.*` (never written by the
Sysmon pipeline) is decided false, exactly as it can never match a Sysmon document. Each generated rule
is scoped to its profile by the adapter's own values plus `host.os_type == windows` and *no*
`event.dataset` (so Windows Security 4688 Observations are never selected).

**Engine additions** (exact, generic): `wildcard` (`*`, `?`, backslash escape), the array operators
`element_in` / `element_contains` / `element_startswith` / `element_endswith` / `element_wildcard`
(Elasticsearch's any-element semantics; negation = no element), tuple values meaning *any of* for the
substring operators, and `exists` on arrays (≥ 1 element).

**Tiers.** Severity medium / high / critical → core; severity low and Elastic building blocks → the
enrich tier (Evidence quality `low`, ADR-0003 Amendment H).

### Measured (2026-10-09)

| | |
|---|---|
| Elastic rule files (production, non-deprecated) | 2,215 |
| Imported / partial / rejected | 237 / 14 / 1,964 |
| Generated engine rules | 1,632 |
| ATT&CK ids with an imported Elastic rule | 209 |
| … not covered by the Sigma pack | **26** (e.g. T1127.001 MSBuild, T1218.004 InstallUtil, T1574.009 unquoted path, T1559 IPC, T1563 session hijacking, T1006 direct volume access) |
| Covered techniques, all active (697) | 336 → **362** |
| Covered techniques used by active Groups (498) | 276 → **293** |
| Groups with ≥ 10 covered techniques | 111 → 114 (72 Groups gain at least one) |

Rejections, by first reason: index not a supported data stream 992; rule type with no single-event
equivalent (new_terms 254, ES|QL 241, EQL sequence 206, ML 106, threshold 27); no ATT&CK mapping 88.
Most frequent dropped-branch reasons: `user.id` (216 — in Sysmon documents it is the event's logging
account, SYSTEM in every supported fixture event, not the acting user, so such branches rarely fire in
Elastic either), `regex` (166), comparisons of an expression or of two fields (`length(…) > 0`,
`startsWith(process.parent.name, process.name)`: 216). The pack regenerates byte-identically.

**On real recordings** (the pinned OTRF corpus, both packs on the same Observations; "Elastic adds" =
ATT&CK ids Elastic detects in that recording and Sigma does not):

| Recording | Observations | Sigma ids | Elastic ids | Elastic detections | Elastic adds |
|---|---|---|---|---|---|
| APT29 eval day 1 | 175,143 | 42 | 13 | 6 | 7 (T1105, T1112, T1560, T1027.010, …) |
| APT29 eval day 2 | 494,098 | 39 | 24 | 13 | 13 (T1136.002, T1552.004, T1546, T1087.002, …) |
| APT3 CALDERA | 63,824 | 27 | 17 | 125 | 12 (T1018, T1036.005, T1140, …) |
| APT3 Empire | 87,929 | 14 | 33 | 68 | 26 (T1566.001, T1569.002, T1218.005, T1564.001, T1074.001, …) |
| 7 LSASS-dump tool runs | 33–55 k each | 7–16 | 2–12 | 3–8 | T1003 everywhere; T1003.001 (Metasploit payload's LSASS access, missed by Sigma there), T1003.003 + T1055.012 (comsvcs) |

Inspected detections are the documented activity (Empire's encoded launcher, a VBS run through a
service shell, `net use \\host\ADMIN$` sweeps, the payload's LSASS access with `GrantedAccess 0x1410`);
some fire on benign process behaviour exactly as Elastic's rule logic does (e.g. a `svchost.exe` LSASS
access outside the rule's exclusion list) — translation is faithful, not tuned. Low-severity and
building-block detections are enrich-tier Evidence.

## Amendment A — further data streams (2026-10-10, owner: "go ahead with the recommended step")

The same method, per data stream (`STREAMS` in `detection_content/elastic_field_map.py`): the rule's
index patterns must match the stream's concrete name; constants are decided at import; every other field
is a derived view reproduced from the pinned pipeline and checked against **that integration's own
pipeline test fixtures** (vendored, blob-id pinned, by `scripts/acquire_elastic_conformance.py`;
`tests/test_elastic_stream_conformance.py`). No divergence is tolerated in any stream.

| Stream (Elastic data stream) | Fixture events compared | Views (examples of what had to be reproduced) |
|---|---|---|
| Windows Security (`system.security`) | 43 | 4688 `process.args` — split on whitespace outside quotes, **quotes kept** (unlike Sysmon's); `process.name`; raw `winlog.event_data.*` after the pipeline's `""` / `-` removal; `PrivilegeList` split; `event.category` / `type` / `action` per event code from the pipeline's table |
| AWS CloudTrail (`aws.cloudtrail`) | 120 | `event.outcome` (error code / message, `ConsoleLogin`); `event.category` / `type` from the pipeline's table; `aws.cloudtrail.request_parameters` = Java `Map.toString()` in **`java.util.HashMap` iteration order** after the pipeline's empty-value removal (114 strings equal); `…flattened.request_parameters.*` (324 leaves equal) |
| Microsoft 365 audit (`o365.audit`) | 371 | `event.code` from the `RecordType` table; renamed operations (Entra, Teams); `event.outcome` from `ResultStatus` |
| Entra audit / sign-in (`azure.auditlogs`, `azure.signinlogs`) | 11 / 66 | operation, outcome, application fields |
| Okta (`okta.system`) | 26 | `event.action`, outcome mapping (`ALLOW` / `DENY` / unknown), actor fields |
| GitHub audit (`github.audit`) | 10 | `github.category` grok, `event.category` / `event.type` by action words |
| Kubernetes audit (`kubernetes.audit_logs`) | 3 | verb, `objectRef.*`, authorization decision → outcome |

Mechanisms this needed:

- **`UNDETERMINED`** (`detection/derived_views.py`): where the pipeline's value depends on something the
  adapter does not keep (M365 DLP outcomes from `PolicyDetails`; an acting process a Security builder does
  not read), the view answers neither a value nor "absent", and the engine makes **every** condition on it
  a non-match — negated or not. A rule can then only fail to fire, never fire on a guess.
- **Always-present array members** (`EventProfile.always_contains`): every M365 record has
  `event.category` "web"; a condition asking for it is decided, any other category is a named gap.
- **Per-field `ignore_above`** (CloudTrail's `request_parameters`: 8191) and **flattened families**
  (`ViewSet.dynamic`).
- **Lookup tables are extracted, not retyped**: `scripts/extract_elastic_pipeline_tables.py` reads them
  from the vendored pipeline YAML; a test regenerates and compares.
- The CloudTrail adapter now keeps `requestParameters` whole (compact JSON, logged key order).

Not offered, and why: **Azure activity logs** — the adapter reads the REST API record shape, Elastic's
pipeline the diagnostic-export shape, so no fixture can be run (rules stay `index:no_supported_data_stream`);
**Linux audit** (`auditd_manager`) — Elastic's normalisation of audit records is a different model from
this adapter's one-Observation-per-record; **PowerShell script blocks** — Elastic's rules search
`powershell.file.script_block_text`, an analysed `text` field (token matching, not string matching), which
has no exact equivalent here; fields the adapters do not keep (IP / ASN enrichment, most
`o365.audit.*` and `kubernetes.audit.requestObject.*` bodies, Security `AccessMask` descriptions) are gaps.
Fixture coverage is thin for Kubernetes (3 events) and GitHub (10): those views are exact where tested and
simple pass-throughs otherwise.

### Measured after Amendment A

| | Sigma only | + Sysmon | + all streams |
|---|---|---|---|
| Elastic rules imported / partial | — | 237 / 14 | **414 / 26** (of 2,215) |
| Generated engine rules | — | 1,632 | 2,378 |
| ATT&CK ids with an Elastic rule | — | 209 | 271 |
| Covered techniques (of 697 active) | 336 | 362 | **395** (59 only by Elastic) |
| Covered techniques used by Groups (of 498) | 276 | 293 | **314** |
| Groups with ≥ 5 / ≥ 10 covered | 145 / 111 | 145 / 114 | 147 / 116 |
| Groups with zero covered | 6 | 6 | 5 |

Rules per stream (a rule can serve several): Sysmon 251, Security 133, CloudTrail 110, M365 22, Okta 22,
GitHub 12, Kubernetes 11, Entra audit 8, Entra sign-in 1. 112 Groups gain covered techniques (APT28 +13,
APT29 +10, Scattered Spider +8, Kimsuky +8).

**On the pinned cloud samples** (Splunk `attack_data`; datasets with at least one detection, Sigma →
Sigma or Elastic): AWS CloudTrail 21 → 29 of 53; M365 6 → 9 of 50; Entra 6 → 10 of 38; Okta 5 → 7 of 16;
GitHub 3 → 4 of 11; Kubernetes 0 → 0 of 6. Technique ids Elastic detects there and Sigma does not: 22
(AWS), 20 (M365), 10 (Entra), 8 (Okta), 2 (GitHub). The M365 building-block rule "Security Compliance
Admin Signal" fires 1,747 times — enrich-tier Evidence, as its Elastic classification says.

## Consequences

- More techniques become detectable where Elastic content is single-event and exact; the rest stays an explicit,
  reasoned gap per rule.
- Two packs are loaded by the engine; the corpus and reports are regenerated with them.

## Alternatives rejected

- **Elastic's `eql` AST** — loses case semantics (above) and is AGPLv3.
- **Running the rules in Kibana's detection engine and importing alerts** (the G1.1 path) — exact by
  construction, but needs the data indexed as Elastic integrations produce it (ingest pipelines, `process.args`,
  `winlog.*`), a running stack, and gives no offline, testable pipeline; kept as a possible later mode.
- **Approximating `new_terms`, threshold or ES|QL aggregations as single-event rules** — changes their meaning.

## Amendment B (2026-10-12) — PowerShell script-block rules, by exact token matching

**Why:** owner instruction 2026-10-11 ("go ahead with the recommended steps"). Amendment A left Elastic's PowerShell
rules out because `powershell.file.script_block_text` is an analysed `text` field with "no exact equivalent here".
This amendment builds the exact equivalent instead of approximating it.

**What the field is — read from the pinned repository, not assumed.** The data stream's manifest
(`packages/windows/data_stream/powershell_operational/manifest.yml` @ `ff5328128a30`) defines

```yaml
powershell_script_analyzer: {type: pattern, pattern: '[\W&&[^-]]+'}
```

and its field definition gives `script_block_text` that analyzer. An Elasticsearch `pattern` analyzer splits the
text on the pattern, drops empty pieces and lower-cases the rest; the pattern is a Java regular expression without
the Unicode flag, so a token is a run of ASCII letters, digits, `_` and `-`, lower-cased.
`detection/derived_powershell.py::powershell_script_tokens` is that analyzer.

**What a rule's value means.** All 36 rules that read this data stream are KQL, and they compare the field with
quoted values. On an analysed field that is a *phrase* query: the value is analysed the same way and matches when
its tokens occur consecutively, in order. So `"System.Reflection.Assembly"` matches `[System.Reflection.Assembly]`
and does not match `System.Assembly`; `"Invoke-Mimikatz"` is one token and does not match `Invoke-Mimikatzzz`.

**How it is decided without a new operator.** The view returns the text as its tokens joined and enclosed by single
spaces; a phrase is translated to the same form of its own tokens. No token contains a space, so "the phrase's form
is a substring of the text's form" is exactly "its tokens occur consecutively" — the engine's existing `contains`
decides it. Alternative phrases on the field (`field : ("a" or "b" …)`) become one any-of condition, as they are
one clause in Elasticsearch, instead of one branch each.

**Refused, never loosened** (each a counted translation gap that drops only its own branch):

| Construct | Why |
|---|---|
| an unquoted value of several tokens | it is not a phrase: Elasticsearch matches any of its tokens |
| a wildcard on the field | matched against individual tokens in Elasticsearch, not reproduced |
| a value with no token (`"::"`) | matches no document; among alternatives it is simply left out |
| the entropy / length fields (`kql:range`) | numeric ranges are not translated (2 rules) |

**The rest of the stream.** One event profile, script-block event 4104: the pipeline's constants for it
(`event.category: process`, `event.type: info`, `event.code`, `event.provider`; no `event.action`) and the views
`file.path` / `file.name` / `file.directory` / `file.extension` (the pipeline's own rule: name and directory only
for a path containing a backslash), `user.id` and `process.pid`. The shared pipeline file is the one the vendored
`default.yml.link` names by SHA-256 (`e07f1bff…8948`), and the views are checked against Elastic's pipeline fixtures
for this data stream (`windows_powershell_operational`, both fixture forms). No fixture script block carries a
script path; those four views are verified by reading the pipeline and are listed as such in the test.

**Result.**

| | Before | After |
|---|---|---|
| Elastic rules usable | 440 | 470 (444 whole, 26 in part) |
| Elastic PowerShell rules usable | 0 | 30 of 36 (2 need numeric ranges, 3 exceed the branch bound, 1 targets another PowerShell event) |
| Techniques with an Elastic rule | 271 | 291 |
| Techniques covered by any content | 395 of 697 | 398 of 697 |
| …of those used by an active Group | 314 of 498 | 317 of 498 |

The net gain is three techniques because Sigma already covered most of what these rules map to. What changes more
is depth: PowerShell activity that Sigma's substring rules missed now has a second, independently written rule set.

**Measured on real recordings** (the 30 rules alone, over every 4104 event):

| Recording | Script-block events | Firings |
|---|---|---|
| `otrf-apt3-empire` | 140 | 5 — AMSI bypass (4), clipboard retrieval (1) |
| `otrf-lsass-01-logonpasswords` | 0 | 0 |
| lab `pilot-02` | 157 | 0 |

`pilot-02` is the lab run whose missed discovery steps `lab-pilot-results.md` tentatively put down to this gap. It
was not the cause: the run's steps are plain built-in commands that none of these rules is written for. That
document is corrected.

**Also in this change (ADR-0008 record of 2026-10-11):** the Windows System log adapter, and a fix to
`scripts/build_coverage_report.py`, which selected "the first `*.rules.json`" and had silently started reading the
actor-specific pack once ADR-0018 added it beside the technique pack.

**Not done:** Elastic's sequence, threshold, new-terms, ES|QL and machine-learning rules (they need state across
events or another query engine); the Elastic Defend, CrowdStrike and SentinelOne data streams (telemetry this
platform does not ingest); Linux `auditd_manager`; Azure activity logs.

## Amendment C (2026-10-12) — threshold and new-terms rules; what the remaining rules can add

**Measured first.** Before building anything, the rejected rules were ranked by what they could add.
All 1,745 rejected Elastic rules together name at most **95** techniques beyond the 398 then covered. By
blocker (upper bounds, overlapping): rules for Elastic Defend endpoint events 58, Linux audit 23, new-terms rules
on sources the platform reads 17, threshold rules 6, Azure activity logs 6, **EQL sequences on sources the
platform reads 3**. No Elastic rule names a threat group in a form that could identify one (one rule names FIN7
and needs network telemetry the platform lacks). The plan was reordered on these numbers.

**Decision.** Threshold and new-terms rules (KQL) are imported: the query is translated exactly as for a
single-event rule, and the rule pack rule carries an `aggregation` saying which sets of matching events are a
detection (`detection/aggregation.py`, evaluated over a whole recording by `detection/stateful.py`). A rule with
an aggregation never fires on one event.

- **Threshold.** Elastic counts the matching events inside each scheduled look-back window, so whether events
  further apart than *look-back − interval* are counted together depends on when the rule happens to run. Only
  that guaranteed distance is used (`from` and `interval` of the rule, Kibana's defaults `now-6m` / `5m` when
  absent; a rule with no such distance is not imported). A detection here is one Elastic raises under every
  schedule. Grouping fields and `cardinality` (distinct values) are reproduced; an event without a grouping value
  is not counted; after a detection the group starts from empty.
- **New terms.** Elastic compares with the history it has indexed (5–15 days in these rules). A recording is all
  the history there is. A value is called new only if no matching event carried it in the history window before
  **and** the recording holds an event of the same log source at least that long before. On a recording shorter
  than the window these rules never fire — the honest result, since the platform cannot know what happened before
  the recording began. A new-terms rule is imported only if **every** branch of its query translates: a missing
  branch is history not seen, which could make an old value look new (for a threshold a missing branch only
  counts fewer events, so partial import stays sound).
- **Evidence.** The detection is anchored on the event that completed it; the Evidence claim states what was
  counted (how many events, for which values, within what time, first at when). The Evidence references the
  anchoring Observation only; the other counted events are named by the claim, not linked.

**Fields added with it.** `cloud.account.id` and `user.id` for AWS CloudTrail, the grouping fields most of these
rules need: read as Elastic's pipeline sets them (`userIdentity.accountId`, else `recipientAccountId`;
`userIdentity.principalId`, undetermined for an `IdentityCenterUser` without one) and checked against Elastic's
CloudTrail fixtures with no divergence (field map `elastic-field-map/4`).

**Result.** 21 multi-event rules imported (18 new-terms, 3 threshold): 493 usable Elastic rules, 300 ATT&CK
ids; covered techniques **398 → 402** of 697 (317 → 320 of the 498 used by Groups). 260 more threshold /
new-terms rules stay rejected, each with its reason — mostly a data stream the platform does not read or an
identity field its views do not have (`user.name`, `host.id`, `user.id` on Windows, `source.ip`).

**Not done, and why.** EQL sequences: at most 3 new techniques for a second parser and a join engine — not
built. Linux audit rules (at most 23): Elastic's auditd integration merges all records of one audit event into
one document and names the system call from a table, where this platform's adapter keeps one Observation per
record and never guesses a system-call name; importing them needs a second, merging reader verified against
Elastic's own normaliser. That is the largest remaining item and is left as the next step. Azure activity logs: Amendment D.

**Checks.** `tests/test_multi_event_rules.py`: a threshold fires for events within the guaranteed distance and
not beyond it, per group, once per burst; cardinality; a value is new only with the history recorded; an
incompletely translated new-terms rule is refused; the claim states what was counted; malformed aggregations are
refused at load; results do not depend on input order.

## Amendment D (2026-10-12) — Azure activity logs in the diagnostic-export layout

**Finding.** Elastic's Azure integration reads the Activity Log as a *diagnostic setting* exports it (Event Hub /
storage account: flat `operationName`, `category`, `resultType`, `time`). The platform's Azure adapter read only
the Azure Monitor REST API form of the same log (`operationName.value`, `status.value`, `eventDataId`). Elastic's
rules are written against the export's values — operation names in upper case, outcome `Success` — and its
pipeline has never seen the REST form, so no exact statement about those rules can be made on REST records.

**Decision.**

- A second reader, `AzureActivityExportSourceAdapter`, for the export layout (`sources/azure_activity.py`),
  routed apart from the REST form and from Entra ID records (same envelope, other log) by `category` and
  `resourceId`. Values are kept as logged. The layout has no event id: the Observation id is the SHA-256 of the
  record's canonical JSON. The event dataset is the same as the REST form's, so the Sigma `azure/activitylogs`
  rules apply to both layouts; the REST form's `status` is a different vocabulary and is not filled from
  `resultType`.
- A data stream `logs-azure.activitylogs-default` with views for the fields the rules read
  (`azure.activitylogs.operation_name`, `event.action`, `event.outcome`, `event.type`,
  `azure.activitylogs.result_type`, `azure.activitylogs.category`), each as the pinned pipeline derives it.
  For a REST-form record every view is **undetermined**, so no Elastic rule fires on it, negated or not.
- Pipeline and fixtures acquired at the pinned integrations commit by `scripts/acquire_elastic_conformance.py`
  (manifest: `data/detection/elastic/conformance/azure_activitylogs/manifest.json`).

**Verification, and its limit.** The views equal Elastic's expected documents on the fixture events the reader
accepts (4 of 18; the others are sign-in records or have no operation name), with no divergence. No fixture event
has a success / failure result, so `event.outcome` — which most of these rules test — is verified by reading the
two pipeline processors and by unit tests of that reading (`tests/test_azure_activity_export.py`), not by a
fixture. It is listed as such in the conformance test.

**Result.** 21 Azure rules imported: 514 usable Elastic rules, 303 ATT&CK ids; covered techniques **404 of 697**
(322 of the 498 used by Groups). Field map `elastic-field-map/5`.

## Amendment E (2026-10-24) — two-stage EQL sequences, and the fields they join on

**Why.** Lateral movement is the platform's largest documented gap (ADR-0027: T1021.002, T1021.003 and T1047 among
the most-missed techniques). Elastic writes exactly these detections as EQL *sequences* — "Incoming DCOM Lateral
Movement with MMC", "Remotely Started Services via RPC", "WMI Incoming Lateral Movement" — and all 206 sequence rules
were rejected as one translation gap (`rule_type:eql_sequence`). The engine already evaluates a two-stage sequence
exactly (ADR-0026 D1: a stage-2 event detects when a stage-1 event on the same host with the same key preceded it
within a span), so translating Elastic's own rules replaces writing new ones (CLAUDE.md principle 8).

**What is translated, exactly.** `sequence [by …] with maxspan=… [q1] by k1… [q2] by k2…`:

- each stage query through the existing single-event path (every branch, per data stream and event profile, with
  the same exactness rules); the stages are two rules of one family; only stage 2 maps to techniques;
- the join: the header's fields for both stages, then the per-stage fields **paired by position**; `host.id`
  is dropped from the key because every engine sequence is on one host — a sequence Elastic joins across hosts is
  only ever narrowed by that, never widened; a key field a profile's events never carry means that profile is never
  joined (as in EQL); `maxspan` is the span;
- the engine's sequence key may now be zero or more fields, compared together in order (zero: the same host only,
  as Elastic's `sequence by host.id` with no stage keys).

**Refused, each with its reason** (`eql_sequence:…`): more than two stages, no `maxspan` (the engine needs a span;
Elastic's would be the rule's look-back), `until`, `with runs`, missing-event stages (`![…]`), unpaired join keys,
and `host.id` paired with another field.

**Fields added to the Sysmon view, from the pinned Elastic pipeline**, each checked against Elastic's own test
fixtures by the conformance test: `process.entity_id`, `process.parent.entity_id` (the GUIDs as written),
`source.ip`, `destination.ip` (type `ip`, held in canonical form), and `network.direction` (`egress` / `ingress`
from Sysmon's `Initiated`, the pipeline's own `set` processors — so the adapter now records it; ADR-0008's note that
the mapping was unverified is answered by the pipeline text). Field map `elastic-field-map/6`.

**Two engine operator families, both narrow.** An `ip` comparison is exact equality of a written address
(canonical form); CIDR, ranges and wildcards stay gaps. Integer ordering (`gt`, `gte`, `lt`, `lte`) on `long`
fields, **positive only**: EQL's `not (port > 1024)` on an event without a port is null, not true, so a negated
ordering comparison is a gap rather than a broader match.

**Result.** 17 of the 206 sequence rules import exactly (was 0), including Incoming DCOM Lateral Movement with MMC,
via MSHTA and with ShellBrowserWindow / ShellWindows, Remotely Started Services via RPC, WMI Incoming Lateral
Movement, Remote Scheduled Task Creation, Service Command Lateral Movement and Incoming Execution via PowerShell
Remoting. The other 189, by cause: 133 read only Elastic Defend or other unsupported data streams; 24 need a field
these streams do not carry; 8 have a stage query with an untranslatable construct; 24 have a shape refused above
(8 no `maxspan`, 6 `until` / `runs` / missing events, 5 three or four stages, 4 unreadable join fields, 1 does not
parse). Elastic rules: 505 imported, 26 partial; covered techniques unchanged at 404 (Elastic alone 303 → 305).

**Checks.** `tests/test_elastic_import.py` (a DCOM sequence imports with the right keys and span and fires on the
right pair only — not outside the span, in the wrong order, on another process's child, on another host, on an
outgoing connection, below the port bound or from loopback; every refused shape gives its reason; a negated
ordering comparison is refused); `tests/test_elastic_stream_conformance.py` (the five new fields against Elastic's
expected documents); the tracked pack regenerates byte for byte.
