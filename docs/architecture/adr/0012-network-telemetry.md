# ADR-0012 — Network telemetry: Zeek (ADR-0008 Wave 2, third format family)

- **Status:** ACCEPTED (2026-10-06, owner delegation: "go with the recommended path", standing instruction to
  proceed step by step; recommended Wave 2 order Linux → cloud → network + IOC layer → macOS). The IOC /
  threat-intelligence layer is a separate decision (a later ADR) — this one covers network *telemetry* only.
- **Builds on:** ADR-0008 (acceptance standard D2, record shapes D4), ADR-0007 (Sigma import, field map,
  false-coverage guards), ADR-0010 D2 / ADR-0011 D4 (product scopes), ADR-0003 (correlation), ADR-0006
  (calibration corpus v2 — the recordings this data belongs to).

## Context — measured, not assumed

- **Detection content.** Against the pinned Sigma release (`r2026-07-01`, Core++) the network logsources hold
  15 Zeek rules (`zeek/dns`, `dce_rpc`, `smb_files`, `http`, `kerberos`, `rdp`) and 46 generic ones (`proxy` 26,
  `webserver` 13, `dns` 7). **Zeek rules add no ATT&CK id** that endpoint rules do not already cover; proxy / web /
  DNS rules would add 9 (T1102.001, T1102.003, T1189, T1221, T1568, T1590, T1595, T1595.002). Network telemetry's
  value here is therefore mainly **corroboration and linkage**, not new technique coverage: the network side of
  behaviour the endpoints already show (lateral movement over SMB / DCE-RPC, Kerberos, C2 channels), and the
  infrastructure facts (IP, domain, certificate) that a later IOC layer will need.
- **Real data that matches the corpus.** OTRF Security-Datasets, at the commit corpus v2 already pins
  (`d9d40ef1`, MIT), publishes **Zeek logs for the same scenarios** as the corpus recordings (whether they
  are the same *runs* was measured — see the record: for APT29 they are not): APT29
  evaluation day 1 (hosts NASHUA, SCRANTON) and day 2 (NEWYORK, SCRANTON, UTICA-A/C/D, UTICA-ONE-DRIVE), and the
  seven LSASS campaigns — 116 files, **~6.1 MB** (per-host archives, per-log files and one combined log per
  APT29 day). Network and host telemetry of one attack, recorded together, is exactly what network ↔ host
  correlation must be validated on. (Splunk `attack_data` holds mostly vendor-proxy / firewall exports, not Zeek.)
- **Record shape (observed).** One JSON object per line, Zeek's own field names with `.` replaced by `_`
  (`id_orig_h`, `id_resp_p`) — Zeek's documented `Log::default_field_name_map` option for Elasticsearch — inside a
  SimpleRock / RockNSM envelope: `@stream` (the Zeek log: `conn`, `dns`, …), `@system` (the sensor), `@proc`
  (`zeek`). `ts` is epoch seconds with a microsecond fraction (UTC by definition).

## Decisions

**D1 — Source and data.** Zeek logs from OTRF at the pinned commit, acquired by the existing commit-pinned,
size- and hash-verified mechanism (`scripts/acquire_corpus_telemetry.py`), cache git-ignored, manifest tracked.
Recommended-path download (owner's standing instruction), recorded in the manifest like every other.

**D2 — Accepted shapes.** Zeek JSON logs in Zeek's native names (`id.orig_h`) **and** the documented
`default_field_name_map` variant (`id_orig_h`) — the same field, renamed by Zeek itself; the log type comes from
the record's `@stream` (envelope) or from the log file the recording declares. Zeek's TSV format is not read until
a sample needs it. One Observation per Zeek log record.

**D3 — Logs, in order.** `conn` (the connection record every other log refers to by `uid`), `dns`, `http`,
`ssl` / `x509`, `kerberos`, `smb_files` / `smb_mapping`, `dce_rpc`, `files`, `notice` — each mapped only where
its fields mean exactly what the ECS field means (`network.source.*` / `destination.*` = `id.orig_*` /
`id.resp_*`, `network.transport` = `proto`), with every Zeek field Sigma reads kept in a `zeek` group as logged.
Zeek's `uid` (one connection) and `fuid` (one file) are kept.

**D4 — Event time.** `ts` (epoch seconds, UTC), microsecond precision; any other form is refused.

**D5 — Product scope: a sensor is not an endpoint.** Zeek Observations describe traffic seen by a **sensor**, not
activity on a host: they carry no `host`, and set ECS `observer.product` = `zeek` and `observer.hostname` = the
sensor (`@system`, as logged). Zeek rules require `observer.product = zeek`; **endpoint products gain a negated
`observer.product exists`** — without it a Zeek DNS record with ECS `network` / `protocol` would fall inside the
Windows `dns_query` scope. Proven, as before, on all the real data (no endpoint rule fires on a Zeek record).

**D6 — Correlation (an ADR-0003 amendment, decided on real data in the implementation).** Two candidate links:
(a) Zeek `uid`: every log record about one connection carries it — one connection instance, asserted by the
sensor → *structural* (like `SAME_AUDIT_EVENT`); (b) **network ↔ host**: a Zeek connection and a host's
network-connection event (Sysmon 3) with the same 5-tuple inside the connection's time span describe one
connection — structural only if the data shows the 5-tuple + time test is unambiguous (ephemeral-port reuse and
NAT are the known failure modes; measured, not assumed). IP addresses, domains and sensors alone stay contextual
(ADR-0003 §6: shared infrastructure is a container).

**D7 — Validation per ADR-0008 D2,** plus: the D5 parity proof on all real Zeek data; the network ↔ host link
measured on the APT29 recordings (how many host connections find exactly one Zeek connection, how many find
several); and the corpus effect stated honestly — network Evidence joins or forms units only through D6 links.

## Consequences

- Network Evidence can corroborate endpoint Evidence of the same attack (APT29 lateral movement, Kerberos, SMB),
  and the infrastructure facts the IOC layer needs (IPs, domains, certificates) enter the evidence graph.
- Endpoint product scopes change once more (D5): every endpoint rule's hash changes; stored artifacts are
  regenerated with the new pack, as for ADR-0010 D2 / ADR-0011 D4.
- Proxy / web-server / generic DNS rules stay telemetry gaps until a source for them is chosen (no matching data
  for the corpus).

## Alternatives rejected

- **Generating Zeek logs ourselves from the OTRF pcaps.** The published Zeek logs are the recorders' own output
  for those runs; regenerating adds a Zeek version and script set to pin without adding information. Kept as a
  fallback if a needed log type is missing.
- **Treating a shared IP or domain as group-forming.** Infrastructure is a container (ADR-0003 §6).
- **Mapping Zeek records onto endpoint logsources** (e.g. Zeek DNS → `dns_query`). A sensor's view of a query
  is not a process's DNS request; Sigma keeps them as separate logsources and so does this design (D5).

## Record — implementation (2026-10-08)

- *Data:* 17 files, 3,276,328 bytes (the per-host / per-campaign archives and the combined APT29 logs; the
  per-log extracts duplicate them), acquired by `scripts/acquire_corpus_telemetry.py --set zeek`, each file's size
  **and git blob id** checked against the pinned commit; manifest `data/telemetry-samples/otrf-zeek/manifest.json`.
- *D2 amended — TSV too.* The LSASS archives hold Zeek's default **TSV** logs (the APT29 files are JSON). TSV is
  Zeek's documented ASCII format (`#separator` / `#set_separator` / `#empty_field` / `#unset_field` / `#path` /
  `#fields`), so it is read exactly as well (`iter_zeek_tsv`: hex escapes undone, unset absent, sets split); a
  data line before its headers or with the wrong column count fails closed.
- *Adapter:* `sources/zeek.py`; domain groups `observer` (ECS `observer.product` / `hostname`) and `zeek`. The
  Observation id is a digest of the record's mapped content: the same record published in the combined log and in
  a per-host archive is one Observation (**all 1,737** APT29 day-1 records found in both forms collapse exactly).
  `ts` is converted from its decimal text (no float rounding).
- *Field map `sigma-field-map/13`:* `zeek/dns`, `dce_rpc`, `smb_files`, `kerberos`, `http` in Zeek's names; Zeek
  product scope `observer.product = zeek`; endpoint products require **no** `observer.product` (D5). Gaps: W3C
  proxy names in the Zeek HTTP rule (`c-uri`, `c-useragent`), vectors (`resp_mime_types`, DNS `answers`), the
  `zeek/rdp` logsource (no rdp log in the data), a CIDR and a keyword rule (translation gaps). **11 Zeek rules
  imported; no new ATT&CK id** (as the context measured).
- *Real data (`scripts/report_zeek_telemetry.py`):* APT29 day 1 1,737 / day 2 2,649 Observations, LSASS campaigns
  230–3,749; every other record is a non-traffic log, refused and counted (`x509`, `weird`, `loaded_scripts`, …).
  **No rule fires on any corpus recording — endpoint or Zeek.** That is the data, checked: APT29's traffic is
  SAMR / LSARPC / DRSUAPI domain discovery and AES Kerberos; no Sigma Zeek rule covers it. Detection is proven by
  golden tests on real records with one labelled change (BZAR task registration, RC4 service ticket, credential
  file over SMB) and the D5 scope in both directions.
- *D6 — measured, not adopted.*
  - **(b) network ↔ host:** **APT29** — the Zeek logs are dated 2020-04-30, the corpus host recordings
    (`apt29_evals_day*_manual`) 2020-05-02: different runs of the scenario; of 1,229 day-1 Sysmon connections none
    has a Zeek connection with its 5-tuple in time (1,219 no tuple; 10 broadcast / NTP tuples days apart).
    **LSASS 05** — 863 of 889 Sysmon connections match a Zeek 5-tuple exactly, but at a constant offset of
    about +12 h 05 min, and the host's own clocks disagree with each other (Sysmon `UtcTime` 16:46:32 vs the event
    log's `TimeCreated` 09:51:51Z for one event). A time test cannot be trusted on this data, and estimating a
    clock offset would be inference, not evidence — so the link is **not adopted**; it waits for a recording
    whose sensor and host clocks agree (the owner's lab recordings, ADR-0006).
  - **(a) Zeek `uid`:** sound as a structural fact, but with no Zeek Evidence on any corpus recording it would
    change nothing measurable; not added until Zeek Evidence exists to link (no complexity for appearance).
- *Consequence:* Zeek telemetry, rules and scope are in place and validated; network Evidence, when it occurs,
  forms single-Evidence units (ADR-0003 Amendment F) with IP / user context links. The corpus is unchanged by
  this ADR.
