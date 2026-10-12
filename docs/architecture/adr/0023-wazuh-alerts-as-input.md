# ADR-0023 — Wazuh alerts as an input

- **Status:** ACCEPTED (2026-10-12, owner instruction: the internship brief suggests Wazuh for TTP identification;
  let the platform take Wazuh's alerts and add the mapping to threat groups Wazuh does not make).
- **Builds on:** ADR-0002 (sources boundary), ADR-0003 Amendment H (enrich tier), ADR-0007 / ADR-0015 (rule tiers),
  ADR-0021 (profile match), CLAUDE.md ("never fabricate", "reuse mature existing capabilities").

## Context

Wazuh's analysis engine already matches its own rules and writes alerts whose rule declares MITRE ATT&CK ids
(`rule.mitre.id`). The platform's other inputs are raw logs that it detects on itself. A Wazuh deployment is a
second, independent detector whose output can feed the same correlation and attribution.

## Decisions

### D1 — Read the alert, not the event inside it

`sources/wazuh.py` reads one alert (a line of the manager's `alerts.json`, or the same document from a
`wazuh-alerts-*` index) into one Observation: time (`timestamp`, zone required), host (`agent.name`), the rule's id,
level, description, groups and declared ATT&CK ids, the alert id, manager, decoder and location. A Wazuh alert
embeds the event it is about (`data.win…`); the recording pipeline recognises the alert first, so the embedded
event is never also read as a Sysmon or Security event — it would lack fields those readers need, and reading both
would count one event twice.

Three kinds of value Wazuh itself decoded are kept as indicators: file-integrity hashes and path (`syscheck`),
a destination address, a queried domain. A value that is not a well-formed hash or address is left out.

### D2 — The rule's own ATT&CK ids, validated

`wazuh_detections.py` turns an alert into a detection of source `wazuh`, rule `wazuh:<rule id>`. Each declared
id is resolved in the pinned knowledge base, following `revoked-by` as the rule importers do. An id the knowledge
base lacks is **not mapped and not replaced**; the Evidence claim names it. An alert with no resolvable id yields
no Evidence. The platform does not re-evaluate the Wazuh rule and does not claim to know which fields matched: the
match basis is the rule id, level and description.

### D3 — Tiers by level (the platform's policy, not Wazuh's)

Wazuh's rule classification describes levels 0–6 as ignored events, notifications, errors, authorised events and
low-relevance attacks. Alerts of those levels are the enrich tier (Evidence quality `low`, never an activity
cluster on their own), as Elastic's `low` severity rules are. Level 7 and above is the core tier. The Wazuh
documentation publishes no low / medium / high bands that could be cited instead; this cut is stated as ours.

### D4 — Limits, stated

- The alert carries no ruleset version: `rule_version` is `as-alerted`. Two managers with different custom rules
  under one id are indistinguishable.
- Correlation between Wazuh alerts is by host and time only: the alert has no process identifiers the platform
  could link by lineage, so an attack chain from Wazuh alerts is coarser than one from raw Sysmon logs.
- Group-specific identification (ADR-0018) needs raw events; from Wazuh alerts alone a group is identified only
  through an advisory indicator match on a decoded hash or address.
- Only synthetic alerts in the documented shape have been read so far; no alert file from a running Wazuh manager
  has been tested.

## Checks

`tests/test_wazuh_alerts.py`: an alert read as written; malformed alerts refused; indicators kept only when
well-formed; core and enrich tiers; an unknown id not mapped and named; no id, no Evidence; a Wazuh alert file
investigated end to end (techniques, host, indicators). The sample alert is the shape of the Wazuh
documentation's PsExec example.
