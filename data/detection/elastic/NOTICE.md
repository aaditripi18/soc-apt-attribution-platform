# Elastic detection content — notice

This directory holds material derived from Elastic's public repositories, used under
the **Elastic License 2.0** (ELv2). Copyright Elasticsearch B.V.

| Path | What | Source (pinned) |
|---|---|---|
| `manifest.json` | List, git blob ids and SHA-256 of every rule file taken | `elastic/detection-rules` @ `195f15c0bac84540bfe47abb8e26dbf8184eb69a` |
| `195f15c0bac8/generated/*.rules.json` | Rule pack generated from those rules by `scripts/import_elastic_rules.py` (ADR-0015) — every rule keeps Elastic's rule id, name, author and a link to the exact rule | same |
| `195f15c0bac8/generated/*.import-report.json` | Per-rule import outcome and reasons | same |
| `conformance/<stream>/` | Elastic's ingest pipelines and their pipeline test fixtures for each translated data stream (Sysmon, Windows Security, CloudTrail, Microsoft 365, Azure, Okta, GitHub, Kubernetes), used unmodified as a test oracle; lookup tables extracted from them live in `src/attribution_platform/detection/pipeline_tables/` | `elastic/integrations` @ `ff5328128a30c75046130ae58ddba450caa1f2dc` |

The rule files themselves are not redistributed: they live in a git-ignored cache that
`scripts/acquire_elastic_rules.py` rebuilds and verifies. Elastic's KQL grammar is
vendored separately under `src/attribution_platform/detection_content/grammars/`
(see its NOTICE).

ELv2 permits use, copying, distribution and derivative works, with limitations that do
not apply to this project: it is not provided to third parties as a hosted or managed
service, licence-key functionality is not circumvented, and Elastic's licensing,
copyright and other notices are kept. Licence text:
<https://github.com/elastic/detection-rules/blob/195f15c0bac84540bfe47abb8e26dbf8184eb69a/LICENSE.txt>.
