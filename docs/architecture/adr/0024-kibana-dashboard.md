# ADR-0024 — A Kibana dashboard of the results

- **Status:** ACCEPTED (2026-10-12, owner instruction: the internship brief names Kibana as the dashboard).
- **Builds on:** ADR-0001 (Elastic Stack as the data plane), ADR-0016 (the console), ADR-0021 (overlap is a
  similarity).

## Decisions

### D1 — Flat, derived indices for charting

The stored records are nested and linked by id for provenance; Kibana aggregations cannot chart them. When an
investigation is run with `--elasticsearch`, `api/kibana_export.py` writes two flat indices **from the same read
model the console serves**:

- `attribution-kibana-detections` — one document per technique-mapped detection inside an activity cluster
  (`@timestamp`, `host.name`, `threat.technique.id/name`, `threat.tactic.name`, cluster, tier).
- `attribution-kibana-group-matches` — one document per Group or Campaign sharing an observed technique
  (`threat.group.*`, `behavioural_overlap_percent`, techniques matched / in profile, `identified`,
  `identified_by`).

Nothing is computed for Kibana that the console does not show. No field is named confidence, probability,
likelihood or score (tested). No command line or raw event is exported. Document ids derive from the
investigation, so a second export overwrites.

### D2 — The dashboard is generated, tracked and installable

`scripts/build_kibana_dashboard.py` writes `kibana/attribution-dashboard.ndjson` (two data views, twelve
visualisations, one dashboard) deterministically and, with `--install`, imports it through Kibana's saved-objects
API. Aggregation-based visualisations are used because their saved-object format is the most stable across
Kibana versions; Kibana migrates them on import. One panel states how to read overlap and what "identified" means.

### D3 — The console stays the place for evidence

Kibana shows counts and tables; the trail behind a result (events, matched fields, sequences) stays in the
console, which the dashboard's note points to.

## Verification, and its limit

Verified against Elasticsearch and Kibana 8.15.3 from the project's `docker-compose.yml`: a reference recording
was run with `--elasticsearch` (48 detections, 120 group matches exported), the file was imported (15 objects,
migrated by Kibana without error), and the aggregation behind each chart returns data. The owner then opened the
rendered dashboard in a signed-in browser (2026-10-12) and confirmed the expected figures: 48 detections, 16
techniques, the tactic chart and the profile table led by APT32 at about 56%. Individual panels were not reviewed
one by one.

Recordings uploaded through the console are not exported; only investigations run from the command line with
`--elasticsearch` are.

## Checks

`tests/test_kibana_export.py`: the export equals the read model flattened (counts, values, overlap, identified),
no judgement words, re-export does not duplicate; the tracked dashboard file is what the builder writes, and every
panel references an existing visualisation and data view.
