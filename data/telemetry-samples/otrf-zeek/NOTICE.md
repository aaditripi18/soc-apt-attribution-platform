# Notice — OTRF Security-Datasets (Zeek logs)

`golden-records.jsonl` contains a small number of records copied verbatim from
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) at commit
`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`, licensed under the
[MIT License](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE).
They are unmodified Zeek log records (JSON lines from the APT29 evaluation day-1
combined log; TSV header blocks with one record from an LSASS campaign archive),
selected deterministically by `scripts/extract_zeek_golden_records.py`; the source
of each is recorded in the file.

`manifest.json` describes the full, verified cache (`data/cache/otrf-compound/`,
git-ignored), rebuilt with `scripts/acquire_corpus_telemetry.py --set zeek`.
