# Notice — splunk/attack_data

`golden-records.jsonl` contains a small number of records copied verbatim from
[splunk/attack_data](https://github.com/splunk/attack_data) at commit
`a28608b53aa3d8222052e8f3ada59e2d9a4adfff`, licensed under the
[Apache License 2.0](https://github.com/splunk/attack_data/blob/a28608b53aa3d8222052e8f3ada59e2d9a4adfff/LICENSE).
They are unmodified Sysmon for Linux event records, selected deterministically by
`scripts/extract_linux_golden_records.py`; the source path of each is recorded in
the file.

`manifest.json` and `selection.txt` describe the full, verified cache
(`data/cache/splunk-attack-data/`, git-ignored), rebuilt with
`scripts/acquire_linux_telemetry.py`.
