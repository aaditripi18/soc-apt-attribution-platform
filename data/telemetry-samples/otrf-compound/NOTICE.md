# NOTICE — OTRF Security-Datasets (compound recordings)

`manifest.json` pins recordings from **OTRF Security-Datasets**
(https://github.com/OTRF/Security-Datasets), commit
`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`, licensed under the **MIT License**
(Copyright (c) Open Threat Research Forge; see the `license_url` in the
manifest).

The recordings themselves (~120 MB compressed, ~3.7 GB uncompressed) are **not**
committed: `scripts/acquire_corpus_telemetry.py` downloads them into the
git-ignored cache `data/cache/otrf-compound/` and verifies every file against the
SHA-256 recorded here (`--verify`). They are read only as data — archives are
streamed, never extracted to disk, never executed.

Contents (doc 15 DC-3): the MITRE ATT&CK Evaluations Round 2 **APT29** recording
(days 1 and 2; blind-actor population only), two **APT3** emulation recordings,
and seven **LSASS credential-dumping** recordings made with seven different
common tools (real hard negatives), with OTRF's own metadata.
