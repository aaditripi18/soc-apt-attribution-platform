# NOTICE — OTRF Security-Datasets (atomic recordings, unseen test set)

`manifest.json` pins 105 Windows atomic recordings and their metadata from **OTRF Security-Datasets**
(https://github.com/OTRF/Security-Datasets), commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`, licensed under the
**MIT License** (Copyright (c) Open Threat Research Forge).

The recordings (about 51 MB compressed) are **not** committed: `scripts/acquire_unseen_atomic.py` downloads them
into the git-ignored cache `data/cache/otrf-atomic-unseen/` and verifies each against its size and git blob id at
the pinned commit (`--verify`). They are read only as data — archives are streamed, never extracted to disk, never
executed. The selection and its rule are in `data/validation/unseen-otrf-atomic/selection.json` (ADR-0027).
