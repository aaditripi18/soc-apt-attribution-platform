# NOTICE — OTRF Security-Datasets samples (MIT License)

The ZIP files in this directory are unmodified files from
[OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets), pinned to commit
`d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` (see `manifest.json` for per-file source paths, sizes and
SHA-256). They are real telemetry recorded in OTRF's Windows lab and are used here only as test data for
source adapters (ADR-0008 D2.3). They are **not** calibration-corpus data and carry no attribution labels.

Copyright (c) the Open Threat Research Forge (OTRF) project and contributors, licensed under the MIT License:
<https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE>.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files, to deal in them without restriction, subject to including the copyright notice and this
permission notice in all copies or substantial portions. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY
OF ANY KIND.

## What these samples contain (inspected 2026-09-24)

Flat Windows EventData JSON (one record per line; fields such as `EventID`, `Channel`, `Image`,
`ProcessGuid` at top level — not Elastic/ECS-nested). Channels: `Microsoft-Windows-Sysmon/Operational`
(event IDs 1, 3, 7, 8, 9, 10, 11, 12, 13, 22, 24), `Security` (e.g. 4688, 4656, 4658, 4663, 4690, 5154,
5156, 5158, 1102) and `System` (104). **No `Microsoft-Windows-PowerShell/Operational` events** (no 4103/4104).
