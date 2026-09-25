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

## What these samples contain

### Round 1 (inspected 2026-09-24): `psh_powershell_httplistener`, `psh_mavinject_dll_notepad`

Flat Windows EventData JSON (one record per line; fields such as `EventID`, `Channel`, `Image`,
`ProcessGuid` at top level — not Elastic/ECS-nested). Channels: `Microsoft-Windows-Sysmon/Operational`
(event IDs 1, 3, 7, 8, 9, 10, 11, 12, 13, 22, 24), `Security` (e.g. 4688, 4656, 4658, 4663, 4690, 5154,
5156, 5158, 1102) and `System` (104). **No `Microsoft-Windows-PowerShell/Operational` events** (no 4103/4104).

### Round 2 (inspected 2026-09-25)

All flat Windows EventData JSON, one member each.

| File | Records | Notable content (real events) |
|---|---|---|
| `psh_lsass_memory_dump_comsvcs.zip` | 184 | LSASS dump via `comsvcs.dll`: Sysmon 10 `rundll32.exe` → `lsass.exe` (`0x1fffff`, `0x1410`) |
| `cmd_lsass_memory_dumpert_syscalls.zip` | 118 | LSASS dump via direct syscalls: Sysmon 10 `Outflank-Dumpert.exe` → `lsass.exe` (`0x1fffff`) |
| `empire_mimikatz_logonpasswords.zip` | 6,026 | Empire Mimikatz; PowerShell/Operational 4103 (1,695), Windows PowerShell 400/600/800, Sysmon 17/18 pipes |
| `empire_smbexec_dcerpc_smb_svcctl.zip` | 7,504 | Empire SMBExec; PowerShell/Operational 4103 (433) and **4104 (1)**, Sysmon 17/18, 23 |
| `empire_wmi_local_event_subscriptions_elevated_user.zip` | 79,896 | Empire WMI persistence; **Sysmon 19/20/21 (1 each)**, 15 (18), 17/18 (32/91), 23 (170), PowerShell 4103 (226), **4104 (1)** |

Not present in any sample: Sysmon 6 (driver load), 25 (process tampering), 26 (file delete detected).
Channel names appear in both `Security` and `security` case in some files (recorded as found).
