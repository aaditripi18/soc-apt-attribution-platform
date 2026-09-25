"""Telemetry-source adapters: source-native events -> the normalized domain contract.

Per docs/architecture/12-deployment-and-endpoint-scope.md (§D.1/§D.2): Sysmon
is a primary v1 source but never an architectural dependency. Every source
(Sysmon, Windows Event Logs, and later PowerShell logging, Defender/EDR,
Linux auditd/journald, Zeek/Suricata, cloud/identity telemetry) is a peer
adapter living in this package. Source-native field names and schemas are
confined here; nothing above this boundary (``domain``, ``extraction``, and
any future attribution logic) may depend on a specific source.

Adding a new telemetry source means adding a new adapter module here — it
must never require changes to ``domain`` or the (future) attribution engine.

Gate status:

- **G0.4 (implemented):** ``adapter`` — the ``SourceAdapter`` structural
  protocol (stable ``source_type`` + ``to_observations``) and the
  fail-closed ``convert()`` boundary function; ``synthetic`` — a trivial
  reference adapter (:class:`SyntheticSourceAdapter`) proving the interface
  is implementable and usable without any real source.
- **G0.11 (implemented), extended by ADR-0008 Wave 1:** ``sysmon`` —
  :class:`SysmonSourceAdapter`, Sysmon event IDs 1, 3, 7, 8, 10, 11, 12, 13,
  15, 17, 18, 19, 20, 21, 22, 23, from collector records (ECS + ``winlog``)
  and flat Windows-EventData exports (OTRF, NXLog); every Sysmon/``winlog.*``
  field name is confined to that module. Plus :func:`load_ndjson_events`, a
  small file-input helper for tests.
- **ADR-0008 Wave 1 (implemented):** ``powershell`` —
  :class:`~attribution_platform.sources.powershell.PowerShellSourceAdapter`,
  PowerShell/Operational 4103 (module logging) and 4104 (script block).
- **ADR-0008 Wave 1, Security batch A (implemented):** ``windows_security`` —
  :class:`~attribution_platform.sources.windows_security.WindowsSecuritySourceAdapter`,
  Security events 4688, 4624, 4776, 4656, 4663, 4658, 5140, 5145;
  ``nxlog_time`` — the shared exact event-time derivation for NXLog exports;
  ``precedence`` — the ADR-0008 D3 source-precedence filter (one
  authoritative source per observation kind per host, suppressions counted).
- All adapters are pure functions over already-parsed JSON (no live
  collection, no host changes) and must pass ADR-0008's acceptance standard
  (exact mapping, fail-closed, real-sample golden tests, …).
- **Not yet implemented:** further Security events (batch B: Kerberos,
  directory service, WFP, services, tasks, account management), System and
  Defender logs; Linux auditd/journald, network (Zeek/Suricata),
  cloud/identity — Wave 2 per ADR-0008 D1.
"""

from __future__ import annotations
