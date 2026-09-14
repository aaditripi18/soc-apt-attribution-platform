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
- **G0.11 (implemented):** ``sysmon`` — the first *real* source adapter,
  :class:`SysmonSourceAdapter` (Winlogbeat/Elastic-Agent Sysmon-module JSON
  -> ``Observation``; v1 supports Process Create and Network Connection
  events; every other Sysmon/``winlog.*`` field name is confined to this one
  module) plus :func:`load_ndjson_events`, a small file-input helper for
  tests (not a second fixture/replay framework — see that module's
  docstring). No live collection and no host changes: a pure function over
  already-parsed JSON, exactly like every other adapter.
- **Not yet implemented:** Windows Event Log (non-Sysmon channels),
  PowerShell logging, Defender/EDR, Linux auditd/journald, network
  (Zeek/Suricata), or cloud/identity source adapters — architecturally
  supported by this same boundary, not v1 requirements
  (docs/architecture/12 §D.1.4); the detection-match record contract (gate
  G0.5's extraction boundary, not this package's concern).
"""

from __future__ import annotations
