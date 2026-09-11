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

Scaffolding only at this gate (G0.0) — no ``SourceAdapter`` interface or
adapters exist yet. Implemented in G0.4.
"""
