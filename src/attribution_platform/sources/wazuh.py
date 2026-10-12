"""The Wazuh alert SourceAdapter (ADR-0023).

One Observation per Wazuh alert — a line of the manager's ``alerts.json``, or
the same document as stored in a ``wazuh-alerts-*`` index. Unlike the other
adapters this one reads a *detection another system already made*: Wazuh's
analysis engine matched one of its rules and wrote the alert. The adapter keeps
what the alert states; :mod:`attribution_platform.wazuh_detections` turns the
rule's own ATT&CK ids into Evidence. No Wazuh rule is re-evaluated here and the
decoded event under ``data`` is not re-interpreted, with the three exceptions
below, which are values Wazuh itself decoded.

**Accepted shape:** an object with ``id`` (the alert id), ``timestamp``,
``rule`` (``id``, ``level``, ``description``; optional ``groups`` and ``mitre``)
and ``agent`` (``name``). Anything else is refused.

**Event time:** ``timestamp`` — ISO 8601 with a zone, as the manager writes it
(``2023-10-16T12:12:18.684+0000``); without a zone it is refused.

**Host:** ``agent.name`` — the endpoint the alert is about (agent ``000`` is
the manager itself). **Identity:** ``wazuh:<manager.name>:<id>``; alert ids are
unique per manager.

**Indicators, as Wazuh decoded them:** file-integrity hashes and path
(``syscheck.sha256_after`` / ``sha1_after`` / ``md5_after``, ``syscheck.path``),
the destination address (``data.dstip``, or Sysmon's
``data.win.eventdata.destinationIp``) and a queried domain
(``data.win.eventdata.queryName``). A value that is not a well-formed hash or
address is left out, never repaired.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from attribution_platform.domain import (
    DnsRef,
    EventMetadata,
    FileRef,
    HashSet,
    HostRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    SourceRef,
    WazuhAlertRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import ip_or_none, scalar_text, zoned_iso_time

WAZUH_SOURCE_TYPE = "wazuh"
WAZUH_DATASET = "wazuh.alerts"
_ADAPTER = "WazuhAlertSourceAdapter"
_HASH_LENGTH = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"\A[0-9a-fA-F]+\Z")
_ATTACK_ID = re.compile(r"\AT\d{4}(?:\.\d{3})?\Z")


def is_wazuh_alert(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is one Wazuh alert."""
    rule, agent = record.get("rule"), record.get("agent")
    return (
        isinstance(rule, Mapping)
        and isinstance(agent, Mapping)
        and "level" in rule
        and "id" in rule
        and "id" in record
        and isinstance(record.get("timestamp"), str)
    )


def _text(value: Any) -> str | None:
    return scalar_text(value, _ADAPTER)


def _strings(value: Any) -> tuple[str, ...]:
    """A JSON list of strings (or one string) as a tuple; anything else is none."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return ()
    return tuple(v.strip() for v in value if isinstance(v, str) and v.strip())


def _at(record: Mapping[str, Any], *path: str) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _hash(value: Any, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text.lower() if len(text) == _HASH_LENGTH[kind] and _HEX.match(text) else None


class WazuhAlertSourceAdapter:
    """Wazuh alerts -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return WAZUH_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_wazuh_alert(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not a Wazuh alert")
        timestamp, precision = zoned_iso_time(raw_record["timestamp"], "timestamp", _ADAPTER)
        rule: Mapping[str, Any] = raw_record["rule"]
        agent: Mapping[str, Any] = raw_record["agent"]
        alert_id, rule_id = _text(raw_record["id"]), _text(rule["id"])
        host = _text(agent.get("name"))
        level = rule["level"]
        if alert_id is None or rule_id is None or host is None:
            raise SourceAdapterError(f"{_ADAPTER}: alert id, rule.id and agent.name are required")
        if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
            raise SourceAdapterError(f"{_ADAPTER}: rule.level={level!r} is not a level 0-16")
        declared = _strings(_at(rule, "mitre", "id"))
        if any(not _ATTACK_ID.match(i) for i in declared):
            raise SourceAdapterError(f"{_ADAPTER}: rule.mitre.id {declared!r} is not ATT&CK ids")
        manager = _text(_at(raw_record, "manager", "name"))
        description = _text(rule.get("description"))

        syscheck = raw_record.get("syscheck")
        file_ref = None
        if isinstance(syscheck, Mapping):
            hashes = {kind: _hash(syscheck.get(f"{kind}_after"), kind) for kind in _HASH_LENGTH}
            path = _text(syscheck.get("path")) if isinstance(syscheck.get("path"), str) else None
            if path is not None or any(hashes.values()):
                file_ref = FileRef(
                    path=path, hashes=HashSet(**hashes) if any(hashes.values()) else None
                )
        destination = None
        for candidate in (
            _at(raw_record, "data", "dstip"),
            _at(raw_record, "data", "win", "eventdata", "destinationIp"),
        ):
            if isinstance(candidate, str) and ip_or_none(candidate.strip()):
                destination = ip_or_none(candidate.strip())
                break
        query = _at(raw_record, "data", "win", "eventdata", "queryName")
        domain = query.strip() if isinstance(query, str) and query.strip() else None

        observation_id = f"wazuh:{manager or '-'}:{alert_id}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(
                    source_type=WAZUH_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(
                    kind="alert",
                    action=description,
                    provider="wazuh",
                    code=rule_id,
                    dataset=WAZUH_DATASET,
                ),
                host=HostRef(name=host),
                file=file_ref,
                network=(
                    NetworkInfo(destination=NetworkEndpoint(ip=destination))
                    if destination
                    else None
                ),
                dns=DnsRef(question_name=domain) if domain else None,
                wazuh=WazuhAlertRef(
                    alert_id=alert_id,
                    rule_id=rule_id,
                    rule_level=str(level),
                    rule_description=description,
                    rule_groups=" ".join(_strings(rule.get("groups"))) or None,
                    mitre_ids=" ".join(dict.fromkeys(declared)) or None,
                    agent_id=_text(agent.get("id")),
                    manager=manager,
                    decoder=_text(_at(raw_record, "decoder", "name")),
                    location=_text(raw_record.get("location"))
                    if isinstance(raw_record.get("location"), str)
                    else None,
                ),
            ),
        )


__all__ = ["WAZUH_DATASET", "WAZUH_SOURCE_TYPE", "WazuhAlertSourceAdapter", "is_wazuh_alert"]
