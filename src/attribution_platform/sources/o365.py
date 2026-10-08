"""The Office 365 Management Activity SourceAdapter (ADR-0011 batch A).

One Observation per unified-audit-log record as the Office 365 Management
Activity API returns it: a JSON object with the common schema (``Id``,
``RecordType``, ``CreationTime``, ``Operation``, ``OrganizationId``,
``UserType``, ``UserKey``, ``Workload``, ``ResultStatus``, ``ObjectId``,
``UserId``, ``ClientIP``) plus its record type's own fields.

**Event time:** ``CreationTime``. The API writes it without a zone, and
Microsoft's common schema defines it as "the date and time in Coordinated
Universal Time (UTC) when the user performed the activity" — a documented zone,
so it is read as UTC (ADR-0011 D5 amendment). A ``CreationTime`` that carries a
zone keeps it; one in any other form is refused.

**Exact values** (ADR-0011 D2): the ``o365`` group holds the common-schema
fields and the record-type fields Sigma's ``m365/audit`` rules read
(``ApplicationId``, ``Directionality``, ``DeliveryAction``) as logged. ECS:
``user.name`` = ``UserId`` (the acting user's UPN), ``user.id`` = ``UserKey``
(its alternative id); ``network.source.ip`` = ``ClientIP`` (or, for Entra ID
records, ``ActorIpAddress``) when it is an IP address, with a ``:port`` /
``[v6]:port`` suffix split off; ``user_agent.original`` = the record's
``UserAgent`` or its ``ExtendedProperties`` ``UserAgent`` entry;
``cloud.account.id`` = ``OrganizationId``; ``event.action`` = ``Operation``.
``cloud.provider`` is not set: the source does not state one (Elastic's own
``o365`` pipeline sets none either).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from attribution_platform.domain import (
    CloudRef,
    EventMetadata,
    NetworkEndpoint,
    NetworkInfo,
    O365Ref,
    Observation,
    SourceRef,
    TimePrecision,
    UserAgentRef,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import ip_or_none, scalar_text

O365_SOURCE_TYPE = "o365_management_activity"
O365_DATASET = "o365.audit"
_ADAPTER = "O365SourceAdapter"
_REQUIRED = ("Id", "RecordType", "CreationTime", "Operation", "OrganizationId", "Workload")
_CREATION_TIME = re.compile(
    r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?P<frac>\.\d+)?(?P<zone>Z|[+-]\d\d:\d\d)?\Z"
)
_V4_PORT = re.compile(r"\A(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\Z")
_V6_PORT = re.compile(r"\A\[(?P<ip>[0-9A-Fa-f:.]+)\]:\d{1,5}\Z")


def is_o365_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is an Office 365 Management Activity record."""
    return all(key in record for key in _REQUIRED)


def _text(value: Any) -> str | None:
    return scalar_text(value, _ADAPTER)


def _ip(value: str | None) -> str | None:
    """An IP address from ``ClientIP``, exactly, with a ``:port`` / ``[v6]:port``
    suffix split off; anything else is not guessed."""
    if value is None:
        return None
    for pattern in (_V4_PORT, _V6_PORT):
        match = pattern.match(value)
        if match:
            return ip_or_none(match["ip"])
    return ip_or_none(value)


def _extended(record: Mapping[str, Any], name: str) -> str | None:
    entries = record.get("ExtendedProperties")
    if not isinstance(entries, list):
        return None
    values = [e.get("Value") for e in entries if isinstance(e, Mapping) and e.get("Name") == name]
    if len(values) > 1:
        raise SourceAdapterError(f"{_ADAPTER}: ExtendedProperties has {name!r} twice")
    return _text(values[0]) if values else None


class O365SourceAdapter:
    """Office 365 Management Activity records -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return O365_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_o365_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not an Office 365 Management Activity record")
        created = raw_record["CreationTime"]
        match = _CREATION_TIME.match(created) if isinstance(created, str) else None
        if match is None:
            raise SourceAdapterError(f"{_ADAPTER}: CreationTime={created!r} is not ISO 8601")
        try:
            parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SourceAdapterError(f"{_ADAPTER}: CreationTime={created!r} is invalid") from exc
        timestamp = parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
        frac = len(match["frac"] or "") - 1
        precision = (
            TimePrecision.SECOND
            if frac <= 0
            else TimePrecision.MILLISECOND
            if frac <= 3
            else TimePrecision.MICROSECOND
        )
        organization = _text(raw_record["OrganizationId"])
        record_id = _text(raw_record["Id"])
        if organization is None or record_id is None:
            raise SourceAdapterError(f"{_ADAPTER}: OrganizationId and Id are required")
        operation = _text(raw_record["Operation"])

        user_name, user_key = _text(raw_record.get("UserId")), _text(raw_record.get("UserKey"))
        source_ip = _ip(_text(raw_record.get("ClientIP"))) or _ip(
            _text(raw_record.get("ActorIpAddress"))
        )
        agent = _text(raw_record.get("UserAgent")) or _extended(raw_record, "UserAgent")
        o365 = O365Ref(
            record_id=record_id,
            record_type=_text(raw_record["RecordType"]),
            workload=_text(raw_record["Workload"]),
            operation=operation,
            result_status=_text(raw_record.get("ResultStatus")),
            user_type=_text(raw_record.get("UserType")),
            object_id=_text(raw_record.get("ObjectId")),
            application_id=_text(raw_record.get("ApplicationId")),
            directionality=_text(raw_record.get("Directionality")),
            delivery_action=_text(raw_record.get("DeliveryAction")),
        )
        observation_id = f"o365:{organization}:{record_id}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(
                    source_type=O365_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(kind="event", action=operation, dataset=O365_DATASET),
                user=UserRef(id=user_key, name=user_name) if user_name or user_key else None,
                network=NetworkInfo(source=NetworkEndpoint(ip=source_ip)) if source_ip else None,
                cloud=CloudRef(account_id=organization),
                user_agent=UserAgentRef(original=agent) if agent else None,
                o365=o365,
            ),
        )


__all__ = ["O365_DATASET", "O365_SOURCE_TYPE", "O365SourceAdapter", "is_o365_record"]
