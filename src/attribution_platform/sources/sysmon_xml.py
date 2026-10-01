"""Sysmon events written as one XML ``<Event>`` document per line — the shape
Sysmon for Linux writes to syslog (ADR-0010 D1).

:func:`parse_sysmon_event_xml` turns one such line into the collector-shaped
record (``winlog.*`` + ``@timestamp``) the Sysmon adapter already reads, so
Linux and Windows events are built by the same builders and cannot drift.
Every ``EventData`` value is kept exactly as written (strings).

Hardened: a document type declaration or entity declaration is refused before
parsing (no DTD processing, no entity expansion), and anything that is not one
well-formed ``<Event>`` with a ``System`` and an ``EventData`` element fails
closed with :class:`~attribution_platform.sources.errors.SourceAdapterError`.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # noqa: S405 - DTD/entity declarations are refused first
from typing import Any

from attribution_platform.sources.errors import SourceAdapterError

_FORBIDDEN = ("<!DOCTYPE", "<!ENTITY")


def _local(tag: str) -> str:
    """An element name without its XML namespace (Windows exports carry one)."""
    return tag.rsplit("}", 1)[-1]


def _child(parent: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in parent if _local(c.tag) == name), None)


def is_sysmon_event_xml(text: str) -> bool:
    """Whether a log line looks like one Sysmon XML event (cheap prefix test)."""
    return text.lstrip().startswith("<Event")


def parse_sysmon_event_xml(text: str) -> dict[str, Any]:
    """One XML ``<Event>`` line → a collector-shaped Sysmon record."""
    upper = text.upper()
    if any(marker in upper for marker in _FORBIDDEN):
        raise SourceAdapterError("Sysmon XML: DTD / entity declarations are refused")
    try:
        root = ET.fromstring(text)  # noqa: S314 - DTD/entity declarations refused above
    except ET.ParseError as exc:
        raise SourceAdapterError(f"Sysmon XML: not well-formed: {exc}") from exc
    if _local(root.tag) != "Event":
        raise SourceAdapterError(f"Sysmon XML: root element is {_local(root.tag)!r}, not 'Event'")
    system, event_data = _child(root, "System"), _child(root, "EventData")
    if system is None or event_data is None:
        raise SourceAdapterError("Sysmon XML: missing System or EventData element")

    def text_of(name: str) -> str | None:
        element = _child(system, name)
        return element.text if element is not None else None

    provider = _child(system, "Provider")
    created = _child(system, "TimeCreated")
    data: dict[str, str] = {}
    for item in event_data:
        if _local(item.tag) != "Data":
            continue
        name = item.get("Name")
        if not name:
            raise SourceAdapterError("Sysmon XML: a Data element has no Name")
        if name in data:
            raise SourceAdapterError(f"Sysmon XML: duplicate Data element {name!r}")
        data[name] = item.text or ""
    winlog: dict[str, Any] = {
        "channel": text_of("Channel"),
        "event_id": text_of("EventID"),
        "record_id": text_of("EventRecordID"),
        "computer_name": text_of("Computer"),
        "provider_name": provider.get("Name") if provider is not None else None,
        "event_data": data,
    }
    record: dict[str, Any] = {"winlog": {k: v for k, v in winlog.items() if v is not None}}
    system_time = created.get("SystemTime") if created is not None else None
    if system_time:
        record["@timestamp"] = system_time
    return record


__all__ = ["is_sysmon_event_xml", "parse_sysmon_event_xml"]
