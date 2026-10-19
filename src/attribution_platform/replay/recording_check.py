"""Intake check for a new recording before it enters the corpus.

Owner-recorded emulations (``docs/operations/lab-recording-guide.md``) and any
other recording are checked here first. The check streams the archive (never
extracting or executing anything) and reports:

- **shape** — how many records are collector (``winlog``), Winlogbeat 6, flat
  NXLog or other flat records, Sysmon XML events or raw auditd lines, and how
  many lines are not JSON at all;
- **sources** — every record is routed exactly as the pipeline routes it
  (``recording_pipeline.channel_of``), so Linux, cloud / SaaS, Zeek and macOS
  recordings are checked by the same adapters that will read them;
- **coverage per Windows host** — record counts per Windows channel, and whether
  each Windows host has the sources the pipeline relies on (Sysmon, Security,
  PowerShell/Operational). These requirements apply to Windows event-log records
  only: a cloud / SaaS record or a network sensor's record has no host by design;
- **conversion** — Observations each adapter produced, and refusals by reason;
- **clock consistency** — for Sysmon events, how far the collector's
  ``@timestamp`` is from Sysmon's own ``UtcTime`` (the sensor's time is used;
  large gaps are reported, never silently corrected);
- **declaration draft** — the ADR-0008 D3 ``declared_sources`` entry for
  ``recordings.json``, from the hosts' own records: Windows hosts by their
  event-log channels, every other host (Linux, macOS) by the source types its
  records were read by.

A **problem** blocks use (e.g. unreadable lines, a Windows host with neither
Sysmon nor Security records, nothing converted); a **warning** is recorded for
review - including a host without Sysmon (its process activity then comes from
Security 4688, without Sysmon's process GUIDs; the lab recording guide still
asks for Sysmon) and archive metadata members that are skipped. Nothing is fixed
or guessed here.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attribution_platform.domain import Observation
from attribution_platform.replay.recording_pipeline import (
    AUDIT_CHANNEL,
    DEFAULT_CHANNEL_ADAPTERS,
    archive_metadata_members,
    channel_of,
    iter_recording_records,
)
from attribution_platform.sources.auditd import is_audit_record
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.winlogbeat import is_winlogbeat6

SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"
POWERSHELL = "microsoft-windows-powershell/operational"
#: A Sysmon clock gap beyond this is reported (the sensor's own time is used).
CLOCK_GAP_SECONDS = 60.0
#: Warn when more than this share of Sysmon events exceed the clock gap.
CLOCK_GAP_WARN_SHARE = 0.01


@dataclass(frozen=True)
class RecordingCheckReport:
    path: str
    sha256: str
    size_bytes: int
    records: int
    unparseable_lines: int
    shapes: Mapping[str, int]
    channels_by_host: Mapping[str, Mapping[str, int]]
    records_by_channel: Mapping[str, int]
    converted_by_source: Mapping[str, int]
    refused_by_reason: Mapping[str, int]
    sysmon_clock_gaps: Mapping[str, int]
    first_event: str | None
    last_event: str | None
    declared_sources: Mapping[str, tuple[str, ...]]
    problems: tuple[str, ...] = field(default=())
    warnings: tuple[str, ...] = field(default=())

    @property
    def accepted(self) -> bool:
        return not self.problems


def _shape(record: Mapping[str, Any]) -> str:
    if isinstance(record.get("winlog"), Mapping):
        return "collector"
    if is_winlogbeat6(record):
        return "winlogbeat6"
    if "EventReceivedTime" in record:
        return "nxlog"
    return "flat"


def _is_windows_event_log(record: Mapping[str, Any]) -> bool:
    """A Windows event-log record (any collector shape), the only kind the
    per-host Sysmon / Security / PowerShell requirements apply to."""
    return (
        isinstance(record.get("winlog"), Mapping)
        or is_winlogbeat6(record)
        or "Channel" in record
        or "EventReceivedTime" in record
    )


def _channel_and_host(record: Mapping[str, Any]) -> tuple[str, str]:
    winlog = record.get("winlog")
    if isinstance(winlog, Mapping):
        return str(winlog.get("channel")), str(winlog.get("computer_name"))
    if is_winlogbeat6(record):
        return str(record.get("log_name")), str(record.get("computer_name"))
    return str(record.get("Channel")), str(record.get("Hostname"))


def _sysmon_gap(record: Mapping[str, Any]) -> float | None:
    """Seconds between the collector timestamp and Sysmon's UtcTime, if both exist."""
    winlog = record.get("winlog")
    data = (
        winlog.get("event_data")
        if isinstance(winlog, Mapping)
        else record.get("event_data", record)
    )
    utc = data.get("UtcTime") if isinstance(data, Mapping) else None
    stamp = record.get("@timestamp")
    if not isinstance(utc, str) or not isinstance(stamp, str):
        return None
    try:
        sensor = datetime.fromisoformat(utc.strip()).replace(tzinfo=UTC)
        collector = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if collector.tzinfo is None:
        return None
    return abs((collector - sensor).total_seconds())


def _host_key(observation: Observation) -> str | None:
    """The host a precedence declaration is keyed by (``host.id``, else
    ``host.name`` — as :mod:`attribution_platform.sources.precedence` keys it)."""
    host = observation.host
    if host is None:
        return None
    for value in (host.id, host.name):
        if value is not None and value.strip():
            return value
    return None


def check_recording(path: Path) -> RecordingCheckReport:
    """Check one recording archive (module docstring)."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    shapes: Counter[str] = Counter()
    channels: dict[str, Counter[str]] = {}
    routed: Counter[str] = Counter()
    host_less_audit = 0
    # non-Windows hosts: the source types actually read on each (declaration draft)
    other_hosts: dict[str, set[str]] = {}
    converted: Counter[str] = Counter()
    refused: Counter[str] = Counter()
    gaps: Counter[str] = Counter()
    records = unparseable = 0
    first: datetime | None = None
    last: datetime | None = None
    seen_ids: set[str] = set()

    def count_unparseable(_line: str) -> None:
        nonlocal unparseable
        unparseable += 1

    for record in iter_recording_records(path, on_unparseable=count_unparseable):
        records += 1
        channel = channel_of(record)
        routed[channel] += 1
        if isinstance(record, str):
            shapes["auditd" if channel == AUDIT_CHANNEL else "sysmon_xml"] += 1
            if is_audit_record(record) and not record.lstrip().startswith("node="):
                host_less_audit += 1
        else:
            shapes[_shape(record)] += 1
            if _is_windows_event_log(record):
                windows_channel, host = _channel_and_host(record)
                channels.setdefault(host, Counter())[windows_channel.casefold()] += 1
                if windows_channel.casefold() == SYSMON:
                    gap = _sysmon_gap(record)
                    if gap is not None:
                        gaps[
                            "within_1s" if gap <= 1 else "within_60s" if gap <= 60 else "beyond_60s"
                        ] += 1
        adapter = DEFAULT_CHANNEL_ADAPTERS.get(channel)
        if adapter is None:
            continue
        try:
            observations = adapter.to_observations(record)
        except SourceAdapterError as exc:
            refused[
                f"{adapter.source_type}: {str(exc).split(' (')[0].split(': ', 1)[-1][:90]}"
            ] += 1
            continue
        for observation in observations:
            host_key = _host_key(observation)
            if host_key is not None and not (
                isinstance(record, Mapping) and _is_windows_event_log(record)
            ):
                other_hosts.setdefault(host_key, set()).add(adapter.source_type)
            if observation.observation_id in seen_ids:
                continue
            seen_ids.add(observation.observation_id)
            converted[adapter.source_type] += 1
            stamp = observation.timestamp
            first = stamp if first is None or stamp < first else first
            last = stamp if last is None or stamp > last else last

    problems: list[str] = []
    warnings: list[str] = []
    if records == 0:
        problems.append("the archive contains no JSON records")
    if unparseable:
        problems.append(f"{unparseable} line(s) are not JSON objects")
    if records and not converted:
        problems.append("no record converted to an Observation — unsupported shape or channels")
    declared: dict[str, tuple[str, ...]] = {}
    for host, counts in sorted(channels.items()):
        if host in ("None", ""):
            problems.append(f"{sum(counts.values())} record(s) carry no host name")
            continue
        if counts.get(SYSMON, 0) == 0 and counts.get(SECURITY, 0) == 0:
            problems.append(f"host {host!r} has neither Sysmon nor Security records")
        elif counts.get(SYSMON, 0) == 0:
            warnings.append(
                f"host {host!r} has no Sysmon records: its process activity comes from "
                "Security 4688, without process GUIDs"
            )
        elif counts.get(SECURITY, 0) == 0:
            warnings.append(f"host {host!r} has no Security-channel records")
        if counts.get(POWERSHELL, 0) == 0:
            warnings.append(f"host {host!r} has no PowerShell/Operational records")
        declared[host] = tuple(
            source
            for source, channel in (("sysmon", SYSMON), ("windows_security", SECURITY))
            if counts.get(channel, 0)
        )
    for host, source_types in sorted(other_hosts.items()):
        if host not in declared:  # Windows hosts keep their channel-based draft
            declared[host] = tuple(sorted(source_types))
    total_gaps = sum(gaps.values())
    if total_gaps and gaps["beyond_60s"] / total_gaps > CLOCK_GAP_WARN_SHARE:
        warnings.append(
            f"{gaps['beyond_60s']} of {total_gaps} Sysmon events are more than "
            f"{CLOCK_GAP_SECONDS:.0f} s from the collector clock (Sysmon's own time is used)"
        )
    if refused:
        warnings.append(f"{sum(refused.values())} record(s) refused by the adapters (see reasons)")
    if host_less_audit:
        warnings.append(
            f"{host_less_audit} auditd record(s) name no host (no node=): the recording's source "
            "declaration must state the logging host (ADR-0010 D4)"
        )
    skipped = archive_metadata_members(path)
    if skipped:
        warnings.append(f"{len(skipped)} archive metadata member(s) skipped (e.g. {skipped[0]!r})")
    unrouted = sum(n for c, n in routed.items() if c not in DEFAULT_CHANNEL_ADAPTERS)
    if unrouted:
        warnings.append(f"{unrouted} record(s) match no supported source and are not read")

    return RecordingCheckReport(
        path=str(path),
        sha256=digest,
        size_bytes=path.stat().st_size,
        records=records,
        unparseable_lines=unparseable,
        shapes=dict(sorted(shapes.items())),
        channels_by_host={h: dict(c.most_common()) for h, c in sorted(channels.items())},
        records_by_channel=dict(sorted(routed.items())),
        converted_by_source=dict(sorted(converted.items())),
        refused_by_reason=dict(refused.most_common(20)),
        sysmon_clock_gaps=dict(sorted(gaps.items())),
        first_event=first.isoformat() if first else None,
        last_event=last.isoformat() if last else None,
        declared_sources=declared,
        problems=tuple(problems),
        warnings=tuple(warnings),
    )


__all__ = ["RecordingCheckReport", "check_recording"]
