"""Real recorded telemetry through the full pipeline (corpus v2, doc 15 DC-3).

A *recording* is an archive of raw Windows event records captured from a real
(emulated-intrusion) environment — e.g. OTRF's APT3 / APT29 datasets. This
module drives it through exactly the engines the rest of the platform uses:

    raw record -> channel-routed SourceAdapter -> Observation
    -> ADR-0008 D3 source precedence (the recording's declared sources)
    -> DetectionEngine -> Evidence (derive_evidence_from_detection)
    -> structural + contextual correlation (Evidence-free Observations as
       witnesses / process-identity proof, ADR-0003 A7 + B)
    -> one BehavioralSequence per CorrelationGroup.

It adds no normalization, detection, correlation or sequence logic of its own,
and — unlike the fixture replay — persists nothing: a recording holds tens of
thousands of Observations and the corpus only needs the attribution units.
The archive's SHA-256 is verified before any record is read (fail closed).
Records the adapters refuse are counted by source, never silently lost.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.correlation import (
    BehavioralSequence,
    CorrelationGroup,
    CorrelationLink,
    construct_behavioral_sequence,
    contextualize,
    correlate_structurally,
)
from attribution_platform.detection import DetectionEngine, derive_evidence_from_detection
from attribution_platform.detection.contracts import DetectionResult
from attribution_platform.detection.stateful import (
    AggregatedMatch,
    evaluate_aggregations,
    source_starts,
)
from attribution_platform.domain import Evidence, HostRef, Observation
from attribution_platform.replay.errors import ReplayError
from attribution_platform.sources.auditd import AuditdSourceAdapter, is_audit_record
from attribution_platform.sources.azure_activity import (
    AzureActivityExportSourceAdapter,
    AzureActivitySourceAdapter,
    is_azure_activity_export_record,
    is_azure_activity_record,
)
from attribution_platform.sources.cloudtrail import CloudTrailSourceAdapter, is_cloudtrail_record
from attribution_platform.sources.entra import EntraIdSourceAdapter, is_entra_record
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.github_audit import (
    GitHubAuditSourceAdapter,
    is_github_audit_record,
)
from attribution_platform.sources.kubernetes_audit import (
    KubernetesAuditSourceAdapter,
    is_kubernetes_audit_record,
)
from attribution_platform.sources.o365 import O365SourceAdapter, is_o365_record
from attribution_platform.sources.okta import OktaSourceAdapter, is_okta_record
from attribution_platform.sources.osquery_es import OsqueryEsSourceAdapter, is_osquery_es_record
from attribution_platform.sources.powershell import PowerShellSourceAdapter
from attribution_platform.sources.precedence import apply_source_precedence
from attribution_platform.sources.sysmon import SysmonSourceAdapter
from attribution_platform.sources.sysmon_xml import is_sysmon_event_xml
from attribution_platform.sources.wazuh import WazuhAlertSourceAdapter, is_wazuh_alert
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter
from attribution_platform.sources.windows_system import WindowsSystemSourceAdapter
from attribution_platform.sources.zeek import (
    ZeekSourceAdapter,
    ZeekTsvReader,
    is_zeek_record,
    is_zeek_tsv_header,
)
from attribution_platform.wazuh_detections import WazuhAlertDetector

#: Channel (case-folded) -> the adapter that reads it. XML event lines (Sysmon
#: for Linux, ADR-0010 D1) are routed by :data:`XML_EVENT_CHANNEL`; the Sysmon
#: adapter parses them and checks their real channel itself.
XML_EVENT_CHANNEL = "<sysmon-xml>"
#: Raw Linux Audit lines (ADR-0010 D4). Their adapter needs the logging host,
#: which :func:`analyze_recording` takes from the recording's source declaration.
AUDIT_CHANNEL = "<auditd>"
#: Cloud records (ADR-0011) carry no event-log channel; they are recognised by
#: their own schema: Entra ID diagnostic export, Office 365 Management Activity,
#: native AWS CloudTrail, Azure Activity (REST form), Okta System Log,
#: GitHub audit log, Kubernetes audit.
ENTRA_CHANNEL = "<entra-id>"
O365_CHANNEL = "<o365>"
CLOUDTRAIL_CHANNEL = "<aws-cloudtrail>"
AZURE_ACTIVITY_CHANNEL = "<azure-activity>"
AZURE_ACTIVITY_EXPORT_CHANNEL = "<azure-activity-export>"
WAZUH_CHANNEL = "<wazuh-alert>"
OKTA_CHANNEL = "<okta>"
GITHUB_CHANNEL = "<github-audit>"
KUBERNETES_AUDIT_CHANNEL = "<kubernetes-audit>"
#: macOS Endpoint Security process events from osquery results (ADR-0014).
OSQUERY_ES_CHANNEL = "<osquery-es>"
#: Zeek log records from a network sensor, JSON or TSV (ADR-0012).
ZEEK_CHANNEL = "<zeek>"
_SYSMON = SysmonSourceAdapter()
DEFAULT_CHANNEL_ADAPTERS: Mapping[str, Any] = {
    "microsoft-windows-sysmon/operational": _SYSMON,
    "linux-sysmon/operational": _SYSMON,
    XML_EVENT_CHANNEL: _SYSMON,
    AUDIT_CHANNEL: AuditdSourceAdapter(),
    ENTRA_CHANNEL: EntraIdSourceAdapter(),
    O365_CHANNEL: O365SourceAdapter(),
    CLOUDTRAIL_CHANNEL: CloudTrailSourceAdapter(),
    AZURE_ACTIVITY_CHANNEL: AzureActivitySourceAdapter(),
    AZURE_ACTIVITY_EXPORT_CHANNEL: AzureActivityExportSourceAdapter(),
    WAZUH_CHANNEL: WazuhAlertSourceAdapter(),
    OKTA_CHANNEL: OktaSourceAdapter(),
    GITHUB_CHANNEL: GitHubAuditSourceAdapter(),
    KUBERNETES_AUDIT_CHANNEL: KubernetesAuditSourceAdapter(),
    OSQUERY_ES_CHANNEL: OsqueryEsSourceAdapter(),
    ZEEK_CHANNEL: ZeekSourceAdapter(),
    "microsoft-windows-powershell/operational": PowerShellSourceAdapter(),
    "security": WindowsSecuritySourceAdapter(),
    "system": WindowsSystemSourceAdapter(),
}


@dataclass(frozen=True)
class RecordingSource:
    """One pinned recording: its archive, the archive's SHA-256, and the
    sources the recording's documentation says were collected on each host
    (the ADR-0008 D3 declaration)."""

    recording_id: str
    path: Path
    sha256: str
    declared_sources: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class RecordingAnalysis:
    """The attribution units a recording produces, plus conversion counts."""

    recording_id: str
    observations: int
    refused_by_source: Mapping[str, int]
    suppressed_by_precedence: int
    evidence: int
    groups: tuple[CorrelationGroup, ...]
    sequences: tuple[BehavioralSequence, ...]
    items: Mapping[str, tuple[Evidence, Observation]] = field(repr=False)
    structural_links: tuple[CorrelationLink, ...] = field(default=(), repr=False)
    contextual_links: tuple[CorrelationLink, ...] = field(default=(), repr=False)


def load_recording_sources(path: Path, repo_root: Path) -> dict[str, RecordingSource]:
    """The pinned recordings declared in a corpus recordings file
    (``data/calibration/corpus/v2/recordings.json``), by id."""
    document = json.loads(path.read_text(encoding="utf-8"))
    sources: dict[str, RecordingSource] = {}
    for entry in document["recordings"]:
        declared = {
            str(host): tuple(str(s) for s in kinds)
            for host, kinds in entry["declared_sources"].items()
        }
        source = RecordingSource(
            recording_id=str(entry["recording_id"]),
            path=repo_root / str(entry["cache_path"]),
            sha256=str(entry["sha256"]),
            declared_sources=declared,
        )
        if source.recording_id in sources:
            raise ReplayError(f"{path}: duplicate recording id {source.recording_id!r}")
        sources[source.recording_id] = source
    return sources


def _verify(source: RecordingSource) -> None:
    digest = hashlib.sha256()
    with source.path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != source.sha256:
        raise ReplayError(
            f"recording {source.recording_id!r}: {source.path} does not match its pinned SHA-256"
        )


def _iter_raw_lines(path: Path) -> Iterator[str]:
    """Every line of a recording, line ending kept (blank lines included)."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                with archive.open(name) as handle:
                    yield from io.TextIOWrapper(handle, encoding="utf-8", errors="replace")
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            for member in sorted(archive.getmembers(), key=lambda m: m.name):
                extracted = archive.extractfile(member) if member.isfile() else None
                if extracted is not None:
                    yield from io.TextIOWrapper(extracted, encoding="utf-8", errors="replace")
    elif path.suffix in (".log", ".json", ".jsonl"):
        with path.open(encoding="utf-8", errors="replace") as handle:
            yield from handle
    else:
        raise ReplayError(f"unsupported recording archive type: {path.name}")


def iter_recording_lines(path: Path) -> Iterator[str]:
    """Stream the non-blank lines of a ``.zip`` / ``.tar.gz`` recording (read
    as data, never extracted to disk, members in name order) or of a plain
    ``.log`` / ``.json`` / ``.jsonl`` text recording."""
    for line in _iter_raw_lines(path):
        if line.strip():
            yield line


def iter_recording_records(
    path: Path, *, on_unparseable: Callable[[str], None] | None = None
) -> Iterator[dict[str, Any] | str]:
    """Stream the records of a recording: JSON lines parsed, and Sysmon XML
    events passed through as text for the Sysmon adapter to parse (so a
    malformed one is that adapter's refusal, counted like any other).

    One XML event may span several physical lines: Sysmon for Linux writes a
    command line's own newlines verbatim (seen in the real AcidRain and
    Atomic Red Team captures). An event therefore runs from a line starting
    ``<Event`` to the line ending ``</Event>``, rejoined exactly as written —
    blank lines and line breaks included — never cut at a line boundary.

    Zeek TSV logs (a ``#separator`` header block, then tab-separated lines) are
    read with :class:`~attribution_platform.sources.zeek.ZeekTsvReader`, one
    record per data line, until the next header block or ``#close``.

    A line that is not a JSON object fails the read (fail closed) unless
    ``on_unparseable`` is given — then it is reported to that callback and
    skipped (the intake check counts such lines; ``recording_check.py``)."""
    pending: list[str] = []
    zeek_tsv = ZeekTsvReader()
    for line in _iter_raw_lines(path):
        if is_zeek_tsv_header(line) or (zeek_tsv.open and not line.lstrip().startswith("{")):
            # Zeek TSV (ADR-0012): header blocks and tab-separated data lines.
            if line.strip():
                record = zeek_tsv.feed(line)
                if record is not None:
                    yield record
            continue
        if pending:
            pending.append(line)
            if line.rstrip().endswith("</Event>"):
                yield "".join(pending).strip()
                pending = []
        elif is_audit_record(line):
            yield line.rstrip("\r\n")
        elif is_sysmon_event_xml(line):
            if line.rstrip().endswith("</Event>"):
                yield line.strip()
            else:
                pending = [line]
        elif line.strip():
            if on_unparseable is None:
                yield json.loads(line)
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                yield parsed
            else:
                on_unparseable(line)
    if pending:
        yield "".join(pending).strip()  # unterminated: the adapter refuses it


def channel_of(record: Mapping[str, Any] | str) -> str:
    """The channel :data:`DEFAULT_CHANNEL_ADAPTERS` routes ``record`` by: a
    Windows event-log channel (case-folded), or one of the ``<...>`` source
    channels for records recognised by their own schema."""
    if isinstance(record, str):
        return AUDIT_CHANNEL if is_audit_record(record) else XML_EVENT_CHANNEL
    # A Wazuh alert embeds the event it is about (``data.win`` ...): it is the
    # alert that is read, so this check comes before every event schema.
    if is_wazuh_alert(record):
        return WAZUH_CHANNEL
    if is_entra_record(record):
        return ENTRA_CHANNEL
    if is_o365_record(record):
        return O365_CHANNEL
    if is_cloudtrail_record(record):
        return CLOUDTRAIL_CHANNEL
    if is_azure_activity_record(record):
        return AZURE_ACTIVITY_CHANNEL
    if is_azure_activity_export_record(record):
        return AZURE_ACTIVITY_EXPORT_CHANNEL
    if is_okta_record(record):
        return OKTA_CHANNEL
    if is_github_audit_record(record):
        return GITHUB_CHANNEL
    if is_kubernetes_audit_record(record):
        return KUBERNETES_AUDIT_CHANNEL
    if is_osquery_es_record(record):
        return OSQUERY_ES_CHANNEL
    if is_zeek_record(record):
        return ZEEK_CHANNEL
    winlog = record.get("winlog")
    value = (
        winlog.get("channel")
        if isinstance(winlog, Mapping)
        else record.get("Channel", record.get("log_name"))
    )
    return str(value).casefold()


def analyze_recording(
    source: RecordingSource,
    *,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    adapters: Mapping[str, Any] = DEFAULT_CHANNEL_ADAPTERS,
) -> RecordingAnalysis:
    """Run ``source`` through the full pipeline (module docstring)."""
    _verify(source)
    audit_hosts = [h for h, kinds in source.declared_sources.items() if "auditd" in kinds]
    if AUDIT_CHANNEL in adapters and len(audit_hosts) == 1:
        # The declaration names the one host whose audit.log this recording holds.
        adapters = {
            **adapters,
            AUDIT_CHANNEL: AuditdSourceAdapter(host=HostRef(name=audit_hosts[0], os_type="linux")),
        }
    observations: dict[str, Observation] = {}
    refused: dict[str, int] = {}
    for record in iter_recording_records(source.path):
        adapter = adapters.get(channel_of(record))
        if adapter is None:
            continue
        try:
            converted = adapter.to_observations(record)
        except SourceAdapterError:
            refused[adapter.source_type] = refused.get(adapter.source_type, 0) + 1
            continue
        for observation in converted:
            observations.setdefault(observation.observation_id, observation)

    ordered = sorted(observations.values(), key=lambda o: o.observation_id)
    precedence = apply_source_precedence(ordered, source.declared_sources)

    detections: dict[str, list[DetectionResult]] = {}
    pending: list[AggregatedMatch] = []
    for observation in precedence.kept:
        fired, matched = engine.evaluate_split(observation)
        detections[observation.observation_id] = list(fired)
        pending.extend(AggregatedMatch(rule, result, observation) for rule, result in matched)
    # Multi-event rules (ADR-0015 Amendment C): counted over the whole recording,
    # each detection anchored on the Observation that completed it.
    for detection, anchor in evaluate_aggregations(
        pending, source_start=source_starts(precedence.kept)
    ):
        detections[anchor.observation_id].append(detection)
    # Wazuh alerts (ADR-0023): the detection Wazuh made, with its own ATT&CK ids.
    wazuh = WazuhAlertDetector(knowledge)
    for observation in precedence.kept:
        if observation.wazuh is not None:
            alerted = wazuh.detect(observation)
            if alerted is not None:
                detections[observation.observation_id].append(alerted)

    items: list[tuple[Evidence, Observation]] = []
    context: list[Observation] = []
    for observation in precedence.kept:
        evidences = [
            evidence
            for detection in detections[observation.observation_id]
            for evidence in derive_evidence_from_detection(
                detection, observation, knowledge=knowledge
            )
        ]
        if evidences:
            items.extend((evidence, observation) for evidence in evidences)
        else:
            context.append(observation)

    structural = correlate_structurally(items, context_observations=context)
    contextual = contextualize(structural, items, context_observations=context)
    by_evidence = {evidence.evidence_id: (evidence, obs) for evidence, obs in items}
    structural_by_id = {link.link_id: link for link in structural.links}
    contextual_by_id = {link.link_id: link for link in contextual.contextual_links}
    sequences = tuple(
        construct_behavioral_sequence(
            group,
            [by_evidence[i] for i in group.member_evidence_ids],
            [structural_by_id[i] for i in group.structural_link_ids],
            [contextual_by_id[i] for i in group.contextual_link_ids],
        )
        for group in contextual.groups
    )
    return RecordingAnalysis(
        recording_id=source.recording_id,
        observations=len(ordered),
        refused_by_source=dict(sorted(refused.items())),
        suppressed_by_precedence=len(precedence.suppressed),
        evidence=len(items),
        groups=contextual.groups,
        sequences=sequences,
        items=by_evidence,
        structural_links=structural.links,
        contextual_links=contextual.contextual_links,
    )


__all__ = [
    "DEFAULT_CHANNEL_ADAPTERS",
    "RecordingAnalysis",
    "RecordingSource",
    "analyze_recording",
    "channel_of",
    "iter_recording_lines",
    "iter_recording_records",
    "load_recording_sources",
]
