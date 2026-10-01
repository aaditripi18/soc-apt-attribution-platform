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
from collections.abc import Iterator, Mapping
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
from attribution_platform.domain import Evidence, Observation
from attribution_platform.replay.errors import ReplayError
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.powershell import PowerShellSourceAdapter
from attribution_platform.sources.precedence import apply_source_precedence
from attribution_platform.sources.sysmon import SysmonSourceAdapter
from attribution_platform.sources.sysmon_xml import is_sysmon_event_xml
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter

#: Channel (case-folded) -> the adapter that reads it. XML event lines (Sysmon
#: for Linux, ADR-0010 D1) are routed by :data:`XML_EVENT_CHANNEL`; the Sysmon
#: adapter parses them and checks their real channel itself.
XML_EVENT_CHANNEL = "<sysmon-xml>"
_SYSMON = SysmonSourceAdapter()
DEFAULT_CHANNEL_ADAPTERS: Mapping[str, Any] = {
    "microsoft-windows-sysmon/operational": _SYSMON,
    "linux-sysmon/operational": _SYSMON,
    XML_EVENT_CHANNEL: _SYSMON,
    "microsoft-windows-powershell/operational": PowerShellSourceAdapter(),
    "security": WindowsSecuritySourceAdapter(),
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


def iter_recording_records(path: Path) -> Iterator[dict[str, Any] | str]:
    """Stream the records of a recording: JSON lines parsed, and Sysmon XML
    events passed through as text for the Sysmon adapter to parse (so a
    malformed one is that adapter's refusal, counted like any other).

    One XML event may span several physical lines: Sysmon for Linux writes a
    command line's own newlines verbatim (seen in the real AcidRain and
    Atomic Red Team captures). An event therefore runs from a line starting
    ``<Event`` to the line ending ``</Event>``, rejoined exactly as written —
    blank lines and line breaks included — never cut at a line boundary."""
    pending: list[str] = []
    for line in _iter_raw_lines(path):
        if pending:
            pending.append(line)
            if line.rstrip().endswith("</Event>"):
                yield "".join(pending).strip()
                pending = []
        elif is_sysmon_event_xml(line):
            if line.rstrip().endswith("</Event>"):
                yield line.strip()
            else:
                pending = [line]
        elif line.strip():
            yield json.loads(line)
    if pending:
        yield "".join(pending).strip()  # unterminated: the adapter refuses it


def _channel(record: Mapping[str, Any] | str) -> str:
    if isinstance(record, str):
        return XML_EVENT_CHANNEL
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
    observations: dict[str, Observation] = {}
    refused: dict[str, int] = {}
    for record in iter_recording_records(source.path):
        adapter = adapters.get(_channel(record))
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

    items: list[tuple[Evidence, Observation]] = []
    context: list[Observation] = []
    for observation in precedence.kept:
        evidences = [
            evidence
            for detection in engine.evaluate([observation])
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
    "iter_recording_lines",
    "iter_recording_records",
    "load_recording_sources",
]
