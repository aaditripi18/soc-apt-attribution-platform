#!/usr/bin/env python3
"""Per-recording conversion and detection report for the cached corpus
telemetry (``data/cache/otrf-compound/``, see ``acquire_corpus_telemetry.py``).

Streams every record of every recording (archives are read as data, never
extracted), routes it by channel to the Sysmon, PowerShell or Security adapter,
and runs every converted Observation through the production Sigma pack. Writes
``data/telemetry-samples/otrf-compound/conversion-report.json``: per recording,
records by channel, conversions and refusals (by reason) per adapter, and
detections — rule families and ATT&CK techniques — per host. Counts only; no
attribution. Deterministic for a given cache, pack and code.

    python scripts/report_corpus_telemetry.py
"""

from __future__ import annotations

import collections
import io
import json
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402
from attribution_platform.detection import DetectionEngine, load_rule_pack  # noqa: E402
from attribution_platform.sources.errors import SourceAdapterError  # noqa: E402
from attribution_platform.sources.powershell import PowerShellSourceAdapter  # noqa: E402
from attribution_platform.sources.sysmon import SysmonSourceAdapter  # noqa: E402
from attribution_platform.sources.windows_security import (  # noqa: E402
    WindowsSecuritySourceAdapter,
)

MANIFEST = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "manifest.json"
OUT = MANIFEST.with_name("conversion-report.json")
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
ADAPTERS: dict[str, Any] = {
    "microsoft-windows-sysmon/operational": SysmonSourceAdapter(),
    "microsoft-windows-powershell/operational": PowerShellSourceAdapter(),
    "security": WindowsSecuritySourceAdapter(),
}


def _records(path: Path) -> Iterator[dict[str, Any]]:
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            (name,) = archive.namelist()
            with archive.open(name) as handle:
                for line in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                    if line.strip():
                        yield json.loads(line)
    else:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                handle = archive.extractfile(member) if member.isfile() else None
                if handle is None:
                    continue
                for line in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                    if line.strip():
                        yield json.loads(line)


def _channel(record: dict[str, Any]) -> str:
    winlog = record.get("winlog")
    value = (
        winlog.get("channel")
        if isinstance(winlog, dict)
        else record.get("Channel", record.get("log_name"))
    )
    return str(value)


def main() -> int:
    knowledge = load_attack_knowledge()
    engine = DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    report: dict[str, Any] = {
        "report_version": "corpus-telemetry-report/1",
        "source_manifest_sha256_by_file": {},
        "sigma_pack": SIGMA_PACK.name,
        "attack_kb_version": knowledge.attack_kb_version,
        "note": "Counts only; no attribution. Detections are of the production Sigma pack.",
        "recordings": {},
    }
    for entry in manifest["files"]:
        if not entry["members"]:
            continue
        path = REPO_ROOT / entry["cache_path"]
        report["source_manifest_sha256_by_file"][path.name] = entry["sha256"]
        channels: collections.Counter[str] = collections.Counter()
        converted: collections.Counter[str] = collections.Counter()
        refused: collections.Counter[str] = collections.Counter()
        families: collections.Counter[str] = collections.Counter()
        techniques: dict[str, collections.Counter[str]] = collections.defaultdict(
            collections.Counter
        )
        seen: set[str] = set()
        duplicates = 0
        for record in _records(path):
            channel = _channel(record)
            channels[channel] += 1
            adapter = ADAPTERS.get(channel.casefold())
            if adapter is None:
                continue
            try:
                observations = adapter.to_observations(record)
            except SourceAdapterError as exc:
                reason = str(exc).split(" (")[0].split(": ", 1)[-1][:90]
                refused[f"{adapter.source_type}: {reason}"] += 1
                continue
            for observation in observations:
                if observation.observation_id in seen:
                    duplicates += 1
                    continue
                seen.add(observation.observation_id)
                converted[adapter.source_type] += 1
                host = observation.host.name if observation.host else "?"
                for detection in engine.evaluate([observation]):
                    families[detection.rule_ref.rule_id.rsplit(":", 1)[0]] += 1
                    for mapping in detection.technique_mappings:
                        techniques[str(host)][str(mapping.attack_ref.external_id)] += 1
        report["recordings"][path.name] = {
            "records_by_channel": dict(channels.most_common()),
            "converted_by_source": dict(sorted(converted.items())),
            "duplicate_observation_ids": duplicates,
            "refused_by_reason": dict(refused.most_common()),
            "detections_by_rule_family": dict(families.most_common()),
            "techniques_by_host": {
                host: dict(sorted(counter.items())) for host, counter in sorted(techniques.items())
            },
            "distinct_techniques": sorted({t for c in techniques.values() for t in c}),
        }
        print(
            f"{path.name}: converted {sum(converted.values()):,}, refused "
            f"{sum(refused.values()):,}, techniques "
            f"{len(report['recordings'][path.name]['distinct_techniques'])}",
            flush=True,
        )
    OUT.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
