#!/usr/bin/env python3
"""Conversion and detection report for the cached Linux telemetry
(``data/cache/splunk-attack-data/``, see ``acquire_linux_telemetry.py``;
ADR-0010 D7).

Two sources, each through the pipeline's own reader and adapters:

- **Sysmon for Linux** logs (multi-line XML events reassembled);
- **auditd** logs (raw records; ``ausearch -i`` records refused for their
  zone-less time). The logs name no host, so each dataset directory — one
  recorded attack-range host — is *declared* as the logging host by its
  dataset path (``HostRef.id``), exactly as a recording's source declaration
  states it; no host name is invented.

Observations are de-duplicated by id per source and run through the
production Sigma pack. Writes
``data/telemetry-samples/splunk-attack-data/conversion-report.json``: totals,
refusals by reason, every fired rule with its Sigma product (the OS-scope
proof: only ``linux`` may appear), and per dataset its documented ATT&CK label
(from the dataset's own YAML descriptor, never from our detections), that label
resolved through the pinned KB's ``revoked-by`` relationships (dataset labels
predate ATT&CK v19's renumbering), and the techniques detected. Deterministic
for a given cache, pack and code. Slow (about 15 minutes); the tests read it.

    python scripts/report_linux_telemetry.py
"""

from __future__ import annotations

import collections
import hashlib
import json
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver  # noqa: E402
from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402
from attribution_platform.detection import DetectionEngine, load_rule_pack  # noqa: E402
from attribution_platform.domain import HostRef, Observation  # noqa: E402
from attribution_platform.replay.recording_pipeline import iter_recording_records  # noqa: E402
from attribution_platform.sources.auditd import AuditdSourceAdapter, is_audit_record  # noqa: E402
from attribution_platform.sources.errors import SourceAdapterError  # noqa: E402
from attribution_platform.sources.sysmon import SysmonSourceAdapter  # noqa: E402

CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data"
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _labels(directory: Path) -> set[str]:
    labels: set[str] = set()
    for descriptor in sorted(directory.glob("*.yml")):
        data = yaml.safe_load(descriptor.read_text(encoding="utf-8")) or {}
        labels.update(data.get("mitre_technique") or [])
    return labels


def _audit_lines(path: Path) -> Iterable[str]:
    with path.open(encoding="utf-8", errors="replace", newline="\n") as handle:
        for line in handle:
            if line.strip():
                yield line.rstrip("\r\n")


def _source_section(
    datasets: list[tuple[Path, list[Path]]],
    records: Callable[[Path], Iterable[Any]],
    adapter_for: Callable[[Path], Any],
    engine: DetectionEngine,
    rule_info: dict[str, tuple[str, str]],
    resolver: ExternalIdResolver,
) -> dict[str, object]:
    observations: dict[str, Observation] = {}
    refused: collections.Counter[str] = collections.Counter()
    rows: list[dict[str, object]] = []
    for directory, logs in datasets:
        adapter = adapter_for(directory)
        local: dict[str, Observation] = {}
        for log in logs:
            for record in records(log):
                try:
                    for obs in adapter.to_observations(record):
                        local.setdefault(obs.observation_id, obs)
                except SourceAdapterError as exc:
                    refused[str(exc).split(" (")[0]] += 1
        observations.update(local)
        documented = sorted(_labels(directory))
        resolved = sorted({resolver.current_external_id(t) or t for t in documented})
        detected = sorted(
            {
                m.attack_ref.external_id
                for d in engine.evaluate(list(local.values()))
                for m in d.technique_mappings
                if m.attack_ref.external_id
            }
        )
        rows.append(
            {
                "dataset": directory.relative_to(CACHE).as_posix(),
                "logs": [log.name for log in logs],
                "observations": len(local),
                "documented_techniques": documented,
                "documented_techniques_current": resolved,
                "detected_techniques": detected,
                "documented_technique_detected": any(
                    t == d or d.startswith(t + ".") or t.startswith(d + ".")
                    for t in resolved
                    for d in detected
                ),
            }
        )
    fired: collections.Counter[tuple[str, str]] = collections.Counter()
    for detection in engine.evaluate(list(observations.values())):
        fired[rule_info[detection.rule_ref.rule_id.split(":")[1]]] += 1
    labelled = [r for r in rows if r["documented_techniques"] and r["observations"]]
    return {
        "observations": len(observations),
        "os_types": sorted({o.host.os_type or "" for o in observations.values() if o.host}),
        "refused_by_reason": dict(sorted(refused.items())),
        "fired_rules": [
            {"product": product, "title": title, "detections": count}
            for (product, title), count in sorted(fired.items())
        ],
        "labelled_datasets_with_observations": len(labelled),
        "labelled_datasets_with_documented_technique_detected": sum(
            1 for r in labelled if r["documented_technique_detected"]
        ),
        "datasets": rows,
    }


def main() -> int:
    knowledge = load_attack_knowledge()
    engine = DetectionEngine(rules=load_rule_pack(PACK, knowledge=knowledge).rules)
    resolver = ExternalIdResolver(knowledge, ("attack-pattern",))
    rows = json.loads(REPORT.read_text(encoding="utf-8"))["rules"]
    rule_info = {r["sigma_id"]: (r["logsource"].split("/")[0], r["title"]) for r in rows}

    def by_directory(logs: Iterable[Path]) -> list[tuple[Path, list[Path]]]:
        grouped: dict[Path, list[Path]] = {}
        for log in sorted(logs, key=lambda p: p.as_posix()):
            grouped.setdefault(log.parent, []).append(log)
        return sorted(grouped.items(), key=lambda item: item[0].as_posix())

    sysmon_logs = list(CACHE.rglob("sysmon_linux*.log"))
    audit_logs = [
        p
        for p in CACHE.rglob("*.log")
        if "sysmon" not in p.name and any(is_audit_record(line) for line in _audit_lines(p))
    ]
    sysmon = SysmonSourceAdapter()
    report = {
        "report_version": 2,
        "source_manifest_sha256": _sha256(SAMPLES / "manifest.json"),
        "sigma_pack_sha256": _sha256(PACK),
        "sysmon_for_linux": _source_section(
            by_directory(sysmon_logs),
            iter_recording_records,
            lambda _directory: sysmon,
            engine,
            rule_info,
            resolver,
        ),
        "auditd": _source_section(
            by_directory(audit_logs),
            _audit_lines,
            lambda directory: AuditdSourceAdapter(
                host=HostRef(
                    id=f"dataset:{directory.relative_to(CACHE).as_posix()}", os_type="linux"
                )
            ),
            engine,
            rule_info,
            resolver,
        ),
    }
    out = SAMPLES / "conversion-report.json"
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    for name in ("sysmon_for_linux", "auditd"):
        section: Any = report[name]
        print(
            f"{name}: {section['observations']} observations; refused "
            f"{section['refused_by_reason']}; "
            f"{section['labelled_datasets_with_documented_technique_detected']}/"
            f"{section['labelled_datasets_with_observations']} labelled datasets detected"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
