#!/usr/bin/env python3
"""Conversion and detection report for the cached Linux telemetry
(``data/cache/splunk-attack-data/``, see ``acquire_linux_telemetry.py``;
ADR-0010 D7).

Streams every Sysmon for Linux log (multi-line XML events reassembled by the
pipeline's own reader), converts it, de-duplicates Observations by id across
logs, and runs them through the production Sigma pack. Writes
``data/telemetry-samples/splunk-attack-data/conversion-report.json``: totals,
refusals by reason, every fired rule with its Sigma product (the OS-scope
proof: only ``linux`` may appear), and per dataset its documented ATT&CK label
(from the dataset's own YAML descriptor, never from our detections) beside the
techniques detected. Deterministic for a given cache, pack and code. Slow
(about 15 minutes); the tests read the report.

    python scripts/report_linux_telemetry.py
"""

from __future__ import annotations

import collections
import hashlib
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402
from attribution_platform.detection import DetectionEngine, load_rule_pack  # noqa: E402
from attribution_platform.domain import Observation  # noqa: E402
from attribution_platform.replay.recording_pipeline import iter_recording_records  # noqa: E402
from attribution_platform.sources.errors import SourceAdapterError  # noqa: E402
from attribution_platform.sources.sysmon import SysmonSourceAdapter  # noqa: E402

CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data"
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    engine = DetectionEngine(rules=load_rule_pack(PACK, knowledge=load_attack_knowledge()).rules)
    rows = json.loads(REPORT.read_text(encoding="utf-8"))["rules"]
    rule_info = {r["sigma_id"]: (r["logsource"].split("/")[0], r["title"]) for r in rows}
    adapter = SysmonSourceAdapter()

    observations: dict[str, Observation] = {}
    refused: collections.Counter[str] = collections.Counter()
    datasets: list[dict[str, object]] = []
    for log in sorted(CACHE.rglob("sysmon_linux*.log"), key=lambda p: p.as_posix()):
        local: dict[str, Observation] = {}
        for record in iter_recording_records(log):
            try:
                for obs in adapter.to_observations(record):
                    local.setdefault(obs.observation_id, obs)
            except SourceAdapterError as exc:
                refused[str(exc).split(" (")[0]] += 1
        observations.update(local)
        labels: set[str] = set()
        for descriptor in sorted(log.parent.glob("*.yml")):
            labels.update(
                yaml.safe_load(descriptor.read_text(encoding="utf-8")).get("mitre_technique") or []
            )
        detected = sorted(
            {
                m.attack_ref.external_id
                for d in engine.evaluate(list(local.values()))
                for m in d.technique_mappings
                if m.attack_ref.external_id
            }
        )
        datasets.append(
            {
                "log": log.relative_to(CACHE).as_posix(),
                "observations": len(local),
                "documented_techniques": sorted(labels),
                "detected_techniques": detected,
                "documented_technique_detected": any(
                    t == d or d.startswith(t + ".") or t.startswith(d + ".")
                    for t in labels
                    for d in detected
                ),
            }
        )

    fired: collections.Counter[tuple[str, str]] = collections.Counter()
    for detection in engine.evaluate(list(observations.values())):
        fired[rule_info[detection.rule_ref.rule_id.split(":")[1]]] += 1
    labelled = [d for d in datasets if d["documented_techniques"]]
    report = {
        "report_version": 1,
        "source_manifest_sha256": _sha256(SAMPLES / "manifest.json"),
        "sigma_pack_sha256": _sha256(PACK),
        "observations": len(observations),
        "os_types": sorted({o.host.os_type or "" for o in observations.values() if o.host}),
        "refused_by_reason": dict(sorted(refused.items())),
        "fired_rules": [
            {"product": product, "title": title, "detections": count}
            for (product, title), count in sorted(fired.items())
        ],
        "labelled_datasets": len(labelled),
        "labelled_datasets_with_documented_technique_detected": sum(
            1 for d in labelled if d["documented_technique_detected"]
        ),
        "datasets": datasets,
    }
    out = SAMPLES / "conversion-report.json"
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(
        f"{report['observations']} observations; refused {dict(refused)}; "
        f"{report['labelled_datasets_with_documented_technique_detected']}/"
        f"{report['labelled_datasets']} labelled datasets detected; wrote {out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
