#!/usr/bin/env python3
"""Conversion and detection report for the cached OTRF Zeek logs (ADR-0012 D7).

Reads every Zeek file in ``data/telemetry-samples/otrf-zeek/manifest.json`` —
the combined JSON log of each APT29 day and the per-host / per-campaign archives
(read in memory as data, never extracted; JSON or TSV, as the file is written)
— through :class:`~attribution_platform.sources.zeek.ZeekSourceAdapter`, grouped
by the corpus recording the logs belong to. Observations are de-duplicated by id
(one record published in several files is one Observation) and run through the
production Sigma pack, every rule included.

Writes ``data/telemetry-samples/otrf-zeek/conversion-report.json``: per
recording the Observations by Zeek log, refusals by reason, and every fired rule
with its Sigma product (the D5 proof: only ``zeek`` may appear). Deterministic
for a given cache, pack and code.

    python scripts/report_zeek_telemetry.py [--pack-dir DIR]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from report_linux_telemetry import GENERATED, _sha256  # noqa: E402

from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402
from attribution_platform.detection import DetectionEngine, load_rule_pack  # noqa: E402
from attribution_platform.domain import Observation  # noqa: E402
from attribution_platform.sources.errors import SourceAdapterError  # noqa: E402
from attribution_platform.sources.zeek import ZeekSourceAdapter, iter_zeek_lines  # noqa: E402

SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "otrf-zeek"
PACK_NAME = "sigma-r2026-07-01-sigma_core++"


def recording_of(source_path: str) -> str:
    """The corpus recording a published Zeek file belongs to (by its OTRF path)."""
    parts = source_path.split("/")
    if parts[2] == "apt29":
        return f"otrf-apt29-{parts[3]}"
    campaign = int(parts[2].removeprefix("LSASS_campaign_"))
    technique = parts[3].removeprefix("metasploit_").split("_lsass_memory_dump")[0]
    return f"otrf-lsass-{campaign:02d}-{technique}"


def iter_file_records(path: Path) -> Iterator[tuple[str, Any]]:
    """``(member, record-or-error)`` for every record of a log or log archive."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                if name.endswith("/"):
                    continue
                text = archive.read(name).decode("utf-8")
                try:
                    for record in iter_zeek_lines(text.splitlines()):
                        yield name, record
                except SourceAdapterError as exc:
                    yield name, exc
    else:
        with path.open(encoding="utf-8") as handle:
            for record in iter_zeek_lines(line.rstrip("\n") for line in handle):
                yield path.name, record


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-dir", type=Path, default=GENERATED)
    args = parser.parse_args(argv)
    pack = args.pack_dir / f"{PACK_NAME}.rules.json"
    knowledge = load_attack_knowledge()
    engine = DetectionEngine(rules=load_rule_pack(pack, knowledge=knowledge).rules)
    rows = json.loads((args.pack_dir / f"{PACK_NAME}.import-report.json").read_text("utf-8"))
    rule_info = {r["sigma_id"]: (r["logsource"].split("/")[0], r["title"]) for r in rows["rules"]}
    manifest = json.loads((SAMPLES / "manifest.json").read_text(encoding="utf-8"))
    adapter = ZeekSourceAdapter()

    observations: dict[str, dict[str, Observation]] = collections.defaultdict(dict)
    refused: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for entry in manifest["files"]:
        recording = recording_of(entry["source_path"])
        for _member, item in iter_file_records(REPO_ROOT / entry["cache_path"]):
            if isinstance(item, SourceAdapterError):
                refused[recording][str(item)] += 1
                continue
            try:
                for obs in adapter.to_observations(item):
                    observations[recording].setdefault(obs.observation_id, obs)
            except SourceAdapterError as exc:
                refused[recording][str(exc)] += 1

    recordings: dict[str, object] = {}
    for recording in sorted(observations):
        kept = list(observations[recording].values())
        by_log = collections.Counter(o.zeek.log for o in kept if o.zeek)
        fired: collections.Counter[tuple[str, str]] = collections.Counter()
        techniques: set[str] = set()
        for detection in engine.evaluate(kept):
            fired[rule_info[detection.rule_ref.rule_id.split(":")[1]]] += 1
            techniques.update(
                m.attack_ref.external_id
                for m in detection.technique_mappings
                if m.attack_ref.external_id
            )
        recordings[recording] = {
            "observations": len(kept),
            "observations_by_log": dict(sorted(by_log.items())),
            "refused_by_reason": dict(sorted(refused[recording].items())),
            "fired_rules": [
                {"product": product, "title": title, "detections": count}
                for (product, title), count in sorted(fired.items())
            ],
            "detected_techniques": sorted(techniques),
        }
    report = {
        "report_version": 1,
        "source_manifest_sha256": _sha256(SAMPLES / "manifest.json"),
        "sigma_pack_sha256": _sha256(pack),
        "recordings": recordings,
    }
    out = SAMPLES / "conversion-report.json"
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    for recording, section in recordings.items():
        data: Any = section
        products = sorted({r["product"] for r in data["fired_rules"]})
        print(
            f"{recording}: {data['observations']} observations; fired products {products}; "
            f"techniques {data['detected_techniques']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
