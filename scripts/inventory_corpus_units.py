#!/usr/bin/env python3
"""Inventory the attribution units each corpus v2 recording produces.

Runs every recording declared in ``data/calibration/corpus/v2/recordings.json``
(or the ids given as arguments) through the full pipeline
(:func:`attribution_platform.replay.recording_pipeline.analyze_recording`) and
writes ``data/calibration/corpus/v2/inventory/<recording_id>.json``: per unit its
group id, a deterministic anchor Observation (the unit's earliest Evidence
Observation), hosts, time span, process images, detected techniques and rule
families. This is the material annotations are authored from — each unit is
then labelled actor activity or background **from the dataset's documented
procedure**, never from these detections alone.

    python scripts/inventory_corpus_units.py [recording_id ...]
"""

from __future__ import annotations

import collections
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402
from attribution_platform.detection import DetectionEngine, load_rule_pack  # noqa: E402
from attribution_platform.replay.recording_pipeline import (  # noqa: E402
    analyze_recording,
    load_recording_sources,
)

CORPUS = REPO_ROOT / "data" / "calibration" / "corpus" / "v2"
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)


def main(argv: list[str]) -> int:
    knowledge = load_attack_knowledge()
    engine = DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)
    sources = load_recording_sources(CORPUS / "recordings.json", REPO_ROOT)
    wanted = argv or sorted(sources)
    (CORPUS / "inventory").mkdir(parents=True, exist_ok=True)
    for recording_id in wanted:
        started = time.time()
        analysis = analyze_recording(sources[recording_id], engine=engine, knowledge=knowledge)
        units = []
        for group in analysis.groups:
            members = [analysis.items[e] for e in group.member_evidence_ids]
            observations = {o.observation_id: o for _, o in members}
            earliest = min(observations.values(), key=lambda o: (o.timestamp, o.observation_id))
            images = collections.Counter(
                (o.process.executable or "?") if o.process else "?" for o in observations.values()
            )
            units.append(
                {
                    "group_id": group.group_id,
                    "anchor_observation_id": earliest.observation_id,
                    "evidence": len(members),
                    "observations": len(observations),
                    "hosts": sorted(
                        {o.host.name for o in observations.values() if o.host and o.host.name}
                    ),
                    "first": min(o.timestamp for o in observations.values()).isoformat(),
                    "last": max(o.timestamp for o in observations.values()).isoformat(),
                    "process_images": dict(images.most_common(8)),
                    "image_names": sorted(
                        {
                            str(o.process.executable).replace("/", "\\").rsplit("\\", 1)[-1].lower()
                            for o in observations.values()
                            if o.process is not None and o.process.executable
                        }
                    ),
                    "techniques": sorted(
                        {
                            e.attack_ref.external_id
                            for e, _ in members
                            if e.attack_ref and e.attack_ref.external_id
                        }
                    ),
                    "rule_families": dict(
                        collections.Counter(
                            e.provenance.method.rsplit(":", 1)[0] for e, _ in members
                        ).most_common(8)
                    ),
                }
            )
        units.sort(key=lambda u: (-int(str(u["evidence"])), str(u["group_id"])))
        document = {
            "recording_id": recording_id,
            "observations": analysis.observations,
            "refused_by_source": dict(analysis.refused_by_source),
            "suppressed_by_precedence": analysis.suppressed_by_precedence,
            "evidence": analysis.evidence,
            "units": units,
        }
        out = CORPUS / "inventory" / f"{recording_id}.json"
        out.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(
            f"{recording_id}: {len(units)} units, {analysis.evidence} evidence, "
            f"{time.time() - started:.0f}s",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
