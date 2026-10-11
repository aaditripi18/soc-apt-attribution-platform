#!/usr/bin/env python3
"""Count firings of the actor-specific rules on the pinned real recordings
(ADR-0018): the false-lead check.

None of the pinned recordings contains the tooling of any Group an actor rule
names (they are public emulations run with stand-in tools, and tool tests), so
every firing here would be a false lead. The script runs every record through
its source adapter and the actor pack alone, and writes the counts.

    python scripts/measure_actor_rule_firings.py [--json data/validation/actor-rule-firings.json]

Recordings come from the git-ignored cache (``scripts/acquire_corpus_telemetry.py``);
a recording that is not present is reported as such, never counted as clean.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.pinned import SIGMA_ACTOR_PACK
from attribution_platform.replay.recording_pipeline import (
    DEFAULT_CHANNEL_ADAPTERS,
    channel_of,
    iter_recording_records,
    load_recording_sources,
)
from attribution_platform.sources.errors import SourceAdapterError

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDINGS = REPO_ROOT / "data" / "calibration" / "corpus" / "v2" / "recordings.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()
    knowledge = load_attack_knowledge()
    pack = load_rule_pack(SIGMA_ACTOR_PACK, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    rows: list[dict[str, object]] = []
    total_observations = total_firings = 0
    for recording_id, source in sorted(load_recording_sources(RECORDINGS, REPO_ROOT).items()):
        if not source.path.is_file():
            rows.append({"recording_id": recording_id, "present": False})
            print(f"{recording_id:<34} not present in the cache")
            continue
        observations = 0
        firings: Counter[str] = Counter()
        for record in iter_recording_records(source.path):
            adapter = DEFAULT_CHANNEL_ADAPTERS.get(channel_of(record))
            if adapter is None:
                continue
            try:
                converted = list(adapter.to_observations(record))
            except SourceAdapterError:
                continue
            observations += len(converted)
            for result in engine.evaluate(converted):
                firings[result.rule_ref.rule_id] += 1
        total_observations += observations
        total_firings += sum(firings.values())
        rows.append(
            {
                "recording_id": recording_id,
                "present": True,
                "sha256": source.sha256,
                "observations": observations,
                "firings": sum(firings.values()),
                "firings_by_rule": dict(sorted(firings.items())),
            }
        )
        print(
            f"{recording_id:<34} {observations:>9,} observations  {sum(firings.values())} firings"
        )
    present = [r for r in rows if r["present"]]
    summary = {
        "actor_pack": pack.pack_id,
        "actor_pack_content_hash": pack.content_hash,
        "actor_rules": len(pack.rules),
        "attack_kb_version": knowledge.attack_kb_version,
        "recordings_measured": len(present),
        "recordings_absent": len(rows) - len(present),
        "observations": total_observations,
        "firings": total_firings,
        "recordings": rows,
    }
    print(
        f"{total_observations:,} observations in {len(present)} recordings: "
        f"{total_firings} firings of {len(pack.rules)} actor rules"
    )
    if args.json is not None:
        args.json.write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
