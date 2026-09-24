#!/usr/bin/env python3
"""Generate the full-universe detection coverage report (ADR-0007 D9/D10).

Loads the pinned ATT&CK KB, every runtime rule pack, and the Sigma import
report, and writes (next to the generated Sigma pack):

  coverage-report.json   every active technique + every active Group
  coverage-summary.md    a short human-readable view

Offline and deterministic. Usage:

    python scripts/build_coverage_report.py [--tag r2026-07-01]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection import load_rule_pack
from attribution_platform.detection_content.coverage_report import (
    build_coverage_report,
    render_coverage_summary,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAG = "r2026-07-01"
CORE_PACK = REPO_ROOT / "fixtures" / "phase1_core_rules.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=DEFAULT_TAG)
    args = parser.parse_args()

    generated = REPO_ROOT / "data" / "detection" / "sigma" / args.tag / "generated"
    sigma_pack = next(generated.glob("*.rules.json"))
    sigma_report = next(generated.glob("*.import-report.json"))

    knowledge = load_attack_knowledge()
    packs = [
        load_rule_pack(CORE_PACK, knowledge=knowledge),
        load_rule_pack(sigma_pack, knowledge=knowledge),
    ]
    report = build_coverage_report(
        knowledge, packs, json.loads(sigma_report.read_text(encoding="utf-8"))
    )
    (generated / "coverage-report.json").write_text(
        json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    (generated / "coverage-summary.md").write_text(
        render_coverage_summary(report), encoding="utf-8", newline="\n"
    )
    print(json.dumps(report["summary"], indent=1))
    print("gap ranking (top 10):")
    for row in report["gap_ranking"][:10]:
        print(" ", row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
