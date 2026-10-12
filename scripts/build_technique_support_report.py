"""Declared versus established technique coverage of the rule packs (ADR-0025).

The coverage report counts a technique as covered when a usable rule *declares*
it. This report adds, without changing that figure, how many techniques at
least one usable rule *establishes* when it fires: structurally (the rule
declares no alternatives for it) or by a recorded review. Deterministic; writes
``data/validation/technique-support-coverage.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from attribution_platform.detection_content.technique_support import (  # noqa: E402
    established_ids,
    load_technique_support_review,
)

PACKS = {
    "sigma": REPO
    / "data/detection/sigma/r2026-07-01/generated/sigma-r2026-07-01-sigma_core++.rules.json",
    "elastic": REPO
    / "data/detection/elastic/195f15c0bac8/generated/elastic-195f15c0bac8.rules.json",
}
REVIEW = REPO / "data/detection/technique-support-review.json"
OUT = REPO / "data/validation/technique-support-coverage.json"


def build() -> dict[str, object]:
    review = load_technique_support_review(REVIEW)
    declared_by: dict[str, set[str]] = {}
    established_by: dict[str, set[str]] = {}
    rules = {"one_claim": 0, "alternatives": 0, "reviewed": 0}
    for path in PACKS.values():
        families: dict[str, set[str]] = {}
        for rule in json.loads(path.read_text(encoding="utf-8"))["rules"]:
            if rule.get("evidence_quality") == "low":
                continue  # enrich tier: context, never compared
            families.setdefault(str(rule["rule_source"]), set()).update(
                str(m["external_id"])
                for m in rule.get("technique_mappings", [])
                if m["object_type"] == "attack-pattern"
            )
        for source, declared in families.items():
            reviewed = review.for_source(source)
            established = established_ids(frozenset(declared), reviewed)
            if reviewed is not None:
                rules["reviewed"] += 1
            elif established == declared:
                rules["one_claim"] += 1
            else:
                rules["alternatives"] += 1
            for technique in declared:
                declared_by.setdefault(technique, set()).add(source)
            for technique in established:
                established_by.setdefault(technique, set()).add(source)
    declared_only = sorted(set(declared_by) - set(established_by))
    return {
        "version": "technique-support-coverage/1",
        "review_sha256": review.sha256,
        "scope": "core-tier rules of the Sigma and Elastic packs "
        "(the enrich tier is never compared)",
        "core_source_rules": rules,
        "techniques_declared_by_a_core_rule": len(declared_by),
        "techniques_established_by_a_core_rule": len(established_by),
        "techniques_declared_only": len(declared_only),
        "declared_only": declared_only,
        "established": sorted(established_by),
    }


def main() -> int:
    report = build()
    OUT.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    print({k: v for k, v in report.items() if not isinstance(v, list)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
