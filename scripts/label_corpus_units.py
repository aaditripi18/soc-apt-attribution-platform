#!/usr/bin/env python3
"""Author corpus v2 annotations from the labelling rules and the unit inventory.

Deterministic and reproducible: for every non-deferred family in
``data/calibration/corpus/v2/labelling-rules.json`` it reads the family's unit
inventory (``inventory/<recording_id>.json``) and applies the documented rule —
a unit is the family's emulated activity iff one of its process images is a
tool the family's documented procedure names and is not a generic host;
every other unit is declared excluded with its reason. It writes
``annotations/<family_id>.annotation.json`` and ``labelling-report.json``
(counts, deferred families with reasons). Labels never come from detections.

    python scripts/label_corpus_units.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "data" / "calibration" / "corpus" / "v2"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"

COVERAGE = [
    "Command Execution",
    "File Creation",
    "Logon Session Creation",
    "Module Load",
    "Network Connection Creation",
    "Network Share Access",
    "Process Access",
    "Process Creation",
    "Process Termination",
    "Script Execution",
    "Windows Registry Key Modification",
]


def _shape(ground_truth: dict[str, Any], family: dict[str, Any], step: str) -> dict[str, Any]:
    provenance = (
        f"Authored from the dataset's documented procedure ({family['procedure_document']}), "
        f"step: {step}; NOT ATT&CK-derived and NOT derived from the engine's detections."
    )
    if ground_truth["label_semantics"] == "unattributable_by_design":
        return {"outcome": "insufficient_evidence", "authorship_provenance": provenance}
    return {
        "outcome": "leading_hypothesis",
        "authorship_provenance": provenance,
        "expected_likelihood_band": "AUTHORED-LEADING",
        "expected_confidence_band": "AUTHORED-HIGH",
    }


def _categories(unit: dict[str, Any]) -> list[str]:
    """Structural facts of the unit (stated rule, not a judgement): one vs
    several Observations, and repeated detections when Evidence outnumbers
    Observations."""
    categories = [
        "one_observation" if unit["observations"] == 1 else "multiple_distinct_observation"
    ]
    if unit["evidence"] > unit["observations"]:
        categories.append("repeated_detection")
    return categories


def main() -> int:
    rules = json.loads((CORPUS / "labelling-rules.json").read_text(encoding="utf-8"))
    recordings = {
        r["recording_id"]: r
        for r in json.loads((CORPUS / "recordings.json").read_text(encoding="utf-8"))["recordings"]
    }
    generic = set(rules["generic_hosts"])
    out_dir = CORPUS / "annotations"
    out_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"rule": rules["rule"], "families": {}}
    for family in rules["families"]:
        family_id = family["family_id"]
        if "deferred" in family:
            report["families"][family_id] = {"deferred": family["deferred"]}
            continue
        recording = recordings[family["recording_id"]]
        inventory = json.loads(
            (CORPUS / "inventory" / f"{family['recording_id']}.json").read_text(encoding="utf-8")
        )
        tools = {k.lower(): v for k, v in family["documented_tools"].items()}
        units = []
        included = 0
        for position, unit in enumerate(inventory["units"]):
            images = set(unit["image_names"])
            named = sorted((images & set(tools)) - generic)
            entry: dict[str, Any] = {
                "unit_id": f"{family_id}-u{position:02d}",
                "anchor_scenario_ids": [unit["anchor_observation_id"]],
            }
            if named:
                step = "; ".join(f"{tool}: {tools[tool]}" for tool in named)
                entry["expected_output_shape"] = _shape(family["ground_truth"], family, step)
                entry["documented_tools"] = named
                entry["categories"] = _categories(unit)
                included += 1
            else:
                entry["exclusion_reason"] = (
                    "No process of this unit runs a tool the documented procedure names "
                    f"(images: {', '.join(sorted(images)) or 'none recorded'}); not "
                    "identifiable as the emulated activity — excluded, not guessed."
                )
            units.append(entry)
        annotation = {
            "scenario_family_id": family_id,
            "case_role": family["case_role"],
            "source_kind": "replay",
            "source_ref": f"otrf:{recording['source_path']}@{OTRF_COMMIT[:8]}",
            "license": "MIT",
            "acquisition_provenance": (
                f"OTRF Security-Datasets recording {recording['source_path']} "
                f"(commit {OTRF_COMMIT}), SHA-256 {recording['sha256']}, acquired by "
                "scripts/acquire_corpus_telemetry.py."
            ),
            "transformation_provenance": (
                "Replayed through the production pipeline (replay/recording_pipeline.py: adapters, "
                "ADR-0008 D3 precedence, Sigma pack r2026-07-01, correlation incl. ADR-0003 "
                "Amendments A-C, behavioral sequences); no manual editing of derived objects. "
                "Units labelled by scripts/label_corpus_units.py from labelling-rules.json."
            ),
            "coverage_assumptions": COVERAGE,
            "ground_truth": {**family["ground_truth"], "campaign_context": []},
            "units": units,
        }
        (out_dir / f"{family_id}.annotation.json").write_text(
            json.dumps(annotation, indent=1) + "\n", encoding="utf-8", newline="\n"
        )
        report["families"][family_id] = {
            "case_role": family["case_role"],
            "units": len(units),
            "included": included,
            "excluded": len(units) - included,
        }
        print(f"{family_id}: {included} included, {len(units) - included} excluded")
    (CORPUS / "labelling-report.json").write_text(
        json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
