#!/usr/bin/env python3
"""Build calibration corpus v2 from its annotations and run the fitting-readiness
gate (doc 15 T9 shape, over the real recordings available now).

Reads ``data/calibration/corpus/v2/annotations/*.annotation.json`` and the pinned
recordings (``recordings.json``; archives from the verified cache), builds the
corpus with the unmodified builder, computes decision inputs for the
calibration / held-out / blind populations, runs the category, split and
provenance validators and the DC-5 readiness gate, and writes
``data/calibration/corpus/v2/build/{manifest,readiness-report}.json``. The
corpus is **not** frozen here — it is frozen only when the gate passes.

    python scripts/build_corpus_v2.py
"""

from __future__ import annotations

import dataclasses
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402
from attribution_platform.calibration.category_validation import (  # noqa: E402
    CaseCategoryRecord,
    CaseCategoryTag,
    validate_category_completeness,
)
from attribution_platform.calibration.contracts import CaseRole  # noqa: E402
from attribution_platform.calibration.corpus_builder import (  # noqa: E402
    build_corpus,
    load_scenario_annotation,
)
from attribution_platform.calibration.decision_inputs import (  # noqa: E402
    build_corpus_decision_inputs,
)
from attribution_platform.calibration.provenance_validation import (  # noqa: E402
    validate_provenance,
)
from attribution_platform.calibration.readiness import validate_fitting_readiness  # noqa: E402
from attribution_platform.calibration.split_validation import validate_split  # noqa: E402
from attribution_platform.calibration.units import analyze_source  # noqa: E402
from attribution_platform.dataplane import FakeElasticClient  # noqa: E402
from attribution_platform.detection import DetectionEngine, load_rule_pack  # noqa: E402
from attribution_platform.domain import EvidenceType  # noqa: E402
from attribution_platform.replay.recording_pipeline import load_recording_sources  # noqa: E402

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


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # the report text uses ≥ / ≈
    knowledge = load_attack_knowledge()
    engine = DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)
    sources = load_recording_sources(CORPUS / "recordings.json", REPO_ROOT)
    recording_of: dict[str, str] = {
        f["family_id"]: f["recording_id"]
        for f in json.loads((CORPUS / "labelling-rules.json").read_text("utf-8"))["families"]
    }
    entries = []
    raw_by_family: dict[str, dict[str, Any]] = {}
    for path in sorted((CORPUS / "annotations").glob("*.annotation.json")):
        annotation = load_scenario_annotation(path)
        raw_by_family[annotation.scenario_family_id] = json.loads(path.read_text("utf-8"))
        entries.append((annotation, sources[recording_of[annotation.scenario_family_id]]))

    corpus = build_corpus(
        entries, client_factory=FakeElasticClient, engine=engine, knowledge=knowledge
    )
    print(f"built {len(corpus.cases)} cases, {corpus.calibration_corpus_version}", flush=True)

    # Category records: each case's authored unit categories plus the evidence
    # types its real sequence carries.
    records = []
    for annotation, source in entries:
        analysis = analyze_source(
            source, client=FakeElasticClient(), engine=engine, knowledge=knowledge
        )
        sequence_by_group = {s.group_id: s for s in analysis.sequences}
        raw_units = {u["unit_id"]: u for u in raw_by_family[annotation.scenario_family_id]["units"]}
        for unit in annotation.units:
            if unit.exclusion_reason is not None:
                continue
            (anchor,) = unit.anchor_scenario_ids
            group = next(g for g in analysis.groups if anchor in set(g.member_observation_ids))
            case = next(c for c in corpus.cases if c.correlation_group_id == group.group_id)
            steps = sequence_by_group[group.group_id].steps
            records.append(
                CaseCategoryRecord(
                    case_id=case.case_id,
                    categories=tuple(
                        CaseCategoryTag(c) for c in raw_units[unit.unit_id].get("categories", [])
                    ),
                    evidence_types=tuple(
                        {EvidenceType(t) for step in steps for t in step.evidence_types}
                    ),
                )
            )

    inputs = build_corpus_decision_inputs(
        corpus,
        entries,
        roles=(CaseRole.CALIBRATION, CaseRole.HELD_OUT_VALIDATION, CaseRole.BLIND_ACTOR_HOLDOUT),
        client_factory=FakeElasticClient,
        engine=engine,
        knowledge=knowledge,
    )
    category_report = validate_category_completeness(corpus.manifest, corpus.cases, tuple(records))
    split_report = validate_split(corpus.cases, corpus.manifest)
    provenance_report = validate_provenance(corpus.manifest)
    readiness = validate_fitting_readiness(
        corpus,
        inputs,
        knowledge=knowledge,
        category_records=records,
        category_report=category_report,
        split_report=split_report,
        provenance_report=provenance_report,
    )

    out = CORPUS / "build"
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(
        json.dumps(_plain(corpus.manifest), indent=1, default=str) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    report = {
        "calibration_corpus_version": corpus.calibration_corpus_version,
        "attack_kb_version": knowledge.attack_kb_version,
        "cases_by_role": {
            role.value: sum(1 for c in corpus.cases if c.case_role is role) for role in CaseRole
        },
        "cases": [
            {
                "case_id": ci.case_id,
                "family": ci.scenario_family_id,
                "role": ci.case_role.value,
                "label": ci.actor_label,
                "observed_features": len(ci.observed_features),
                "candidates": len(ci.candidates),
            }
            for ci in inputs.cases
        ],
        "existing_validators": {
            "category_completeness_valid": category_report.is_valid,
            "category_violations": len(category_report.violations),
            "split_valid": split_report.is_valid,
            "split_violations": len(split_report.violations),
            "provenance_valid": provenance_report.is_valid,
            "provenance_violations": len(provenance_report.violations),
        },
        "readiness": _plain(readiness),
    }
    (out / "readiness-report.json").write_text(
        json.dumps(report, indent=1, default=str) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"ready: {readiness.is_ready}; violations: {len(readiness.violations)}")
    for violation in readiness.violations:
        print(f"  {violation.violation_type.value}: {violation.detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
