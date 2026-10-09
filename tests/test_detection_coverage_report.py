"""ADR-0007 D9/D10 full-universe coverage report tests (T4).

Status-rule precedence is checked on constructed import reports; the real
committed report is checked for completeness (every active technique and Group,
no allowlist), internal consistency against the pinned KB, known anchors, and
byte-identical regeneration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    is_active,
    techniques_used_by,
)
from attribution_platform.attack_knowledge.verification import EXPECTED_ATTACK_KB_VERSION
from attribution_platform.detection import RulePack, load_rule_pack
from attribution_platform.detection_content.coverage_report import (
    TechniqueStatus,
    build_coverage_report,
    render_coverage_summary,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
SIGMA_PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
SIGMA_REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"
ELASTIC_GENERATED = REPO_ROOT / "data" / "detection" / "elastic" / "195f15c0bac8" / "generated"
ELASTIC_PACK = ELASTIC_GENERATED / "elastic-195f15c0bac8.rules.json"
ELASTIC_REPORT = ELASTIC_GENERATED / "elastic-195f15c0bac8.import-report.json"
COVERAGE_JSON = GENERATED / "coverage-report.json"
COVERAGE_MD = GENERATED / "coverage-summary.md"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def real_packs(knowledge: AttackKnowledge) -> list[RulePack]:
    """Production detection content, exactly as scripts/build_coverage_report.py loads it."""
    return [
        load_rule_pack(SIGMA_PACK, knowledge=knowledge),
        load_rule_pack(ELASTIC_PACK, knowledge=knowledge),
    ]


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))
    return data


def _import_report(knowledge: AttackKnowledge, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "provenance": {"attack_kb_version": knowledge.attack_kb_version, "sigma_release": "t"},
        "rules": rows,
    }


def _row(attack_ids: list[str], rejection: str, reasons: dict[str, int]) -> dict[str, Any]:
    return {
        "status": "rejected",
        "rejection": rejection,
        "gap_reasons": reasons,
        "attack_ids": attack_ids,
    }


def _status(report: dict[str, Any], attack_id: str) -> str:
    return str(next(t["status"] for t in report["techniques"] if t["attack_id"] == attack_id))


# ===========================================================================
# Status precedence (constructed inputs, no rule packs)
# ===========================================================================


def test_telemetry_only_rule_beats_translation_rule(knowledge: AttackKnowledge) -> None:
    rows = [
        _row(
            ["T1033"], "translation_gap", {"translation_gap:value_type:SigmaRegularExpression": 1}
        ),
        _row(["T1033"], "telemetry_gap", {"logsource:windows/ps_script": 1}),
        _row(["T1057"], "translation_gap", {"translation_gap:keyword_search": 1}),
    ]
    report = build_coverage_report(knowledge, [], _import_report(knowledge, rows))
    assert _status(report, "T1033") == "telemetry_gap"
    assert _status(report, "T1057") == "translation_gap"


def test_mixed_gap_rule_counts_as_translation(knowledge: AttackKnowledge) -> None:
    rows = [
        _row(
            ["T1033"],
            "translation_gap",
            {"telemetry_gap:field:OriginalFileName": 1, "translation_gap:keyword_search": 1},
        )
    ]
    report = build_coverage_report(knowledge, [], _import_report(knowledge, rows))
    assert _status(report, "T1033") == "translation_gap"


def test_covered_beats_every_gap(knowledge: AttackKnowledge, real_packs: list[RulePack]) -> None:
    rows = [_row(["T1033"], "telemetry_gap", {"logsource:windows/ps_script": 1})]
    report = build_coverage_report(knowledge, real_packs, _import_report(knowledge, rows))
    assert _status(report, "T1033") == "covered"


def test_no_rule_splits_observable_from_unobservable(knowledge: AttackKnowledge) -> None:
    report = build_coverage_report(knowledge, [], _import_report(knowledge, []))
    rows = {t["attack_id"]: t for t in report["techniques"]}
    for row in rows.values():
        expected = (
            "no_sigma_rule"
            if row["supported_platforms"] and row["has_data_component"]
            else "not_observable_on_supported_platforms"
        )
        assert row["status"] == expected
    # Acquire Infrastructure: PRE — no telemetry platform observes it
    assert rows["T1583.001"]["status"] == "not_observable_on_supported_platforms"


def test_policy_and_mapping_rejections_are_not_gaps(knowledge: AttackKnowledge) -> None:
    rows = [
        _row(["T1033"], "excluded_by_policy", {"policy:deprecated/high": 1}),
        _row(["T1033"], "no_attack_mapping", {}),
    ]
    report = build_coverage_report(knowledge, [], _import_report(knowledge, rows))
    assert _status(report, "T1033") in {"no_sigma_rule", "not_observable_on_supported_platforms"}


def test_kb_version_mismatch_fails_closed(knowledge: AttackKnowledge) -> None:
    bad = {"provenance": {"attack_kb_version": "enterprise-attack-0.0"}, "rules": []}
    with pytest.raises(ValueError, match="enterprise-attack-0.0"):
        build_coverage_report(knowledge, [], bad)


def test_gap_ranking_counts_only_telemetry_gap_techniques(knowledge: AttackKnowledge) -> None:
    rows = [
        _row(["T1033", "T1057"], "telemetry_gap", {"logsource:windows/ps_script": 2}),
        _row(["T1082"], "telemetry_gap", {"telemetry_gap:field:ParentImage": 1}),
    ]
    report = build_coverage_report(knowledge, [], _import_report(knowledge, rows))
    ranking = {r["blocker"]: r for r in report["gap_ranking"]}
    assert ranking["logsource:windows/ps_script"]["techniques_upper_bound"] == 2
    assert ranking["logsource:windows/ps_script"]["supported_product"] is True
    assert ranking["field:ParentImage"]["techniques_upper_bound"] == 1


# ===========================================================================
# The real committed report
# ===========================================================================


def test_every_active_technique_appears_exactly_once(
    report: dict[str, Any], knowledge: AttackKnowledge
) -> None:
    active = [o for o in (*knowledge.techniques(), *knowledge.sub_techniques()) if is_active(o)]
    ids = [t["attack_id"] for t in report["techniques"]]
    assert len(ids) == len(set(ids)) == len(active) == report["summary"]["active_techniques"]
    assert {t["status"] for t in report["techniques"]} <= {s.value for s in TechniqueStatus}
    assert sum(report["summary"]["techniques_by_status"].values()) == len(active)


def test_every_active_group_appears_with_consistent_counts(
    report: dict[str, Any], knowledge: AttackKnowledge
) -> None:
    groups = active_groups(knowledge)
    assert len(report["groups"]) == len(groups) == report["summary"]["active_groups"]
    by_attack_id = {g["attack_id"]: g for g in report["groups"]}
    status_of = {t["attack_id"]: t["status"] for t in report["techniques"]}
    for group in groups:
        ext = next(
            r["external_id"]
            for r in group["external_references"]
            if r.get("source_name") == "mitre-attack"
        )
        row = by_attack_id[ext]
        assert row["profile_techniques"] == len(techniques_used_by(knowledge, str(group["id"])))
        assert row["covered"] + len(row["uncovered"]) == row["profile_techniques"]
        assert sum(row["by_status"].values()) == row["profile_techniques"]
        for item in row["uncovered"]:
            assert status_of[item["attack_id"]] == item["status"] != "covered"


def test_group_used_totals_match_union_of_profiles(report: dict[str, Any]) -> None:
    used = {t["attack_id"] for g in report["groups"] for t in g["uncovered"]}
    covered_used = report["summary"]["group_used_techniques_by_status"]["covered"]
    assert (
        sum(report["summary"]["group_used_techniques_by_status"].values())
        == report["summary"]["group_used_techniques"]
    )
    assert len(used) == report["summary"]["group_used_techniques"] - covered_used


def test_known_anchor_statuses(report: dict[str, Any]) -> None:
    assert _status(report, "T1033") == "covered"  # whoami (Sigma, T3 true positive)
    assert _status(report, "T1003.001") == "covered"  # LSASS Memory
    # Domains (pre-compromise, PRE platform)
    assert _status(report, "T1583.001") == "not_observable_on_supported_platforms"


def test_committed_report_and_summary_regenerate_byte_identically(
    knowledge: AttackKnowledge, real_packs: list[RulePack]
) -> None:
    fresh = build_coverage_report(
        knowledge,
        real_packs,
        json.loads(SIGMA_REPORT.read_text(encoding="utf-8")),
        json.loads(ELASTIC_REPORT.read_text(encoding="utf-8")),
    )
    assert json.dumps(fresh, indent=1, ensure_ascii=False) + "\n" == COVERAGE_JSON.read_text(
        encoding="utf-8"
    )
    assert render_coverage_summary(fresh) == COVERAGE_MD.read_text(encoding="utf-8")


def test_provenance_pins_every_input(report: dict[str, Any], real_packs: list[RulePack]) -> None:
    prov = report["provenance"]
    assert prov["attack_kb_version"] == EXPECTED_ATTACK_KB_VERSION
    assert {p["content_hash"] for p in prov["rule_packs"]} == {p.content_hash for p in real_packs}
    assert prov["sigma_import"]["sigma_archive_sha256"]
    assert prov["elastic_import"]["source_commit"].startswith("195f15c0bac8")


def test_coverage_by_content_source(report: dict[str, Any]) -> None:
    summary = report["summary"]
    by_origin = summary["covered_techniques_by_origin"]
    only = summary["covered_techniques_by_origin_only"]
    covered = summary["techniques_by_status"]["covered"]
    # Every covered technique is covered by Sigma, by Elastic, or by both.
    assert (
        by_origin["sigma"] + by_origin["elastic"] - covered
        == covered - only["sigma"] - only["elastic"]
    )
    msbuild = next(t for t in report["techniques"] if t["attack_id"] == "T1127.001")
    assert msbuild["status"] == "covered"
    assert msbuild["rule_sources_by_origin"] == {"elastic": msbuild["rule_sources"]}


def test_supported_platforms_follow_the_field_map() -> None:
    """Every product the field map scopes has an ATT&CK platform mapping, and the
    supported platforms are exactly theirs — no fixed scope."""
    from attribution_platform.detection_content.coverage_report import (
        PRODUCT_PLATFORMS,
        supported_platforms,
    )
    from attribution_platform.detection_content.sigma_field_map import PRODUCT_OS_SCOPES

    assert set(PRODUCT_OS_SCOPES) <= set(PRODUCT_PLATFORMS)
    platforms = supported_platforms()
    assert {"Windows", "Linux", "IaaS", "Identity Provider", "SaaS"} <= set(platforms)
    assert "PRE" not in platforms and "Network Devices" not in platforms


def test_a_logsource_of_an_unsupported_product_is_not_a_supported_blocker(
    knowledge: AttackKnowledge,
) -> None:
    rows = [_row(["T1033"], "telemetry_gap", {"logsource:bitbucket/audit": 1})]
    report = build_coverage_report(knowledge, [], _import_report(knowledge, rows))
    ranking = {r["blocker"]: r for r in report["gap_ranking"]}
    assert ranking["logsource:bitbucket/audit"]["supported_product"] is False
