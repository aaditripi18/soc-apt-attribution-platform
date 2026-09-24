"""ATT&CK release diff (doc 11 §G upgrade step) — v19.0 → v19.2 change report.

Checks the diff is internally consistent with the two vendored bundles, that a
release diffed against itself is empty, and that the committed change report
regenerates byte-identically.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from attribution_platform.attack_knowledge.diff import diff_attack_versions, render_attack_diff
from attribution_platform.attack_knowledge.loader import (
    AttackKnowledge,
    attack_artifact_dir,
    load_attack_knowledge,
)
from attribution_platform.attack_knowledge.traversal import active_groups

OLD = "enterprise-attack-19.0"
NEW = "enterprise-attack-19.2"
REPORT_DIR = attack_artifact_dir(NEW)
REPORT_JSON = REPORT_DIR / f"changes-from-{OLD}.json"
REPORT_MD = REPORT_DIR / f"changes-from-{OLD}.md"


@pytest.fixture(scope="module")
def old() -> AttackKnowledge:
    return load_attack_knowledge(OLD)


@pytest.fixture(scope="module")
def new() -> AttackKnowledge:
    return load_attack_knowledge(NEW)


@pytest.fixture(scope="module")
def diff(old: AttackKnowledge, new: AttackKnowledge) -> dict[str, Any]:
    return diff_attack_versions(old, new)


def test_counts_are_consistent(diff: dict[str, Any]) -> None:
    for kind, row in diff["kinds"].items():
        assert row["active_after"] == row["active_before"] + len(row["added"]) - len(
            row["retired"]
        ), kind


def test_added_groups_are_active_only_in_the_new_release(
    diff: dict[str, Any], old: AttackKnowledge, new: AttackKnowledge
) -> None:
    def names(kb: AttackKnowledge) -> set[str]:
        return {str(g["name"]) for g in active_groups(kb)}

    added = {g["name"] for g in diff["kinds"]["groups"]["added"]}
    assert added == names(new) - names(old)
    assert added  # v19.2 does add Groups (the reason for this upgrade)


def test_release_diffed_against_itself_is_empty(new: AttackKnowledge) -> None:
    same = diff_attack_versions(new, new)
    for row in same["kinds"].values():
        assert row["added"] == row["retired"] == row["modified"] == []
    assert same["group_profile_changes"] == []


def test_committed_change_report_regenerates_byte_identically(diff: dict[str, Any]) -> None:
    assert json.dumps(diff, indent=1, ensure_ascii=False) + "\n" == REPORT_JSON.read_text(
        encoding="utf-8"
    )
    assert render_attack_diff(diff) == REPORT_MD.read_text(encoding="utf-8")
