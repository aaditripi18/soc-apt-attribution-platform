"""The enrich content tier (ADR-0007 Amendment A, ADR-0003 Amendment H).

Generic Sigma rules below the Core++ level come from a separately pinned
archive, are imported only if ``low`` / ``informational``, and mark their
Evidence ``quality = LOW``. Such Evidence joins a unit only through a structural
link to other Evidence; a component made of it alone is not a unit — so a broad
rule on benign activity cannot flood an investigation with units (measured on
the real LSASS hard-negative runs, ADR-0007 Amendment A).
"""

from __future__ import annotations

import hashlib
import json
import textwrap
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import correlate_structurally
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection.errors import DetectionError
from attribution_platform.detection.evidence import derive_evidence_from_detection
from attribution_platform.detection_content.sigma_import import (
    SigmaImportError,
    import_sigma_archive,
)
from attribution_platform.domain import (
    EventMetadata,
    Evidence,
    EvidenceQuality,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
)

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
CORE_ID = "11111111-1111-1111-1111-111111111111"
LOW_ID = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _rule(rule_id: str, image: str, *, level: str) -> str:
    return textwrap.dedent(
        f"""\
        title: Rule {rule_id[:4]}
        id: {rule_id}
        status: test
        author: Test Author
        tags:
          - attack.t1033
        logsource:
          category: process_creation
          product: windows
        detection:
          sel:
            Image|endswith: '{image}'
          condition: sel
        level: {level}
        """
    )


def _archive(path: Path, *rules: str) -> tuple[Path, str]:
    with zipfile.ZipFile(path, "w") as z:
        for i, text in enumerate(rules):
            z.writestr(f"rules/windows/r{i:02d}.yml", text)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _import(
    tmp_path: Path, knowledge: AttackKnowledge, enrich: tuple[str, ...]
) -> dict[str, object]:
    core, core_sha = _archive(tmp_path / "core.zip", _rule(CORE_ID, "\\core.exe", level="high"))
    low, low_sha = _archive(tmp_path / "enrich.zip", *enrich)
    result = import_sigma_archive(
        core,
        knowledge=knowledge,
        release_tag="test-tag",
        archive_sha256=core_sha,
        enrich_archive=low,
        enrich_archive_sha256=low_sha,
    )
    return {"pack": result.pack, "report": result.report}


# ===========================================================================
# Importer
# ===========================================================================


def test_low_rules_in_the_enrich_archive_become_low_quality_rules(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    out = _import(tmp_path, knowledge, (_rule(LOW_ID, "\\low.exe", level="low"),))
    rules = {r["rule_family"]: r for r in out["pack"]["rules"]}  # type: ignore[index]
    assert rules[f"sigma:{LOW_ID}"]["evidence_quality"] == "low"
    assert "evidence_quality" not in rules[f"sigma:{CORE_ID}"]
    rows = {r["sigma_id"]: r for r in out["report"]["rules"]}  # type: ignore[index]
    assert rows[LOW_ID]["content_tier"] == "enrich" and "content_tier" not in rows[CORE_ID]
    assert out["pack"]["provenance"]["enrich_archive"]["file"] == "enrich.zip"  # type: ignore[index]


def test_enrich_archive_accepts_only_low_and_informational(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    out = _import(tmp_path, knowledge, (_rule(LOW_ID, "\\x.exe", level="high"),))
    (row,) = [r for r in out["report"]["rules"] if r["sigma_id"] == LOW_ID]  # type: ignore[index]
    assert row["rejection"] == "excluded_by_policy"


def test_a_rule_in_both_archives_is_refused(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    with pytest.raises(SigmaImportError, match="both archives"):
        _import(tmp_path, knowledge, (_rule(CORE_ID, "\\core.exe", level="low"),))


def test_enrich_archive_needs_its_hash(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    core, sha = _archive(tmp_path / "core.zip", _rule(CORE_ID, "\\core.exe", level="high"))
    with pytest.raises(SigmaImportError, match="go together"):
        import_sigma_archive(
            core, knowledge=knowledge, release_tag="t", archive_sha256=sha, enrich_archive=core
        )


# ===========================================================================
# Detection -> Evidence quality
# ===========================================================================


def _obs(observation_id: str, image: str, entity: str) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=T0,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=observation_id),
        event=EventMetadata(kind="event", category=("process",), type=("start",)),
        host=HostRef(name="host-1", os_type="windows"),
        process=ProcessRef(executable=image, entity_id=entity),
    )


def _engine(tmp_path: Path, knowledge: AttackKnowledge) -> DetectionEngine:
    out = _import(tmp_path, knowledge, (_rule(LOW_ID, "\\low.exe", level="low"),))
    pack = tmp_path / "pack.json"
    pack.write_text(json.dumps(out["pack"]), encoding="utf-8")
    return DetectionEngine(rules=load_rule_pack(pack, knowledge=knowledge).rules)


def _items(
    engine: DetectionEngine, knowledge: AttackKnowledge, *obs: Observation
) -> list[tuple[Evidence, Observation]]:
    by_id = {o.observation_id: o for o in obs}
    return [
        (evidence, by_id[d.supporting_observation_ids[0]])
        for d in engine.evaluate(list(obs))
        for evidence in derive_evidence_from_detection(
            d, by_id[d.supporting_observation_ids[0]], knowledge=knowledge
        )
    ]


def test_enrich_evidence_is_low_quality(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    engine = _engine(tmp_path, knowledge)
    items = _items(engine, knowledge, _obs("o-low", "C:\\low.exe", "{A}"))
    assert [e.quality for e, _ in items] == [EvidenceQuality.LOW]
    core = _items(engine, knowledge, _obs("o-core", "C:\\core.exe", "{B}"))
    assert [e.quality for e, _ in core] == [None]


def test_invalid_evidence_quality_in_a_pack_fails_closed(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    out = _import(tmp_path, knowledge, (_rule(LOW_ID, "\\low.exe", level="low"),))
    out["pack"]["rules"][0]["evidence_quality"] = "very-low"  # type: ignore[index]
    pack = tmp_path / "bad.json"
    pack.write_text(json.dumps(out["pack"]), encoding="utf-8")
    with pytest.raises(DetectionError, match="evidence_quality"):
        load_rule_pack(pack, knowledge=knowledge)


# ===========================================================================
# ADR-0003 Amendment H: enrich Evidence never forms a unit on its own
# ===========================================================================


def test_enrich_evidence_alone_forms_no_unit(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    engine = _engine(tmp_path, knowledge)
    items = _items(engine, knowledge, _obs("o-low", "C:\\low.exe", "{A}"))
    assert correlate_structurally(items).groups == ()


def test_enrich_evidence_joins_the_unit_it_is_linked_to(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """Same process instance: the core detection forms the unit, the
    low-level detection on that instance joins it."""
    engine = _engine(tmp_path, knowledge)
    items = _items(
        engine,
        knowledge,
        _obs("o-core", "C:\\core.exe", "{SAME}"),
        _obs("o-low", "C:\\low.exe", "{SAME}"),
        _obs("o-other-low", "C:\\low.exe", "{OTHER}"),
    )
    (group,) = correlate_structurally(items).groups
    members = {
        e.provenance.source_observation_ids[0]
        for e, _ in items
        if e.evidence_id in group.member_evidence_ids
    }
    assert members == {"o-core", "o-low"}  # the unlinked low-level detection is no unit
