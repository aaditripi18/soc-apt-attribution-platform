"""ADR-0018: actor-specific Evidence.

A Sigma rule that names a Group becomes evidence about that Group only when the
reviewed decision accepts the tag; then a match yields Evidence referencing the
Group, the unit analysis lists it, and the investigation's assessment names the
Group as a lead. Nothing about the technique comparison changes.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.detection_content.pinned import (
    SIGMA_ACTOR_IMPORT_REPORT,
    SIGMA_ACTOR_PACK,
    SIGMA_PACK,
)
from attribution_platform.detection_content.sigma_actor_import import (
    import_sigma_actor_archive,
    load_actor_tag_review,
)
from attribution_platform.detection_content.sigma_import import SigmaImportError
from attribution_platform.investigation import load_attribution_analysis, run_investigation
from attribution_platform.investigation.assessment import load_assessment
from attribution_platform.investigation.dossier import render_dossier
from attribution_platform.investigation.records import search_unit_summaries
from attribution_platform.replay.recording_pipeline import RecordingSource

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01"
ARCHIVE = RELEASE / "sigma_actor_specific.zip"
MANIFEST = RELEASE / "manifest-sigma_actor_specific.json"
REVIEW = RELEASE / "actor-tag-review.json"
HOST = "WS01.example.local"
# The staging path published for one Mustang Panda campaign — an indicator
# string, exactly as the reviewed Sigma rule carries it.
ARTEFACT = "C:\\Users\\Public\\Libraries\\PhotoTvRHD\\SolidPDFCreator.dll"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def packs(knowledge: AttackKnowledge) -> tuple[RulePack, RulePack]:
    return (
        load_rule_pack(SIGMA_PACK, knowledge=knowledge),
        load_rule_pack(SIGMA_ACTOR_PACK, knowledge=knowledge),
    )


def _process_create(record_id: int, guid: str, parent: str, image: str, cmd: str) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-01-01T12:00:{record_id:02d}.000Z",
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "UtcTime": f"2026-01-01 12:00:{record_id:02d}.000",
                "ProcessGuid": guid,
                "ProcessId": str(1000 + record_id),
                "Image": image,
                "CommandLine": cmd,
                "ParentProcessGuid": parent,
            },
        },
    }


def _investigate(
    tmp_path: Path, knowledge: AttackKnowledge, packs: tuple[RulePack, ...], commands: list[str]
) -> tuple[FakeElasticClient, Any]:
    cmd = "C:\\Windows\\System32\\cmd.exe"
    records = [
        _process_create(i + 1, f"{{P{i}}}", "{ROOT}", cmd, command)
        for i, command in enumerate(commands)
    ]
    path = tmp_path / "rec.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("rec.json", "\n".join(json.dumps(r) for r in records) + "\n")
    client = FakeElasticClient()
    record = run_investigation(
        RecordingSource(
            recording_id="rec-actor-test",
            path=path,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            declared_sources={HOST: ("sysmon",)},
        ),
        client=client,
        engine=DetectionEngine(rules=tuple(r for pack in packs for r in pack.rules)),
        knowledge=knowledge,
        detection_pack_content_hash="test",
    )
    return client, record


# ===========================================================================
# The reviewed content
# ===========================================================================


def test_committed_actor_pack_regenerates_byte_identically(knowledge: AttackKnowledge) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() == manifest["artifact"]["sha256"]
    result = import_sigma_actor_archive(
        ARCHIVE,
        knowledge=knowledge,
        release_tag="r2026-07-01",
        archive_sha256=manifest["artifact"]["sha256"],
        actor_tag_review=REVIEW,
    )
    for data, path in ((result.pack, SIGMA_ACTOR_PACK), (result.report, SIGMA_ACTOR_IMPORT_REPORT)):
        assert json.dumps(data, indent=1, ensure_ascii=False) + "\n" == path.read_text(
            encoding="utf-8"
        )


def test_only_accepted_group_tags_become_rules_and_they_map_to_the_group_alone(
    knowledge: AttackKnowledge, packs: tuple[RulePack, RulePack]
) -> None:
    review = load_actor_tag_review(REVIEW)
    accepted_rules = {sigma_id for (sigma_id, _), (ok, _) in review.items() if ok}
    report = json.loads(SIGMA_ACTOR_IMPORT_REPORT.read_text(encoding="utf-8"))
    assert report["summary"]["group_tags_reviewed"] == len(review)
    for row in report["rules"]:
        accepted = [t for t in row["actor_tags"] if t["decision"] == "accept"]
        assert all(t["reason"] for t in row["actor_tags"])
        if not accepted:
            assert row["status"] == "rejected" and row["sigma_id"] not in accepted_rules
    actor_pack = packs[1]
    assert actor_pack.rules
    for rule in actor_pack.rules:
        assert rule.rule_ref.rule_id.startswith("sigma-actor:")
        sigma_id = rule.rule_ref.rule_id.split(":")[1]
        assert sigma_id in accepted_rules
        # the Group, and nothing else: no technique rides along
        assert {m.attack_ref.object_type for m in rule.technique_mappings} == {"intrusion-set"}
        for mapping in rule.technique_mappings:
            tag = f"attack.{(mapping.attack_ref.external_id or '').lower()}"
            assert review[(sigma_id, tag)][0] is True
            assert "accepted by the actor-tag review" in mapping.mapping_basis
    # a framework's default task is not a Group (the Empire rule Sigma tags APT3)
    rejected_titles = {
        r["title"]
        for r in report["rules"]
        if not any(t["decision"] == "accept" for t in r["actor_tags"])
    }
    assert "HackTool - Default PowerSploit/Empire Scheduled Task Creation" in rejected_titles


def test_an_unreviewed_group_tag_fails_the_import(
    knowledge: AttackKnowledge, tmp_path: Path
) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    review = json.loads(REVIEW.read_text(encoding="utf-8"))
    review["decisions"] = review["decisions"][1:]  # one decision missing
    partial = tmp_path / "actor-tag-review.json"
    partial.write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(SigmaImportError, match="no reviewed decision"):
        import_sigma_actor_archive(
            ARCHIVE,
            knowledge=knowledge,
            release_tag="r2026-07-01",
            archive_sha256=manifest["artifact"]["sha256"],
            actor_tag_review=partial,
        )
    review["decisions"][0]["reason"] = " "
    partial.write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(SigmaImportError, match="has no reason"):
        load_actor_tag_review(partial)


# ===========================================================================
# From a matched artefact to a named lead
# ===========================================================================


def test_a_matched_artefact_names_its_group_as_a_lead(
    knowledge: AttackKnowledge, packs: tuple[RulePack, RulePack], tmp_path: Path
) -> None:
    client, record = _investigate(
        tmp_path,
        knowledge,
        packs,
        [f"cmd.exe /c copy SolidPDFCreator.dll {ARTEFACT}", "whoami /all -all"],
    )
    analyses = [dict(load_attribution_analysis(client, g) or {}) for g in record.units]
    hits = [a for a in analyses if a["actor_specific_evidence"]]
    assert len(hits) == 1
    (item,) = hits[0]["actor_specific_evidence"]
    assert (item["actor_name"], item["actor_attack_id"]) == ("Mustang Panda", "G0129")
    assert item["rule_id"].startswith("sigma-actor:")
    assert "accepted by the actor-tag review" in item["claim"]

    # a Group reference is never a technique: not a decision feature, not in the summary
    assert not [t for t in hits[0]["observed_feature_technique_ids"] if "intrusion-set" in t]
    summaries = search_unit_summaries(client, {"match_all": {}}, size=100)
    assert not [t for s in summaries for t in s["technique_ids"] if not t.startswith("T")]

    assessment = dict(load_assessment(client, record.investigation_id) or {})
    assert assessment["verdict"] == "actor_specific_evidence"
    assert [lead["actor_name"] for lead in assessment["actor_leads"]] == ["Mustang Panda"]
    assert "Mustang Panda" in assessment["statement"]
    assert "lead to verify" in assessment["statement"]
    assert "not a calibrated conclusion" in assessment["statement"]
    dossier = render_dossier(client, knowledge, record.investigation_id)
    assert "Actor-specific evidence — **Mustang Panda**" in dossier


def test_without_the_artefact_no_group_is_named(
    knowledge: AttackKnowledge, packs: tuple[RulePack, RulePack], tmp_path: Path
) -> None:
    """The same activity without the published path: technique Evidence only."""
    client, record = _investigate(
        tmp_path,
        knowledge,
        packs,
        ["cmd.exe /c copy SolidPDFCreator.dll C:\\Temp\\SolidPDFCreator.dll", "whoami /all -all"],
    )
    for group_id in record.units:
        analysis = dict(load_attribution_analysis(client, group_id) or {})
        assert analysis["actor_specific_evidence"] == []
    assessment = dict(load_assessment(client, record.investigation_id) or {})
    assert assessment["verdict"] != "actor_specific_evidence"
    assert assessment["actor_leads"] == []
    assert "Mustang Panda" not in assessment["statement"]


def test_leads_to_different_groups_single_none_out(knowledge: AttackKnowledge) -> None:
    from attribution_platform.investigation.assessment import Verdict, assess_investigation

    def lead(name: str, attack_id: str, evidence_id: str) -> dict[str, Any]:
        return {
            "actor_name": name,
            "actor_attack_id": attack_id,
            "actor_stix_id": f"intrusion-set--{attack_id}",
            "rule_id": f"sigma-actor:{evidence_id}:000",
            "claim": "…",
            "evidence_id": evidence_id,
            "observation_id": "o",
            "observed_at": None,
        }

    analysis = {
        "group_id": "u1",
        "observed_feature_technique_ids": [],
        "candidates": [],
        "indicator_matches": [],
        "actor_specific_evidence": [lead("OilRig", "G0049", "a"), lead("Turla", "G0010", "b")],
    }
    record = assess_investigation(knowledge, "inv", [analysis])
    assert record.verdict is Verdict.ACTOR_SPECIFIC_EVIDENCE
    assert "2 different Groups" in record.statement and "none is singled out" in record.statement
