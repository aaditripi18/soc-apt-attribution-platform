"""ADR-0007 T3: Sigma importer tests.

Translation is checked on small hand-written Sigma rules packed into temporary
archives (every operator/modifier path, De Morgan filters, partial import that
is never broader, gaps, DNF bound, policy, tag resolution incl. revoked-by and
ignored Group tags). The real pinned archive is checked for hash, byte-identical
regeneration of the committed pack/report, loadability, a true positive, and
DRL author attribution reaching the Evidence claim.
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import textwrap
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import (
    DetectionEngine,
    derive_evidence_from_detection,
    load_rule_pack,
)
from attribution_platform.detection_content.sigma_import import (
    SigmaImportError,
    SigmaImportResult,
    import_sigma_archive,
    load_software_tag_review,
)
from attribution_platform.domain import (
    EventMetadata,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    ProcessRef,
    SourceRef,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01"
MANIFEST = json.loads((RELEASE_DIR / "manifest.json").read_text(encoding="utf-8"))
ARCHIVE = RELEASE_DIR / MANIFEST["artifact"]["filename"]
GENERATED = RELEASE_DIR / "generated"
PACK_PATH = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
REPORT_PATH = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"
REVIEW_PATH = RELEASE_DIR / "software-tag-review.json"
ENRICH_MANIFEST_PATH = RELEASE_DIR / "manifest-sigma_enrich_low.json"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _rule_yaml(
    detection: str,
    *,
    rule_id: str = "11111111-1111-1111-1111-111111111111",
    tags: tuple[str, ...] = ("attack.t1033",),
    category: str = "process_creation",
    product: str = "windows",
    status: str = "test",
    level: str = "high",
) -> str:
    tag_lines = "\n".join(f"  - {t}" for t in tags)
    return (
        f"title: Test rule {rule_id[:4]}\n"
        f"id: {rule_id}\n"
        f"status: {status}\n"
        "author: Test Author\n"
        f"tags:\n{tag_lines}\n"
        f"logsource:\n  category: {category}\n  product: {product}\n"
        f"detection:\n{textwrap.indent(textwrap.dedent(detection).strip(), '  ')}\n"
        f"level: {level}\n"
    )


def _import(
    tmp_path: Path,
    knowledge: AttackKnowledge,
    *rules: str,
    dnf_bound: int = 64,
    review: list[dict[str, str]] | None = None,
) -> SigmaImportResult:
    archive = tmp_path / "rules.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for i, text in enumerate(rules):
            z.writestr(f"rules/windows/r{i:02d}.yml", text)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    review_path = None
    if review is not None:
        review_path = tmp_path / "review.json"
        review_path.write_text(json.dumps({"decisions": review}), encoding="utf-8")
    return import_sigma_archive(
        archive,
        knowledge=knowledge,
        release_tag="test-tag",
        archive_sha256=sha,
        dnf_bound=dnf_bound,
        software_tag_review=review_path,
    )


_PRODUCT_SCOPE_FIELDS = frozenset({"host.os_type", "cloud.account_id", "observer.product"})


def _conditions(result: SigmaImportResult) -> list[list[tuple[Any, ...]]]:
    """Non-scope conditions of each generated rule, as comparable tuples
    (the logsource scope and the product scope — ``host.os_type`` (ADR-0010),
    ``cloud.account_id`` (ADR-0011) and ``observer.product`` (ADR-0012) — are
    left out; ``test_rules_carry_the_os_scope`` pins the latter)."""
    out = []
    for rule in result.pack["rules"]:
        out.append(
            [
                (
                    c["field_path"],
                    c["operator"],
                    c.get("value"),
                    c.get("case_insensitive", False),
                    c.get("negate", False),
                )
                for c in rule["conditions"]
                if c["operator"] != "has_element" and c["field_path"] not in _PRODUCT_SCOPE_FIELDS
            ]
        )
    return out


def _outcome(result: SigmaImportResult) -> dict[str, Any]:
    (row,) = result.report["rules"]
    return dict(row)


# ===========================================================================
# Value translation
# ===========================================================================


def test_string_modifiers_map_to_operators(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            r"""
            sel:
              Image|endswith: '\whoami.exe'
              CommandLine|startswith: 'whoami'
              CommandLine|contains: ' /all'
            eq:
              CommandLine: 'whoami /all'
            condition: sel and eq
            """
        ),
    )
    assert _conditions(result) == [
        [
            ("process.executable", "endswith", "\\whoami.exe", True, False),
            ("process.command_line", "startswith", "whoami", True, False),
            ("process.command_line", "contains", " /all", True, False),
            ("process.command_line", "equals", "whoami /all", True, False),
        ]
    ]
    assert _outcome(result)["status"] == "imported"


def test_scope_conditions_come_from_logsource(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml("sel:\n  Image|endswith: '\\a.exe'\ncondition: sel"),
    )
    scope = [
        (c["field_path"], c["value"])
        for c in result.pack["rules"][0]["conditions"]
        if c["operator"] == "has_element"
    ]
    assert scope == [("event.category", "process"), ("event.type", "start")]


def test_rules_carry_the_os_scope(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    """ADR-0010 D2: a Windows rule refuses Linux / macOS hosts; a Linux rule
    requires a Linux host. Placed after the indexed logsource scope."""
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml("sel:\n  Image|endswith: '\\a.exe'\ncondition: sel"),
        _rule_yaml(
            "sel:\n  Image|endswith: '/bash'\ncondition: sel",
            rule_id="22222222-2222-2222-2222-222222222222",
            product="linux",
        ),
    )
    by_family = {r["rule_family"]: r["conditions"] for r in result.pack["rules"]}
    os_scope = {
        family: [
            (c["value"], c.get("negate", False))
            for c in conditions
            if c["field_path"] == "host.os_type"
        ]
        for family, conditions in by_family.items()
    }
    assert sorted(os_scope.values()) == [
        [("linux", False)],
        [("linux", True), ("macos", True)],
    ]
    for conditions in by_family.values():
        assert conditions[0]["field_path"] == "event.category"  # the index key stays first


def test_cased_modifier_is_case_sensitive(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml("sel:\n  CommandLine|cased|contains: 'VeryCase'\ncondition: sel"),
    )
    assert _conditions(result) == [[("process.command_line", "contains", "VeryCase", False, False)]]


def test_null_exists_and_wildcard_only(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            """
            sel:
              CommandLine: null
              Image: '*'
            condition: sel
            """
        ),
    )
    assert _conditions(result) == [
        [
            ("process.command_line", "exists", None, False, True),
            ("process.executable", "exists", None, False, False),
        ]
    ]


def test_windash_expands_to_one_rule_per_variant(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml("sel:\n  CommandLine|contains|windash: ' -all'\ncondition: sel"),
    )
    values = sorted(conds[0][2] for conds in _conditions(result))
    assert " -all" in values and " /all" in values
    assert len(values) == len(set(values)) >= 3


def test_numbers_map_to_equals_on_network_fields(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            "sel:\n  DestinationPort: 4444\n  DestinationIp: '203.0.113.9'\ncondition: sel",
            category="network_connection",
        ),
    )
    assert _conditions(result) == [
        [
            ("network.destination.port", "equals", "4444", False, False),
            ("network.destination.ip", "equals", "203.0.113.9", True, False),
        ]
    ]


# ===========================================================================
# Condition structure: DNF, De Morgan, partial import
# ===========================================================================


def test_or_list_becomes_one_rule_per_value(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            r"""
            sel:
              Image|endswith:
                - '\a.exe'
                - '\b.exe'
            condition: sel
            """
        ),
    )
    assert len(result.pack["rules"]) == 2
    assert {r["rule_source"] for r in result.pack["rules"]} == {
        "sigma:11111111-1111-1111-1111-111111111111"
    }
    assert [r["rule_id"][-3:] for r in result.pack["rules"]] == ["000", "001"]


def test_not_filter_list_uses_de_morgan(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            r"""
            sel:
              CommandLine|contains: 'x.vbs'
            filter:
              Image|endswith:
                - '\cscript.exe'
                - '\wscript.exe'
            condition: sel and not filter
            """
        ),
    )
    assert _conditions(result) == [
        [
            ("process.command_line", "contains", "x.vbs", True, False),
            ("process.executable", "endswith", "\\cscript.exe", True, True),
            ("process.executable", "endswith", "\\wscript.exe", True, True),
        ]
    ]


def test_unmapped_field_in_or_branch_gives_partial_import(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            r"""
            sel:
              - Image|endswith: '\whoami.exe'
              - Hashes|contains: 'IMPHASH=0123456789ABCDEF'
            condition: sel
            """
        ),
    )
    assert _conditions(result) == [
        [("process.executable", "endswith", "\\whoami.exe", True, False)]
    ]
    row = _outcome(result)
    assert row["status"] == "partial"
    assert (row["conjuncts_imported"], row["conjuncts_total"]) == (1, 2)
    assert row["gap_reasons"] == {"telemetry_gap:field:Hashes": 1}


def test_unmapped_field_in_negated_filter_never_broadens(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """Dropping 'not filter' alone would make the rule fire more often than its
    author wrote — the whole conjunct must go instead."""
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            r"""
            sel:
              Image|endswith: '\rundll32.exe'
            filter:
              User|contains: 'SYSTEM'
            condition: sel and not filter
            """
        ),
    )
    assert result.pack["rules"] == []
    row = _outcome(result)
    assert row["status"] == "rejected"
    assert row["rejection"] == "telemetry_gap"


@pytest.mark.parametrize(
    ("detection", "reason"),
    [
        ("sel:\n  CommandLine|re: 'a.*b'\ncondition: sel", "value_type:SigmaRegularExpression"),
        ("sel:\n  CommandLine|contains: 'a*b'\ncondition: sel", "interior_wildcard_or_empty"),
        ("sel:\n  CommandLine|contains: 'a?b'\ncondition: sel", "single_char_wildcard"),
        ("keywords:\n  - 'mimikatz'\ncondition: keywords", "keyword_search"),
    ],
)
def test_untranslatable_constructs_are_translation_gaps(
    tmp_path: Path, knowledge: AttackKnowledge, detection: str, reason: str
) -> None:
    result = _import(tmp_path, knowledge, _rule_yaml(detection))
    row = _outcome(result)
    assert result.pack["rules"] == []
    assert row["rejection"] == "translation_gap"
    assert row["gap_reasons"] == {f"translation_gap:{reason}": 1}


def test_dnf_bound_rejects_whole_rule(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    rule = _rule_yaml(
        """
        a:
          CommandLine|contains: ['1', '2', '3']
        b:
          Image|endswith: ['x', 'y', 'z']
        condition: a and b
        """
    )
    assert len(_import(tmp_path, knowledge, rule, dnf_bound=9).pack["rules"]) == 9
    result = _import(tmp_path, knowledge, rule, dnf_bound=8)
    assert result.pack["rules"] == []
    assert _outcome(result)["gap_reasons"] == {"dnf_bound_exceeded:>8": 1}


# ===========================================================================
# Logsource, policy, tags
# ===========================================================================


def test_unsupported_logsource_is_telemetry_gap(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml("sel:\n  ImageLoaded|endswith: '.sys'\ncondition: sel", category="driver_load"),
        _rule_yaml(
            "sel:\n  Image|endswith: '/bash'\ncondition: sel",
            rule_id="22222222-2222-2222-2222-222222222222",
            product="macos",  # linux/process_creation is supported since ADR-0010
        ),
    )
    assert result.pack["rules"] == []
    assert {r["rejection"] for r in result.report["rules"]} == {"telemetry_gap"}


@pytest.mark.parametrize(("status", "level"), [("deprecated", "high"), ("test", "low")])
def test_policy_exclusions(
    tmp_path: Path, knowledge: AttackKnowledge, status: str, level: str
) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml("sel:\n  Image|endswith: '\\a.exe'\ncondition: sel", status=status, level=level),
    )
    assert _outcome(result)["rejection"] == "excluded_by_policy"


def test_group_tags_never_become_mappings(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            "sel:\n  Image|endswith: '\\a.exe'\ncondition: sel",
            tags=("attack.t1033", "attack.g0016", "attack.discovery"),
        ),
    )
    mappings = result.pack["rules"][0]["technique_mappings"]
    assert [m["external_id"] for m in mappings] == ["T1033"]
    assert all(m["object_type"] == "attack-pattern" for m in mappings)
    assert _outcome(result)["ignored_group_tags"] == ["attack.g0016"]


def test_rule_without_resolvable_mapping_is_not_imported(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml(
            "sel:\n  Image|endswith: '\\a.exe'\ncondition: sel",
            tags=("attack.g0016", "attack.t1153", "attack.t9999"),
        ),
    )
    row = _outcome(result)
    assert row["rejection"] == "no_attack_mapping"
    assert row["dropped_tags"] == ["attack.t1153", "attack.t9999"]  # deprecated, unknown


def test_revoked_technique_follows_revoked_by(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    result = _import(
        tmp_path,
        knowledge,
        _rule_yaml("sel:\n  Image|endswith: '\\a.exe'\ncondition: sel", tags=("attack.t1156",)),
    )
    (mapping,) = result.pack["rules"][0]["technique_mappings"]
    assert mapping["external_id"] == "T1546.004"
    assert "T1156 is revoked, followed ATT&CK revoked-by to T1546.004" in mapping["mapping_basis"]


_SOFTWARE_RULE = _rule_yaml(
    "sel:\n  Image|endswith: '\\a.exe'\ncondition: sel",
    tags=("attack.t1003.001", "attack.s0002"),
)
_RULE_ID = "11111111-1111-1111-1111-111111111111"


def _mapping_types(result: SigmaImportResult) -> dict[str, str]:
    return {
        m["external_id"]: m["object_type"] for m in result.pack["rules"][0]["technique_mappings"]
    }


def test_unreviewed_software_tag_is_not_evidence(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """ADR-0007 D3 amendment: without a reviewed acceptance, a software tag is
    recorded and ignored (tool identity is strong evidence; authors' tags are
    often wrong). The technique tag still maps."""
    reviews: tuple[list[dict[str, str]] | None, ...] = (None, [])
    for review in reviews:
        result = _import(tmp_path, knowledge, _SOFTWARE_RULE, review=review)
        assert _mapping_types(result) == {"T1003.001": "attack-pattern"}
        assert _outcome(result)["ignored_software_tags"] == ["attack.s0002"]


def test_rejected_software_tag_is_not_evidence(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    review = [{"sigma_id": _RULE_ID, "tag": "attack.s0002", "decision": "reject", "reason": "x"}]
    result = _import(tmp_path, knowledge, _SOFTWARE_RULE, review=review)
    assert _mapping_types(result) == {"T1003.001": "attack-pattern"}


def test_accepted_software_tag_maps_to_software(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    review = [{"sigma_id": _RULE_ID, "tag": "attack.s0002", "decision": "accept", "reason": "x"}]
    result = _import(tmp_path, knowledge, _SOFTWARE_RULE, review=review)
    types = _mapping_types(result)
    assert types["T1003.001"] == "attack-pattern"
    assert types["S0002"] in {"malware", "tool"}
    assert _outcome(result)["ignored_software_tags"] == []


def test_acceptance_is_per_rule(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    other = _rule_yaml(
        "sel:\n  Image|endswith: '\\b.exe'\ncondition: sel",
        rule_id="22222222-2222-2222-2222-222222222222",
        tags=("attack.t1003.001", "attack.s0002"),
    )
    review = [{"sigma_id": _RULE_ID, "tag": "attack.s0002", "decision": "accept", "reason": "x"}]
    result = _import(tmp_path, knowledge, _SOFTWARE_RULE, other, review=review)
    by_rule = {
        r["rule_family"]: {m["external_id"] for m in r["technique_mappings"]}
        for r in result.pack["rules"]
    }
    assert by_rule[f"sigma:{_RULE_ID}"] == {"T1003.001", "S0002"}
    assert by_rule["sigma:22222222-2222-2222-2222-222222222222"] == {"T1003.001"}


@pytest.mark.parametrize(
    ("decisions", "match"),
    [
        (
            [
                {"sigma_id": "a", "tag": "attack.s0002", "decision": "accept", "reason": "x"},
                {"sigma_id": "a", "tag": "attack.s0002", "decision": "reject", "reason": "y"},
            ],
            "duplicate",
        ),
        ([{"sigma_id": "a", "tag": "attack.s0002", "decision": "maybe", "reason": "x"}], "accept"),
        ([{"sigma_id": "a", "tag": "attack.s0002", "decision": "accept", "reason": " "}], "reason"),
    ],
)
def test_review_file_fails_closed(
    tmp_path: Path, decisions: list[dict[str, str]], match: str
) -> None:
    path = tmp_path / "review.json"
    path.write_text(json.dumps({"decisions": decisions}), encoding="utf-8")
    with pytest.raises(SigmaImportError, match=match):
        load_software_tag_review(path)


def test_real_review_covers_every_imported_software_tag_and_is_applied() -> None:
    """Completeness: every software tag on an imported rule of this release has
    a reviewed decision with a reason, and the pack carries exactly the accepted ones."""
    review = json.loads(REVIEW_PATH.read_text(encoding="utf-8"))
    decided = {(d["sigma_id"], d["tag"]) for d in review["decisions"]}
    assert all(d["reason"].strip() for d in review["decisions"])
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    for row in report["rules"]:
        if row["status"] == "rejected":
            continue
        for tag in row["ignored_software_tags"]:
            assert (row["sigma_id"], tag) in decided, (row["title"], tag)
    accepted = {(d["sigma_id"], d["tag"]) for d in review["decisions"] if d["decision"] == "accept"}
    pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
    in_pack = {
        (r["rule_family"].removeprefix("sigma:"), "attack." + m["external_id"].lower())
        for r in pack["rules"]
        for m in r["technique_mappings"]
        if m["object_type"] != "attack-pattern"
    }
    assert in_pack == accepted
    assert len(accepted) == 14  # + WCE wceaux.dll, SDelete (batch A); PSEXESVC.exe (enrich tier)


# ===========================================================================
# Inputs, determinism, loadability
# ===========================================================================


def test_archive_hash_mismatch_fails_closed(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    archive = tmp_path / "rules.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("r.yml", _rule_yaml("sel:\n  Image: 'a'\ncondition: sel"))
    with pytest.raises(SigmaImportError, match="does not match"):
        import_sigma_archive(archive, knowledge=knowledge, release_tag="t", archive_sha256="0" * 64)


def test_small_import_is_deterministic_and_loadable(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    rules = (
        _rule_yaml("sel:\n  Image|endswith: ['\\b.exe', '\\a.exe']\ncondition: sel"),
        _rule_yaml(
            "sel:\n  CommandLine|contains: 'x'\ncondition: sel",
            rule_id="00000000-0000-0000-0000-000000000000",
        ),
    )
    first = _import(tmp_path, knowledge, *rules)
    second = _import(tmp_path, knowledge, *reversed(rules))
    # The archives differ only in member order (so their recorded SHA-256
    # differs, as do the positional file names); the generated rules must not.
    assert first.pack["rules"] == second.pack["rules"]
    assert first.report["summary"] == second.report["summary"]
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(first.pack), encoding="utf-8")
    assert len(load_rule_pack(path, knowledge=knowledge).rules) == 3


# ===========================================================================
# The real pinned archive and committed generated artifacts
# ===========================================================================


def test_vendored_archive_matches_manifest_hash() -> None:
    assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() == MANIFEST["artifact"]["sha256"]


def _render(data: dict[str, Any]) -> str:
    """Exactly scripts/import_sigma_rules.py's serialization."""
    return json.dumps(data, indent=1, ensure_ascii=False) + "\n"


def test_committed_pack_and_report_regenerate_byte_identically(
    knowledge: AttackKnowledge,
) -> None:
    enrich = json.loads(ENRICH_MANIFEST_PATH.read_text(encoding="utf-8"))
    result = import_sigma_archive(
        ARCHIVE,
        knowledge=knowledge,
        release_tag="r2026-07-01",
        archive_sha256=MANIFEST["artifact"]["sha256"],
        software_tag_review=REVIEW_PATH,
        enrich_archive=ARCHIVE.parent / enrich["artifact"]["filename"],
        enrich_archive_sha256=enrich["artifact"]["sha256"],
    )
    assert _render(result.pack) == PACK_PATH.read_text(encoding="utf-8")
    assert _render(result.report) == REPORT_PATH.read_text(encoding="utf-8")


def _obs(observation_id: str, **entities: Any) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        **entities,
    )


def test_real_pack_fires_on_true_positive_with_drl_attribution(
    knowledge: AttackKnowledge,
) -> None:
    pack = load_rule_pack(PACK_PATH, knowledge=knowledge)
    obs = _obs(
        "o1",
        event=EventMetadata(kind="event", category=("process",), type=("start",)),
        process=ProcessRef(
            executable="C:\\Windows\\System32\\WHOAMI.EXE", command_line="whoami /all"
        ),
    )
    whoami_source = "sigma:c248c896-e412-4279-8c15-1c558067b6fa"
    rules = tuple(r for r in pack.rules if r.rule_source == whoami_source)
    (detection,) = DetectionEngine(rules=rules).evaluate([obs])
    (evidence,) = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
    assert evidence.attack_ref is not None and evidence.attack_ref.external_id == "T1033"
    assert "author: " in evidence.claim  # DRL 1.1: author carried into match output


def test_real_pack_scope_keeps_process_rules_off_network_events(
    knowledge: AttackKnowledge,
) -> None:
    pack = load_rule_pack(PACK_PATH, knowledge=knowledge)
    process_rules = tuple(
        r for r in pack.rules if r.rule_source == "sigma:c248c896-e412-4279-8c15-1c558067b6fa"
    )
    network_event = _obs(
        "o2",
        event=EventMetadata(kind="event", category=("network",), type=("connection", "start")),
        process=ProcessRef(executable="C:\\Windows\\System32\\whoami.exe", command_line="/all"),
        network=NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.1", port=443)),
    )
    assert DetectionEngine(rules=process_rules).evaluate([network_event]) == ()


def test_report_lists_every_archive_rule_with_a_link() -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    enrich = json.loads(ENRICH_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert report["summary"]["sigma_rules_total"] == (
        MANIFEST["archive_contents"]["yaml_rule_files"] + enrich["artifact"]["members"]
    )
    tiers = [row.get("content_tier", "core") for row in report["rules"]]
    assert tiers.count("enrich") == enrich["artifact"]["members"] == 224
    for row in report["rules"]:
        assert row["rule_url"].startswith("https://github.com/SigmaHQ/sigma/blob/r2026-07-01/")


def test_runtime_detection_never_imports_pysigma_or_importer() -> None:
    detection_dir = REPO_ROOT / "src" / "attribution_platform" / "detection"
    for source in detection_dir.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not name.startswith("sigma"), source
                assert "detection_content" not in name, source
    probe = (
        "import sys, attribution_platform.detection, attribution_platform.detection_content; "
        "print(any(m == 'sigma' or m.startswith('sigma.') for m in sys.modules))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == "False"
