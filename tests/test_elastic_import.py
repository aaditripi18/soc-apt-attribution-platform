"""Elastic prebuilt-rule importer (ADR-0015): exact translation or a named gap.

Rules here are small TOML documents in Elastic's own rule format, imported through
the public entry point, loaded by the ordinary rule-pack loader and evaluated on
Observations the Sysmon / Windows Security adapters make from raw events.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.elastic_field_map import (
    SYSMON_PROFILES,
    applies_to_sysmon,
)
from attribution_platform.detection_content.elastic_import import (
    ElasticImportError,
    import_elastic_rules,
)
from attribution_platform.domain import Observation
from attribution_platform.sources.sysmon import SysmonSourceAdapter
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter

BS = chr(92)
SYSMON_INDEX = '["logs-endpoint.events.process-*", "logs-windows.sysmon_operational-*"]'


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _toml(
    rule_id: str,
    query: str,
    *,
    rule_type: str = "eql",
    language: str = "eql",
    index: str = SYSMON_INDEX,
    severity: str = "medium",
    technique: str = "T1033",
    subtechnique: str | None = None,
    extra: str = "",
) -> str:
    sub = (
        f'\n[[rule.threat.technique.subtechnique]]\nid = "{subtechnique}"\n'
        f'name = "sub"\nreference = "https://attack.mitre.org/"\n'
        if subtechnique
        else ""
    )
    return (
        '[metadata]\nmaturity = "production"\n\n[rule]\n'
        f'author = ["Elastic"]\nname = "Rule {rule_id}"\nrule_id = "{rule_id}"\n'
        f'type = "{rule_type}"\nlanguage = "{language}"\nindex = {index}\n'
        f'severity = "{severity}"\nversion = 3\n{extra}'
        f"query = '''\n{query}\n'''\n\n"
        '[[rule.threat]]\nframework = "MITRE ATT&CK"\n'
        '[rule.threat.tactic]\nid = "TA0007"\nname = "Discovery"\n'
        'reference = "https://attack.mitre.org/"\n'
        f'[[rule.threat.technique]]\nid = "{technique}"\nname = "t"\n'
        f'reference = "https://attack.mitre.org/"\n{sub}'
    )


def _import(
    tmp_path: Path, knowledge: AttackKnowledge, rules: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any], DetectionEngine]:
    files = []
    for name, text in rules.items():
        path = tmp_path / "cache" / "rules" / "windows" / f"{name}.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        files.append(
            {
                "path": f"rules/windows/{name}.toml",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"source": "test", "source_commit": "0" * 40, "files": files}),
        encoding="utf-8",
    )
    result = import_elastic_rules(tmp_path / "cache", manifest, knowledge=knowledge)
    engine = DetectionEngine(rules=())
    if result.pack["rules"]:  # the loader refuses an empty pack
        pack_path = tmp_path / "pack.json"
        pack_path.write_text(json.dumps(result.pack), encoding="utf-8")
        engine = DetectionEngine(rules=load_rule_pack(pack_path, knowledge=knowledge).rules)
    return result.pack, {r["rule_id"]: r for r in result.report["rules"]}, engine


def _sysmon(event_id: int, **event_data: str) -> Observation:
    (observation,) = SysmonSourceAdapter().to_observations(
        {
            "@timestamp": "2026-01-01T00:00:00Z",
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": event_id,
                "record_id": 7,
                "computer_name": "host",
                "event_data": {"ProcessId": "10", **event_data},
            },
        }
    )
    return observation


def _fired(engine: DetectionEngine, observation: Observation) -> set[str]:
    return {d.rule_ref.rule_id.split(":")[1] for d in engine.evaluate([observation])}


WHOAMI = "C:" + BS + "Windows" + BS + "System32" + BS + "whoami.exe"


def test_index_scope() -> None:
    assert applies_to_sysmon(("logs-windows.sysmon_operational-*",))
    assert applies_to_sysmon(("logs-windows.*",))
    assert not applies_to_sysmon(("logs-endpoint.events.process-*", "winlogbeat-*"))
    assert not applies_to_sysmon(("logs-*", "-logs-windows.sysmon_operational-*"))


def test_single_event_eql_imports_and_fires_exactly(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    query = (
        'process where host.os.type == "windows" and event.type == "start" and '
        'process.name : "WHOAMI.EXE" and process.args : "/all"'
    )
    pack, report, engine = _import(tmp_path, knowledge, {"r1": _toml("r1", query)})
    assert report["r1"]["status"] == "imported"
    # event.type "start" + category "process" hold for Sysmon 1 and 7 (Image loaded
    # is category [process, library], type [change, start] in Elastic's pipeline).
    assert report["r1"]["profiles"] == ["sysmon:1", "sysmon:7"]
    first = pack["rules"][0]
    assert first["conditions"][0] == {
        "field_path": "event.category",
        "operator": "has_element",
        "value": "process",
    }
    assert first["rule_family"] == "elastic:r1"
    assert {
        "field_path": "elastic_sysmon.process.args",
        "operator": "has_element",
        "value": "/all",
        "case_insensitive": True,
    } in first["conditions"]
    hit = _sysmon(1, Image=WHOAMI, CommandLine="whoami.exe /ALL")
    assert _fired(engine, hit) == {"r1"}
    assert _fired(engine, _sysmon(1, Image=WHOAMI, CommandLine="whoami.exe /groups")) == set()
    detection = engine.evaluate([hit])[0]
    assert [m.attack_ref.external_id for m in detection.technique_mappings] == ["T1033"]
    assert detection.detection_source == "elastic:r1"


def test_case_sensitive_operators_stay_case_sensitive(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    query = 'process where event.type == "start" and process.name == "whoami.exe"'
    _, _, engine = _import(tmp_path, knowledge, {"r2": _toml("r2", query)})
    assert _fired(engine, _sysmon(1, Image=WHOAMI)) == {"r2"}
    upper = "C:" + BS + "Windows" + BS + "WHOAMI.EXE"
    assert _fired(engine, _sysmon(1, Image=upper)) == set()


def test_constant_fields_are_decided_per_event(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    rules = {
        # Elastic's own action text for Sysmon 1: only the process-creation profile.
        "a": _toml("a", 'any where event.action == "Process creation" and process.name : "x.exe"'),
        # Elastic Defend's action value never occurs in a Sysmon document.
        "b": _toml("b", 'process where event.action == "exec" and process.name : "x.exe"'),
        # Defend-only fields are absent from Sysmon documents.
        "c": _toml("c", "process where process.code_signature.trusted == false"),
        "d": _toml(
            "d",
            'process where event.type == "start" and process.name : "x.exe" and '
            "not process.code_signature.trusted == true",
        ),
    }
    pack, report, _ = _import(tmp_path, knowledge, rules)
    assert report["a"]["profiles"] == ["sysmon:1"]
    assert report["b"]["rejection"] == "telemetry_gap"
    assert report["b"]["gap_reasons"] == {"event:no_supported_event_satisfies_scope": 1}
    assert report["c"]["gap_reasons"] == {"event:no_supported_event_satisfies_scope": 1}
    assert report["d"]["status"] == "imported"
    d_rule = next(r for r in pack["rules"] if r["rule_family"] == "elastic:d")
    assert all("code_signature" not in c["field_path"] for c in d_rule["conditions"])


def test_gaps_are_named_and_branches_never_broaden(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    query = (
        'process where event.type == "start" and '
        '(process.name : "a.exe" or (process.name : "b.exe" and user.id : "S-1-5-18") or '
        'process.command_line regex~ ".*x.*")'
    )
    pack, report, engine = _import(tmp_path, knowledge, {"p": _toml("p", query)})
    outcome = report["p"]
    assert outcome["status"] == "partial"
    assert outcome["gap_reasons"]["telemetry_gap:field:user.id"] >= 1
    assert outcome["gap_reasons"]["translation_gap:eql:regex"] >= 1
    a_exe = "C:" + BS + "a.exe"
    b_exe = "C:" + BS + "b.exe"
    assert _fired(engine, _sysmon(1, Image=a_exe)) == {"p"}
    assert _fired(engine, _sysmon(1, Image=b_exe)) == set()  # its branch was dropped


def test_rule_types_and_indices_outside_scope_are_rejected(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    rules = {
        "seq": _toml("seq", "sequence by host.id [process where true] [file where true]"),
        "nt": _toml("nt", 'process.name:"a"', rule_type="new_terms", language="kuery"),
        "endpoint": _toml(
            "endpoint", 'process where process.name : "a"', index='["logs-endpoint.events.*"]'
        ),
        "nomap": _toml("nomap", 'process where process.name : "a"', technique="T9999"),
    }
    _, report, _ = _import(tmp_path, knowledge, rules)
    assert report["seq"]["gap_reasons"] == {"rule_type:eql_sequence": 1}
    assert report["nt"]["gap_reasons"] == {"rule_type:new_terms/kuery": 1}
    assert report["endpoint"]["gap_reasons"] == {"index:no_supported_data_stream": 1}
    assert report["nomap"]["rejection"] == "no_attack_mapping"
    assert report["nomap"]["dropped_attack_ids"] == ["T9999"]


def test_kql_rules_and_array_fields(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    query = 'event.category:process and process.args:("-enc" or -EncodedCommand)'
    _, report, engine = _import(
        tmp_path,
        knowledge,
        {
            "k": _toml(
                "k",
                query,
                rule_type="query",
                language="kuery",
                technique="T1059",
                subtechnique="T1059.001",
            )
        },
    )
    assert report["k"]["attack_ids"] == ["T1059", "T1059.001"]
    ps = "C:" + BS + "p" + BS + "powershell.exe"
    assert _fired(engine, _sysmon(1, Image=ps, CommandLine='powershell.exe "-enc" AAAA')) == {"k"}
    # KQL on a keyword field is case-sensitive.
    assert _fired(engine, _sysmon(1, Image=ps, CommandLine="powershell.exe -ENC AAAA")) == set()


def test_tiers(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    q = 'process where event.type == "start" and process.name : "a.exe"'
    rules = {
        "core": _toml("core", q),
        "low": _toml("low", q, severity="low"),
        "bb": _toml("bb", q, extra='building_block_type = "default"\n'),
    }
    pack, report, _ = _import(tmp_path, knowledge, rules)
    quality = {r["rule_family"]: r.get("evidence_quality") for r in pack["rules"]}
    assert quality == {"elastic:core": None, "elastic:low": "low", "elastic:bb": "low"}
    assert report["bb"]["content_tier"] == "enrich"


def test_other_windows_sources_are_never_selected(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    query = 'process where event.type == "start" and process.name : "whoami.exe"'
    _, _, engine = _import(tmp_path, knowledge, {"s": _toml("s", query)})
    (security,) = WindowsSecuritySourceAdapter().to_observations(
        {
            "@timestamp": "2026-01-01T00:00:00Z",
            "winlog": {
                "channel": "Security",
                "event_id": 4688,
                "record_id": 8,
                "computer_name": "host",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "event_data": {
                    "NewProcessName": WHOAMI,
                    "NewProcessId": "0x10",
                    "ProcessId": "0x4",
                    "CommandLine": "whoami",
                },
            },
        }
    )
    assert security.process is not None and security.process.name == "whoami.exe"
    assert _fired(engine, security) == set()


def test_manifest_hash_is_enforced(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    path = tmp_path / "cache" / "rules" / "x.toml"
    path.parent.mkdir(parents=True)
    path.write_text(_toml("x", 'process where process.name : "a"'), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "source": "t",
                "source_commit": "0" * 40,
                "files": [{"path": "rules/x.toml", "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ElasticImportError, match="SHA-256"):
        import_elastic_rules(tmp_path / "cache", manifest, knowledge=knowledge)


def test_every_profile_selector_leads_with_the_engine_index_key() -> None:
    for profile in SYSMON_PROFILES:
        field, operator, _, negate = profile.selector[0]
        assert (field, operator, negate) == ("event.category", "has_element", False)


REPO = Path(__file__).resolve().parents[1]
ELASTIC_DIR = REPO / "data" / "detection" / "elastic"
GENERATED = ELASTIC_DIR / "195f15c0bac8" / "generated"


def test_tracked_pack_loads_and_matches_its_manifest(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(GENERATED / "elastic-195f15c0bac8.rules.json", knowledge=knowledge)
    assert pack.rules
    data = json.loads((GENERATED / "elastic-195f15c0bac8.rules.json").read_text(encoding="utf-8"))
    manifest = ELASTIC_DIR / "manifest.json"
    assert (
        data["provenance"]["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    )
    assert data["provenance"]["attack_kb_version"] == knowledge.attack_kb_version
    # Every condition reads either a profile selector field or a verified derived view.
    for rule in pack.rules:
        for condition in rule.conditions:
            assert condition.field_path.startswith(
                (
                    "elastic_",
                    "event.category",
                    "event.type",
                    "event.action",
                    "event.dataset",
                    "event.code",
                    "host.os_type",
                )
            ), condition.field_path


def test_tracked_pack_regenerates_byte_for_byte(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    manifest = json.loads((ELASTIC_DIR / "manifest.json").read_text(encoding="utf-8"))
    cache = REPO / "data" / "cache" / "elastic-detection-rules" / manifest["source_commit"][:12]
    if not cache.is_dir():
        pytest.skip("rule cache absent: run scripts/acquire_elastic_rules.py")
    result = import_elastic_rules(cache, ELASTIC_DIR / "manifest.json", knowledge=knowledge)
    for name, data in (("rules", result.pack), ("import-report", result.report)):
        text = json.dumps(data, indent=1, sort_keys=False, ensure_ascii=False) + "\n"
        tracked = (GENERATED / f"elastic-195f15c0bac8.{name}.json").read_text(encoding="utf-8")
        assert text == tracked, name


# --- further data streams (cloud audit logs, Windows Security) -----------------------


def _cloudtrail(**fields: Any) -> Observation:
    from attribution_platform.sources.cloudtrail import CloudTrailSourceAdapter

    record = {
        "eventVersion": "1.08",
        "eventTime": "2026-01-01T00:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "eventID": "e-1",
        "recipientAccountId": "111122223333",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/a"},
        **fields,
    }
    (observation,) = CloudTrailSourceAdapter().to_observations(record)
    return observation


def test_cloudtrail_rules_read_pipeline_faithful_fields(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    index = '["filebeat-*", "logs-aws.cloudtrail-*"]'
    rules = {
        "ct1": _toml(
            "ct1",
            "event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and "
            "event.action:CreateUser and event.outcome:success",
            rule_type="query",
            language="kuery",
            index=index,
            technique="T1136",
            subtechnique="T1136.003",
        ),
        "ct2": _toml(
            "ct2",
            'any where data_stream.dataset == "aws.cloudtrail" and event.action == "PutUserPolicy" '
            'and aws.cloudtrail.request_parameters like "*policyName=Admin*" and '
            'aws.cloudtrail.flattened.request_parameters.userName == "bob"',
            index=index,
            technique="T1098",
        ),
        "ct3": _toml(
            "ct3",
            'iam where event.dataset == "aws.cloudtrail" and event.action == "CreateUser"',
            index=index,
            technique="T1136",
        ),
    }
    pack, report, engine = _import(tmp_path, knowledge, rules)
    assert all(report[r]["status"] == "imported" for r in rules), report
    assert report["ct1"]["profiles"] == ["cloudtrail"]
    first = next(r for r in pack["rules"] if r["rule_family"] == "elastic:ct1")
    assert first["conditions"][0] == {
        "field_path": "event.dataset",
        "operator": "equals",
        "value": "aws.cloudtrail",
    }
    created = _cloudtrail(requestParameters={"userName": "bob"})
    assert _fired(engine, created) == {"ct1", "ct3"}  # CreateUser is category iam
    # A record with an error code is a failure in the CloudTrail pipeline.
    assert _fired(engine, _cloudtrail(errorCode="AccessDenied")) == {"ct3"}
    policy = _cloudtrail(
        eventName="PutUserPolicy",
        requestParameters={"userName": "bob", "policyName": "Admin", "policyDocument": "{}"},
    )
    assert _fired(engine, policy) == {"ct2"}
    other_user = _cloudtrail(
        eventName="PutUserPolicy", requestParameters={"userName": "eve", "policyName": "Admin"}
    )
    assert _fired(engine, other_user) == set()
    assert _fired(engine, _sysmon(1, Image=WHOAMI)) == set()


def test_always_present_array_members_decide_only_themselves(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    index = '["logs-o365.audit-*"]'
    rules = {
        # Every O365 record is event.category "web" in the O365 pipeline: decided.
        "web": _toml(
            "web",
            "event.dataset:o365.audit and event.category:web and event.action:New-InboxRule",
            rule_type="query",
            language="kuery",
            index=index,
            technique="T1564",
        ),
        # Any other category depends on the audit schema: a named gap, not a guess.
        "auth": _toml(
            "auth",
            "event.dataset:o365.audit and event.category:authentication",
            rule_type="query",
            language="kuery",
            index=index,
            technique="T1078",
        ),
    }
    _, report, _ = _import(tmp_path, knowledge, rules)
    assert report["web"]["status"] == "imported"
    assert report["auth"]["gap_reasons"] == {"translation_gap:undetermined:event.category": 1}


def test_security_4688_rules_use_the_security_pipeline_semantics(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    index = '["logs-system.security*", "logs-windows.sysmon_operational-*"]'
    query = (
        'process where host.os.type == "windows" and event.type == "start" and '
        '(process.name : "net.exe" or process.pe.original_file_name == "net.exe") and '
        'process.args : "user"'
    )
    pack, report, engine = _import(tmp_path, knowledge, {"n": _toml("n", query, index=index)})
    assert report["n"]["status"] == "imported"
    assert "security:4688" in report["n"]["profiles"] and "sysmon:1" in report["n"]["profiles"]
    security_rules = [r for r in pack["rules"] if ":security:4688:" in r["rule_id"]]
    # The PE branch is decided false for 4688 (the Security pipeline sets no PE data).
    assert len(security_rules) == 1
    assert all("pe." not in c["field_path"] for c in security_rules[0]["conditions"])
    net = "C:" + BS + "Windows" + BS + "System32" + BS + "net.exe"

    def security(command_line: str) -> Observation:
        (observation,) = WindowsSecuritySourceAdapter().to_observations(
            {
                "@timestamp": "2026-01-01T00:00:00Z",
                "winlog": {
                    "channel": "Security",
                    "event_id": 4688,
                    "record_id": 9,
                    "computer_name": "host",
                    "provider_name": "Microsoft-Windows-Security-Auditing",
                    "event_data": {
                        "NewProcessName": net,
                        "NewProcessId": "0x10",
                        "ProcessId": "0x4",
                        "CommandLine": command_line,
                    },
                },
            }
        )
        return observation

    assert _fired(engine, security("net user /add x")) == {"n"}
    # The Security pipeline keeps the quotes in process.args: no element is "user".
    assert _fired(engine, security('net "user" /add x')) == set()
    # The Sysmon pipeline strips them, so the same command line matches there.
    assert _fired(engine, _sysmon(1, Image=net, CommandLine='net "user" /add x')) == {"n"}
