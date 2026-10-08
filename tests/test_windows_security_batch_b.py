"""Windows Security log adapter — batch B (ADR-0008).

Golden tests on one real record per newly supported event
(``data/telemetry-samples/otrf-compound/golden-records.jsonl``, extracted by
``scripts/extract_golden_records.py`` from the OTRF APT3 CALDERA / Empire and
APT29 recordings, in all three record shapes): conversion, exact field
mapping, fail-closed cases, persistence round-trip, the field-map event-code
guard, and detection.

Detection on the 26 unmodified real records raises exactly one detection —
Password Policy Enumerated (T1201) on a 4661 SAM-domain handle opened in the
CALDERA APT3 run's user session during its documented discovery phases —
pinned below. That the new rules fire is otherwise proven on real records with
one clearly labelled field changed, each checked against its unmodified form.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient, load_observation, persist_observation
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain import Observation
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "golden-records.jsonl"
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
SIGMA_PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
ADAPTER = WindowsSecuritySourceAdapter()
ROWS = [json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines()]
RECORDS: dict[str, dict[str, Any]] = {row["golden_id"]: row["record"] for row in ROWS}
BATCH_B = sorted(g for g in RECORDS if g.startswith("b-"))

#: golden id -> the ``event.action`` batch B assigns.
ACTIONS = {
    "b-4611": "logon_process_registered",
    "b-4625": "logon_failed",
    "b-4648": "explicit_credential_logon",
    "b-4648-nxlog": "explicit_credential_logon",
    "b-4657": "registry_value_modified",
    "b-4661": "object_handle_request_directory",
    "b-4662": "directory_object_operation",
    "b-4672": "special_privileges_assigned",
    "b-4673": "privileged_service_called",
    "b-4674": "privileged_object_operation",
    "b-4697": "service_installed",
    "b-4697-apt29": "service_installed",
    "b-4698": "scheduled_task_created",
    "b-4702": "scheduled_task_updated",
    "b-4720": "user_account_created",
    "b-4722": "user_account_enabled",
    "b-4724": "password_reset_attempted",
    "b-4728": "member_added_to_global_group",
    "b-4732": "member_added_to_local_group",
    "b-4738": "user_account_changed",
    "b-4768": "kerberos_tgt_request",
    "b-4769": "kerberos_service_ticket_request",
    "b-4771": "kerberos_preauth_failed",
    "b-5379": "credential_manager_read",
    "b-5441": "wfp_filter_present",
    "b-5447": "wfp_filter_changed",
}


def _data(record: dict[str, Any]) -> dict[str, Any]:
    """The event fields of a record in any of the three shapes."""
    if "winlog" in record:
        return dict(record["winlog"]["event_data"])
    if "event_data" in record:
        return dict(record["event_data"])
    return record


def _with(golden_id: str, **changes: str) -> dict[str, Any]:
    """A copy of a real golden record with named event fields changed."""
    record: dict[str, Any] = json.loads(json.dumps(RECORDS[golden_id]))
    target = (
        record["winlog"]["event_data"] if "winlog" in record else record.get("event_data", record)
    )
    target.update(changes)
    return record


def _convert(golden_id: str) -> Observation:
    (obs,) = ADAPTER.to_observations(RECORDS[golden_id])
    return obs


@pytest.fixture(scope="module")
def engine() -> DetectionEngine:
    pack = load_rule_pack(SIGMA_PACK, knowledge=load_attack_knowledge())
    return DetectionEngine(rules=pack.rules)


def _fired(engine: DetectionEngine, record: dict[str, Any]) -> dict[str, set[str]]:
    (obs,) = ADAPTER.to_observations(record)
    return {
        d.rule_ref.rule_id.rsplit(":", 1)[0]: {
            m.attack_ref.external_id for m in d.technique_mappings if m.attack_ref.external_id
        }
        for d in engine.evaluate([obs])
    }


# ===========================================================================
# Conversion and exact fields
# ===========================================================================


def test_every_batch_b_event_has_a_real_golden_record() -> None:
    assert sorted(ACTIONS) == BATCH_B


@pytest.mark.parametrize("golden_id", BATCH_B)
def test_real_record_converts(golden_id: str) -> None:
    obs = _convert(golden_id)
    assert obs.event is not None and obs.event.action == ACTIONS[golden_id]
    assert obs.event.dataset == "system.security"
    assert obs.event.code == golden_id.split("-")[1]
    assert obs.host is not None and obs.host.name and obs.host.name != "WECserver"
    assert obs.timestamp.tzinfo is not None


def test_kerberos_service_ticket_fields() -> None:
    obs = _convert("b-4769")
    assert obs.service is not None and obs.kerberos is not None and obs.logon is not None
    assert (obs.service.name, obs.service.id) == (
        "HFDC01$",
        "S-1-5-21-1335669728-3348681605-2758348201-1008",
    )
    assert obs.kerberos.ticket_encryption_type == "0x12"
    assert obs.kerberos.ticket_options == "0x40800000"
    assert obs.logon.status == "0x0"
    assert obs.target_user is not None and obs.target_user.name == "pgustavo@SHIRE.COM"
    assert obs.network is not None and obs.network.source is not None
    assert obs.network.source.ip == "::ffff:172.18.39.105"


def test_kerberos_failure_keeps_its_status_and_client_sid() -> None:
    obs = _convert("b-4771")
    assert obs.logon is not None and obs.logon.status == "0x18"
    assert obs.target_user is not None
    assert obs.target_user.id == "S-1-5-21-2511471446-1103646877-3980648787-1107"


def test_real_apt29_service_install_fields() -> None:
    """The APT29 day-1 persistence service, exactly as logged (NXLog flat)."""
    obs = _convert("b-4697-apt29")
    assert obs.service is not None
    assert obs.service.name == "javamtsup"
    assert obs.service.file_name == "C:\\Windows\\System32\\javamtsup.exe"
    assert (obs.service.type, obs.service.start_type, obs.service.account) == (
        "0x10",
        "2",
        "LocalSystem",
    )
    assert obs.logon is not None and obs.logon.subject_logon_id == "0x372e81"
    assert obs.process is None  # this Windows build logs no ClientProcessId


def test_directory_service_properties_are_kept_verbatim() -> None:
    obs = _convert("b-4661")
    assert obs.object_access is not None
    assert obs.object_access.type == "SAM_DOMAIN"
    data = _data(RECORDS["b-4661"])
    assert obs.object_access.properties == data["Properties"]
    assert obs.object_access.access_list == data["AccessList"]
    assert obs.process is not None and obs.process.pid == 0x30C


def test_registry_value_change_fields() -> None:
    obs = _convert("b-4657")
    data = _data(RECORDS["b-4657"])
    assert obs.object_access is not None
    assert obs.object_access.old_value == data["OldValue"]
    assert obs.object_access.operation_type == data["OperationType"]
    assert obs.object_access.old_value_type == data["OldValueType"]


def test_account_management_fields() -> None:
    created = _convert("b-4720")
    assert created.account_change is not None
    assert created.account_change.sam_account_name == "toby"
    assert (created.account_change.old_uac_value, created.account_change.new_uac_value) == (
        "0x0",
        "0x15",
    )
    added = _convert("b-4732")
    assert added.target_user is not None and added.target_user.id == "S-1-5-32-545"
    assert added.account_change is not None
    assert added.account_change.member_sid == "S-1-5-21-3790546881-876066702-777742360-1000"


def test_scheduled_task_fields() -> None:
    created, updated = _convert("b-4698"), _convert("b-4702")
    assert created.scheduled_task is not None and updated.scheduled_task is not None
    assert created.scheduled_task.name == "\\Resume Viewer Update Checker"
    assert (created.scheduled_task.content or "").startswith("<?xml")
    assert updated.scheduled_task.content is None
    assert (updated.scheduled_task.content_new or "").startswith("<?xml")


def test_privilege_and_explicit_credential_fields() -> None:
    privileges = _convert("b-4672")
    assert privileges.privilege is not None
    assert "SeBackupPrivilege" in (privileges.privilege.privilege_list or "")
    explicit = _convert("b-4648-nxlog")
    assert explicit.logon is not None
    assert (explicit.logon.target_server_name, explicit.logon.target_info) == (
        "NASHUA",
        "cifs/NASHUA",
    )


def test_wfp_filter_user_is_the_logged_sid_only() -> None:
    obs = _convert("b-5447")
    assert obs.wfp_filter is not None and obs.wfp_filter.name == "Interface Un-quarantine filter"
    assert obs.user is not None and (obs.user.id, obs.user.name) == ("S-1-5-19", None)


def test_credential_manager_read_fields() -> None:
    obs = _convert("b-5379")
    assert obs.credential_read is not None
    assert obs.credential_read.target_name == (
        "WindowsLive:(token):name=02hvamfdrqlrjifi;serviceuri=*"
    )
    assert obs.process is not None and obs.process.pid == 8736  # decimal ClientProcessId


def test_hex_client_process_id_fails_closed() -> None:
    with pytest.raises(SourceAdapterError, match="decimal process id"):
        ADAPTER.to_observations(_with("b-5379", ClientProcessId="0x2220"))


@pytest.mark.parametrize("golden_id", BATCH_B)
def test_observation_round_trips_through_persistence(golden_id: str) -> None:
    obs = _convert(golden_id)
    client = FakeElasticClient()
    persist_observation(client, obs)
    assert load_observation(client, obs.observation_id) == obs


# ===========================================================================
# Detection
# ===========================================================================


def test_unmodified_real_records_raise_only_the_discovery_detection(
    engine: DetectionEngine,
) -> None:
    fired = {g: _fired(engine, RECORDS[g]) for g in BATCH_B}
    assert {g: f for g, f in fired.items() if f} == {
        "b-4661": {"sigma:12ba6a38-adb3-4d6b-91ba-a7fb248e3199": {"T1201"}},
        # enrich tier (LOW quality, ADR-0007 Amendment A): the APT29 day-2 account
        # creation and group membership of "toby" by kmalone
        "b-4720": {"sigma:66b6be3d-55d0-4f47-9855-d69df21740ea": {"T1136.001"}},
        "b-4728": {"sigma:c43c26be-2e87-46c7-8661-284588c5a53e": {"T1098"}},
    }


@pytest.mark.parametrize(
    ("golden_id", "changes", "rule", "technique"),
    [
        # Kerberoasting: an RC4 service ticket for a user-account SPN
        (
            "b-4769",
            {"TicketEncryptionType": "0x17", "ServiceName": "svc_sql"},
            "d04ae2b8-ad54-4de0-bd87-4bc1da66aa59",
            "T1558.003",
        ),
        # DCSync: the replication extended right requested by a user account
        (
            "b-4662",
            {
                "AccessMask": "0x100",
                "Properties": "%%7688\n{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
                "SubjectUserName": "pgustavo",
            },
            "611eab06-a145-4dfa-a295-3ccc5c20f59a",
            "T1003.006",
        ),
        # a remote-access product installed as a service
        (
            "b-4697-apt29",
            {"ServiceName": "TeamViewer"},
            "c8b00925-926c-47e3-beea-298fd563728e",
            "T1543.003",
        ),
        # a local account created with a trailing '$'
        (
            "b-4720",
            {"TargetUserName": "toby$"},
            "7b449a5e-1db5-4dd0-a2dc-4e3a67282538",
            "T1136.001",
        ),
        # the member added to Administrators instead of Users
        (
            "b-4732",
            {"TargetSid": "S-1-5-32-544", "TargetUserName": "Administrators"},
            "c265cf08-3f99-46c1-8d59-328247057d57",
            "T1098",
        ),
        # Rubeus's logon-process name
        (
            "b-4611",
            {"LogonProcessName": "User32LogonProcesss"},
            "12e6d621-194f-4f59-90cc-1959e21e69f7",
            "T1558.003",
        ),
        # a failed logon to an expired account
        ("b-4625", {"Status": "0xC0000072"}, "9eb99343-d336-4020-a3cd-67f3819e68ee", "T1078"),
        # EDRSilencer's filter name
        (
            "b-5447",
            {"FilterName": "Custom Outbound Filter"},
            "98054878-5eab-434c-85d4-72d4e5a3361b",
            "T1685",
        ),
    ],
)
def test_modified_real_record_fires_and_the_real_one_does_not(
    engine: DetectionEngine,
    golden_id: str,
    changes: dict[str, str],
    rule: str,
    technique: str,
) -> None:
    fired = _fired(engine, _with(golden_id, **changes))
    assert technique in fired[f"sigma:{rule}"]
    assert f"sigma:{rule}" not in _fired(engine, RECORDS[golden_id])


def test_dcsync_by_a_machine_account_is_filtered(engine: DetectionEngine) -> None:
    record = _with(
        "b-4662",
        AccessMask="0x100",
        Properties="{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
        SubjectUserName="HFDC02$",
    )
    assert "sigma:611eab06-a145-4dfa-a295-3ccc5c20f59a" not in _fired(engine, record)


def test_untranslatable_rules_stay_gaps_not_coverage() -> None:
    """PetitPotam's filter compares CertThumbprint with the empty string and
    the UAC rule uses single-character wildcards: neither is approximated —
    a dropped negated filter would widen the rule."""
    report = json.loads(
        (GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json").read_text(
            encoding="utf-8"
        )
    )
    rows = {r["sigma_id"]: r for r in report["rules"]}
    petitpotam = rows["6a53d871-682d-40b6-83e0-b7c1a6c4e3a5"]
    assert petitpotam["status"] == "rejected"
    assert "translation_gap:interior_wildcard_or_empty" in petitpotam["gap_reasons"]
    assert rows["f6de9536-0441-4b3f-a646-f4e00f300ffd"]["status"] == "rejected"
