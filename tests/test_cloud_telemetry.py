"""Cloud batches A–C: Entra ID (Azure Monitor diagnostic export), Office 365
(Management Activity API), AWS CloudTrail (native), Azure Activity (REST form),
Okta System Log, GitHub audit log and Kubernetes audit adapters, logsources and
the product scopes (ADR-0011).

Golden tests on real records from ``splunk/attack_data`` (Apache-2.0,
``splunk-attack-data-cloud/golden-records.jsonl``): exact fields and the
documented event time per category, refusals (unsupported categories, a time
without a zone, an impossible time), the pipeline routing, detection through
the production pack, the D4 product scope in both directions, persistence
round-trips, and the whole-cache report.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane.persistence import _observation_from_document
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.sigma_field_map import (
    FIELD_MAPS,
    LOGSOURCE_SCOPES,
    PRODUCT_OS_SCOPES,
)
from attribution_platform.domain import CloudRef, Observation, TimePrecision, to_serializable
from attribution_platform.replay.recording_pipeline import (
    AZURE_ACTIVITY_CHANNEL,
    CLOUDTRAIL_CHANNEL,
    DEFAULT_CHANNEL_ADAPTERS,
    ENTRA_CHANNEL,
    GITHUB_CHANNEL,
    KUBERNETES_AUDIT_CHANNEL,
    O365_CHANNEL,
    OKTA_CHANNEL,
    _channel,
)
from attribution_platform.sources.adapter import SourceAdapter
from attribution_platform.sources.azure_activity import AzureActivitySourceAdapter
from attribution_platform.sources.cloudtrail import CloudTrailSourceAdapter
from attribution_platform.sources.entra import EntraIdSourceAdapter
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.github_audit import GitHubAuditSourceAdapter
from attribution_platform.sources.kubernetes_audit import KubernetesAuditSourceAdapter
from attribution_platform.sources.o365 import O365SourceAdapter
from attribution_platform.sources.okta import OktaSourceAdapter
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples"
CLOUD = SAMPLES / "splunk-attack-data-cloud"
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
IMPORT_REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"
RECORDS: dict[str, dict[str, Any]] = {
    row["golden_id"]: json.loads(row["record"])
    for row in (
        json.loads(line)
        for line in (CLOUD / "golden-records.jsonl").read_text(encoding="utf-8").splitlines()
    )
}
ENTRA, O365, TRAIL = EntraIdSourceAdapter(), O365SourceAdapter(), CloudTrailSourceAdapter()
ADAPTERS: dict[str, SourceAdapter] = {
    "entra": ENTRA,
    "o365": O365,
    "aws": TRAIL,
    "azure": AzureActivitySourceAdapter(),
    "okta": OktaSourceAdapter(),
    "github": GitHubAuditSourceAdapter(),
    "k8s": KubernetesAuditSourceAdapter(),
}
CHANNELS = {
    "entra": ENTRA_CHANNEL,
    "o365": O365_CHANNEL,
    "aws": CLOUDTRAIL_CHANNEL,
    "azure": AZURE_ACTIVITY_CHANNEL,
    "okta": OKTA_CHANNEL,
    "github": GITHUB_CHANNEL,
    "k8s": KUBERNETES_AUDIT_CHANNEL,
}
#: golden-id prefix -> the one Sigma product allowed to fire on it.
PRODUCTS = {
    "entra": "azure",
    "o365": "m365",
    "aws": "aws",
    "azure": "azure",
    "okta": "okta",
    "github": "github",
    "k8s": "kubernetes",
}
REFUSED = {"entra-graph-activity", "entra-risky-user", "o365-invalid-time", "aws-ocsf"}


def _convert(golden_id: str, record: Mapping[str, Any] | None = None) -> Observation:
    adapter = ADAPTERS[golden_id.split("-")[0]]
    (obs,) = adapter.to_observations(record if record is not None else RECORDS[golden_id])
    return obs


@pytest.fixture(scope="module")
def engine() -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(PACK, knowledge=load_attack_knowledge()).rules)


@pytest.fixture(scope="module")
def products() -> dict[str, str]:
    rows = json.loads(IMPORT_REPORT.read_text(encoding="utf-8"))["rules"]
    return {r["sigma_id"]: r["logsource"].split("/")[0] for r in rows}


def _fired(engine: DetectionEngine, observations: list[Observation]) -> set[str]:
    return {
        m.attack_ref.external_id
        for d in engine.evaluate(observations)
        for m in d.technique_mappings
        if m.attack_ref.external_id
    }


def _fired_products(
    engine: DetectionEngine, products: dict[str, str], observations: list[Observation]
) -> set[str]:
    return {products[d.rule_ref.rule_id.split(":")[1]] for d in engine.evaluate(observations)}


# ===========================================================================
# Entra ID: exact fields, documented event time per category
# ===========================================================================


def test_interactive_sign_in_is_exact() -> None:
    obs = _convert("entra-signin")
    tenant = "fc69e276-e9e8-4af9-9002-1e410d77244e"
    assert obs.observation_id == f"entra:{tenant}:SignInLogs:8ea54432-1fc4-4266-a632-ba8a664c4b00"
    # properties.createdDateTime (sign-in initiated), not the export's later ``time``
    assert obs.timestamp == datetime(2023, 7, 24, 20, 57, 43, 134260, tzinfo=UTC)
    assert obs.timestamp_precision is TimePrecision.MICROSECOND
    assert obs.event is not None
    assert (obs.event.dataset, obs.event.action, obs.event.outcome) == (
        "azure.signinlogs",
        "Sign-in activity",
        "success",
    )
    assert obs.user is not None
    assert (obs.user.id, obs.user.name) == (
        "3bd47e42-37c9-442f-a2b4-f04de61ef0ce",
        "strt_admin@splunkresearch.com",
    )
    assert obs.network is not None and obs.network.source is not None
    assert obs.network.source.ip == "72.43.121.35"
    assert obs.user_agent is not None and obs.user_agent.original is not None
    assert obs.user_agent.original.endswith("Chrome/114.0.0.0 Safari/537.36")
    assert obs.cloud == CloudRef(provider="azure", account_id=tenant)
    assert obs.host is None and obs.process is None
    entra = obs.entra
    assert entra is not None
    assert (entra.log_category, entra.result_type, entra.authentication_requirement) == (
        "SignInLogs",
        "0",
        "singleFactorAuthentication",
    )
    assert (entra.app_display_name, entra.resource_display_name) == (
        "Azure Portal",
        "Windows Azure Service Management API",
    )
    assert entra.audit_category is None


def test_failed_mfa_sign_in_keeps_result_type_and_description() -> None:
    entra = _convert("entra-signin-mfa-interrupted").entra
    assert entra is not None
    assert entra.result_type == "500121"
    assert entra.result_description == "Authentication failed during strong authentication request."
    assert _convert("entra-signin-mfa-interrupted").event.outcome == "failure"  # type: ignore[union-attr]


def test_non_interactive_and_service_principal_sign_ins() -> None:
    noninteractive = _convert("entra-signin-noninteractive")
    assert noninteractive.event is not None
    assert noninteractive.event.dataset == "azure.signinlogs"
    principal = _convert("entra-signin-service-principal")
    assert principal.user is None  # a service principal is not a user (no userId / UPN)
    assert principal.entra is not None
    assert principal.entra.app_id == "2f7d225e-ae9b-478c-842b-1716c08f3384"


def test_audit_record_is_exact() -> None:
    obs = _convert("entra-audit-security-info")
    assert obs.timestamp == datetime(2023, 10, 31, 17, 59, 20, 811596, tzinfo=UTC)
    assert obs.event is not None
    assert (obs.event.dataset, obs.event.outcome) == ("azure.auditlogs", "success")
    assert obs.user is not None  # properties.initiatedBy.user
    assert obs.user.name == "user15@splunkresearch.onmicrosoft.com"
    entra = obs.entra
    assert entra is not None
    assert entra.audit_category == "UserManagement"  # properties.category, not "AuditLogs"
    assert entra.log_category == "AuditLogs"
    assert (entra.operation_name, entra.logged_by_service, entra.result) == (
        "User registered security info",
        "Authentication Methods",
        "success",
    )


def test_risk_event_uses_the_activity_time() -> None:
    """The export's ``time`` here is ``8/2/2023 1:08:44 PM`` (no zone); the
    adapter reads ``properties.activityDateTime`` — when the risky activity
    happened — which is ISO 8601 and zoned."""
    obs = _convert("entra-risk-event")
    assert RECORDS["entra-risk-event"]["time"] == "8/2/2023 1:08:44 PM"
    assert obs.timestamp == datetime(2023, 8, 1, 19, 55, 29, 638000, tzinfo=UTC)
    assert obs.timestamp_precision is TimePrecision.MILLISECOND
    assert obs.event is not None and obs.event.dataset == "azure.identity_protection"
    assert obs.entra is not None
    assert (obs.entra.risk_event_type, obs.entra.risk_level) == ("maliciousIPAddress", "high")


@pytest.mark.parametrize("golden_id", ["entra-graph-activity", "entra-risky-user"])
def test_categories_without_a_logsource_are_refused(golden_id: str) -> None:
    with pytest.raises(SourceAdapterError, match="is not supported"):
        _convert(golden_id)


def _with_props(golden_id: str, **changes: Any) -> dict[str, Any]:
    record = dict(RECORDS[golden_id])
    record["properties"] = {**record["properties"], **changes}
    return record


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"createdDateTime": "2023-07-24T20:57:43.1342605"}, "has no zone"),
        ({"createdDateTime": "7/24/2023 8:57:43 PM"}, "not ISO 8601"),
        ({"createdDateTime": None}, "is missing"),
        ({"id": None}, "properties.id are required"),
        ({"appId": {"nested": 1}}, "expected a scalar"),
    ],
)
def test_entra_records_fail_closed(changes: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        _convert("entra-signin", _with_props("entra-signin", **changes))


def test_entra_booleans_are_recorded_as_logged_text() -> None:
    record = _with_props("entra-signin", deviceDetail={"isCompliant": False})
    entra = _convert("entra-signin", record).entra
    assert entra is not None and entra.device_is_compliant == "false"


# ===========================================================================
# Office 365 Management Activity
# ===========================================================================


def test_o365_logon_is_exact_and_creation_time_is_documented_utc() -> None:
    obs = _convert("o365-aad-user-logged-in")
    assert RECORDS["o365-aad-user-logged-in"]["CreationTime"] == "2024-02-08T21:45:04"
    assert obs.timestamp == datetime(2024, 2, 8, 21, 45, 4, tzinfo=UTC)
    assert obs.timestamp_precision is TimePrecision.SECOND
    org = "75243ab2-44f8-435c-a7a6-b479385df6d4"
    assert obs.observation_id == f"o365:{org}:38aa73b1-5d21-439d-b613-9a45cfe5ac00"
    assert obs.event is not None
    assert (obs.event.dataset, obs.event.action) == ("o365.audit", "UserLoggedIn")
    assert obs.cloud == CloudRef(account_id=org)  # the source states no provider
    assert obs.user is not None
    assert (obs.user.id, obs.user.name) == (
        "e4c722ac-3b83-478d-8f52-c388885dc30f",
        "user30@splunkresearch.onmicrosoft.com",
    )
    # the ExtendedProperties "UserAgent" entry
    assert obs.user_agent is not None and obs.user_agent.original is not None
    assert "Chrome/121.0.0.0" in obs.user_agent.original
    o365 = obs.o365
    assert o365 is not None
    assert (o365.record_type, o365.workload, o365.result_status, o365.application_id) == (
        "15",
        "AzureActiveDirectory",
        "Success",
        "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    )


def test_client_ip_port_is_split_exactly() -> None:
    assert RECORDS["o365-exchange-client-ip-port"]["ClientIP"] == "120.1.121.43:28973"
    obs = _convert("o365-exchange-client-ip-port")
    assert obs.network is not None and obs.network.source is not None
    assert obs.network.source.ip == "120.1.121.43"


@pytest.mark.parametrize(
    ("client_ip", "expected"),
    [("[2001:db8::1]:443", "2001:db8::1"), ("2001:db8::1", "2001:db8::1"), ("not-an-ip", None)],
)
def test_client_ip_forms(client_ip: str, expected: str | None) -> None:
    record = {**RECORDS["o365-exchange-client-ip-port"], "ClientIP": client_ip}
    obs = _convert("o365-exchange-client-ip-port", record)
    assert (obs.network.source.ip if obs.network and obs.network.source else None) == expected


def test_top_level_user_agent_is_read() -> None:
    obs = _convert("o365-sharepoint-user-agent")
    assert obs.user_agent is not None and obs.user_agent.original is not None
    assert obs.user_agent.original.startswith("Mozilla/5.0 (Windows NT 10.0")


def test_zoned_creation_time_keeps_its_zone() -> None:
    record = {**RECORDS["o365-aad-user-logged-in"], "CreationTime": "2024-02-08T21:45:04+02:00"}
    assert _convert("o365-aad-user-logged-in", record).timestamp == datetime(
        2024, 2, 8, 19, 45, 4, tzinfo=UTC
    )


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"CreationTime": "2/8/2024 9:45:04 PM"}, "not ISO 8601"),
        ({"OrganizationId": ""}, "are required"),
        ({"ExtendedProperties": [{"Name": "UserAgent", "Value": "a"}] * 2}, "twice"),
    ],
)
def test_o365_records_fail_closed(change: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        _convert("o365-aad-user-logged-in", {**RECORDS["o365-aad-user-logged-in"], **change})


def test_impossible_creation_time_is_refused() -> None:
    with pytest.raises(SourceAdapterError, match="is invalid"):
        _convert("o365-invalid-time")


# ===========================================================================
# Pipeline routing and persistence
# ===========================================================================


@pytest.mark.parametrize("golden_id", sorted(set(RECORDS) - {"aws-ocsf"}))
def test_records_route_to_their_adapter(golden_id: str) -> None:
    channel = _channel(RECORDS[golden_id])
    assert channel == CHANNELS[golden_id.split("-")[0]]
    assert DEFAULT_CHANNEL_ADAPTERS[channel] is ADAPTERS_IN_PIPELINE[channel]


ADAPTERS_IN_PIPELINE = {c: DEFAULT_CHANNEL_ADAPTERS[c] for c in CHANNELS.values()}


def test_security_lake_ocsf_records_are_not_read() -> None:
    """Amazon Security Lake OCSF is a second schema for the same events (D1):
    no adapter reads it, and the CloudTrail adapter refuses it."""
    assert _channel(RECORDS["aws-ocsf"]) not in DEFAULT_CHANNEL_ADAPTERS
    with pytest.raises(SourceAdapterError, match="not a native CloudTrail record"):
        _convert("aws-ocsf")


@pytest.mark.parametrize("golden_id", sorted(set(RECORDS) - REFUSED))
def test_cloud_observations_round_trip_through_persistence(golden_id: str) -> None:
    obs = _convert(golden_id)
    document = json.loads(json.dumps(to_serializable(obs)))
    assert _observation_from_document(document) == obs


# ===========================================================================
# Detection and the cloud product scope (ADR-0011 D4)
# ===========================================================================


def test_cloud_logsources_are_dataset_scoped() -> None:
    assert LOGSOURCE_SCOPES[("azure", "signinlogs")] == (
        ("event.dataset", "equals", "azure.signinlogs"),
    )
    assert LOGSOURCE_SCOPES[("m365", "audit")] == (("event.dataset", "equals", "o365.audit"),)
    assert FIELD_MAPS[("azure", "auditlogs")]["Category"] == "entra.audit_category"
    assert "properties.message" not in FIELD_MAPS[("azure", "auditlogs")]
    assert "Status" not in FIELD_MAPS[("azure", "signinlogs")]
    assert LOGSOURCE_SCOPES[("aws", "cloudtrail")] == (
        ("event.dataset", "equals", "aws.cloudtrail"),
    )
    assert "requestParameters" not in FIELD_MAPS[("aws", "cloudtrail")]
    for product in ("windows", "linux"):
        assert ("cloud.account_id", "exists", None, True) in PRODUCT_OS_SCOPES[product]


@pytest.mark.parametrize(
    ("golden_id", "technique"),
    [
        ("entra-signin-mfa-interrupted", "T1621"),  # Multifactor Authentication Interrupted
        ("entra-audit-security-info", "T1556"),  # Change to Authentication Method
        ("entra-audit-disable-strong-auth", "T1556"),  # Disabled MFA
        ("entra-risk-event", "T1090"),  # maliciousIPAddress risk detection
        ("o365-aad-disable-strong-auth", "T1556.006"),
        ("o365-aad-add-domain", "T1484.002"),  # New Federated Domain Added
        ("o365-ti-mail-data", "T1566.002"),  # Suspicious Email Delivered
        ("aws-console-login-root", "T1078.004"),  # root console login without MFA
        ("aws-console-login-failed", "T1110"),
        ("aws-stop-logging", "T1685.002"),  # CloudTrail Important Change
        ("okta-mfa-deactivate", "T1556.006"),
        ("okta-account-lock", "T1531"),
        ("github-dependabot-disable", "T1195.001"),
        ("github-repo-destroy", "T1213.003"),
    ],
)
def test_real_records_detect_their_technique(
    engine: DetectionEngine, golden_id: str, technique: str
) -> None:
    assert technique in _fired(engine, [_convert(golden_id)])


def test_benign_records_do_not_fire(engine: DetectionEngine) -> None:
    for golden_id in (
        "entra-signin",
        "entra-signin-noninteractive",
        "o365-aad-user-logged-in",
        "aws-service-source",
        "azure-activity-runbook-write",
        "okta-session-start",
        "k8s-anonymous-get",
        "k8s-create-pod",
    ):
        assert _fired(engine, [_convert(golden_id)]) == set(), golden_id


def test_blocked_email_does_not_fire(engine: DetectionEngine) -> None:
    record = {**RECORDS["o365-ti-mail-data"], "DeliveryAction": "Blocked"}
    assert "T1566.002" not in _fired(engine, [_convert("o365-ti-mail-data", record)])


def test_only_cloud_rules_fire_on_cloud_records(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    entra = [_convert(g) for g in sorted(set(RECORDS) - REFUSED) if g.startswith("entra")]
    o365 = [_convert(g) for g in sorted(set(RECORDS) - REFUSED) if g.startswith("o365")]
    trail = [_convert(g) for g in sorted(set(RECORDS) - REFUSED) if g.startswith("aws")]
    assert _fired_products(engine, products, entra) == {"azure"}
    assert _fired_products(engine, products, o365) == {"m365"}
    assert _fired_products(engine, products, trail) == {"aws"}
    for golden_id in sorted(set(RECORDS) - REFUSED):
        fired = _fired_products(engine, products, [_convert(golden_id)])
        assert fired <= {PRODUCTS[golden_id.split("-")[0]]}, golden_id


def test_an_aws_rule_stops_when_the_provider_is_not_aws(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    obs = _convert("aws-stop-logging")
    assert obs.cloud is not None
    as_azure = dataclasses.replace(obs, cloud=dataclasses.replace(obs.cloud, provider="azure"))
    assert _fired_products(engine, products, [as_azure]) == set()


def test_an_endpoint_detection_stops_when_the_record_is_a_cloud_record(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    """A real Windows Observation the pack detects, given a cloud account: the
    Windows rule must stop firing — the scope, not luck."""
    golden = SAMPLES / "otrf-compound" / "golden-records.jsonl"
    rows = [json.loads(line) for line in golden.read_text(encoding="utf-8").splitlines()]
    record = next(r["record"] for r in rows if r["golden_id"] == "b-4661")
    (windows,) = WindowsSecuritySourceAdapter().to_observations(record)
    assert _fired_products(engine, products, [windows]) == {"windows"}
    as_cloud = dataclasses.replace(windows, cloud=CloudRef(account_id="tenant"))
    assert _fired_products(engine, products, [as_cloud]) == set()


# ===========================================================================
# Real data (the whole verified cache)
# ===========================================================================


def test_real_cloud_report_conversion_and_scope() -> None:
    """``scripts/report_cloud_telemetry.py`` over the whole verified cache,
    regenerated whenever the data or the pack changes (enforced below)."""
    report = json.loads((CLOUD / "conversion-report.json").read_text(encoding="utf-8"))
    manifest = CLOUD / "manifest.json"
    assert report["source_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert report["sigma_pack_sha256"] == hashlib.sha256(PACK.read_bytes()).hexdigest()
    entra, o365 = report["entra_id"], report["o365"]
    assert entra["observations"] == 579
    assert entra["refused_by_reason"] == {
        "EntraIdSourceAdapter: category 'MicrosoftGraphActivityLogs' is not supported": 39,
        "EntraIdSourceAdapter: category 'RiskyUsers' is not supported": 2,
    }
    assert o365["observations"] == 1413
    assert o365["refused_by_reason"] == {
        "O365SourceAdapter: CreationTime='2023-10-10T17:08:65' is invalid": 2
    }
    assert {r["product"] for r in entra["fired_rules"]} == {"azure"}
    assert {r["product"] for r in o365["fired_rules"]} == {"m365"}
    # measured documented-label recall (labels resolved through ATT&CK revoked-by)
    assert (
        entra["labelled_datasets_with_observations"],
        entra["labelled_datasets_with_documented_technique_detected"],
    ) == (40, 6)
    assert (
        o365["labelled_datasets_with_observations"],
        o365["labelled_datasets_with_documented_technique_detected"],
    ) == (50, 2)
    trail = report["aws_cloudtrail"]
    assert trail["observations"] == 21690  # unique event ids (43,152 records)
    assert trail["refused_by_reason"] == {}
    assert {r["product"] for r in trail["fired_rules"]} == {"aws"}
    assert (
        trail["labelled_datasets_with_observations"],
        trail["labelled_datasets_with_documented_technique_detected"],
    ) == (40, 9)
    # batch C: few, short samples — parsing and scope are what they validate
    expected = {
        "azure_activity": (17, (3, 0)),
        "okta": (98, (16, 1)),
        "github_audit": (16, (0, 0)),  # no YAML descriptor: no documented label to count
        "kubernetes_audit": (12, (6, 0)),
    }
    for name, (observations, recall) in expected.items():
        section = report[name]
        assert section["observations"] == observations, name
        assert section["refused_by_reason"] == {}, name
        assert (
            section["labelled_datasets_with_observations"],
            section["labelled_datasets_with_documented_technique_detected"],
        ) == recall, name
    assert {r["product"] for r in report["okta"]["fired_rules"]} == {"okta"}
    assert {r["product"] for r in report["github_audit"]["fired_rules"]} == {"github"}
    assert report["azure_activity"]["fired_rules"] == []
    assert report["kubernetes_audit"]["fired_rules"] == []


# ===========================================================================
# Batch B: AWS CloudTrail
# ===========================================================================


def test_cloudtrail_console_login_is_exact() -> None:
    obs = _convert("aws-console-login-root")
    assert obs.observation_id == "cloudtrail:111111111111:630d3da9-9cdc-44a4-a617-33e2f8f21a32"
    assert obs.timestamp == datetime(2022, 10, 4, 20, 12, 11, tzinfo=UTC)
    assert obs.timestamp_precision is TimePrecision.SECOND
    assert obs.cloud == CloudRef(
        provider="aws",
        account_id="111111111111",
        region="us-east-1",
        service_name="signin.amazonaws.com",
    )
    assert obs.event is not None
    assert (obs.event.dataset, obs.event.action, obs.event.outcome) == (
        "aws.cloudtrail",
        "ConsoleLogin",
        "success",
    )
    assert obs.network is not None and obs.network.source is not None
    assert obs.network.source.ip == "142.254.89.27"
    trail = obs.aws_cloudtrail
    assert trail is not None
    assert (trail.user_identity_type, trail.user_identity_arn) == (
        "Root",
        "arn:aws:iam::111111111111:root",
    )
    assert (trail.mfa_used, trail.console_login, trail.read_only) == ("No", "Success", "false")


def test_cloudtrail_failures_and_outcome() -> None:
    failed = _convert("aws-console-login-failed")
    assert failed.event is not None and failed.event.outcome == "failure"  # ConsoleLogin result
    assert failed.aws_cloudtrail is not None
    assert failed.aws_cloudtrail.error_message == "Failed authentication"
    denied = _convert("aws-access-denied")
    assert denied.event is not None and denied.event.outcome == "failure"  # errorCode
    assert denied.aws_cloudtrail is not None
    assert denied.aws_cloudtrail.error_code == "AccessDenied"
    assert denied.user is not None and denied.user.name == "rhino_escalate"
    stop = _convert("aws-stop-logging")
    assert stop.event is not None and stop.event.outcome is None  # not claimed from silence


def test_cloudtrail_service_source_is_not_an_ip() -> None:
    obs = _convert("aws-service-source")
    assert obs.aws_cloudtrail is not None
    assert obs.aws_cloudtrail.source_ip_address == "eks.amazonaws.com"  # as logged
    assert obs.network is None  # never put into network.source.ip
    assert obs.aws_cloudtrail.user_identity_invoked_by == "eks.amazonaws.com"


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"eventTime": "2022-10-04T20:12:11"}, "has no zone"),
        ({"eventTime": "10/04/2022 20:12"}, "not ISO 8601"),
        ({"recipientAccountId": None}, "are required"),
        ({"errorCode": ["x"]}, "expected a scalar"),
    ],
)
def test_cloudtrail_records_fail_closed(change: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        _convert("aws-console-login-root", {**RECORDS["aws-console-login-root"], **change})


# ===========================================================================
# Batch C: Azure Activity, Okta, GitHub audit, Kubernetes audit
# ===========================================================================


def test_azure_activity_record_is_exact() -> None:
    obs = _convert("azure-activity-runbook-write")
    subscription = "1aee0e3d-b75b-440a-a927-76f0552a14e6"
    assert obs.timestamp == datetime(2022, 8, 22, 18, 57, 32, 313953, tzinfo=UTC)
    assert obs.cloud == CloudRef(provider="azure", account_id=subscription)
    assert obs.user is not None and obs.user.name == "evilAdmin@contoso.com"
    activity = obs.azure_activity
    assert activity is not None
    assert activity.operation_name == "Microsoft.Automation/automationAccounts/runbooks/write"
    assert (activity.status, activity.sub_status) == ("Succeeded", "Created")
    assert activity.category is None  # the record carries eventSource, not category


def test_azure_activity_rule_fires_on_a_modified_real_record(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    """One labelled change (the operation) on a real record: the Key Vault rule
    fires (Sigma writes the operation upper-case; matching is case-insensitive,
    as Sigma specifies) — and stops when the provider is not Azure."""
    record = json.loads(json.dumps(RECORDS["azure-activity-runbook-write"]))
    record["operationName"]["value"] = "Microsoft.KeyVault/vaults/delete"
    obs = _convert("azure-activity-runbook-write", record)
    assert "T1552.001" in _fired(engine, [obs])
    assert obs.cloud is not None
    as_aws = dataclasses.replace(obs, cloud=dataclasses.replace(obs.cloud, provider="aws"))
    assert _fired_products(engine, products, [as_aws]) == set()


def test_okta_event_is_exact() -> None:
    obs = _convert("okta-mfa-deactivate")
    assert obs.observation_id == "okta:5e2d38e1-dfc4-11ee-be83-538191b64b24"
    assert obs.timestamp == datetime(2024, 3, 11, 16, 28, 18, 167000, tzinfo=UTC)
    assert obs.event is not None
    assert (obs.event.dataset, obs.event.action, obs.event.outcome) == (
        "okta.system",
        "user.mfa.factor.deactivate",
        "success",
    )
    assert obs.user is not None
    assert (obs.user.id, obs.user.name) == ("00ufb5gta21oowKfZ5d7", "user15@splunkresearch.com")
    assert obs.cloud is None  # the event names no org: none is invented
    okta = obs.okta
    assert okta is not None
    assert (okta.legacy_event_type, okta.outcome_reason, okta.security_is_proxy) == (
        "core.user.factor.deactivate",
        "User reset OKTA_VERIFY_PUSH factor",
        "false",
    )


def test_okta_proxy_session_rule_needs_the_logged_flag(engine: DetectionEngine) -> None:
    record = json.loads(json.dumps(RECORDS["okta-session-start"]))
    assert "T1685" not in _fired(engine, [_convert("okta-session-start", record)])
    record["securityContext"]["isProxy"] = True
    assert "T1685" in _fired(engine, [_convert("okta-session-start", record)])


def test_github_event_is_exact() -> None:
    obs = _convert("github-dependabot-disable")
    assert RECORDS["github-dependabot-disable"]["@timestamp"] == 1736850926658
    assert obs.timestamp == datetime(2025, 1, 14, 10, 35, 26, 658000, tzinfo=UTC)
    assert obs.timestamp_precision is TimePrecision.MILLISECOND
    assert obs.user is not None
    assert (obs.user.id, obs.user.name) == ("8362376", "P4T12ICK")
    assert obs.github is not None
    assert (obs.github.action, obs.github.org, obs.github.repo) == (
        "repository_vulnerability_alerts.disable",
        "pbtest2",
        "pbtest2/pbtest5",
    )


def test_kubernetes_audit_event_is_exact() -> None:
    obs = _convert("k8s-anonymous-get")
    assert obs.observation_id == ("k8s-audit:2e4874e8-1d18-4396-ab83-5fd931b2a293:ResponseComplete")
    assert obs.timestamp == datetime(2023, 12, 7, 7, 39, 5, 558148, tzinfo=UTC)
    assert obs.user is not None and obs.user.name == "system:anonymous"
    assert obs.network is not None and obs.network.source is not None
    assert obs.network.source.ip == "35.203.211.49"
    audit = obs.kubernetes_audit
    assert audit is not None
    assert (audit.verb, audit.response_code, audit.authorization_decision) == (
        "get",
        "403",
        "forbid",
    )


@pytest.mark.parametrize(
    ("change", "technique"),
    [
        ({"namespace": "kube-system"}, "T1036.005"),  # pod created in a system namespace
        ({"subresource": "exec"}, "T1609"),  # exec into a pod
    ],
)
def test_kubernetes_rules_fire_on_a_modified_real_record(
    engine: DetectionEngine, change: dict[str, str], technique: str
) -> None:
    record = json.loads(json.dumps(RECORDS["k8s-create-pod"]))
    assert technique not in _fired(engine, [_convert("k8s-create-pod", record)])
    record["objectRef"].update(change)
    assert technique in _fired(engine, [_convert("k8s-create-pod", record)])


@pytest.mark.parametrize(
    ("golden_id", "change", "match"),
    [
        ("okta-session-start", {"published": "2024-04-08T19:08:01.522"}, "has no zone"),
        ("okta-session-start", {"uuid": ""}, "uuid is required"),
        ("github-repo-destroy", {"@timestamp": "2025-01-14"}, "not epoch milliseconds"),
        ("github-repo-destroy", {"@timestamp": True}, "not epoch milliseconds"),
        ("k8s-create-pod", {"stage": None}, "auditID and stage are required"),
        ("azure-activity-runbook-write", {"subscriptionId": None}, "are required"),
    ],
)
def test_batch_c_records_fail_closed(golden_id: str, change: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        _convert(golden_id, {**RECORDS[golden_id], **change})
