"""ADR-0023: Wazuh alerts as an input. The alert is read as Wazuh wrote it; its
rule's ATT&CK ids become Evidence only where the pinned knowledge base has them."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api.read_model import (
    get_investigation,
    get_investigation_activity,
    get_investigation_observables,
)
from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection.evidence import derive_evidence_from_detection
from attribution_platform.domain import EvidenceQuality
from attribution_platform.replay.recording_pipeline import WAZUH_CHANNEL, channel_of
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.wazuh import WazuhAlertSourceAdapter, is_wazuh_alert
from attribution_platform.wazuh_detections import WazuhAlertDetector

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_dossier import _investigate  # noqa: E402

SHA256 = "ab" * 32


def _alert(**changes: Any) -> dict[str, Any]:
    """The shape of the manager's ``alerts.json`` (Wazuh documentation's PsExec
    service example, with a decoded Sysmon event under ``data.win``)."""
    alert: dict[str, Any] = {
        "timestamp": "2023-10-16T12:12:18.684+0000",
        "rule": {
            "level": 10,
            "description": "PsExec service running as NT AUTHORITY\\SYSTEM has been created",
            "id": "110011",
            "mitre": {
                "id": ["T1543.003"],
                "tactic": ["Persistence", "Privilege Escalation"],
                "technique": ["Windows Service"],
            },
            "firedtimes": 1,
            "groups": ["windows", "sysmon"],
        },
        "agent": {"id": "002", "name": "Windows11", "ip": "172.20.10.3"},
        "manager": {"name": "wazuh-server"},
        "id": "1694607138.3688437",
        "decoder": {"name": "windows_eventchannel"},
        "data": {"win": {"system": {"eventID": "13", "channel": "x"}, "eventdata": {}}},
        "location": "EventChannel",
    }
    for key, value in changes.items():
        if key in ("level", "mitre", "description"):
            alert["rule"][key] = value
        else:
            alert[key] = value
    return alert


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _observe(alert: dict[str, Any]) -> Any:
    (observation,) = WazuhAlertSourceAdapter().to_observations(alert)
    return observation


def test_an_alert_is_read_as_wazuh_wrote_it() -> None:
    observation = _observe(_alert())
    assert observation.observation_id == "wazuh:wazuh-server:1694607138.3688437"
    assert observation.timestamp.isoformat() == "2023-10-16T12:12:18.684000+00:00"
    assert observation.host.name == "Windows11"
    assert observation.event.kind == "alert" and observation.event.dataset == "wazuh.alerts"
    assert observation.event.code == "110011"
    alert = observation.wazuh
    assert (alert.rule_id, alert.rule_level, alert.mitre_ids) == ("110011", "10", "T1543.003")
    assert alert.rule_groups == "windows sysmon" and alert.agent_id == "002"
    assert alert.decoder == "windows_eventchannel" and alert.location == "EventChannel"
    # the alert embeds a Windows event: it is still routed as the alert it is
    assert is_wazuh_alert(_alert()) and channel_of(_alert()) == WAZUH_CHANNEL


@pytest.mark.parametrize(
    "alert",
    [
        _alert(timestamp="2023-10-16T12:12:18.684"),  # no zone
        _alert(level=17),
        _alert(level="10"),
        _alert(mitre={"id": ["Persistence"]}),
        _alert(agent={"id": "002"}),
        _alert(id=None),
        {"rule": {"id": "1"}, "agent": {}},
    ],
)
def test_malformed_alerts_are_refused(alert: dict[str, Any]) -> None:
    with pytest.raises(SourceAdapterError):
        WazuhAlertSourceAdapter().to_observations(alert)


def test_indicators_are_kept_only_when_well_formed() -> None:
    fim = _alert(
        syscheck={"path": "/etc/cron.d/x", "sha256_after": SHA256.upper(), "md5_after": "zz"}
    )
    observation = _observe(fim)
    assert observation.file.path == "/etc/cron.d/x"
    assert observation.file.hashes.sha256 == SHA256 and observation.file.hashes.md5 is None
    network = _alert(
        data={"win": {"eventdata": {"destinationIp": "203.0.113.9", "queryName": "a.example."}}}
    )
    observation = _observe(network)
    assert observation.network.destination.ip == "203.0.113.9"
    assert observation.dns.question_name == "a.example."
    assert _observe(_alert(data={"dstip": "not an address"})).network is None


def test_the_rules_own_attack_ids_become_evidence(knowledge: AttackKnowledge) -> None:
    detector = WazuhAlertDetector(knowledge)
    observation = _observe(_alert())
    detection = detector.detect(observation)
    assert detection is not None and detection.detection_source == "wazuh"
    assert detection.rule_ref.rule_id == "wazuh:110011"
    assert detection.rule_ref.rule_version == "as-alerted"
    assert detection.evidence_quality is None  # level 10: core tier
    (evidence,) = derive_evidence_from_detection(detection, observation, knowledge=knowledge)
    assert evidence.attack_ref.external_id == "T1543.003"
    assert (
        "Wazuh rule 110011" in evidence.claim and "(level 10) declares T1543.003" in evidence.claim
    )
    # a low level is the enrich tier
    low = detector.detect(_observe(_alert(level=3)))
    assert low is not None and low.evidence_quality is EvidenceQuality.LOW
    assert detector.detect(_observe(_alert(level=7))).evidence_quality is None
    # an id the knowledge base lacks is not mapped, and the Evidence says so
    mixed = _observe(_alert(mitre={"id": ["T1543.003", "T9999", "T1543.003"]}))
    detection = detector.detect(mixed)
    assert [m.attack_ref.external_id for m in detection.technique_mappings] == ["T1543.003"]
    (evidence,) = derive_evidence_from_detection(detection, mixed, knowledge=knowledge)
    assert "not mapped: T9999" in evidence.claim
    # nothing resolvable, or nothing declared: no detection, nothing claimed
    assert detector.detect(_observe(_alert(mitre={"id": ["T9999"]}))) is None
    assert detector.detect(_observe(_alert(mitre=None))) is None


def test_a_wazuh_alert_file_is_investigated_end_to_end(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    alerts = [
        _alert(),
        _alert(
            id="1694607139.1",
            timestamp="2023-10-16T12:13:00.000+0000",
            mitre={"id": ["T1105"]},
            description="Suspicious download",
            data={"win": {"eventdata": {"destinationIp": "203.0.113.9"}}},
        ),
        _alert(id="1694607140.1", mitre=None, description="No technique declared"),
    ]
    text = "".join(json.dumps(a) + "\n" for a in alerts)
    client, investigation_id = _investigate(tmp_path, "alerts.json", text)
    record = get_investigation(client, investigation_id)
    assert record["evidence"] == 2
    activity = get_investigation_activity(client, investigation_id)
    assert sorted(e["attack_id"] for e in activity["events"]) == ["T1105", "T1543.003"]
    assert {e["host"] for e in activity["events"]} == {"Windows11"}
    observables = get_investigation_observables(client, investigation_id)["observables"]
    assert [(o["kind"], o["value"]) for o in observables] == [("ip", "203.0.113.9")]
