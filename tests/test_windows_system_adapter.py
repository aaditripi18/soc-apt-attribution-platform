"""The Windows System log adapter (ADR-0008 Amendment: System log) on real
OTRF records: Service Control Manager 7045 in both collector shapes, exact
values, and fail-closed on everything else."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.pinned import SIGMA_ACTOR_PACK, SIGMA_PACK
from attribution_platform.detection_content.sigma_field_map import (
    FIELD_MAPS,
    LOGSOURCE_SCOPES,
    SUPPORTED_EVENT_CODES,
)
from attribution_platform.domain import TimePrecision
from attribution_platform.replay.recording_pipeline import DEFAULT_CHANNEL_ADAPTERS, channel_of
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter
from attribution_platform.sources.windows_system import (
    SUPPORTED_EVENT_IDS,
    SYSTEM_DATASET,
    WindowsSystemSourceAdapter,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "golden-records.jsonl"
ADAPTER = WindowsSystemSourceAdapter()


def _golden(golden_id: str) -> dict[str, Any]:
    for line in GOLDEN.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["golden_id"] == golden_id:
            record: dict[str, Any] = row["record"]
            return record
    raise AssertionError(golden_id)


def test_a_real_winlogbeat_service_installation() -> None:
    (obs,) = ADAPTER.to_observations(_golden("sys-7045"))
    assert obs.observation_id == "windows_system:HFDC01.shire.com:29600"
    assert obs.timestamp.isoformat() == "2019-05-14T23:13:31.343000+00:00"
    assert obs.timestamp_precision is None
    assert obs.event is not None
    assert (obs.event.dataset, obs.event.code, obs.event.action, obs.event.provider) == (
        SYSTEM_DATASET,
        "7045",
        "service_installed",
        "Service Control Manager",
    )
    assert (obs.event.category, obs.event.type) == ((), ())  # none is invented
    assert obs.host is not None and (obs.host.name, obs.host.os_type) == (
        "HFDC01.shire.com",  # the host of the event, not the forwarding server
        "windows",
    )
    assert obs.user is not None and (obs.user.name, obs.user.domain) == ("pgustavo", "SHIRE")
    service = obs.service
    assert service is not None
    assert service.name == "Adobe Flash Updater"
    assert service.file_name is not None and service.file_name.startswith('cmd.exe /c "C:\\Users')
    assert service.file_name.endswith(" ")  # exactly as logged, trailing space included
    assert (service.type, service.start_type, service.account) == (
        "user mode service",
        "auto start",
        "LocalSystem",
    )


def test_a_real_nxlog_service_installation_takes_no_ambiguous_account() -> None:
    record = _golden("sys-7045-apt29")
    (obs,) = ADAPTER.to_observations(record)
    assert obs.observation_id == "windows_system:SCRANTON.dmevals.local:549"
    assert obs.timestamp.isoformat() == "2020-05-02T03:04:15+00:00"
    assert obs.timestamp_precision is TimePrecision.SECOND
    service = obs.service
    assert service is not None
    assert service.name == "Java(TM) Virtual Machine Support Service"
    assert service.file_name == "C:\\Windows\\System32\\javamtsup.exe"
    # the record's AccountName is the collector's or the event's — it cannot be told
    assert record["AccountName"] == "pbeesly"
    assert service.account is None
    assert obs.user is not None
    assert (obs.user.id, obs.user.name) == (record["UserID"], None)


def test_the_same_installation_in_the_security_log_is_a_different_record() -> None:
    """4697 and 7045 of one installation: different names, different events."""
    (security,) = WindowsSecuritySourceAdapter().to_observations(_golden("b-4697-apt29"))
    (system,) = ADAPTER.to_observations(_golden("sys-7045-apt29"))
    assert security.service is not None and system.service is not None
    assert security.service.name == "javamtsup"  # the key name
    assert system.service.name == "Java(TM) Virtual Machine Support Service"  # the display name
    assert security.event is not None and system.event is not None
    assert (security.event.dataset, security.event.code) == ("system.security", "4697")
    assert (system.event.dataset, system.event.code) == ("system.system", "7045")
    assert security.observation_id != system.observation_id


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda r: r.update(event_id=7036), "unsupported event id 7036"),
        (lambda r: r.update(source_name="Some Other Provider"), "is not supported"),
        (lambda r: r.update(log_name="Application"), "is not 'System'"),
        (lambda r: r.pop("record_number"), "missing required event record id"),
        (lambda r: r.pop("computer_name"), "missing required host name"),
        (lambda r: r["event_data"].pop("ServiceName"), "has no ServiceName"),
        (lambda r: r.update(event_id="x"), "is invalid"),
    ],
)
def test_anything_else_fails_closed(change: Any, message: str) -> None:
    record = copy.deepcopy(_golden("sys-7045"))
    change(record)
    with pytest.raises(SourceAdapterError, match=message):
        ADAPTER.to_observations(record)


def test_other_real_system_events_are_refused_and_flat_records_need_event_time() -> None:
    with pytest.raises(SourceAdapterError, match="unsupported event id 7036"):
        ADAPTER.to_observations(_golden("wlb6-system-7"))
    flat = copy.deepcopy(_golden("sys-7045-apt29"))
    del flat["EventTime"]
    with pytest.raises(SourceAdapterError, match="no EventTime"):
        ADAPTER.to_observations(flat)
    with pytest.raises(SourceAdapterError, match="expects a Mapping"):
        ADAPTER.to_observations("text")


def test_the_channel_is_routed_and_the_field_map_matches_the_adapter() -> None:
    for golden_id in ("sys-7045", "sys-7045-apt29"):
        assert isinstance(
            DEFAULT_CHANNEL_ADAPTERS[channel_of(_golden(golden_id))], WindowsSystemSourceAdapter
        )
    key = ("windows", "system")
    assert SUPPORTED_EVENT_CODES[key] == {str(i) for i in SUPPORTED_EVENT_IDS}
    assert LOGSOURCE_SCOPES[key] == (("event.dataset", "equals", SYSTEM_DATASET),)
    assert FIELD_MAPS[key]["ImagePath"] == "service.file_name"


def test_real_installations_fire_imported_system_rules_and_no_actor_rule() -> None:
    """The APT3 emulation installs a service that runs a script through cmd.exe:
    Sigma's System-log rules now see it. Neither real installation carries a
    Group's own artefact, so no actor rule fires."""
    knowledge = load_attack_knowledge()
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    actor = load_rule_pack(SIGMA_ACTOR_PACK, knowledge=knowledge)
    system_rules = tuple(
        r
        for r in pack.rules
        if any(c.field_path == "event.dataset" and c.value == SYSTEM_DATASET for c in r.conditions)
    )
    assert len({r.rule_ref.rule_id.split(":")[1] for r in system_rules}) == 33
    observations = [
        *ADAPTER.to_observations(_golden("sys-7045")),
        *ADAPTER.to_observations(_golden("sys-7045-apt29")),
    ]
    fired = DetectionEngine(rules=system_rules).evaluate(observations)
    assert {i for f in fired for i in f.supporting_observation_ids} == {
        "windows_system:HFDC01.shire.com:29600"
    }
    assert DetectionEngine(rules=actor.rules).evaluate(observations) == ()
