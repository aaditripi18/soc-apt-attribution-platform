"""Linux Audit (auditd) adapter and the SAME_AUDIT_EVENT link (ADR-0010 D4,
ADR-0003 Amendment G).

Golden tests on real raw records from ``splunk/attack_data`` (Apache-2.0,
``golden-records.jsonl``): exact fields and UTC time, the ENRICHED suffix, the
nested ``msg='…'``, refusal of ``ausearch -i`` records (zone-less local time) and
of a post-processed record (bare arguments auditd never writes), the declared
host, the auditd logsource and OS scope, and the structural same-event link.
auditd's hex encoding of untrusted strings is not present in the real data, so
it is tested on its documented form.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.correlation import correlate_structurally
from attribution_platform.correlation.contracts import LinkClass
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.sigma_field_map import FIELD_MAPS, LOGSOURCE_SCOPES
from attribution_platform.domain import Evidence, EvidenceType, HostRef, Observation
from attribution_platform.extraction import RuleRef, derive_evidence
from attribution_platform.replay.recording_pipeline import (
    AUDIT_CHANNEL,
    DEFAULT_CHANNEL_ADAPTERS,
    channel_of,
    iter_recording_records,
)
from attribution_platform.sources.auditd import AuditdSourceAdapter
from attribution_platform.sources.errors import SourceAdapterError

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data" / "golden-records.jsonl"
PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
RECORDS: dict[str, str] = {
    row["golden_id"]: row["record"]
    for row in (json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines())
    if row["golden_id"].startswith("auditd")
}
HOST = HostRef(id="dataset:lab-host", os_type="linux")
ADAPTER = AuditdSourceAdapter(host=HOST)


def _convert(record: str, adapter: AuditdSourceAdapter = ADAPTER) -> Observation:
    (obs,) = adapter.to_observations(record)
    return obs


# ===========================================================================
# Exact fields
# ===========================================================================


def test_enriched_syscall_record() -> None:
    obs = _convert(RECORDS["auditd-syscall-enriched"])
    assert obs.timestamp == datetime(2024, 8, 19, 14, 14, 41, 293000, tzinfo=UTC)  # epoch
    assert obs.observation_id == "auditd:dataset:lab-host:4522:SYSCALL"
    assert obs.event is not None and obs.event.dataset == "auditd.log"
    assert obs.event.action == "SYSCALL"
    audit = obs.audit
    assert audit is not None
    assert (audit.record_type, audit.event_serial, audit.syscall) == ("SYSCALL", "4522", "42")
    assert audit.syscall_name == "connect"  # only from the ENRICHED suffix
    assert (audit.a0, audit.a1) == ("4", "7ff808e23354")  # raw hex syscall arguments
    assert (audit.comm, audit.key) == ("route", "network_connect_4")
    assert obs.process is not None
    assert (obs.process.executable, obs.process.name) == ("/usr/sbin/route", "route")
    assert (obs.process.pid, obs.process.parent_pid) == (1703, 1021)
    assert obs.user is not None and (obs.user.id, obs.user.name) == ("1000", "ubuntu")
    assert obs.host == HOST


def test_execve_arguments_are_argv_strings() -> None:
    audit = _convert(RECORDS["auditd-execve"]).audit
    assert audit is not None
    assert (audit.argc, audit.a0, audit.a1, audit.a2, audit.a3, audit.a4) == (
        "4",
        "split",
        "-b",
        "1000000",
        "split_me.txt",
        None,
    )


def test_path_record_and_item_in_the_id() -> None:
    obs = _convert(RECORDS["auditd-path"])
    assert obs.audit is not None
    assert (obs.audit.name, obs.audit.nametype, obs.audit.item) == (
        "/etc/cron.weekly/logrotate",
        "CREATE",
        "1",
    )
    assert obs.observation_id.endswith(":6379:PATH:1")


def test_nested_msg_fields() -> None:
    stop = _convert(RECORDS["auditd-service_stop"])
    assert stop.audit is not None and (stop.audit.unit, stop.audit.res) == ("auditd", "success")
    assert stop.process is not None and stop.process.executable == "/usr/lib/systemd/systemd"
    added = _convert(RECORDS["auditd-add_user"])
    assert added.audit is not None and added.audit.op == "adding user"
    assert added.process is not None and added.process.executable == "/usr/sbin/useradd"


def test_node_names_the_host() -> None:
    obs = _convert("node=lab01 " + RECORDS["auditd-execve"], AuditdSourceAdapter())
    assert obs.host == HostRef(name="lab01", os_type="linux")


# ===========================================================================
# Fail closed
# ===========================================================================


def test_ausearch_interpreted_record_is_refused() -> None:
    with pytest.raises(SourceAdapterError, match="no zone"):
        ADAPTER.to_observations(RECORDS["auditd-interpreted"])


def test_post_processed_bare_argument_is_refused() -> None:
    with pytest.raises(SourceAdapterError, match="neither quoted nor hex"):
        ADAPTER.to_observations(RECORDS["auditd-bare-argument"])


def test_no_host_is_refused() -> None:
    with pytest.raises(SourceAdapterError, match="no declared host"):
        AuditdSourceAdapter().to_observations(RECORDS["auditd-execve"])


@pytest.mark.parametrize(
    ("line", "match"),
    [
        ("hello world", "not an audit record"),
        ('type=EXECVE msg=audit(1.5:1): a0="x"', "unrecognised audit timestamp"),
        ('type=EXECVE msg=audit(1700000000.000:1): a0_len=9 a0[0]="ab"', "split EXECVE"),
        ('type=EXECVE msg=audit(1700000000.000:1): a0="x" a0="y"', "duplicate"),
        ("type=EXECVE msg=audit(1700000000.000:1): a0=FFFE", "not UTF-8"),
    ],
)
def test_malformed_records_fail_closed(line: str, match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(line)


def test_hex_and_null_untrusted_strings_follow_auditds_encoding() -> None:
    """Not in the real data: auditd hex-encodes an argument containing a space."""
    line = 'type=EXECVE msg=audit(1700000000.000:7): argc=3 a0="sh" a1="-c" ' "a2=6563686F206869"
    audit = _convert(line).audit
    assert audit is not None and audit.a2 == "echo hi"
    path = _convert("type=PATH msg=audit(1700000000.000:7): item=0 name=(null) nametype=UNKNOWN")
    assert path.audit is not None and path.audit.name is None


# ===========================================================================
# Pipeline routing and declared host
# ===========================================================================


def test_audit_lines_route_to_the_auditd_adapter(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    path.write_text(RECORDS["auditd-execve"] + "\n", encoding="utf-8")
    (record,) = list(iter_recording_records(path))
    assert channel_of(record) == AUDIT_CHANNEL
    assert isinstance(DEFAULT_CHANNEL_ADAPTERS[AUDIT_CHANNEL], AuditdSourceAdapter)


# ===========================================================================
# Detection: logsource, OS scope
# ===========================================================================


def test_auditd_logsource_is_dataset_scoped() -> None:
    assert LOGSOURCE_SCOPES[("linux", "auditd")] == (("event.dataset", "equals", "auditd.log"),)
    assert FIELD_MAPS[("linux", "auditd")]["SYSCALL"] == "audit.syscall_name"


def test_real_insmod_record_detects_kernel_module_loading() -> None:
    """A modified real SYSCALL record (one labelled change: comm/exe of insmod)
    fires the auditd kernel-module rule — and not when the host is Windows."""
    engine = DetectionEngine(rules=load_rule_pack(PACK, knowledge=load_attack_knowledge()).rules)
    record = (
        RECORDS["auditd-syscall"]
        .replace('comm="route"', 'comm="insmod"')
        .replace('exe="/usr/sbin/route"', 'exe="/usr/bin/kmod"')
    )
    obs = _convert(record)
    techniques = {
        m.attack_ref.external_id for d in engine.evaluate([obs]) for m in d.technique_mappings
    }
    assert "T1547.006" in techniques
    assert obs.host is not None
    on_windows = dataclasses.replace(obs, host=dataclasses.replace(obs.host, os_type="windows"))
    assert engine.evaluate([on_windows]) == ()


# ===========================================================================
# ADR-0003 Amendment G: SAME_AUDIT_EVENT
# ===========================================================================


def _evidence(evidence_id: str, obs: Observation) -> tuple[Evidence, Observation]:
    evidence = derive_evidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="auditd same-event correlation test evidence",
        observations=(obs,),
        rule_ref=RuleRef(rule_id="test-rule", rule_version="1.0"),
    )
    return evidence, obs


def test_records_of_one_audit_event_form_one_group() -> None:
    syscall = _convert(RECORDS["auditd-syscall"])
    execve = _convert(
        RECORDS["auditd-execve"].replace(
            "msg=audit(1723450480.055:305481)", "msg=audit(1724076881.293:4522)"
        )
    )
    result = correlate_structurally([_evidence("e-1", syscall), _evidence("e-2", execve)])
    (group,) = result.groups
    assert set(group.member_evidence_ids) == {"e-1", "e-2"}
    assert [link.link_class for link in result.links] == [LinkClass.SAME_AUDIT_EVENT]
    assert result.links[0].basis.field_path == "audit.event_serial"


def test_same_serial_on_another_host_is_not_linked() -> None:
    syscall = _convert(RECORDS["auditd-syscall"])
    other = _convert(
        RECORDS["auditd-execve"].replace(
            "msg=audit(1723450480.055:305481)", "msg=audit(1724076881.293:4522)"
        ),
        AuditdSourceAdapter(host=HostRef(id="dataset:other-host", os_type="linux")),
    )
    result = correlate_structurally([_evidence("e-1", syscall), _evidence("e-2", other)])
    assert result.links == () and len(result.groups) == 2


def test_link_class_vocabulary_has_five_structural_members() -> None:
    assert LinkClass.SAME_AUDIT_EVENT.is_structural
    assert sum(1 for c in LinkClass if c.is_structural) == 5


# ===========================================================================
# Dataset labels resolve through ATT&CK's own revocations
# ===========================================================================


def test_older_dataset_labels_resolve_through_revoked_by() -> None:
    resolver = ExternalIdResolver(load_attack_knowledge(), ("attack-pattern",))
    assert resolver.current_external_id("T1562.004") == "T1686"  # revoked in ATT&CK v19
    assert resolver.current_external_id("T1547.006") == "T1547.006"
    assert resolver.current_external_id("T9999") is None
