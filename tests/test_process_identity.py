"""ADR-0003 Amendment B — proven process identity for pid-only telemetry.

Synthetic cases cover every B1 proof rule and refusal; a golden real record
covers Sysmon 5 (process terminated); a real-data check (runs only when the
corpus telemetry cache is present) pins the measured resolution on OTRF's APT3
CALDERA recording.
"""

from __future__ import annotations

import dataclasses
import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.correlation.process_identity import (
    ResolutionBasis,
    UnresolvedReason,
    resolve_process_identities,
)
from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
    UserRef,
)
from attribution_platform.sources.sysmon import SysmonSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
HOST = HostRef(name="WIN-HOST")


def _obs(
    oid: str,
    *,
    seconds: float,
    pid: int | None = 100,
    entity: str | None = None,
    kind: str | None = None,
    host: HostRef | None = HOST,
    precision: TimePrecision | None = None,
) -> Observation:
    event = EventMetadata(kind="event", category=("process",), type=(kind,)) if kind else None
    return Observation(
        observation_id=oid,
        timestamp=T0 + timedelta(seconds=seconds),
        timestamp_precision=precision,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=oid),
        event=event,
        host=host,
        process=ProcessRef(pid=pid, entity_id=entity),
    )


def _start(oid: str, seconds: float, entity: str, pid: int = 100) -> Observation:
    return _obs(oid, seconds=seconds, pid=pid, entity=entity, kind="start")


def _end(oid: str, seconds: float, entity: str) -> Observation:
    return _obs(oid, seconds=seconds, pid=100, entity=entity, kind="end")


def _pid_only(oid: str = "ps", seconds: float = 10, **kw: Any) -> Observation:
    return _obs(oid, seconds=seconds, **kw)


def _one(observations: list[Observation]) -> Any:
    result = resolve_process_identities(observations)
    return result.by_observation_id().get("ps"), dict(result.unresolved).get("ps")


def test_start_and_end_resolves_with_its_proof() -> None:
    resolved, _ = _one([_start("s", 0, "A"), _pid_only(), _end("e", 20, "A")])
    assert resolved.entity_id == "A"
    assert resolved.basis is ResolutionBasis.START_AND_END
    assert resolved.proof_observation_ids == ("s", "e")


def test_not_ended_resolves_only_with_end_coverage_on_the_host() -> None:
    other_end = _end("e-other", 5, "B")  # the host does record process ends
    resolved, _ = _one([_start("s", 0, "A"), _pid_only(), other_end])
    assert resolved.basis is ResolutionBasis.START_NOT_ENDED
    assert resolved.proof_observation_ids == ("s",)
    _, reason = _one([_start("s", 0, "A"), _pid_only()])
    assert reason is UnresolvedReason.NO_END_COVERAGE  # absence proves nothing


def test_pid_reuse_picks_the_owner_at_that_time() -> None:
    first, second = _start("s1", 0, "A"), _start("s2", 30, "B")
    ends = [_end("e1", 20, "A"), _end("e2", 60, "B")]
    early = resolve_process_identities([first, second, *ends, _pid_only("ps", 10)])
    late = resolve_process_identities([first, second, *ends, _pid_only("ps", 40)])
    assert early.by_observation_id()["ps"].entity_id == "A"
    assert late.by_observation_id()["ps"].entity_id == "B"


@pytest.mark.parametrize(
    ("observations", "reason"),
    [
        ([_pid_only()], UnresolvedReason.NO_START),
        ([_start("s", 20, "A"), _end("e", 30, "A"), _pid_only()], UnresolvedReason.NO_START),
        ([_start("s", 0, "A"), _end("e", 5, "A"), _pid_only()], UnresolvedReason.ENDED_BEFORE),
        (
            [_start("s1", 5, "A"), _start("s2", 5, "B"), _end("e", 60, "A"), _pid_only()],
            UnresolvedReason.AMBIGUOUS_START,
        ),
        ([_start("s", 0, "A"), _end("e", 20, "A"), _pid_only(host=None)], UnresolvedReason.NO_HOST),
    ],
)
def test_refusals(observations: list[Observation], reason: UnresolvedReason) -> None:
    resolved, got = _one(observations)
    assert resolved is None and got is reason


def test_precision_tie_between_two_starts_is_ambiguous() -> None:
    # two starts 300 ms apart, observed at second precision: the sensor cannot
    # tell which came last, so the owner is not proved
    starts = [
        _obs("s1", seconds=5.1, entity="A", kind="start", precision=TimePrecision.SECOND),
        _obs("s2", seconds=5.4, entity="B", kind="start", precision=TimePrecision.SECOND),
    ]
    _, reason = _one([*starts, _end("e", 60, "B"), _pid_only()])
    assert reason is UnresolvedReason.AMBIGUOUS_START


def test_host_scoped_and_collector_identities_left_alone() -> None:
    other_host = _start("s", 0, "A")
    other_host = Observation(**{**other_host.__dict__, "host": HostRef(name="OTHER")})
    _, reason = _one([other_host, _end("e", 20, "A"), _pid_only()])
    assert reason is UnresolvedReason.NO_START
    with_guid = _obs("ps", seconds=10, entity="Z")
    result = resolve_process_identities([_start("s", 0, "A"), _end("e", 20, "A"), with_guid])
    assert result.resolved == () and result.unresolved == ()


def _as(observation: Observation, name: str | None, domain: str | None = None) -> Observation:
    return dataclasses.replace(observation, user=UserRef(name=name, domain=domain))


@pytest.mark.parametrize(
    ("owner", "acting", "resolved"),
    [
        (("dschrute", "DMEVALS"), ("dschrute", "DMEVALS"), True),  # the process's own account
        (("DSchrute", "DMEVALS"), ("dschrute", "dmevals"), True),  # names are case-insensitive
        (("SYSTEM", "NT AUTHORITY"), ("WIN-HOST$", "LAB"), True),  # SYSTEM as the machine account
        (("NETWORK SERVICE", "NT AUTHORITY"), ("win-host$", "LAB"), True),
        (("SYSTEM", "NT AUTHORITY"), ("OTHER-HOST$", "LAB"), False),  # another machine
        (("SYSTEM", "NT AUTHORITY"), ("pgustavo", "SHIRE"), False),  # lsass serving a user
        (("NETWORK SERVICE", "NT AUTHORITY"), ("pgustavo", "SHIRE"), False),  # WmiPrvSE
        (("dschrute", "DMEVALS"), ("mscott", "DMEVALS"), False),
        (("SYSTEM", "NT AUTHORITY"), ("-", "-"), True),  # no acting account logged
        (("SYSTEM", "NT AUTHORITY"), None, True),  # unknown: nothing proves impersonation
        (None, ("pgustavo", "SHIRE"), True),
    ],
)
def test_b3_principal_consistency(
    owner: tuple[str, str] | None, acting: tuple[str, str] | None, resolved: bool
) -> None:
    start, event = _start("s", 0, "A"), _pid_only()
    if owner is not None:
        start = _as(start, *owner)
    if acting is not None:
        event = _as(event, *acting)
    binding, reason = _one([start, event, _end("e", 20, "A")])
    assert (binding is not None) is resolved
    assert reason == (None if resolved else UnresolvedReason.PRINCIPAL_MISMATCH)


def test_deterministic_regardless_of_input_order() -> None:
    observations = [_start("s", 0, "A"), _end("e", 20, "A"), _pid_only("ps"), _pid_only("ps2", 12)]
    assert resolve_process_identities(observations) == resolve_process_identities(
        list(reversed(observations))
    )


# ===========================================================================
# Sysmon 5 (real golden record) and real-data resolution
# ===========================================================================


def _golden(golden_id: str) -> dict[str, Any]:
    path = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "golden-records.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["golden_id"] == golden_id:
            return dict(row["record"])
    raise KeyError(golden_id)


def test_sysmon_5_is_a_process_end() -> None:
    record = _golden("wlb6-sysmon-5")
    (obs,) = SysmonSourceAdapter().to_observations(record)
    assert obs.event is not None
    assert (obs.event.category, obs.event.type, obs.event.action) == (
        ("process",),
        ("end",),
        "process_end",
    )
    assert obs.process is not None
    assert obs.process.entity_id == record["event_data"]["ProcessGuid"]
    assert obs.process.pid == int(record["event_data"]["ProcessId"])


CALDERA = (
    REPO_ROOT
    / "data"
    / "cache"
    / "otrf-compound"
    / "windows"
    / "apt3"
    / "caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz"
)


@pytest.mark.skipif(not CALDERA.is_file(), reason="corpus telemetry cache not present")
def test_real_caldera_powershell_events_resolve_to_powershell_hosts() -> None:
    from attribution_platform.sources.errors import SourceAdapterError
    from attribution_platform.sources.powershell import PowerShellSourceAdapter

    adapters: dict[str, Any] = {
        "microsoft-windows-sysmon/operational": SysmonSourceAdapter(),
        "microsoft-windows-powershell/operational": PowerShellSourceAdapter(),
    }
    observations: dict[str, Observation] = {}
    with tarfile.open(CALDERA, "r:gz") as archive:
        member = next(m for m in archive.getmembers() if m.isfile())
        handle = archive.extractfile(member)
        assert handle is not None
        for line in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
            record = json.loads(line)
            adapter = adapters.get(str(record["winlog"].get("channel")).casefold())
            if adapter is None:
                continue
            try:
                for obs in adapter.to_observations(record):
                    observations.setdefault(obs.observation_id, obs)
            except SourceAdapterError:
                continue
    result = resolve_process_identities(observations.values())
    powershell = [
        r
        for r in result.resolved
        if observations[r.observation_id].raw_reference.source_type == "windows_powershell"
    ]
    assert len(powershell) == 12659  # of 12,679 PowerShell events (99.8 %)
    owners = {
        (observations[r.start_observation_id].process.executable or "").lower().rsplit("\\", 1)[-1]  # type: ignore[union-attr]
        for r in powershell
    }
    assert owners == {"powershell.exe"}  # never consulted by the resolver


RECORDINGS = REPO_ROOT / "data" / "calibration" / "corpus" / "v2" / "recordings.json"


@pytest.mark.skipif(not CALDERA.is_file(), reason="corpus telemetry cache not present")
def test_real_caldera_wmi_provider_serving_the_user_is_not_bound() -> None:
    """B3 on real data (Amendment E): WmiPrvSE.exe, running as NETWORK SERVICE,
    logs 186 object-access events on behalf of the emulated user ``pgustavo``.
    They are refused, never bound to the shared provider instance; the user's
    own processes' Security events still bind."""
    from attribution_platform.replay.recording_pipeline import (
        DEFAULT_CHANNEL_ADAPTERS,
        iter_recording_records,
        load_recording_sources,
    )
    from attribution_platform.sources.errors import SourceAdapterError
    from attribution_platform.sources.precedence import apply_source_precedence

    source = load_recording_sources(RECORDINGS, REPO_ROOT)["otrf-apt3-caldera"]
    observations: dict[str, Observation] = {}
    for record in iter_recording_records(source.path):
        if isinstance(record, str):
            continue  # Sysmon-for-Linux XML text: not in this Windows recording
        channel = str(
            (record.get("winlog") or {}).get("channel") or record.get("Channel") or ""
        ).casefold()
        adapter = DEFAULT_CHANNEL_ADAPTERS.get(channel)
        if adapter is None:
            continue
        try:
            for obs in adapter.to_observations(record):
                observations.setdefault(obs.observation_id, obs)
        except SourceAdapterError:
            continue
    kept = apply_source_precedence(
        sorted(observations.values(), key=lambda o: o.observation_id), source.declared_sources
    ).kept
    by_id = {o.observation_id: o for o in kept}
    result = resolve_process_identities(kept)
    mismatched = [
        by_id[oid]
        for oid, reason in result.unresolved
        if reason is UnresolvedReason.PRINCIPAL_MISMATCH
    ]
    assert len(mismatched) == 186
    assert {(o.process.name, o.user.name) for o in mismatched} == {  # type: ignore[union-attr]
        ("WmiPrvSE.exe", "pgustavo")
    }
    security_bound = [
        r
        for r in result.resolved
        if by_id[r.observation_id].raw_reference.source_type == "windows_security"
    ]
    assert security_bound  # the user's own processes' events still bind
