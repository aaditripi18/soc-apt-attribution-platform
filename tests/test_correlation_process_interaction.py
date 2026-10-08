"""ADR-0003 Amendment A — process interaction correlation (A6 validation).

Structural ``PROCESS_INTERACTION`` (remote-thread injection) and contextual
``PROCESS_ACCESS_TARGET`` (handle access). Covers: the link on synthetic
Observations; the causality bound (A2) including precision ties; required
identifiers (A3); host scoping; witnesses that carry no Evidence (A7);
process access never forming or merging a group (A4); determinism and
idempotency; the replay pipeline passing witnesses; and the real OTRF
mavinject -> notepad chain.

On the real sample the production Sigma pack fires only on the mavinject
process creation, so production Evidence alone forms no group (nothing to
correlate — correct). The structural proof therefore adds one clearly
labelled *test* Evidence item on real telemetry: notepad loading the injected
``C:\\ProgramData\\T1055.dll`` 15 ms after the remote thread.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import (
    CorrelationError,
    LinkClass,
    construct_behavioral_sequence,
    contextualize,
    correlate_structurally,
)
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain import (
    Evidence,
    EvidenceType,
    HostRef,
    Observation,
    ProcessAccessRef,
    ProcessRef,
    RemoteThreadRef,
    SourceRef,
    TimePrecision,
)
from attribution_platform.extraction import RuleRef, derive_evidence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_sysmon_real_samples import MAVINJECT, SIGMA_PACK, _convert_all  # noqa: E402

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
HOST = HostRef(name="WIN-HOST")
INJECTOR = "{injector-guid}"
TARGET = "{target-guid}"


def _singletons(groups: tuple[Any, ...], count: int) -> bool:
    """ADR-0003 Amendment F: ``count`` unmerged Evidence, each its own
    single-Evidence group with no structural link."""
    return len(groups) == count and all(
        len(g.member_evidence_ids) == 1 and g.structural_link_ids == () for g in groups
    )


def _obs(
    observation_id: str,
    entity_id: str,
    *,
    timestamp: datetime = T0,
    host: HostRef | None = HOST,
    target: str | None = None,
    remote_thread: bool = False,
    access: bool = False,
    precision: TimePrecision | None = None,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=timestamp,
        timestamp_precision=precision,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=observation_id),
        host=host,
        process=ProcessRef(entity_id=entity_id) if entity_id else ProcessRef(pid=4),
        target_process=ProcessRef(entity_id=target, pid=8) if target is not None else None,
        remote_thread=RemoteThreadRef(start_function="LoadLibraryW") if remote_thread else None,
        process_access=ProcessAccessRef(granted_access="0x1fffff") if access else None,
    )


def _ev(evidence_id: str, observation: Observation) -> tuple[Evidence, Observation]:
    evidence = derive_evidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="test evidence for process-interaction correlation",
        observations=(observation,),
        rule_ref=RuleRef(rule_id="test-rule", rule_version="1"),
    )
    return (evidence, observation)


def _injection(**kwargs: object) -> Observation:
    return _obs("inject", INJECTOR, target=TARGET, remote_thread=True, **kwargs)  # type: ignore[arg-type]


def _classes(result: object) -> list[LinkClass]:
    return [link.link_class for link in result.links]  # type: ignore[attr-defined]


# ===========================================================================
# PROCESS_INTERACTION (structural)
# ===========================================================================


def test_injection_links_injector_evidence_to_later_target_evidence() -> None:
    injector = _ev("e-injector", _obs("o-injector", INJECTOR))
    after = _ev("e-after", _obs("o-after", TARGET, timestamp=T0 + timedelta(seconds=1)))
    result = correlate_structurally([injector, after], context_observations=[_injection()])
    (link,) = result.links
    assert link.link_class is LinkClass.PROCESS_INTERACTION
    assert link.link_class.is_structural
    # directional: injecting side first; witness recorded in provenance
    assert (link.basis.observation_id_a, link.basis.observation_id_b) == ("o-injector", "o-after")
    assert link.basis.field_path == "target_process.entity_id"
    assert link.basis.observed_value == TARGET
    assert link.basis.uncertainty_note is None
    assert link.provenance.source_observation_ids == ("inject", "o-after", "o-injector")
    (group,) = result.groups
    assert set(group.member_evidence_ids) == {"e-injector", "e-after"}
    # the witness is never a group member
    assert "inject" not in group.member_observation_ids


def test_injection_event_that_is_itself_evidence_links_directly() -> None:
    inject = _ev("e-inject", _injection())
    after = _ev("e-after", _obs("o-after", TARGET, timestamp=T0 + timedelta(seconds=1)))
    result = correlate_structurally([inject, after])
    assert _classes(result) == [LinkClass.PROCESS_INTERACTION]
    assert len(result.groups) == 1


def test_target_activity_before_the_injection_is_not_linked() -> None:
    injector = _ev("e-injector", _obs("o-injector", INJECTOR))
    before = _ev("e-before", _obs("o-before", TARGET, timestamp=T0 - timedelta(seconds=7)))
    result = correlate_structurally([injector, before], context_observations=[_injection()])
    assert result.links == () and _singletons(result.groups, 2)


def test_equal_timestamp_is_linked() -> None:
    injector = _ev("e-injector", _obs("o-injector", INJECTOR))
    same = _ev("e-same", _obs("o-same", TARGET, timestamp=T0))
    result = correlate_structurally([injector, same], context_observations=[_injection()])
    assert _classes(result) == [LinkClass.PROCESS_INTERACTION]


def test_precision_tie_is_linked_but_a_confident_order_is_not() -> None:
    injection = _injection(
        timestamp=T0 + timedelta(milliseconds=600), precision=TimePrecision.MILLISECOND
    )
    injector = _ev("e-injector", _obs("o-injector", INJECTOR))
    # second-precision target event in the same second: the sensor cannot order them
    tied = _ev("e-tied", _obs("o-tied", TARGET, timestamp=T0, precision=TimePrecision.SECOND))
    result = correlate_structurally([injector, tied], context_observations=[injection])
    assert _classes(result) == [LinkClass.PROCESS_INTERACTION]
    earlier = _ev(
        "e-earlier",
        _obs(
            "o-earlier", TARGET, timestamp=T0 - timedelta(seconds=1), precision=TimePrecision.SECOND
        ),
    )
    result = correlate_structurally([injector, earlier], context_observations=[injection])
    assert result.links == ()


@pytest.mark.parametrize(
    "witness",
    [
        _obs("inject", INJECTOR, target=None, remote_thread=True),  # no target at all
        _obs("inject", INJECTOR, target="", remote_thread=True),  # pid-only target
        _obs("inject", "", target=TARGET, remote_thread=True),  # pid-only source
        _obs("inject", INJECTOR, target=TARGET, remote_thread=True, host=None),  # no host scope
        _obs("inject", INJECTOR, target=TARGET),  # not a remote-thread event
    ],
)
def test_missing_identifiers_form_no_link(witness: Observation) -> None:
    injector = _ev("e-injector", _obs("o-injector", INJECTOR))
    after = _ev("e-after", _obs("o-after", TARGET, timestamp=T0 + timedelta(seconds=1)))
    result = correlate_structurally([injector, after], context_observations=[witness])
    assert result.links == ()


def test_injection_is_host_scoped() -> None:
    injector = _ev("e-injector", _obs("o-injector", INJECTOR))
    other_host = _ev(
        "e-other",
        _obs("o-other", TARGET, timestamp=T0 + timedelta(seconds=1), host=HostRef(name="OTHER")),
    )
    result = correlate_structurally([injector, other_host], context_observations=[_injection()])
    assert result.links == ()


def test_one_hop_only_never_transitive_through_a_third_process() -> None:
    # injector -> TARGET, and separately TARGET -> THIRD; evidence only on
    # injector and THIRD: no direct injection between them, so no link.
    third_injection = _obs(
        "inject-2",
        TARGET,
        target="{third}",
        remote_thread=True,
        timestamp=T0 + timedelta(seconds=2),
    )
    injector = _ev("e-injector", _obs("o-injector", INJECTOR))
    third = _ev("e-third", _obs("o-third", "{third}", timestamp=T0 + timedelta(seconds=3)))
    result = correlate_structurally(
        [injector, third], context_observations=[_injection(), third_injection]
    )
    assert result.links == ()


def test_deterministic_and_idempotent() -> None:
    items = [
        _ev("e-injector", _obs("o-injector", INJECTOR)),
        _ev("e-a", _obs("o-a", TARGET, timestamp=T0 + timedelta(seconds=1))),
        _ev("e-b", _obs("o-b", TARGET, timestamp=T0 + timedelta(seconds=2))),
    ]
    later_witness = _injection(timestamp=T0 + timedelta(milliseconds=500))
    later_witness = Observation(**{**later_witness.__dict__, "observation_id": "inject-2"})
    forward = correlate_structurally(items, context_observations=[_injection(), later_witness])
    backward = correlate_structurally(
        list(reversed(items)), context_observations=[later_witness, _injection()]
    )
    assert forward == backward
    # the earliest attesting injection is the one recorded
    interaction = [
        link for link in forward.links if link.link_class is LinkClass.PROCESS_INTERACTION
    ]
    assert all("inject" in link.provenance.source_observation_ids for link in interaction)


def test_context_observations_are_validated() -> None:
    with pytest.raises(CorrelationError, match="context_observations"):
        correlate_structurally([], context_observations=["not an observation"])  # type: ignore[list-item]


# ===========================================================================
# PROCESS_ACCESS_TARGET (contextual, A4)
# ===========================================================================


def test_process_access_never_forms_or_merges_a_group() -> None:
    access = _obs("access", INJECTOR, target=TARGET, access=True)
    accessor = _ev("e-accessor", _obs("o-accessor", INJECTOR))
    accessed = _ev("e-accessed", _obs("o-accessed", TARGET, timestamp=T0 + timedelta(seconds=1)))
    items = [accessor, accessed]
    structural = correlate_structurally(items, context_observations=[access])
    assert structural.links == () and _singletons(structural.groups, 2)  # access merges nothing
    contextual = contextualize(structural, items, context_observations=[access])
    (link,) = [
        link
        for link in contextual.contextual_links
        if link.link_class is LinkClass.PROCESS_ACCESS_TARGET
    ]
    assert not link.link_class.is_structural
    assert link.basis.uncertainty_note and "benign" in link.basis.uncertainty_note
    assert "access" in link.provenance.source_observation_ids
    assert _singletons(contextual.groups, 2)


def test_process_access_attaches_to_existing_groups_without_merging_them() -> None:
    # two separate structural groups (one per process instance), related only by access
    access = _obs("access", INJECTOR, target=TARGET, access=True)
    items = [
        _ev("e-s1", _obs("o-s1", INJECTOR)),
        _ev("e-s2", _obs("o-s2", INJECTOR, timestamp=T0 + timedelta(seconds=1))),
        _ev("e-t1", _obs("o-t1", TARGET, timestamp=T0 + timedelta(seconds=2))),
        _ev("e-t2", _obs("o-t2", TARGET, timestamp=T0 + timedelta(seconds=3))),
    ]
    structural = correlate_structurally(items, context_observations=[access])
    assert len(structural.groups) == 2
    contextual = contextualize(structural, items, context_observations=[access])
    assert [g.group_id for g in contextual.groups] == [g.group_id for g in structural.groups]
    assert all(g.contextual_link_ids for g in contextual.groups)


# ===========================================================================
# Real telemetry: OTRF mavinject -> notepad (Sysmon 1/7/8/10)
# ===========================================================================


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def real() -> list[Observation]:
    observations, _ = _convert_all(MAVINJECT)
    return observations


def _real_injection(real: list[Observation]) -> Observation:
    (injection,) = [o for o in real if o.remote_thread is not None]
    return injection


def _dll_load(real: list[Observation], path: str) -> Observation:
    return next(o for o in real if o.dll is not None and o.dll.path == path)


def test_real_injection_chain_forms_one_group(
    real: list[Observation], knowledge: AttackKnowledge
) -> None:
    engine = DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)
    detections = [d for d in engine.evaluate(real) if d.evidence_quality is None]  # core tier
    (detected_id,) = {d.supporting_observation_ids for d in detections}
    mavinject_start = next(o for o in real if o.observation_id == detected_id[0])
    injection = _real_injection(real)
    assert mavinject_start.process is not None and injection.process is not None
    assert mavinject_start.process.entity_id == injection.process.entity_id

    # production evidence alone: one item, its own single-Evidence group
    production = [_ev("e-mavinject", mavinject_start)]
    context = [o for o in real if o.observation_id != mavinject_start.observation_id]
    assert _singletons(correlate_structurally(production, context_observations=context).groups, 1)

    # + test evidence on notepad loading the injected DLL (15 ms after the thread)
    injected_dll = _dll_load(real, "C:\\ProgramData\\T1055.dll")
    assert injected_dll.timestamp - injection.timestamp == timedelta(milliseconds=15)
    items = [*production, _ev("e-t1055-dll", injected_dll)]
    context = [o for o in context if o.observation_id != injected_dll.observation_id]
    result = correlate_structurally(items, context_observations=context)
    (link,) = result.links
    assert link.link_class is LinkClass.PROCESS_INTERACTION
    assert injection.observation_id in link.provenance.source_observation_ids
    (group,) = result.groups
    assert set(group.member_evidence_ids) == {"e-mavinject", "e-t1055-dll"}

    # the group reconstructs into a behavioral sequence without error
    sequence = construct_behavioral_sequence(group, items, result.links)
    assert len(sequence.steps) == 2
    # Recorded limitation: ADR-0004's ordering vocabulary (lineage, same
    # entity) has no injection edge yet, so the two sides stay unordered.
    assert sequence.edges == () and sequence.gaps == ()

    # mavinject's two handle opens on notepad are recorded as context only
    contextual = contextualize(result, items, context_observations=context)
    assert [g.group_id for g in contextual.groups] == [group.group_id]
    assert any(
        link.link_class is LinkClass.PROCESS_ACCESS_TARGET for link in contextual.contextual_links
    )


def test_real_notepad_activity_before_the_injection_stays_out(real: list[Observation]) -> None:
    injection = _real_injection(real)
    assert injection.process is not None
    mavinject_start = next(
        o
        for o in real
        if o.process is not None
        and o.process.entity_id == injection.process.entity_id
        and o.event is not None
        and o.event.type == ("start",)
    )
    # notepad's own start-up DLL load, 7 s before the injection
    early = _dll_load(real, "C:\\Windows\\System32\\uxtheme.dll")
    assert early.timestamp < injection.timestamp
    items = [_ev("e-mavinject", mavinject_start), _ev("e-early", early)]
    result = correlate_structurally(items, context_observations=[injection])
    assert result.links == () and _singletons(result.groups, 2)
