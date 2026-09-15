"""Tests for gate G2.4.3: the TEMPORAL_PROXIMITY contextual correlation
dimension.

Covers: the matching algorithm (symmetric, inclusive `elapsed_time <=
window`, zero window valid, negative window rejected, precision-truncated
comparison per ADR-0004 D6's own convention, cross-host/same-host both
permitted and un-special-cased, coexistence with SAME_PROCESS_ENTITY,
pairwise-only, deterministic ids/ordering); the versioned, content-hashed
`TemporalProximityConfig` (caller cannot fabricate `content_hash`; it
changes when the window changes); provenance (fixed uncertainty note naming
coincidence/no-causality/no-ordering/no-attribution, `observed_value` =
raw elapsed delta, `method_content_hash` = config hash); group attachment
(union of existing + new contextual links, never a replacement; a link
spanning two groups attaches to both without merging them); the central
G2.4.3 invariant that TEMPORAL_PROXIMITY can never be structural, can never
enter `_STRUCTURAL_LINK_CLASSES`, and (by construction, `build_correlation_group`
rejecting it) can never form/merge a `CorrelationGroup`; and architecture
guards (no `attack_knowledge`/`sources`/`dataplane`/`replay`/`api` import,
no construction of `sequence.py`/`sequence_engine.py` objects, no
attribution/scoring vocabulary).

Uses the same pure-Python golden-corpus pattern `test_correlation_contextual.py`
already established (domain contracts + `derive_evidence`), not a JSON
fixture/replay pipeline.

Does NOT touch `contextual.py`, `structural.py`, `sequence.py`,
`sequence_engine.py`, or any G0.x/G1.x source/test/fixture. Offline,
deterministic.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from attribution_platform.correlation import (
    ContextualCorrelationResult,
    CorrelationError,
    LinkClass,
    StructuralCorrelationResult,
    TemporalProximityConfig,
    TemporalProximityResult,
    compute_temporal_proximity,
    contextualize,
    correlate_structurally,
)
from attribution_platform.correlation.contracts import _STRUCTURAL_LINK_CLASSES
from attribution_platform.domain import (
    Evidence,
    EvidenceType,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
)
from attribution_platform.extraction import RuleRef, derive_evidence

REPO_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = REPO_ROOT / "src" / "attribution_platform" / "correlation"
TEMPORAL_PROXIMITY_FILE = CORRELATION_DIR / "temporal_proximity.py"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _obs(
    observation_id: str,
    *,
    timestamp: datetime = T0,
    timestamp_precision: TimePrecision | None = None,
    host: HostRef | None = None,
    process: ProcessRef | None = None,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=timestamp,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        timestamp_precision=timestamp_precision,
        host=host,
        process=process,
    )


def _evidence(
    evidence_id: str, observation: Observation, *, rule_id: str = "golden-rule"
) -> Evidence:
    return derive_evidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="synthetic G2.4.3 golden-corpus evidence",
        observations=(observation,),
        rule_ref=RuleRef(rule_id=rule_id, rule_version="1.0"),
    )


def _pair(
    evidence_id: str, observation: Observation, **kwargs: object
) -> tuple[Evidence, Observation]:
    return (_evidence(evidence_id, observation, **kwargs), observation)  # type: ignore[arg-type]


def _compute(
    items: list[tuple[Evidence, Observation]], window: timedelta
) -> tuple[
    StructuralCorrelationResult,
    ContextualCorrelationResult,
    TemporalProximityConfig,
    TemporalProximityResult,
]:
    structural_result = correlate_structurally(items)
    contextual_result = contextualize(structural_result, items)
    config = TemporalProximityConfig(window=window)
    result = compute_temporal_proximity(structural_result, contextual_result, items, config)
    return structural_result, contextual_result, config, result


# ===========================================================================
# 1-9. Matching semantics
# ===========================================================================


def test_1_inside_window_match() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=3))
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(seconds=5))
    assert len(result.temporal_proximity_links) == 1
    link = result.temporal_proximity_links[0]
    assert link.link_class == LinkClass.TEMPORAL_PROXIMITY
    assert {link.anchor_a, link.anchor_b} == {"ev-1", "ev-2"}


def test_2_outside_window_non_match() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=10))
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(seconds=5))
    assert result.temporal_proximity_links == ()


def test_3_exact_inclusive_boundary() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=5))
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(seconds=5))
    assert len(result.temporal_proximity_links) == 1  # <=, not <


def test_4_zero_window_matches_only_equal_timestamps() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0)
    obs_c = _obs("obs-c", timestamp=T0 + timedelta(microseconds=1))
    _, _, _, result_equal = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(0))
    assert len(result_equal.temporal_proximity_links) == 1
    _, _, _, result_diff = _compute([_pair("ev-1", obs_a), _pair("ev-3", obs_c)], timedelta(0))
    assert result_diff.temporal_proximity_links == ()


def test_5_negative_window_rejected_at_construction() -> None:
    with pytest.raises(CorrelationError, match="non-negative"):
        TemporalProximityConfig(window=timedelta(seconds=-1))


def test_6_coarse_precision_truncation_semantics() -> None:
    """Both timestamps truncated to the coarser (SECOND) granularity before
    comparison -- differ by 800ms raw, 0s after truncation, so they match a
    zero window despite not being exactly equal."""
    obs_a = _obs(
        "obs-a",
        timestamp=T0.replace(microsecond=100_000),
        timestamp_precision=TimePrecision.SECOND,
    )
    obs_b = _obs(
        "obs-b",
        timestamp=T0.replace(microsecond=900_000),
        timestamp_precision=TimePrecision.SECOND,
    )
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(0))
    assert len(result.temporal_proximity_links) == 1


def test_6b_unknown_precision_falls_back_to_raw_comparison() -> None:
    obs_a = _obs("obs-a", timestamp=T0, timestamp_precision=TimePrecision.UNKNOWN)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=10))
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(seconds=5))
    assert result.temporal_proximity_links == ()


def test_7_equal_timestamps_have_zero_elapsed_and_match_any_nonnegative_window() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0)
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(seconds=1))
    assert len(result.temporal_proximity_links) == 1
    assert result.temporal_proximity_links[0].basis.observed_value == repr(0.0)


def test_8_cross_host_match() -> None:
    obs_a = _obs("obs-a", timestamp=T0, host=HostRef(id="HOST-A"))
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1), host=HostRef(id="HOST-B"))
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(seconds=5))
    assert len(result.temporal_proximity_links) == 1


def test_9_same_host_match_no_special_treatment() -> None:
    host = HostRef(id="HOST-A")
    obs_a = _obs("obs-a", timestamp=T0, host=host)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1), host=host)
    _, _, _, result = _compute([_pair("ev-1", obs_a), _pair("ev-2", obs_b)], timedelta(seconds=5))
    assert len(result.temporal_proximity_links) == 1
    assert result.temporal_proximity_links[0].link_class == LinkClass.TEMPORAL_PROXIMITY


def test_10_same_process_entity_and_temporal_proximity_coexist() -> None:
    host = HostRef(id="H1")
    obs_a = _obs("obs-a", timestamp=T0, host=host, process=ProcessRef(entity_id="{X}"))
    obs_b = _obs(
        "obs-b", timestamp=T0 + timedelta(seconds=1), host=host, process=ProcessRef(entity_id="{X}")
    )
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    structural_result, contextual_result, config, result = _compute(items, timedelta(seconds=5))
    assert any(link.link_class == LinkClass.SAME_PROCESS_ENTITY for link in structural_result.links)
    assert len(result.temporal_proximity_links) == 1


# ===========================================================================
# 11-14. Multiplicity, determinism, ids, config hashing
# ===========================================================================


def test_11_multiple_pairwise_matches_no_aggregation() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1))
    obs_c = _obs("obs-c", timestamp=T0 + timedelta(seconds=2))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b), _pair("ev-3", obs_c)]
    _, _, _, result = _compute(items, timedelta(seconds=5))
    assert len(result.temporal_proximity_links) == 3  # C(3,2), each independent
    pairs = {frozenset((link.anchor_a, link.anchor_b)) for link in result.temporal_proximity_links}
    assert pairs == {
        frozenset({"ev-1", "ev-2"}),
        frozenset({"ev-1", "ev-3"}),
        frozenset({"ev-2", "ev-3"}),
    }


def test_12_reversed_shuffled_input_is_deterministic() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1))
    obs_c = _obs("obs-c", timestamp=T0 + timedelta(seconds=2))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b), _pair("ev-3", obs_c)]
    _, _, _, forward = _compute(items, timedelta(seconds=5))
    _, _, _, reversed_ = _compute(list(reversed(items)), timedelta(seconds=5))
    assert forward.temporal_proximity_links == reversed_.temporal_proximity_links


def test_13_deterministic_link_ids_stable_across_runs() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    _, _, _, result_1 = _compute(items, timedelta(seconds=5))
    _, _, _, result_2 = _compute(items, timedelta(seconds=5))
    assert (
        result_1.temporal_proximity_links[0].link_id == result_2.temporal_proximity_links[0].link_id
    )


def test_14_configuration_hash_changes_with_window() -> None:
    cfg_a = TemporalProximityConfig(window=timedelta(seconds=5))
    cfg_b = TemporalProximityConfig(window=timedelta(seconds=10))
    assert cfg_a.content_hash != cfg_b.content_hash

    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    structural_result = correlate_structurally(items)
    contextual_result = contextualize(structural_result, items)
    link_a = compute_temporal_proximity(
        structural_result, contextual_result, items, cfg_a
    ).temporal_proximity_links[0]
    link_b = compute_temporal_proximity(
        structural_result, contextual_result, items, cfg_b
    ).temporal_proximity_links[0]
    assert link_a.link_id != link_b.link_id
    assert link_a.provenance.method_content_hash == cfg_a.content_hash
    assert link_b.provenance.method_content_hash == cfg_b.content_hash


def test_caller_cannot_fabricate_content_hash() -> None:
    with pytest.raises(TypeError):
        TemporalProximityConfig(window=timedelta(seconds=5), content_hash="fabricated")  # type: ignore[call-arg]


def test_config_rejects_non_timedelta_window() -> None:
    with pytest.raises(CorrelationError, match="timedelta"):
        TemporalProximityConfig(window=5)  # type: ignore[arg-type]


# ===========================================================================
# 15. Provenance correctness
# ===========================================================================


def test_15_provenance_correctness() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=3))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    _, _, config, result = _compute(items, timedelta(seconds=5))
    link = result.temporal_proximity_links[0]

    assert link.basis.field_path == "observation.timestamp"
    assert link.basis.observed_value == repr(3.0)
    assert link.basis.uncertainty_note is not None
    assert "coincidence" in link.basis.uncertainty_note
    assert "causality" in link.basis.uncertainty_note
    assert "ordering" in link.basis.uncertainty_note
    assert "attribution" in link.basis.uncertainty_note
    assert link.provenance.method_content_hash == config.content_hash
    assert set(link.provenance.source_evidence_ids) == {"ev-1", "ev-2"}
    assert set(link.provenance.source_observation_ids) == {"obs-a", "obs-b"}


def test_endpoint_ordering_is_id_composition_only_not_chronology() -> None:
    """observation_id_a/_b order must never encode which event happened
    first -- only the lexicographically-lower evidence_id, regardless of
    which Observation's timestamp is earlier."""
    obs_a = _obs("obs-a", timestamp=T0 + timedelta(seconds=10))  # LATER, but ev-1
    obs_b = _obs("obs-b", timestamp=T0)  # EARLIER, but ev-2
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    _, _, _, result = _compute(items, timedelta(seconds=15))
    link = result.temporal_proximity_links[0]
    # ev-1 sorts first lexicographically -> its observation is _a, even
    # though it is chronologically LATER.
    assert link.basis.observation_id_a == "obs-a"
    assert link.basis.observation_id_b == "obs-b"


# ===========================================================================
# 16-17. Group attachment: union, never replacement; cross-group, never merge
# ===========================================================================


def test_16_link_attaches_to_both_touched_groups_and_unions_existing_links() -> None:
    host_a = HostRef(id="H1")
    host_b = HostRef(id="H2")
    obs_p = _obs("obs-p", timestamp=T0, host=host_a, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs(
        "obs-c",
        timestamp=T0 + timedelta(seconds=1),
        host=host_a,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"),
    )
    obs_x = _obs("obs-x", timestamp=T0, host=host_b, process=ProcessRef(entity_id="{X}"))
    obs_y = _obs(
        "obs-y",
        timestamp=T0 + timedelta(seconds=1, milliseconds=200),
        host=host_b,
        process=ProcessRef(parent_entity_id="{X}", entity_id="{Y}"),
    )
    items = [
        _pair("ev-p", obs_p),
        _pair("ev-c", obs_c),
        _pair("ev-x", obs_x),
        _pair("ev-y", obs_y),
    ]
    structural_result, contextual_result, config, result = _compute(items, timedelta(seconds=1))

    assert len(contextual_result.groups) == 2
    pre_existing_counts = {g.group_id: len(g.contextual_link_ids) for g in contextual_result.groups}
    assert all(
        count >= 1 for count in pre_existing_counts.values()
    )  # SAME_HOST_ID already attached

    assert len(result.groups) == 2
    for group in result.groups:
        # union, never replacement: at least the pre-existing count, strictly more
        # once a temporal-proximity link touches it
        assert len(group.contextual_link_ids) >= pre_existing_counts[group.group_id]
        pre_existing_ids = next(
            g.contextual_link_ids for g in contextual_result.groups if g.group_id == group.group_id
        )
        assert set(pre_existing_ids) <= set(group.contextual_link_ids)


def test_17_groups_never_merge_despite_cross_group_temporal_link() -> None:
    host_a = HostRef(id="H1")
    host_b = HostRef(id="H2")
    obs_p = _obs("obs-p", timestamp=T0, host=host_a, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs(
        "obs-c",
        timestamp=T0 + timedelta(seconds=1),
        host=host_a,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"),
    )
    obs_x = _obs("obs-x", timestamp=T0, host=host_b, process=ProcessRef(entity_id="{X}"))
    obs_y = _obs(
        "obs-y",
        timestamp=T0 + timedelta(seconds=1),
        host=host_b,
        process=ProcessRef(parent_entity_id="{X}", entity_id="{Y}"),
    )
    items = [
        _pair("ev-p", obs_p),
        _pair("ev-c", obs_c),
        _pair("ev-x", obs_x),
        _pair("ev-y", obs_y),
    ]
    _, contextual_result, _, result = _compute(items, timedelta(seconds=5))

    assert len(result.groups) == 2
    ids = {g.group_id for g in result.groups}
    original_ids = {g.group_id for g in contextual_result.groups}
    assert ids == original_ids  # same group_ids, unchanged, never merged
    member_sets = [set(g.member_evidence_ids) for g in result.groups]
    assert member_sets[0].isdisjoint(member_sets[1])
    for g in result.groups:
        assert g.structural_link_ids == next(
            og.structural_link_ids for og in contextual_result.groups if og.group_id == g.group_id
        )


# ===========================================================================
# 18. Structural isolation
# ===========================================================================


def test_18_temporal_proximity_link_cannot_be_structural() -> None:
    assert LinkClass.TEMPORAL_PROXIMITY.is_structural is False
    assert LinkClass.TEMPORAL_PROXIMITY not in _STRUCTURAL_LINK_CLASSES


def test_temporal_proximity_link_rejected_from_structural_links_parameter() -> None:
    from attribution_platform.correlation import build_correlation_group

    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    _, _, _, result = _compute(items, timedelta(seconds=5))
    link = result.temporal_proximity_links[0]

    with pytest.raises(CorrelationError, match="contextual link_class"):
        build_correlation_group(
            group_id="corr-group::fake",
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-a", "obs-b"),
            structural_links=(link,),
            provenance=link.provenance,
        )


def test_temporal_proximity_alone_creates_no_structural_link_or_group() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=T0 + timedelta(seconds=1))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    structural_result, _, _, result = _compute(items, timedelta(seconds=5))
    assert structural_result.links == ()
    assert structural_result.groups == ()
    assert result.groups == ()  # no structural group exists to attach to


# ===========================================================================
# Fail-closed input validation (mirrors G2.1/G2.2's own boundary)
# ===========================================================================


def test_rejects_non_evidence_item() -> None:
    obs_a = _obs("obs-a")
    structural_result = correlate_structurally([])
    contextual_result = contextualize(structural_result, [])
    config = TemporalProximityConfig(window=timedelta(seconds=5))
    with pytest.raises(CorrelationError, match="must be a domain Evidence"):
        compute_temporal_proximity(
            structural_result,
            contextual_result,
            [("not-evidence", obs_a)],  # type: ignore[list-item]
            config,
        )


def test_rejects_wrong_type_for_structural_result() -> None:
    contextual_result = contextualize(correlate_structurally([]), [])
    config = TemporalProximityConfig(window=timedelta(seconds=5))
    with pytest.raises(CorrelationError, match="StructuralCorrelationResult"):
        compute_temporal_proximity("not-a-result", contextual_result, [], config)  # type: ignore[arg-type]


# ===========================================================================
# 28. ATT&CK / attribution boundary + architecture guards
# ===========================================================================


def test_module_never_imports_attack_knowledge_sources_dataplane_replay_api() -> None:
    forbidden = ("attack_knowledge", "sources", "dataplane", "replay", "api")
    tree = ast.parse(TEMPORAL_PROXIMITY_FILE.read_text(encoding="utf-8"))
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and any(f"attribution_platform.{layer}" in node.module for layer in forbidden)
        ):
            offending.append(f"from {node.module} import ...")
    assert not offending, f"temporal_proximity.py must not import {forbidden}: {offending}"


def test_module_never_imports_sequence_or_sequence_engine() -> None:
    tree = ast.parse(TEMPORAL_PROXIMITY_FILE.read_text(encoding="utf-8"))
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and (node.module.endswith(".sequence") or node.module.endswith(".sequence_engine"))
        ):
            offending.append(f"from {node.module} import ...")
    assert (
        not offending
    ), f"temporal_proximity.py must not import sequence.py/sequence_engine.py: {offending}"


def test_module_never_constructs_sequence_objects_directly() -> None:
    tree = ast.parse(TEMPORAL_PROXIMITY_FILE.read_text(encoding="utf-8"))
    forbidden_calls = {
        "BehavioralSequence",
        "BehavioralStep",
        "SequenceEdge",
        "SequenceGap",
        "SequenceParallelGroup",
    }
    offending = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden_calls
    ]
    assert not offending, f"temporal_proximity.py must not construct {offending} directly"


def test_module_never_constructs_correlation_group_directly() -> None:
    """CorrelationGroup must only ever be produced via build_correlation_group
    (re-verification), never the raw constructor."""
    tree = ast.parse(TEMPORAL_PROXIMITY_FILE.read_text(encoding="utf-8"))
    offending = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "CorrelationGroup"
    ]
    assert (
        not offending
    ), f"temporal_proximity.py must not construct CorrelationGroup directly: {offending}"


def test_module_introduces_no_attribution_or_scoring_identifiers() -> None:
    forbidden_terms = (
        "likelihood",
        "confidence",
        "candidate",
        "actor",
        "campaign",
        "calibrat",
        "score",
        "weight",
        "ach",
    )
    tree = ast.parse(TEMPORAL_PROXIMITY_FILE.read_text(encoding="utf-8"))
    offending: list[str] = []
    for node in ast.walk(tree):
        name: str | None = None
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            name = node.name
        elif isinstance(node, ast.arg):
            name = node.arg
        if name is None:
            continue
        lowered = name.lower()
        for term in forbidden_terms:
            if term in lowered:
                offending.append(f"{name!r} contains forbidden term {term!r}")
    assert not offending, f"forbidden attribution/scoring identifiers found: {offending}"
