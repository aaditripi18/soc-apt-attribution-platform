"""Tests for the parameterized Amendment-B decision-quantity engine
(ADR-0005 §B2/§B5; B1-M fitting prerequisite).

Semantic tests over hand-computable inputs: decision_support (distinct-feature
``D`` once — NOT the raw-support ``contribution_value`` scale),
decision_support_norm (``min_profile_floor``-parameterized), net /
contributor_separation, concentration, and separation_from_null. The
candidate-independent §B2 baseline (``compute_unattributed_decision_support``)
is exercised against the real pinned KB with exactly-hand-computable ``D·g``
values, proving it is derived from the real §D3 machinery, is
candidate-independent, and is never the Unattributed summary's empty ``0``.
Deterministic, PYTHONHASHSEED-independent, input-immutable; no fitting.
"""

from __future__ import annotations

import inspect
import subprocess
import sys
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import active_groups, groups_using_technique
from attribution_platform.attribution import decision_quantities as dq_module
from attribution_platform.attribution.ach_matrix import ACHMatrix, compute_diagnosticity_ref
from attribution_platform.attribution.comparative_analysis import (
    ComparativeEvidenceResult,
    DiagnosticityOutcome,
    EvidenceContribution,
    HypothesisSupportSummary,
    UnattributedBaseline,
    compute_unattributed_decision_support,
)
from attribution_platform.attribution.contracts import (
    EvidenceAssessment,
    EvidenceRole,
    Relevance,
)
from attribution_platform.attribution.decision_quantities import (
    compute_decision_quantities,
    concentration,
    contributor_separation,
    decision_support,
    decision_support_norm,
    net,
    separation_from_null,
)
from attribution_platform.attribution.errors import AttributionError

REPO_ROOT = Path(__file__).resolve().parents[1]
_KB_VERSION = "enterprise-attack-19.0"


def _baseline(value: float, *, group_id: str = "corr-group::x") -> UnattributedBaseline:
    return UnattributedBaseline(
        group_id=group_id,
        attack_kb_version=_KB_VERSION,
        decision_support=value,
        observed_feature_count=1,
    )


def _resolved(
    features: tuple[str, ...], *, g: float, d: float, cells: int = 1
) -> EvidenceContribution:
    # contribution_value is the RAW-support scale: d*cells for an atomic, d for a
    # combination (ADR-0005 §D4). decision_support must ignore this and use d once.
    contribution_value = d * cells if len(features) == 1 else d
    return EvidenceContribution(
        feature_stix_ids=features,
        diagnosticity_outcome=DiagnosticityOutcome.RESOLVED,
        g_value=g,
        d_value=d,
        assessment_ids=("assess-1",),
        contribution_value=contribution_value,
    )


def _outside(features: tuple[str, ...]) -> EvidenceContribution:
    return EvidenceContribution(
        feature_stix_ids=features,
        diagnosticity_outcome=DiagnosticityOutcome.OUTSIDE_CALIBRATED_REGIME,
        g_value=None,
        d_value=None,
        assessment_ids=("assess-1",),
        contribution_value=0.0,
    )


def _summary(
    contribs: tuple[EvidenceContribution, ...],
    *,
    profile_breadth: int | None,
    hid: str = "hyp-1",
    cid: str = "cand-1",
) -> HypothesisSupportSummary:
    raw = sum(c.contribution_value for c in contribs)
    return HypothesisSupportSummary(
        hypothesis_id=hid,
        candidate_id=cid,
        support_value=raw,
        raw_support_value=raw,
        profile_breadth=profile_breadth,
        profile_breadth_floor_applied=False,
        contributions=contribs,
    )


# ===========================================================================
# decision_support — distinct-feature D once (NOT raw-support scale)
# ===========================================================================


def test_decision_support_sums_d_value_once_per_contributor() -> None:
    s = _summary(
        (_resolved(("t-a",), g=0.5, d=0.5), _resolved(("t-b",), g=0.2, d=0.8)),
        profile_breadth=4,
    )
    assert decision_support(s) == pytest.approx(1.3)


def test_decision_support_ignores_atomic_repetition_multiplicity() -> None:
    # An atomic observed 3 times has contribution_value = d*3 (raw-support), but
    # decision_support counts its D exactly once (ADR-0005 §B2/§B5).
    s = _summary((_resolved(("t-a",), g=0.3, d=0.4, cells=3),), profile_breadth=2)
    assert s.raw_support_value == pytest.approx(1.2)  # raw-support scale (d*3)
    assert decision_support(s) == pytest.approx(0.4)  # decision scale (D once)


def test_decision_support_combination_counts_once() -> None:
    s = _summary((_resolved(("t-a", "t-b"), g=0.1, d=0.9),), profile_breadth=3)
    assert decision_support(s) == pytest.approx(0.9)


def test_decision_support_outside_calibrated_regime_contributes_zero() -> None:
    s = _summary(
        (_resolved(("t-a",), g=0.5, d=0.5), _outside(("t-b",))),
        profile_breadth=2,
    )
    assert decision_support(s) == pytest.approx(0.5)


def test_decision_support_empty_is_zero() -> None:
    assert decision_support(_summary((), profile_breadth=3)) == 0.0


# ===========================================================================
# decision_support_norm — min_profile_floor parameterized
# ===========================================================================


def test_decision_support_norm_divides_by_effective_breadth() -> None:
    s = _summary((_resolved(("t-a",), g=0.2, d=0.8),), profile_breadth=4)
    # breadth 4 >= floor 2 -> divide by 4
    assert decision_support_norm(s, min_profile_floor=2) == pytest.approx(0.2)


def test_decision_support_norm_applies_floor_when_breadth_below_floor() -> None:
    s = _summary((_resolved(("t-a",), g=0.2, d=0.8),), profile_breadth=1)
    # breadth 1 < floor 4 -> divide by 4
    assert decision_support_norm(s, min_profile_floor=4) == pytest.approx(0.2)


def test_decision_support_norm_is_none_for_unattributed() -> None:
    # Unattributed sentinel: profile_breadth is None, outside the normalization domain.
    s = _summary((), profile_breadth=None, hid="unattributed", cid="unattributed")
    assert decision_support_norm(s, min_profile_floor=2) is None


# ===========================================================================
# net / contributor_separation / concentration
# ===========================================================================


def test_net_is_d_times_one_minus_g() -> None:
    assert net(_resolved(("t-a",), g=0.25, d=0.8)) == pytest.approx(0.6)
    assert net(_outside(("t-a",))) == 0.0


def test_contributor_separation_sums_net() -> None:
    s = _summary(
        (_resolved(("t-a",), g=0.5, d=0.5), _resolved(("t-b",), g=0.2, d=0.8)),
        profile_breadth=4,
    )
    # net = 0.25 + 0.64
    assert contributor_separation(s) == pytest.approx(0.89)


def test_concentration_single_dominant_contributor() -> None:
    s = _summary(
        (_resolved(("t-a",), g=0.0, d=1.0), _resolved(("t-b",), g=0.9, d=0.1)),
        profile_breadth=4,
    )
    # nets: 1.0 and 0.01 -> concentration = 1.0 / 1.01
    assert concentration(s) == pytest.approx(1.0 / 1.01)


def test_concentration_equal_contributors_is_half() -> None:
    s = _summary(
        (_resolved(("t-a",), g=0.5, d=0.5), _resolved(("t-b",), g=0.5, d=0.5)),
        profile_breadth=4,
    )
    assert concentration(s) == pytest.approx(0.5)


def test_concentration_is_none_when_separation_zero() -> None:
    # All contributors outside the calibrated regime -> separation 0 -> None.
    s = _summary((_outside(("t-a",)), _outside(("t-b",))), profile_breadth=2)
    assert contributor_separation(s) == 0.0
    assert concentration(s) is None


def test_concentration_in_unit_interval() -> None:
    s = _summary(
        (
            _resolved(("t-a",), g=0.1, d=0.9),
            _resolved(("t-b",), g=0.4, d=0.6),
            _resolved(("t-c",), g=0.7, d=0.3),
        ),
        profile_breadth=5,
    )
    value = concentration(s)
    assert value is not None and 0.0 <= value <= 1.0


# ===========================================================================
# compute_decision_quantities — result-level, null/unattributed, sensitivity
# ===========================================================================


def _result() -> ComparativeEvidenceResult:
    real = _summary(
        (_resolved(("t-a",), g=0.2, d=0.8), _resolved(("t-b",), g=0.5, d=0.5)),
        profile_breadth=4,
        hid="hyp-real",
        cid="cand-real",
    )
    unattributed = _summary((), profile_breadth=None, hid="hyp-unattr", cid="unattributed")
    return ComparativeEvidenceResult(
        group_id="corr-group::x",
        attack_kb_version="enterprise-attack-19.0",
        hypothesis_summaries=(real, unattributed),
    )


def test_compute_maps_every_hypothesis_and_handles_unattributed() -> None:
    out = compute_decision_quantities(
        _result(), min_profile_floor=2, unattributed_baseline=_baseline(0.5)
    )
    assert out.group_id == "corr-group::x"
    assert out.attack_kb_version == "enterprise-attack-19.0"
    assert out.min_profile_floor == 2
    assert out.unattributed_decision_support == pytest.approx(0.5)
    assert len(out.hypotheses) == 2
    by_id = {h.hypothesis_id: h for h in out.hypotheses}
    real = by_id["hyp-real"]
    assert real.decision_support == pytest.approx(1.3)
    assert real.decision_support_norm == pytest.approx(1.3 / 4)
    # separation_from_null = decision_support - baseline = 1.3 - 0.5
    assert real.separation_from_null == pytest.approx(0.8)
    assert real.contributor_separation == pytest.approx(0.8 * 0.8 + 0.5 * 0.5)
    unattr = by_id["hyp-unattr"]
    assert unattr.decision_support == 0.0
    assert unattr.decision_support_norm is None
    assert unattr.concentration is None


def test_min_profile_floor_only_affects_normalization() -> None:
    a = compute_decision_quantities(
        _result(), min_profile_floor=2, unattributed_baseline=_baseline(0.5)
    )
    b = compute_decision_quantities(
        _result(), min_profile_floor=8, unattributed_baseline=_baseline(0.5)
    )
    ra = next(h for h in a.hypotheses if h.hypothesis_id == "hyp-real")
    rb = next(h for h in b.hypotheses if h.hypothesis_id == "hyp-real")
    # breadth 4: floor 2 -> /4 ; floor 8 -> /8 (norm changes)
    assert ra.decision_support_norm == pytest.approx(1.3 / 4)
    assert rb.decision_support_norm == pytest.approx(1.3 / 8)
    # the un-normalized quantities are independent of the floor
    assert ra.decision_support == rb.decision_support
    assert ra.separation_from_null == rb.separation_from_null
    assert ra.contributor_separation == rb.contributor_separation
    assert ra.concentration == rb.concentration


def test_min_profile_floor_must_be_int_ge_one() -> None:
    for bad in (0, -1):
        with pytest.raises(AttributionError, match=">= 1"):
            compute_decision_quantities(
                _result(), min_profile_floor=bad, unattributed_baseline=_baseline(0.0)
            )
    with pytest.raises(AttributionError, match="must be an int"):
        # bool is an int subtype at the type level; rejected at runtime (fail closed).
        compute_decision_quantities(
            _result(), min_profile_floor=True, unattributed_baseline=_baseline(0.0)
        )


# ===========================================================================
# Determinism / immutability / no-hidden-state
# ===========================================================================


def test_repeated_computation_identical() -> None:
    assert compute_decision_quantities(
        _result(), min_profile_floor=3, unattributed_baseline=_baseline(0.5)
    ) == compute_decision_quantities(
        _result(), min_profile_floor=3, unattributed_baseline=_baseline(0.5)
    )


def test_inputs_not_mutated() -> None:
    result = _result()
    before = (
        result.group_id,
        tuple((s.hypothesis_id, s.contributions) for s in result.hypothesis_summaries),
    )
    compute_decision_quantities(result, min_profile_floor=3, unattributed_baseline=_baseline(0.5))
    after = (
        result.group_id,
        tuple((s.hypothesis_id, s.contributions) for s in result.hypothesis_summaries),
    )
    assert before == after


def test_min_profile_floor_is_required_keyword_no_default() -> None:
    # No hidden/fitted default: the floor must be supplied explicitly.
    for fn in (compute_decision_quantities, decision_support_norm):
        param = inspect.signature(fn).parameters["min_profile_floor"]
        assert param.default is inspect.Parameter.empty
        assert param.kind is inspect.Parameter.KEYWORD_ONLY


def test_module_does_not_access_attack_knowledge_or_hashlib() -> None:
    for name in ("AttackKnowledge", "hashlib", "random"):
        assert not hasattr(dq_module, name), f"decision_quantities must not reference {name!r}"


_SUBPROCESS = """
from attribution_platform.attribution.comparative_analysis import (
    ComparativeEvidenceResult,
    DiagnosticityOutcome,
    EvidenceContribution,
    HypothesisSupportSummary,
    UnattributedBaseline,
)
from attribution_platform.attribution.decision_quantities import compute_decision_quantities

R = DiagnosticityOutcome.RESOLVED
c1 = EvidenceContribution(
    feature_stix_ids=("t-a",), diagnosticity_outcome=R,
    g_value=0.2, d_value=0.8, assessment_ids=("a",), contribution_value=0.8)
c2 = EvidenceContribution(
    feature_stix_ids=("t-b", "t-c"), diagnosticity_outcome=R,
    g_value=0.5, d_value=0.5, assessment_ids=("a",), contribution_value=0.5)
s = HypothesisSupportSummary(
    hypothesis_id="h", candidate_id="c", support_value=1.3, raw_support_value=1.3,
    profile_breadth=3, profile_breadth_floor_applied=False, contributions=(c1, c2))
r = ComparativeEvidenceResult(group_id="g", attack_kb_version="v", hypothesis_summaries=(s,))
b = UnattributedBaseline(group_id="g", attack_kb_version="v", decision_support=0.5,
    observed_feature_count=2)
h = compute_decision_quantities(r, min_profile_floor=2, unattributed_baseline=b).hypotheses[0]
print(
    f"{h.decision_support}|{h.decision_support_norm}|{h.separation_from_null}"
    f"|{h.contributor_separation}|{h.concentration}")
"""


def _run_under_seed(seed: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", _SUBPROCESS],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    ).stdout.strip()


def test_pythonhashseed_independent() -> None:
    first = _run_under_seed("0")
    assert first
    assert first == _run_under_seed("1") == _run_under_seed("424242")


# ===========================================================================
# separation_from_null (arithmetic) + the candidate-independent §B2 baseline
# ===========================================================================


def test_separation_from_null_is_decision_support_minus_baseline() -> None:
    s = _summary(
        (_resolved(("t-a",), g=0.2, d=0.8), _resolved(("t-b",), g=0.5, d=0.5)),
        profile_breadth=4,
    )
    assert separation_from_null(s, unattributed_decision_support=0.5) == pytest.approx(1.3 - 0.5)


def test_baseline_is_candidate_independent_by_construction() -> None:
    # The §B2 baseline takes only (matrix, knowledge) — never a candidate set.
    assert list(inspect.signature(compute_unattributed_decision_support).parameters) == [
        "matrix",
        "knowledge",
    ]


def test_compute_rejects_baseline_from_a_different_case() -> None:
    with pytest.raises(AttributionError, match="group_id"):
        compute_decision_quantities(
            _result(),
            min_profile_floor=2,
            unattributed_baseline=_baseline(0.5, group_id="a-different-group"),
        )


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _first_used_technique(kb: AttackKnowledge) -> str:
    for technique in kb.techniques():
        if groups_using_technique(kb, str(technique["id"])):
            return str(technique["id"])
    raise AssertionError("expected at least one technique with an active-Group user")


def _matrix(
    kb: AttackKnowledge,
    technique_ids: tuple[str, ...],
    *,
    role: EvidenceRole = EvidenceRole.SUPPORTING,
    group_id: str = "corr-group::real",
) -> ACHMatrix:
    assessments = tuple(
        EvidenceAssessment(
            assessment_id=f"assess-{i}",
            hypothesis_id="hyp-x",
            step_id="step-1",
            technique_stix_id=technique_id,
            role=role,
            relevance=Relevance.CONSISTENT,
            diagnosticity_ref=compute_diagnosticity_ref(technique_id, kb.attack_kb_version),
        )
        for i, technique_id in enumerate(technique_ids)
    )
    return ACHMatrix(
        group_id=group_id, attack_kb_version=kb.attack_kb_version, assessments=assessments
    )


def test_baseline_single_feature_is_exactly_d_times_g_from_real_machinery(
    knowledge: AttackKnowledge,
) -> None:
    technique = _first_used_technique(knowledge)
    active_count = len(active_groups(knowledge))
    g = len(groups_using_technique(knowledge, technique)) / active_count
    baseline = compute_unattributed_decision_support(_matrix(knowledge, (technique,)), knowledge)
    # exact §B2 D*g using the real §D3 g (D = 1 - g), proving reuse of the real machinery
    assert baseline.decision_support == pytest.approx((1.0 - g) * g)
    assert baseline.observed_feature_count == 1
    assert baseline.decision_support > 0.0  # a real, non-zero baseline
    assert baseline.group_id == "corr-group::real"
    assert baseline.attack_kb_version == knowledge.attack_kb_version


def test_baseline_is_not_the_unattributed_summarys_empty_zero(
    knowledge: AttackKnowledge,
) -> None:
    # The Unattributed hypothesis's support is 0.0; the §B2 baseline is NOT that.
    baseline = compute_unattributed_decision_support(
        _matrix(knowledge, (_first_used_technique(knowledge),)), knowledge
    )
    assert baseline.decision_support > 0.0
    real = _summary((_resolved(("f",), g=0.2, d=0.8),), profile_breadth=4)
    using_real = separation_from_null(real, unattributed_decision_support=baseline.decision_support)
    using_empty_zero = separation_from_null(real, unattributed_decision_support=0.0)
    assert using_real != using_empty_zero
    assert using_real == pytest.approx(0.8 - baseline.decision_support)


def test_baseline_multi_feature_is_positive(knowledge: AttackKnowledge) -> None:
    used = tuple(
        str(t["id"])
        for t in knowledge.techniques()
        if groups_using_technique(knowledge, str(t["id"]))
    )[:2]
    if len(used) < 2:  # pragma: no cover - the real bundle has many
        pytest.skip("need two techniques with active-Group users")
    baseline = compute_unattributed_decision_support(_matrix(knowledge, used), knowledge)
    assert baseline.observed_feature_count == 2
    assert baseline.decision_support > 0.0


def test_baseline_rejects_contradicting_cells(knowledge: AttackKnowledge) -> None:
    matrix = _matrix(
        knowledge, (_first_used_technique(knowledge),), role=EvidenceRole.CONTRADICTING
    )
    with pytest.raises(AttributionError, match="CONTRADICTING"):
        compute_unattributed_decision_support(matrix, knowledge)


def test_baseline_deterministic_and_does_not_mutate_knowledge(
    knowledge: AttackKnowledge,
) -> None:
    matrix = _matrix(knowledge, (_first_used_technique(knowledge),))
    fingerprint = knowledge.object_fingerprint
    a = compute_unattributed_decision_support(matrix, knowledge)
    b = compute_unattributed_decision_support(matrix, knowledge)
    assert a == b
    assert knowledge.object_fingerprint is fingerprint


_BASELINE_SUBPROCESS = """
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import groups_using_technique
from attribution_platform.attribution.ach_matrix import ACHMatrix, compute_diagnosticity_ref
from attribution_platform.attribution.comparative_analysis import (
    compute_unattributed_decision_support)
from attribution_platform.attribution.contracts import EvidenceAssessment, EvidenceRole, Relevance

kb = load_attack_knowledge()
tid = next(str(t["id"]) for t in kb.techniques() if groups_using_technique(kb, str(t["id"])))
matrix = ACHMatrix(
    group_id="g", attack_kb_version=kb.attack_kb_version,
    assessments=(EvidenceAssessment(
        assessment_id="a", hypothesis_id="h", step_id="s", technique_stix_id=tid,
        role=EvidenceRole.SUPPORTING, relevance=Relevance.CONSISTENT,
        diagnosticity_ref=compute_diagnosticity_ref(tid, kb.attack_kb_version)),))
print(compute_unattributed_decision_support(matrix, kb).decision_support)
"""


def _run_baseline_under_seed(seed: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", _BASELINE_SUBPROCESS],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    ).stdout.strip()


def test_baseline_pythonhashseed_independent() -> None:
    first = _run_baseline_under_seed("0")
    assert first and float(first) > 0.0
    assert first == _run_baseline_under_seed("1") == _run_baseline_under_seed("424242")
