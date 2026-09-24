"""Parameterized Amendment-B decision quantities (B1-M fitting prerequisite).

A small, deterministic, **parameterized computation layer** over a Gate 3.5
:class:`~attribution_platform.attribution.comparative_analysis.ComparativeEvidenceResult`.
It computes the Amendment-B (ADR-0005 §B2/§B5) *distinct-feature DECISION-SUPPORT
scale* quantities the later B1-M fitting and the (not-yet-built) G3.6
likelihood/confidence/abstention stages consume — **as pure functions of the
comparative result and the explicitly-supplied parameters**, never fitting them,
never choosing a value, never emitting a decision/likelihood/confidence/WEP/
abstention, and never a ``calibration_version``.

**Exact locked definitions (ADR-0005 Amendment B, verbatim scale):**

- ``decision_support(h)`` — the distinct-feature decision aggregate (§B2/§B4):
  ``Σ over h's distinct decision contributors: contribution(contributor)`` where
  a distinct atomic feature ``x`` contributes ``D(x)`` **once** (no
  ``occurrence_count`` — repetition is not part of the decision basis, §B5) and a
  combination ``C`` contributes ``D(C)`` **once**. A contributor whose ``g``/``D``
  is undefined (§D3 ``OUTSIDE_CALIBRATED_REGIME``) contributes ``0`` (§B2). This
  is the ``d_value`` of each :class:`EvidenceContribution` (once), **not** its
  ``contribution_value`` (which multiplies an atomic by its supporting-cell count
  for the *raw-support* scale — a different scale, §D4).
- ``decision_support_norm(h) = decision_support(h) / ProfileBreadth_effective(h)``
  where ``ProfileBreadth_effective(h) = max(ProfileBreadth(h), min_profile_floor)``
  (§B2 form B / Amendment A). Undefined (``None``) for the ``Unattributed``
  sentinel, which has ``profile_breadth is None`` and is outside the
  normalization domain.
- ``net(contributor) = contribution(contributor) · (1 − g(contributor))`` =
  ``D(f)·(1 − g(f))`` ``≥ 0`` (§B5).
- ``contributor_separation(h) = Σ over h's own valid decision contributors:
  net(contributor)`` — built **only** over the candidate's own contributors
  (§B5), a **different quantity** from ``separation_from_null`` (§B2).
- ``concentration(h) = max_contributor[net] / contributor_separation(h)`` — in
  ``[0, 1]``, evaluated **only when** ``contributor_separation(h) > 0`` (§B5);
  ``None`` otherwise.

- ``separation_from_null(h) = decision_support(h) − decision_support(Unattributed)``
  (§B2), both on the **un-normalized** decision-support form. Its
  candidate-independent baseline ``decision_support(Unattributed)`` is **not**
  derivable from a ``ComparativeEvidenceResult`` (the ``Unattributed`` summary
  carries an empty contribution set — reading its ``support_value`` would
  incorrectly yield ``0``). It is supplied by the caller as an
  ``UnattributedBaseline`` from ``compute_unattributed_decision_support`` (both
  in :mod:`attribution_platform.attribution.comparative_analysis`), which reuses
  the **single authoritative** §D3 partition/``g``/``D`` machinery (never a
  second definition). This module performs only the final subtraction.

Determinism: pure functions of ``(ComparativeEvidenceResult, min_profile_floor)``;
contributions are consumed in their already-canonical tuple order; no RNG, no
hashing, no global/fitted state, no input mutation, no ``AttackKnowledge`` access.
"""

from __future__ import annotations

from dataclasses import dataclass

from attribution_platform.attribution.comparative_analysis import (
    ComparativeEvidenceResult,
    EvidenceContribution,
    HypothesisSupportSummary,
    UnattributedBaseline,
)
from attribution_platform.attribution.errors import AttributionError

#: Method identity for this parameterized quantity layer (provenance only;
#: this module fits nothing and stamps no version of its own).
DECISION_QUANTITIES_METHOD = "amendment-b-decision-quantities"
DECISION_QUANTITIES_METHOD_VERSION = "1.0"


def _require_min_profile_floor(min_profile_floor: int) -> None:
    if isinstance(min_profile_floor, bool) or not isinstance(min_profile_floor, int):
        raise AttributionError(
            f"min_profile_floor must be an int, got {type(min_profile_floor).__name__}"
        )
    if min_profile_floor < 1:
        raise AttributionError(
            f"min_profile_floor must be an integer >= 1 (ADR-0005 §D16 structural bound), "
            f"got {min_profile_floor}"
        )


def net(contribution: EvidenceContribution) -> float:
    """``net(contributor) = D(f)·(1 − g(f)) ≥ 0`` (ADR-0005 §B5). A contributor
    outside the calibrated regime (undefined ``g``/``D``) is not a valid decision
    contributor and yields ``0.0`` — the same neutral treatment §B2/§B5 give it
    everywhere."""
    if contribution.d_value is None or contribution.g_value is None:
        return 0.0
    return contribution.d_value * (1.0 - contribution.g_value)


def decision_support(summary: HypothesisSupportSummary) -> float:
    """``decision_support(h)`` — the distinct-feature decision aggregate
    (ADR-0005 §B2/§B4): each distinct contributor's ``D`` (``d_value``) counted
    **once**; ``OUTSIDE_CALIBRATED_REGIME`` contributors contribute ``0``. Uses
    ``d_value`` (the decision-support scale), never ``contribution_value`` (the
    raw-support scale that folds in atomic repetition)."""
    return sum(c.d_value for c in summary.contributions if c.d_value is not None)


def decision_support_norm(
    summary: HypothesisSupportSummary, *, min_profile_floor: int
) -> float | None:
    """``decision_support_norm(h) = decision_support(h) /
    max(ProfileBreadth(h), min_profile_floor)`` (ADR-0005 §B2 form B). ``None`` for
    the ``Unattributed`` sentinel (``profile_breadth is None`` — outside the
    normalization domain). ``min_profile_floor`` is an explicit, caller-supplied
    §D16 parameter (integer ``>= 1``); this layer never chooses its value."""
    _require_min_profile_floor(min_profile_floor)
    if summary.profile_breadth is None:
        return None
    effective_breadth = max(summary.profile_breadth, min_profile_floor)
    return decision_support(summary) / effective_breadth


def contributor_separation(summary: HypothesisSupportSummary) -> float:
    """``contributor_separation(h) = Σ net(contributor)`` over h's own valid
    decision contributors (ADR-0005 §B5) — the concentration denominator, built
    **only** over the candidate's own contributors. A **different quantity** from
    ``separation_from_null`` (§B2), which is not computed here."""
    return sum(net(c) for c in summary.contributions)


def separation_from_null(
    summary: HypothesisSupportSummary, *, unattributed_decision_support: float
) -> float:
    """``separation_from_null(h) = decision_support(h) −
    decision_support(Unattributed)`` (ADR-0005 §B2), both on the un-normalized
    decision-support form. ``unattributed_decision_support`` is the §B2
    candidate-independent baseline value (from
    :func:`~attribution_platform.attribution.comparative_analysis.compute_unattributed_decision_support`)
    — **never** the ``Unattributed`` hypothesis's empty ``support_value``. This
    is the abstention quantity; it is a **different** quantity from
    ``contributor_separation`` (§B5), which this layer computes separately."""
    return decision_support(summary) - unattributed_decision_support


def concentration(summary: HypothesisSupportSummary) -> float | None:
    """``concentration(h) = max_contributor[net] / contributor_separation(h)``
    (ADR-0005 §B5), guaranteed in ``[0, 1]`` by the shared decomposition.
    Evaluated **only when** ``contributor_separation(h) > 0``; ``None`` otherwise
    (no valid separating contributor to concentrate over)."""
    nets = [net(c) for c in summary.contributions]
    separation = sum(nets)
    if separation <= 0.0:
        return None
    return max(nets) / separation


@dataclass(frozen=True)
class HypothesisDecisionQuantities:
    """The Amendment-B decision quantities for one hypothesis — a reusable,
    parameterized, non-decision aggregate (never a likelihood/confidence/WEP/
    abstention verdict). ``decision_support_norm``/``concentration`` are ``None``
    where undefined (the ``Unattributed`` sentinel / a zero contributor
    separation), never a fabricated numeric substitute."""

    hypothesis_id: str
    candidate_id: str
    decision_support: float
    decision_support_norm: float | None
    separation_from_null: float
    contributor_separation: float
    concentration: float | None


@dataclass(frozen=True)
class DecisionQuantitiesResult:
    """The per-hypothesis decision quantities for one attribution unit, carrying
    the same ``group_id``/``attack_kb_version`` identity its source
    ``ComparativeEvidenceResult`` did (read-only; the source is never mutated).
    ``min_profile_floor`` is echoed as the explicit parameter used, for
    provenance — this layer never fits or chooses it."""

    group_id: str
    attack_kb_version: str
    min_profile_floor: int
    unattributed_decision_support: float
    hypotheses: tuple[HypothesisDecisionQuantities, ...] = ()


def compute_decision_quantities(
    result: ComparativeEvidenceResult,
    *,
    min_profile_floor: int,
    unattributed_baseline: UnattributedBaseline,
) -> DecisionQuantitiesResult:
    """Compute the Amendment-B decision quantities for every hypothesis in a
    Gate 3.5 ``ComparativeEvidenceResult`` (deterministic, input-immutable,
    parameterized). ``separation_from_null`` uses ``unattributed_baseline`` — the
    §B2 candidate-independent baseline computed by
    :func:`~attribution_platform.attribution.comparative_analysis.compute_unattributed_decision_support`
    over the **same** case — never the ``Unattributed`` summary's empty support.
    Fails closed if the baseline is for a different ``group_id``/``attack_kb_version``."""
    _require_min_profile_floor(min_profile_floor)
    if not isinstance(result, ComparativeEvidenceResult):
        raise AttributionError(
            f"compute_decision_quantities: result must be a ComparativeEvidenceResult, "
            f"got {type(result).__name__}"
        )
    if not isinstance(unattributed_baseline, UnattributedBaseline):
        raise AttributionError(
            "compute_decision_quantities: unattributed_baseline must be an "
            f"UnattributedBaseline, got {type(unattributed_baseline).__name__}"
        )
    if unattributed_baseline.group_id != result.group_id:
        raise AttributionError(
            f"compute_decision_quantities: unattributed_baseline.group_id "
            f"{unattributed_baseline.group_id!r} does not match result.group_id "
            f"{result.group_id!r} — the baseline must be from the same case"
        )
    if unattributed_baseline.attack_kb_version != result.attack_kb_version:
        raise AttributionError(
            "compute_decision_quantities: unattributed_baseline.attack_kb_version "
            f"{unattributed_baseline.attack_kb_version!r} does not match "
            f"result.attack_kb_version {result.attack_kb_version!r}"
        )
    baseline = unattributed_baseline.decision_support
    hypotheses = tuple(
        HypothesisDecisionQuantities(
            hypothesis_id=summary.hypothesis_id,
            candidate_id=summary.candidate_id,
            decision_support=decision_support(summary),
            decision_support_norm=decision_support_norm(
                summary, min_profile_floor=min_profile_floor
            ),
            separation_from_null=separation_from_null(
                summary, unattributed_decision_support=baseline
            ),
            contributor_separation=contributor_separation(summary),
            concentration=concentration(summary),
        )
        for summary in result.hypothesis_summaries
    )
    return DecisionQuantitiesResult(
        group_id=result.group_id,
        attack_kb_version=result.attack_kb_version,
        min_profile_floor=min_profile_floor,
        unattributed_decision_support=baseline,
        hypotheses=hypotheses,
    )


__all__ = [
    "DECISION_QUANTITIES_METHOD",
    "DECISION_QUANTITIES_METHOD_VERSION",
    "net",
    "decision_support",
    "decision_support_norm",
    "separation_from_null",
    "contributor_separation",
    "concentration",
    "HypothesisDecisionQuantities",
    "DecisionQuantitiesResult",
    "compute_decision_quantities",
]
