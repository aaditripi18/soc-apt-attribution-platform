"""CoverageProfile construction (Phase-3 prerequisite B3).

ADR-0005 §D2, as clarified by **Amendment C (2026-09-21)** and specified in
``docs/architecture/11-coverage-model.md``. This module constructs the frozen
:class:`~attribution_platform.attribution.contracts.CoverageProfile` contract
for one ``(CorrelationGroup, technique)`` pair from the pinned ATT&CK detection
graph and the case's own telemetry facts.

**Construction only — no attribution decision, no scoring, no consumption.**
Nothing here computes likelihood/confidence/WEP/abstention, generates
candidates, builds an ACH matrix, or *consumes* a ``CoverageProfile``. It reads
only: the pinned ATT&CK detection graph (via
:func:`~attribution_platform.attack_knowledge.traversal.required_data_components`),
the technique identity, the caller-supplied technique-observation presence, and
the caller-supplied telemetry availability. It never reads candidate sets,
``g(x)``/``g(C)``/``D(x)``, ACH results, hypotheses, or any attribution output
(the anti-circularity boundary, doc 11 §8).

**Canonical vocabulary (locked, doc 11 §2).** ``data_sources_required`` and
``data_sources_available`` are **active ATT&CK v19 ``x-mitre-data-component``
names**. The required side is derived deterministically from the pinned KB; the
available side is an **explicit caller input** — never inferred here.

**Calibration vs production (locked, doc 11 §4/§7).** ``available_data_components``
is supplied by the caller: production passes ``()`` (fail-closed — no approved
telemetry-to-ATT&CK mapping exists yet, so an unobserved technique with a
non-empty requirement resolves to ``NOT_OBSERVABLE`` and production can never
emit ``OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE``); a calibration caller may pass
a labeled case's declared ``coverage_assumptions`` (canonical data-component
names). Passing ``None`` marks availability as **indeterminate/unresolved** →
``UNKNOWN`` (doc 11 §5). This module never reads a ``CalibrationCase`` and holds
no calibration-vs-production branch — the separation is a property of which
caller passes which availability.

Determinism: a pure function of ``(pinned AttackKnowledge, group_id,
technique_stix_id, observed_present, available_data_components, provenance,
observation_interval)`` — sorted-unique component sets, ``PYTHONHASHSEED``-
independent, never mutating ``knowledge``. Identity uses the existing
:func:`~attribution_platform.attribution.contracts.compute_coverage_profile_id`
and the pinned ``attack_kb_version``; no second identity mechanism is created.
"""

from __future__ import annotations

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import required_data_components
from attribution_platform.attribution.contracts import (
    AttributionProvenance,
    CoverageProfile,
    CoverageState,
    compute_coverage_profile_id,
)
from attribution_platform.domain.entities import TimeSpan

#: Identity of this construction method (for a caller that stamps it into the
#: supplied :class:`AttributionProvenance`); this module never fabricates a
#: provenance itself.
COVERAGE_CONSTRUCTION_METHOD = "coverage-profile-construction"
COVERAGE_CONSTRUCTION_METHOD_VERSION = "1.0"


def _derive_coverage_state(
    *,
    observed_present: bool,
    required: tuple[str, ...],
    available: tuple[str, ...] | None,
) -> CoverageState:
    """The locked four-state rule (ADR-0005 §D2 / Amendment C; doc 11 §5).

    Binary "adequate coverage" (a non-empty required-∩-available intersection);
    no thresholds, percentages, weights, or per-technique exceptions. Order is
    significant: an observed technique is ``OBSERVED_PRESENT`` regardless of
    required/available; indeterminate availability (``None``) and an empty
    requirement both fail closed to ``UNKNOWN``."""
    if observed_present:
        return CoverageState.OBSERVED_PRESENT
    if available is None:
        # availability indeterminate / unresolved -> fail closed (doc 11 §5).
        return CoverageState.UNKNOWN
    if not required:
        # no derivable data-source requirement -> fail closed, never assumed
        # observable or adequately absent (doc 11 §5/§11).
        return CoverageState.UNKNOWN
    if set(required) & set(available):
        return CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE
    return CoverageState.NOT_OBSERVABLE


def build_coverage_profile(
    knowledge: AttackKnowledge,
    *,
    group_id: str,
    technique_stix_id: str,
    observed_present: bool,
    provenance: AttributionProvenance,
    available_data_components: tuple[str, ...] | None = (),
    observation_interval: TimeSpan | None = None,
) -> CoverageProfile:
    """Construct the ``CoverageProfile`` for one ``(group, technique)`` pair.

    - ``required`` = :func:`required_data_components` over the pinned detection
      graph (active-filtered at every hop; fails closed on an unknown or
      non-``attack-pattern`` ``technique_stix_id``; an inactive technique or one
      with no resolvable active data-component yields ``()``).
    - ``available`` = ``available_data_components`` — an explicit caller input.
      Production passes ``()``; calibration passes a case's declared
      ``coverage_assumptions``; ``None`` marks availability indeterminate.
    - ``observed_present`` = whether the case's active ``Evidence`` identified
      this technique (computed by the caller from ``Evidence.attack_ref`` — this
      module takes the boolean, never the evidence set, preserving the
      anti-circularity boundary).
    - ``state`` = the locked four-state rule (:func:`_derive_coverage_state`).
    - identity via :func:`compute_coverage_profile_id`; ``attack_kb_version``
      from the pinned ``knowledge``; ``provenance``/``observation_interval`` are
      the caller's, passed through unchanged.
    """
    required = required_data_components(knowledge, technique_stix_id)
    state = _derive_coverage_state(
        observed_present=observed_present,
        required=required,
        available=available_data_components,
    )
    available_tuple: tuple[str, ...] = (
        () if available_data_components is None else tuple(available_data_components)
    )
    return CoverageProfile(
        coverage_id=compute_coverage_profile_id(group_id, technique_stix_id),
        group_id=group_id,
        technique_stix_id=technique_stix_id,
        attack_kb_version=knowledge.attack_kb_version,
        state=state,
        provenance=provenance,
        data_sources_required=required,
        data_sources_available=available_tuple,
        observation_interval=observation_interval,
    )
