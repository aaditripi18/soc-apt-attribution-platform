"""Phase 3 — the Attribution Engine's own domain layer.

Per `ADR-0005 <../../../docs/architecture/adr/0005-attribution-engine-specification.md>`_
(ACCEPTED 2026-09-16): the Phase-3-owned contracts and, later, the
algorithms that produce them, built on top of the real, frozen Phase 0–2
domain/correlation objects and the Gate 3.1 ATT&CK knowledge-traversal layer
— never a second Evidence model, never a mutation of any Phase 0–2 object.

Gate status:

- **G3.1 (implemented, in ``attack_knowledge.traversal``):** entity
  resolution, alias resolution, active/revoked/deprecated filtering, and
  ``uses``-relationship traversal over the pinned ATT&CK KB.
- **G3.2 (implemented):** ``contracts`` — the frozen Phase-3 domain
  contracts ADR-0005 §D2/§D5/§D9/§D10 specify (``CoverageProfile``,
  ``Candidate``, ``Hypothesis``, ``EvidenceAssessment``,
  ``AttributionAssessment``, ``NextEvidence``, ``AttributionResult``,
  ``AttributionProvenance``, and the ``Likelihood``/``Confidence`` value
  objects). Data contracts only — no candidate generation, no ACH matrix,
  no diagnosticity computation, no likelihood/confidence calculation, no
  abstention, no calibration, no next-evidence algorithm. See
  ``contracts``'s own module docstring for the exact scope boundary.
- **G3.3 (implemented):** ``candidate_generation`` —
  :func:`~attribution_platform.attribution.candidate_generation.generate_candidates`
  (ADR-0005 §D7): the deterministic candidate/hypothesis SET construction
  for one attribution unit (one ``CorrelationGroup`` + its
  ``BehavioralSequence``), dynamically discovered from the pinned ATT&CK KB
  via the Gate 3.1 traversal layer — always includes the explicit
  Unattributed hypothesis, never a hard-coded actor list, never a score.
  **Set construction only** — no diagnosticity, no ACH, no likelihood/
  confidence, no abstention, no calibration. See that module's own
  docstring for the exact scope boundary.
- **G3.4 (implemented):** ``ach_matrix`` —
  :func:`~attribution_platform.attribution.ach_matrix.build_ach_matrix`
  (ADR-0005 §D4/§D8): deterministic ACH evidence-assessment / matrix
  construction from a Gate 3.3
  :class:`~attribution_platform.attribution.candidate_generation.CandidateGenerationResult`
  — structured evidence × hypothesis assessment only, never a candidate
  regeneration and never an attribution decision. The matrix is
  deliberately sparse: only ``CONSISTENT``/``SUPPORTING`` cells are
  materialized (see that module's own docstring for the proof that
  ``INCONSISTENT`` is not reachable without the not-yet-implemented
  ``CoverageProfile`` wiring). No diagnosticity (`g(x)`/`D(x)`), no ACH
  scoring, no likelihood/confidence, no abstention, no calibration.
- **G3.5 (implemented):** ``comparative_analysis`` —
  :func:`~attribution_platform.attribution.comparative_analysis.compute_comparative_evidence`
  (ADR-0005 §D3/§D4/§D8/§D9): deterministic `support(h)` comparative
  evidence aggregation from a Gate 3.4 ``ACHMatrix`` — diagnosticity
  (`g(x)`/`D(x)`/`g(C)`/`D(C)`, active-Group-population-relative,
  candidate-type-invariant) and the deterministic combination-partition
  selection rule, both per ADR-0005 §D3 exactly. **Internal comparative
  aggregation only** — no likelihood/WEP, no confidence, no calibration, no
  abstention, no winner/final attribution. See that module's own docstring
  for the exact scope boundary and its explicitly-flagged interpretive
  completions (the combination-partition *search* procedure, and the
  currently-always-zero `contradiction_strength` term).
- **B3 (implemented):** ``coverage`` —
  :func:`~attribution_platform.attribution.coverage.build_coverage_profile`
  (ADR-0005 §D2 as clarified by Amendment C (2026-09-21);
  ``docs/architecture/11-coverage-model.md``): deterministic construction of
  the ``CoverageProfile`` contract for one ``(CorrelationGroup, technique)``
  pair, from the pinned ATT&CK v19 detection graph
  (:func:`~attribution_platform.attack_knowledge.traversal.required_data_components`)
  and caller-supplied observation-presence + telemetry availability. **Construction
  only** — no coverage *consumption*, no scoring, no likelihood/confidence,
  no abstention, no calibration, no G3.6, and no telemetry-to-ATT&CK mapping
  (production availability fails closed with ``available=()``). See that
  module's own docstring for the exact scope and anti-circularity boundary.
- **Not yet implemented:** likelihood/WEP computation, confidence
  computation, abstention, calibration, next-evidence guidance, final
  attribution, persistence.
"""

from __future__ import annotations

from attribution_platform.attribution.ach_matrix import (
    ACH_MATRIX_METHOD,
    ACH_MATRIX_METHOD_VERSION,
    ACHMatrix,
    build_ach_matrix,
    compute_diagnosticity_ref,
)
from attribution_platform.attribution.candidate_generation import (
    CANDIDATE_GENERATION_METHOD,
    CANDIDATE_GENERATION_METHOD_VERSION,
    CandidateGenerationResult,
    generate_candidates,
)
from attribution_platform.attribution.comparative_analysis import (
    COMPARATIVE_ANALYSIS_METHOD,
    COMPARATIVE_ANALYSIS_METHOD_VERSION,
    DEFAULT_MIN_PROFILE_FLOOR,
    ComparativeEvidenceResult,
    DiagnosticityOutcome,
    EvidenceContribution,
    HypothesisSupportSummary,
    UnattributedBaseline,
    compute_comparative_evidence,
    compute_unattributed_decision_support,
)
from attribution_platform.attribution.contracts import (
    ATTRIBUTION_ASSESSMENT_SCHEMA_VERSION,
    ATTRIBUTION_PROVENANCE_SCHEMA_VERSION,
    ATTRIBUTION_RESULT_SCHEMA_VERSION,
    CANDIDATE_SCHEMA_VERSION,
    COVERAGE_PROFILE_SCHEMA_VERSION,
    EVIDENCE_ASSESSMENT_SCHEMA_VERSION,
    HYPOTHESIS_SCHEMA_VERSION,
    NEXT_EVIDENCE_SCHEMA_VERSION,
    UNATTRIBUTED_CANDIDATE_ID,
    AttributionAssessment,
    AttributionProvenance,
    AttributionResult,
    Candidate,
    CandidateType,
    Confidence,
    ConfidenceBand,
    ConfidenceReason,
    CoverageProfile,
    CoverageState,
    EvidenceAssessment,
    EvidenceRole,
    Hypothesis,
    Likelihood,
    NextEvidence,
    Relevance,
    SeparationBand,
    compute_attribution_assessment_id,
    compute_attribution_result_id,
    compute_candidate_id,
    compute_coverage_profile_id,
    compute_evidence_assessment_id,
    compute_hypothesis_id,
    compute_next_evidence_id,
    is_unattributed_hypothesis,
)
from attribution_platform.attribution.coverage import (
    COVERAGE_CONSTRUCTION_METHOD,
    COVERAGE_CONSTRUCTION_METHOD_VERSION,
    build_coverage_profile,
)
from attribution_platform.attribution.errors import AttributionError

__all__ = [
    "AttributionError",
    "CoverageState",
    "CoverageProfile",
    "COVERAGE_PROFILE_SCHEMA_VERSION",
    "compute_coverage_profile_id",
    "AttributionProvenance",
    "ATTRIBUTION_PROVENANCE_SCHEMA_VERSION",
    "CandidateType",
    "Candidate",
    "CANDIDATE_SCHEMA_VERSION",
    "compute_candidate_id",
    "UNATTRIBUTED_CANDIDATE_ID",
    "Hypothesis",
    "HYPOTHESIS_SCHEMA_VERSION",
    "compute_hypothesis_id",
    "is_unattributed_hypothesis",
    "EvidenceRole",
    "Relevance",
    "EvidenceAssessment",
    "EVIDENCE_ASSESSMENT_SCHEMA_VERSION",
    "compute_evidence_assessment_id",
    "SeparationBand",
    "Likelihood",
    "ConfidenceBand",
    "ConfidenceReason",
    "Confidence",
    "AttributionAssessment",
    "ATTRIBUTION_ASSESSMENT_SCHEMA_VERSION",
    "compute_attribution_assessment_id",
    "NextEvidence",
    "NEXT_EVIDENCE_SCHEMA_VERSION",
    "compute_next_evidence_id",
    "AttributionResult",
    "ATTRIBUTION_RESULT_SCHEMA_VERSION",
    "compute_attribution_result_id",
    "generate_candidates",
    "CandidateGenerationResult",
    "CANDIDATE_GENERATION_METHOD",
    "CANDIDATE_GENERATION_METHOD_VERSION",
    "build_ach_matrix",
    "ACHMatrix",
    "compute_diagnosticity_ref",
    "ACH_MATRIX_METHOD",
    "ACH_MATRIX_METHOD_VERSION",
    "compute_comparative_evidence",
    "compute_unattributed_decision_support",
    "ComparativeEvidenceResult",
    "HypothesisSupportSummary",
    "EvidenceContribution",
    "UnattributedBaseline",
    "DiagnosticityOutcome",
    "COMPARATIVE_ANALYSIS_METHOD",
    "COMPARATIVE_ANALYSIS_METHOD_VERSION",
    "DEFAULT_MIN_PROFILE_FLOOR",
    "build_coverage_profile",
    "COVERAGE_CONSTRUCTION_METHOD",
    "COVERAGE_CONSTRUCTION_METHOD_VERSION",
]
