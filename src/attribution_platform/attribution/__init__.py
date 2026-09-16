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
- **Not yet implemented:** candidate generation, ACH scoring, likelihood/
  confidence computation, abstention, calibration, next-evidence guidance,
  persistence.
"""

from __future__ import annotations

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
]
