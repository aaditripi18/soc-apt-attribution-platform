"""Investigations: engine runs whose every result is persisted for the
read-model API (ADR-0009).

An investigation runs the unmodified pipeline over one source (a pinned
recording or a replay fixture), runs the Gate 3.3-3.5 attribution stages on
every attribution unit, and persists everything the API serves: Evidence and
their Observations, correlation links and groups, behavioral sequences, one
explicitly **uncalibrated** attribution analysis per unit (ADR-0009 D3), and
the Investigation record itself. The API never computes; this package is where
the computation happens.
"""

from __future__ import annotations

from attribution_platform.investigation.records import (
    ATTRIBUTION_ANALYSES_INDEX,
    INVESTIGATIONS_INDEX,
    AttributionAnalysisRecord,
    CalibrationStatus,
    CandidateView,
    ContributionView,
    HypothesisView,
    InvestigationRecord,
    list_investigations,
    load_attribution_analysis,
    load_investigation,
    persist_attribution_analysis,
    persist_investigation,
)
from attribution_platform.investigation.run import INVESTIGATION_METHOD_VERSION, run_investigation

__all__ = [
    "ATTRIBUTION_ANALYSES_INDEX",
    "INVESTIGATIONS_INDEX",
    "INVESTIGATION_METHOD_VERSION",
    "AttributionAnalysisRecord",
    "CalibrationStatus",
    "CandidateView",
    "ContributionView",
    "HypothesisView",
    "InvestigationRecord",
    "list_investigations",
    "load_attribution_analysis",
    "load_investigation",
    "persist_attribution_analysis",
    "persist_investigation",
    "run_investigation",
]
