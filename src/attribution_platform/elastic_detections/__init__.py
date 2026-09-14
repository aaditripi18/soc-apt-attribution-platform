"""Elastic Detection Engine alerts -> the existing DetectionResult/Evidence
path (gate G1.1).

Cross-cutting integration, not core detection logic — mirrors why
``replay/`` (gate G0.9) is its own top-level package rather than living
inside ``sources``, ``extraction``, or ``dataplane``: this package composes
``dataplane`` (a bounded, read-only Elastic query), ``attack_knowledge``
(ATT&CK-mapping validation), and ``detection`` (the output contract +
existing Evidence fan-out) — a combination none of those packages may
depend on *from* each other. ``detection`` itself stays exactly what G1.0
made it: source-agnostic and Elastic-free. Nothing in this package modifies
``detection.rules.DetectionEngine`` or any G1.0 contract; it only
*constructs* the same ``DetectionResult`` type an Elastic-free rule engine
run would have.

Gate status:

- **G1.1 (implemented):** ``alerts`` — ``fetch_recent_alerts()`` (a bounded,
  read-only Elastic query via the G0.8 ``ElasticClient.search`` addition)
  and ``normalize_elastic_alert()`` (pure: one Elastic Security alert
  document -> one G1.0 ``DetectionResult``, with every ATT&CK mapping
  validated against the pinned v19.0 KB via the existing
  ``resolve_attack_ref`` — never trusted from Elastic blindly). The
  resulting ``DetectionResult`` is fed into the existing, unmodified
  ``attribution_platform.detection.derive_evidence_from_detection`` by the
  caller — no second Evidence-derivation implementation exists here.
- **Not yet implemented:** multi-event/correlated alerts (Phase 2); writing
  anything back to Elastic (read-only); persistence of the resulting
  DetectionResult/Evidence (a later gate's concern, same as G1.0); any
  attribution, candidate generation, or scoring.
"""

from __future__ import annotations

from attribution_platform.elastic_detections.alerts import (
    DEFAULT_ALERT_FETCH_SIZE,
    DEFAULT_ALERTS_INDEX,
    ELASTIC_ALERT_SOURCE,
    fetch_recent_alerts,
    normalize_elastic_alert,
)

__all__ = [
    "ELASTIC_ALERT_SOURCE",
    "DEFAULT_ALERTS_INDEX",
    "DEFAULT_ALERT_FETCH_SIZE",
    "fetch_recent_alerts",
    "normalize_elastic_alert",
]
