"""Wazuh alert -> DetectionResult (ADR-0023).

A Wazuh alert is a detection Wazuh already made. This module does not judge it
again: it records *that Wazuh rule R fired on this host at this time* and takes
the ATT&CK ids the rule itself declares (``rule.mitre.id``).

**ATT&CK ids are validated, never trusted.** Each declared id is resolved in
the pinned knowledge base (following ``revoked-by``, as the rule importers do).
An id the knowledge base does not have is not mapped and not replaced; it is
named in the match basis, so the Evidence says the rule declared it. An alert
none of whose ids resolve — or that declares none — yields no detection: it
stays an Observation, with nothing claimed about technique.

**Tiers** (the platform's policy, stated; not Wazuh's). Wazuh's rule
classification describes levels 0–6 as ignored events, notifications, errors,
authorised events and "low relevance" attacks. Alerts of those levels are the
enrich tier — Evidence quality ``low``, which never forms an activity cluster on
its own (ADR-0003 Amendment H) — exactly as Elastic's ``low`` severity rules
are. Level 7 and above is the core tier.

**What this is not.** The alert's ``rule_version`` is not in the alert; it is
recorded as ``as-alerted``. Which fields of the event made the Wazuh rule match
is not in the alert either, so the match basis names the rule, its level and
its description, and nothing more.
"""

from __future__ import annotations

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver
from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.detection.contracts import (
    DetectionResult,
    MatchBasis,
    MatchedField,
    TechniqueMapping,
)
from attribution_platform.domain import (
    AttackRef,
    EvidenceQuality,
    EvidenceType,
    Observation,
    TimeSpan,
)
from attribution_platform.extraction.detection_match import RuleRef

WAZUH_DETECTION_SOURCE = "wazuh"
WAZUH_RULE_VERSION = "as-alerted"
#: Alerts below this level are the enrich tier (module docstring).
CORE_LEVEL = 7
_TECHNIQUE_TYPE = "attack-pattern"


class WazuhAlertDetector:
    """Builds the detection of one Wazuh alert Observation."""

    def __init__(self, knowledge: AttackKnowledge) -> None:
        self._knowledge = knowledge
        self._resolver = ExternalIdResolver(knowledge, (_TECHNIQUE_TYPE,))

    def detect(self, observation: Observation) -> DetectionResult | None:
        alert = observation.wazuh
        if alert is None or not alert.rule_id or not alert.mitre_ids:
            return None
        level = int(str(alert.rule_level))
        mappings: dict[str, TechniqueMapping] = {}
        unresolved: list[str] = []
        for declared in str(alert.mitre_ids).split():
            resolved = self._resolver.resolve(declared)
            if resolved is None:
                unresolved.append(declared)
                continue
            obj, revoked_from = resolved
            external_id = next(
                str(r["external_id"])
                for r in obj.get("external_references") or ()
                if r.get("source_name") == "mitre-attack" and r.get("external_id")
            )
            basis = (
                f"Wazuh rule {alert.rule_id} '{alert.rule_description or ''}' "
                f"(level {level}) declares {declared}"
            )
            if revoked_from:
                basis += f"; {declared} is revoked, followed ATT&CK revoked-by to {external_id}"
            mappings.setdefault(
                str(obj["id"]),
                TechniqueMapping(
                    attack_ref=AttackRef(
                        stix_id=str(obj["id"]),
                        object_type=_TECHNIQUE_TYPE,
                        attack_kb_version=self._knowledge.attack_kb_version,
                        external_id=external_id,
                    ),
                    mapping_basis=basis,
                    mapping_source=WAZUH_DETECTION_SOURCE,
                ),
            )
        if not mappings:
            return None
        matched = [
            MatchedField("wazuh.rule_id", "equals", str(alert.rule_id), str(alert.rule_id)),
            MatchedField("wazuh.rule_level", "equals", str(level), str(level)),
        ]
        if alert.rule_description:
            matched.append(
                MatchedField(
                    "wazuh.rule_description",
                    "equals",
                    str(alert.rule_description),
                    str(alert.rule_description),
                )
            )
        note = (
            f"declared by the rule but not in {self._knowledge.attack_kb_version}, "
            f"not mapped: {', '.join(unresolved)}"
            if unresolved
            else None
        )
        return DetectionResult(
            detection_id=f"wazuh:{alert.rule_id}::{observation.observation_id}",
            rule_ref=RuleRef(rule_id=f"wazuh:{alert.rule_id}", rule_version=WAZUH_RULE_VERSION),
            detection_source=WAZUH_DETECTION_SOURCE,
            supporting_observation_ids=(observation.observation_id,),
            match_basis=MatchBasis(matched_fields=tuple(matched)),
            technique_mappings=tuple(mappings[k] for k in sorted(mappings)),
            evidence_type=EvidenceType.BEHAVIORAL,
            time_span=TimeSpan(start=observation.timestamp, end=observation.timestamp),
            evidence_quality=EvidenceQuality.LOW if level < CORE_LEVEL else None,
            aggregate_note=note,
        )


__all__ = [
    "CORE_LEVEL",
    "WAZUH_DETECTION_SOURCE",
    "WAZUH_RULE_VERSION",
    "WazuhAlertDetector",
]
