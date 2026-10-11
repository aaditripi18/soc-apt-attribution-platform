"""The attribution assessment of one investigation (ADR-0017).

A unit is a few linked events; the question an analyst asks is about the whole
intrusion: *can this be attributed, and to whom?* This module answers it from
the stored per-unit analyses — as a **verdict with its reasons**, never as a
ranked list.

What the verdict may say, and why no more:

- ``NO_DECISION_FEATURES`` — nothing observed can be compared with ATT&CK
  profiles.
- ``NOT_DISTINGUISHABLE`` — many Groups and Campaigns are consistent with what
  was observed, and nothing observed is specific to one of them.
- ``THIRD_PARTY_LEAD`` — additionally, an observed value equals an indicator a
  pinned government advisory attributes to a named actor (ADR-0013). That is the
  publisher's claim about the indicator, reported as a lead and never promoted
  to a conclusion.

- ``ACTOR_SPECIFIC_EVIDENCE`` (ADR-0018) — a rule written from published
  reporting on one Group's own tooling matched, and the reviewed actor-tag
  decision accepted that rule. The Group is named, with the matched artefact
  and the review's reason, as a lead to verify.

Technique overlap never names anyone. On the recordings whose emulated actor is
known, every ordering of technique overlap named the wrong actor, and a
technique ATT&CK records for a single Group pointed at the wrong Group every
time (ADR-0005 implementation record 2026-10-11; ADR-0017 "Measured"). Overlap
counts are therefore stored as facts per candidate, in name order, and nothing
here orders candidates by them or singles one out. A Group is named only by
evidence specific to it, and even then the verdict is not a calibrated
conclusion: no calibration version exists.

Pooling every unit treats the investigation as one intrusion. That is an
assumption about the source, stated in ``limits``, not something this module
can establish.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    campaigns_using_technique,
    groups_using_technique,
    techniques_used_by,
)
from attribution_platform.dataplane import ElasticClient
from attribution_platform.investigation.records import _load, _persist, _to_json

#: 1.1: actor-specific Evidence (ADR-0018). 1.2: candidates linked only through
#: observed software are counted apart from those with an observed technique.
ASSESSMENT_METHOD_VERSION = "1.2"
ASSESSMENT_SCHEMA_VERSION = "investigation-assessment/2"
ASSESSMENTS_INDEX = "attribution-platform-investigation-assessments-v1"
ASSESSMENTS_MAPPING: Mapping[str, Any] = {"investigation_id": {"type": "keyword"}}

#: Shares of the observed techniques at which candidates are counted.
_OVERLAP_SHARES = (0.25, 0.5, 0.75, 1.0)

LIMITS = (
    "Every unit of the investigation is pooled, which treats the source as one intrusion. "
    "If it holds unrelated activity, read the units separately.",
    "A Group's ATT&CK profile is what has been publicly reported about it, not everything it "
    "does; absence from a profile is not evidence of absence.",
    "Only techniques the pinned detection content can observe on this telemetry can appear "
    "(see Detection Coverage).",
)


class Verdict(Enum):
    NO_DECISION_FEATURES = "no_decision_features"
    NOT_DISTINGUISHABLE = "not_distinguishable"
    THIRD_PARTY_LEAD = "third_party_lead"
    ACTOR_SPECIFIC_EVIDENCE = "actor_specific_evidence"


@dataclass(frozen=True)
class ObservedTechnique:
    technique_id: str
    technique_stix_id: str
    technique_name: str
    #: units in which it is a decision feature
    units: int
    #: active Groups / Campaigns ATT&CK records using the technique itself
    groups_using: int
    campaigns_using: int


@dataclass(frozen=True)
class CandidateOverlap:
    """One consistent Group or Campaign: facts only, kept in name order."""

    candidate_id: str  # ATT&CK id (G#### / C####), or the STIX id when it has none
    stix_id: str
    name: str
    kind: str  # "group" | "campaign"
    profile_techniques: int
    matched_technique_ids: tuple[str, ...]
    units_as_candidate: int


@dataclass(frozen=True)
class OverlapCount:
    """How many candidates' profiles include at least ``min_matched`` observed techniques."""

    min_matched: int
    candidates: int


@dataclass(frozen=True)
class IndicatorLead:
    """An advisory indicator match that names an actor (the publisher's claim)."""

    actor_name: str
    actor_attack_id: str | None
    indicator_name: str
    kind: str
    value: str
    report_name: str | None
    within_validity: bool | None
    attribution_quote: str | None
    group_id: str


@dataclass(frozen=True)
class ActorLead:
    """Actor-specific Evidence (ADR-0018): the Group, and what matched."""

    actor_name: str
    actor_attack_id: str | None
    actor_stix_id: str
    rule_id: str
    claim: str
    evidence_id: str
    observation_id: str
    observed_at: str | None
    group_id: str


@dataclass(frozen=True)
class InvestigationAssessmentRecord:
    investigation_id: str
    attack_kb_version: str
    units_total: int
    units_with_decision_features: int
    active_groups: int
    observed_techniques: tuple[ObservedTechnique, ...]
    candidate_groups: int
    candidate_campaigns: int
    candidates: tuple[CandidateOverlap, ...]
    overlap_counts: tuple[OverlapCount, ...]
    indicator_leads: tuple[IndicatorLead, ...]
    actor_leads: tuple[ActorLead, ...]
    verdict: Verdict
    statement: str
    reasons: tuple[str, ...]
    limits: tuple[str, ...] = LIMITS
    method_version: str = ASSESSMENT_METHOD_VERSION
    schema_version: str = field(default=ASSESSMENT_SCHEMA_VERSION)


def _external_id(obj: Mapping[str, Any] | None) -> str | None:
    for ref in (obj or {}).get("external_references") or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def _plural(count: int, one: str, many: str | None = None) -> str:
    return f"{count} {one if count == 1 else (many or one + 's')}"


def assess_investigation(
    knowledge: AttackKnowledge,
    investigation_id: str,
    analyses: Sequence[Mapping[str, Any]],
) -> InvestigationAssessmentRecord:
    """The assessment of one investigation from its stored unit analyses (as
    JSON data — exactly what the read model holds). Deterministic."""
    units_per_technique: dict[str, int] = {}
    units_per_candidate: dict[str, int] = {}
    candidate_view: dict[str, Mapping[str, Any]] = {}
    leads: list[IndicatorLead] = []
    actor_leads: list[ActorLead] = []
    for analysis in analyses:
        for stix_id in analysis["observed_feature_technique_ids"]:
            units_per_technique[stix_id] = units_per_technique.get(stix_id, 0) + 1
        for candidate in analysis["candidates"]:
            stix_id = str(candidate["stix_id"])
            units_per_candidate[stix_id] = units_per_candidate.get(stix_id, 0) + 1
            candidate_view.setdefault(stix_id, candidate)
        for item in analysis.get("actor_specific_evidence") or ():
            actor_leads.append(
                ActorLead(
                    actor_name=str(item["actor_name"]),
                    actor_attack_id=item.get("actor_attack_id"),
                    actor_stix_id=str(item["actor_stix_id"]),
                    rule_id=str(item["rule_id"]),
                    claim=str(item["claim"]),
                    evidence_id=str(item["evidence_id"]),
                    observation_id=str(item["observation_id"]),
                    observed_at=item.get("observed_at"),
                    group_id=str(analysis["group_id"]),
                )
            )
        for match in analysis.get("indicator_matches") or ():
            if match.get("named_actor"):
                leads.append(
                    IndicatorLead(
                        actor_name=str(match["named_actor"]),
                        actor_attack_id=match.get("named_actor_attack_id"),
                        indicator_name=str(match["indicator_name"]),
                        kind=str(match["kind"]),
                        value=str(match["value"]),
                        report_name=match.get("report_name"),
                        within_validity=match.get("within_validity"),
                        attribution_quote=match.get("attribution_quote"),
                        group_id=str(analysis["group_id"]),
                    )
                )
    leads.sort(key=lambda lead: (lead.actor_name.lower(), lead.value, lead.group_id))
    actor_leads.sort(key=lambda lead: (lead.actor_name.lower(), lead.evidence_id))

    observed = set(units_per_technique)
    techniques = []
    for stix_id in observed:
        obj: Mapping[str, Any] = knowledge.get_by_id(stix_id) or {}
        techniques.append(
            ObservedTechnique(
                technique_id=_external_id(obj) or stix_id,
                technique_stix_id=stix_id,
                technique_name=str(obj.get("name", "")),
                units=units_per_technique[stix_id],
                groups_using=len(groups_using_technique(knowledge, stix_id)),
                campaigns_using=len(campaigns_using_technique(knowledge, stix_id)),
            )
        )
    techniques.sort(key=lambda t: t.technique_id)
    attack_id = {t.technique_stix_id: t.technique_id for t in techniques}

    candidates = []
    for stix_id, view in candidate_view.items():
        profile = set(techniques_used_by(knowledge, stix_id))
        candidates.append(
            CandidateOverlap(
                candidate_id=str(view.get("attack_external_id") or stix_id),
                stix_id=stix_id,
                name=str(view["name"]),
                kind=str(view["kind"]),
                profile_techniques=len(profile),
                matched_technique_ids=tuple(sorted(attack_id[t] for t in profile & observed)),
                units_as_candidate=units_per_candidate[stix_id],
            )
        )
    candidates.sort(key=lambda c: (c.name.lower(), c.candidate_id))
    groups = sum(1 for c in candidates if c.kind == "group")

    total = len(observed)
    thresholds = sorted({1, *(max(1, math.ceil(share * total)) for share in _OVERLAP_SHARES)})
    overlap_counts = tuple(
        OverlapCount(
            min_matched=threshold,
            candidates=sum(1 for c in candidates if len(c.matched_technique_ids) >= threshold),
        )
        for threshold in (thresholds if total else ())
    )

    with_features = sum(1 for a in analyses if a["observed_feature_technique_ids"])
    reasons: list[str] = []
    if total == 0:
        verdict = Verdict.NO_DECISION_FEATURES
        statement = (
            "Nothing here can be attributed: no technique was observed that is both supported by "
            "core Evidence and recorded for an ATT&CK Group or Campaign."
        )
    else:
        half = max(1, math.ceil(0.5 * total))
        at_half = sum(1 for c in candidates if len(c.matched_technique_ids) >= half)
        everything = sum(1 for c in candidates if len(c.matched_technique_ids) == total)
        shared = sum(1 for t in techniques if t.groups_using + t.campaigns_using > 1)
        overlapping = [c for c in candidates if c.matched_technique_ids]
        overlapping_groups = sum(1 for c in overlapping if c.kind == "group")
        actors = _plural(
            len(overlapping), "ATT&CK Group or Campaign", "ATT&CK Groups and Campaigns"
        )
        reasons.append(
            f"{actors} ({overlapping_groups} Groups, {len(overlapping) - overlapping_groups} "
            f"Campaigns) {'has' if len(overlapping) == 1 else 'have'} at least one "
            f"of the {_plural(total, 'observed technique')} in their recorded profile."
        )
        software_only = len(candidates) - len(overlapping)
        if software_only:
            reasons.append(
                f"{software_only} more {'is' if software_only == 1 else 'are'} linked only "
                "through software observed here that ATT&CK records them using, not through a "
                "technique."
            )
        all_of_them = (
            "none has" if everything == 0 else "1 has" if everything == 1 else f"{everything} have"
        )
        reasons.append(
            f"{at_half} of them {'has' if at_half == 1 else 'have'} at least half "
            f"({half} of {total}); {all_of_them} all of them."
        )
        reasons.append(
            f"{shared} of the {_plural(total, 'observed technique')} "
            f"{'is' if shared == 1 else 'are'} recorded for more than one Group or Campaign."
        )
        verdict = Verdict.NOT_DISTINGUISHABLE
        statement = (
            "No actor can be singled out from this evidence. Many Groups are consistent with it, "
            "and nothing observed is specific to one of them."
        )
        if leads:
            verdict = Verdict.THIRD_PARTY_LEAD
            names = sorted({lead.actor_name for lead in leads}, key=str.lower)
            statement = (
                "No actor can be singled out from the observed behaviour. "
                f"{_plural(len(leads), 'observed value')} "
                f"{'equals' if len(leads) == 1 else 'equal'} an indicator that a government "
                f"advisory attributes to {', '.join(names)} — the publisher's claim about the "
                "indicator, to be checked, not a conclusion about this intrusion."
            )
            if len(names) > 1:
                reasons.append(f"The advisory leads name {len(names)} different actors.")
    if actor_leads:
        verdict = Verdict.ACTOR_SPECIFIC_EVIDENCE
        named = sorted({lead.actor_name for lead in actor_leads}, key=str.lower)
        rule_count = len({lead.rule_id.rsplit(":", 1)[0] for lead in actor_leads})
        matches = _plural(len(actor_leads), "match", "matches")
        rules_text = _plural(rule_count, "rule")
        if len(named) == 1:
            statement = (
                f"Evidence specific to {named[0]} was observed: {matches} of {rules_text} written "
                "from published reporting on that Group's own tooling. This points to "
                f"{named[0]} and is a lead to verify — not a calibrated conclusion, and anyone "
                "who has the same tooling or copies its artefacts would produce it too."
            )
        else:
            statement = (
                f"Evidence specific to {len(named)} different Groups was observed "
                f"({', '.join(named)}): {matches} of {rules_text} written from published "
                "reporting on each Group's own tooling. The leads disagree, so none is "
                "singled out; each is to be verified."
            )
        reasons.insert(
            0,
            "Technique overlap does not single out an actor here (the counts below); the Group "
            "is named only because an artefact specific to it matched."
            if total
            else "No technique comparison applies; the Group is named only because an artefact "
            "specific to it matched.",
        )
    return InvestigationAssessmentRecord(
        investigation_id=investigation_id,
        attack_kb_version=knowledge.attack_kb_version,
        units_total=len(analyses),
        units_with_decision_features=with_features,
        active_groups=len(active_groups(knowledge)),
        observed_techniques=tuple(techniques),
        candidate_groups=groups,
        candidate_campaigns=len(candidates) - groups,
        candidates=tuple(candidates),
        overlap_counts=overlap_counts,
        indicator_leads=tuple(leads),
        actor_leads=tuple(actor_leads),
        verdict=verdict,
        statement=statement,
        reasons=tuple(reasons),
    )


def assessment_to_json(record: InvestigationAssessmentRecord) -> dict[str, Any]:
    return dict(_to_json(record))


def persist_assessment(client: ElasticClient, record: InvestigationAssessmentRecord) -> None:
    _persist(
        client,
        ASSESSMENTS_INDEX,
        ASSESSMENTS_MAPPING,
        record.investigation_id,
        assessment_to_json(record),
    )


def load_assessment(client: ElasticClient, investigation_id: str) -> Mapping[str, Any] | None:
    """The stored assessment of one investigation as JSON data, or ``None``."""
    return _load(client, ASSESSMENTS_INDEX, investigation_id)


__all__ = [
    "ASSESSMENTS_INDEX",
    "ASSESSMENT_METHOD_VERSION",
    "InvestigationAssessmentRecord",
    "Verdict",
    "assess_investigation",
    "assessment_to_json",
    "load_assessment",
    "persist_assessment",
]
