"""Behavioural profile match and response guidance for one investigation
(ADR-0021).

ADR-0017's assessment answers "can an actor be singled out?" and, for most
intrusions, the answer is no: the behaviour is consistent with many Groups. An
analyst still needs two things from that situation, and this module provides
them from the stored assessment and the pinned ATT&CK data alone:

1. **How close is the observed behaviour to each Group's profile** — a
   *behavioural overlap*, with the Groups that cannot be told apart shown as
   one cluster.
2. **What to do about what was observed** — the mitigations ATT&CK records
   for the observed techniques.

**The overlap score.** For an investigation with observed techniques ``T``
(the decision features of ADR-0005) and a Group with recorded techniques ``P``::

    weight(t)  = 1 - (active Groups recorded using t) / (active Groups)
    overlap    = sum(weight(t) for t in T ∩ P) / sum(weight(t) for t in T)

``weight`` is ADR-0005's diagnosticity ``D``: a technique nearly every Group
uses weighs almost nothing, a rare one weighs almost one. ``overlap`` is the
share of the observed behaviour, so weighted, that the Group's public profile
contains. It is a number between 0 and 1 with one meaning and no fitted
parameter.

**What it is not.** It is a similarity between behaviour and a public profile,
not a probability that the Group is responsible. On the recordings whose actor
is known, the Group with the highest overlap was not the actor (ADR-0005 record
2026-10-11: the actor's position was 14 to 121). Groups with long public
profiles overlap with almost anything; Groups differ in how much has been
published about them. So candidates are *ordered* by overlap, which is what an
analyst asks for, and nothing here calls the first one the answer: the stored
verdict (ADR-0017 / ADR-0018) remains the only statement about who did it, and
a Group named there on specific evidence is carried here as ``named``.

**Clusters.** Candidates whose profiles contain exactly the same observed
techniques have the same overlap for the same reason and cannot be told apart
by this evidence. They are returned as one cluster.

**Mitigations** are ATT&CK's own ``mitigates`` relationships for the observed
techniques (a sub-technique also takes its parent's), ordered by how many
observed techniques each addresses — a count of recorded facts.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from attribution_platform.attack_knowledge.external_ids import external_id
from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    groups_using_technique,
    is_active,
    techniques_used_by,
)
from attribution_platform.dataplane import ElasticClient
from attribution_platform.investigation.records import _load, _persist, _to_json

PROFILE_MATCH_METHOD_VERSION = "1.1"
PROFILE_MATCH_SCHEMA_VERSION = "profile-match/1"
PROFILE_MATCH_INDEX = "attribution-platform-profile-matches-v1"
PROFILE_MATCH_MAPPING: Mapping[str, Any] = {"investigation_id": {"type": "keyword"}}

_MITIGATION_TYPE = "course-of-action"
_SUBTECHNIQUE_OF = "subtechnique-of"
_MITIGATES = "mitigates"
_ROUND = 6


@dataclass(frozen=True)
class WeightedTechnique:
    technique_id: str
    technique_stix_id: str
    technique_name: str
    groups_using: int
    #: 1 - groups_using / active_groups
    weight: float


@dataclass(frozen=True)
class ProfileMatch:
    candidate_id: str
    stix_id: str
    name: str
    kind: str  # "group" | "campaign"
    matched_technique_ids: tuple[str, ...]
    matched: int
    profile_techniques: int
    #: weighted share of the observed behaviour the profile contains (0..1)
    overlap: float
    #: share of the profile's own techniques that were observed (0..1)
    profile_share: float
    cluster_id: str
    #: named by the verdict on evidence specific to it ("actor_specific" /
    #: "advisory_indicator"), else None
    named_by: str | None


@dataclass(frozen=True)
class ProfileCluster:
    """Candidates whose profiles contain exactly the same observed techniques."""

    cluster_id: str
    label: str
    overlap: float
    matched_technique_ids: tuple[str, ...]
    member_ids: tuple[str, ...]
    member_names: tuple[str, ...]


@dataclass(frozen=True)
class Mitigation:
    mitigation_id: str
    stix_id: str
    name: str
    description: str
    #: observed techniques ATT&CK records it as mitigating
    technique_ids: tuple[str, ...]


@dataclass(frozen=True)
class ProfileMatchRecord:
    investigation_id: str
    attack_kb_version: str
    active_groups: int
    observed: tuple[WeightedTechnique, ...]
    total_weight: float
    #: ordered by overlap (highest first), then matched count, then name
    matches: tuple[ProfileMatch, ...]
    clusters: tuple[ProfileCluster, ...]
    mitigations: tuple[Mitigation, ...]
    #: observed techniques for which ATT&CK records no mitigation
    techniques_without_mitigation: tuple[str, ...]
    #: candidates of the assessment whose profile holds no observed technique
    #: (linked through observed software only); they are not in ``matches``
    candidates_without_technique_overlap: int = 0
    method_version: str = PROFILE_MATCH_METHOD_VERSION
    schema_version: str = field(default=PROFILE_MATCH_SCHEMA_VERSION)


def _first_paragraph(text: str) -> str:
    """ATT&CK's description up to its first blank line, citations removed, and
    without a final sentence that only introduces a list."""
    paragraph = text.strip().split("\n\n", 1)[0].replace("\n", " ")
    out: list[str] = []
    depth = 0
    index = 0
    while index < len(paragraph):
        if paragraph.startswith("(Citation:", index):
            depth += 1
            index += len("(Citation:")
            continue
        if depth and paragraph[index] == ")":
            depth -= 1
        elif not depth:
            out.append(paragraph[index])
        index += 1
    text = " ".join("".join(out).split())
    if text.endswith(":"):
        # a lead-in to a list that is not carried ("... through the following measures:")
        cut = text.rfind(".", 0, len(text) - 1)
        text = text[: cut + 1] if cut > 0 else text
    return text


def _label(position: int) -> str:
    """A, B … Z, AA, AB …"""
    letters = ""
    position += 1
    while position:
        position, remainder = divmod(position - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return f"Cluster {letters}"


def _mitigations(
    knowledge: AttackKnowledge, observed: tuple[WeightedTechnique, ...]
) -> tuple[tuple[Mitigation, ...], tuple[str, ...]]:
    parent: dict[str, str] = {}
    mitigated_by: dict[str, set[str]] = {}
    for relationship in knowledge.relationships():
        if not is_active(relationship):
            continue
        kind = relationship.get("relationship_type")
        source, target = str(relationship["source_ref"]), str(relationship["target_ref"])
        if kind == _SUBTECHNIQUE_OF:
            parent[source] = target
        elif kind == _MITIGATES:
            mitigated_by.setdefault(target, set()).add(source)
    techniques_of: dict[str, set[str]] = {}
    without: list[str] = []
    for technique in observed:
        stix_id = technique.technique_stix_id
        sources = set(mitigated_by.get(stix_id, ()))
        if stix_id in parent:  # a sub-technique is also addressed by its parent's mitigations
            sources |= mitigated_by.get(parent[stix_id], set())
        active = {s for s in sources if _is_mitigation(knowledge, s)}
        if not active:
            without.append(technique.technique_id)
        for source in active:
            techniques_of.setdefault(source, set()).add(technique.technique_id)
    mitigations = []
    for stix_id, technique_ids in techniques_of.items():
        obj = knowledge.get_by_id(stix_id)
        if obj is None:  # pragma: no cover - _is_mitigation resolved it above
            continue
        mitigations.append(
            Mitigation(
                mitigation_id=str(external_id(obj) or stix_id),
                stix_id=stix_id,
                name=str(obj.get("name", "")),
                description=_first_paragraph(str(obj.get("description", ""))),
                technique_ids=tuple(sorted(technique_ids)),
            )
        )
    mitigations.sort(key=lambda m: (-len(m.technique_ids), m.mitigation_id))
    return tuple(mitigations), tuple(sorted(without))


def _is_mitigation(knowledge: AttackKnowledge, stix_id: str) -> bool:
    obj = knowledge.get_by_id(stix_id)
    return obj is not None and obj.get("type") == _MITIGATION_TYPE and is_active(obj)


def match_profiles(knowledge: AttackKnowledge, assessment: Mapping[str, Any]) -> ProfileMatchRecord:
    """The profile match of one investigation from its stored assessment (as
    JSON data — what the read model holds). Deterministic."""
    groups_total = len(active_groups(knowledge))
    observed = tuple(
        WeightedTechnique(
            technique_id=str(t["technique_id"]),
            technique_stix_id=str(t["technique_stix_id"]),
            technique_name=str(t["technique_name"]),
            groups_using=(users := len(groups_using_technique(knowledge, t["technique_stix_id"]))),
            weight=round(1 - users / groups_total, _ROUND) if groups_total else 0.0,
        )
        for t in assessment["observed_techniques"]
    )
    weight_of = {t.technique_id: t.weight for t in observed}
    total = sum(weight_of.values())
    observed_ids = set(weight_of)

    named: dict[str, str] = {}
    for lead in assessment.get("indicator_leads") or ():
        if lead.get("actor_attack_id"):
            named[str(lead["actor_attack_id"])] = "advisory_indicator"
    for lead in assessment.get("actor_leads") or ():
        if lead.get("actor_attack_id"):
            named[str(lead["actor_attack_id"])] = "actor_specific"

    rows = []
    without_overlap = 0
    for candidate in assessment["candidates"]:
        matched = tuple(sorted(t for t in candidate["matched_technique_ids"] if t in observed_ids))
        if not matched:
            # a candidate linked only through observed software: no behaviour to compare
            without_overlap += 1
            continue
        profile_size = len(techniques_used_by(knowledge, str(candidate["stix_id"])))
        cluster_id = "cluster-" + hashlib.sha256("|".join(matched).encode()).hexdigest()[:12]
        rows.append(
            ProfileMatch(
                candidate_id=str(candidate["candidate_id"]),
                stix_id=str(candidate["stix_id"]),
                name=str(candidate["name"]),
                kind=str(candidate["kind"]),
                matched_technique_ids=matched,
                matched=len(matched),
                profile_techniques=profile_size,
                overlap=round(sum(weight_of[t] for t in matched) / total, _ROUND) if total else 0.0,
                profile_share=round(len(matched) / profile_size, _ROUND) if profile_size else 0.0,
                cluster_id=cluster_id,
                named_by=named.get(str(candidate["candidate_id"])),
            )
        )
    rows.sort(key=lambda m: (-m.overlap, -m.matched, m.name.lower(), m.candidate_id))

    members: dict[str, list[ProfileMatch]] = {}
    for row in rows:
        members.setdefault(row.cluster_id, []).append(row)
    clusters = tuple(
        ProfileCluster(
            cluster_id=cluster_id,
            label=_label(position),
            overlap=group[0].overlap,
            matched_technique_ids=group[0].matched_technique_ids,
            member_ids=tuple(m.candidate_id for m in group),
            member_names=tuple(m.name for m in group),
        )
        for position, (cluster_id, group) in enumerate(members.items())
    )
    mitigations, without = _mitigations(knowledge, observed)
    return ProfileMatchRecord(
        investigation_id=str(assessment["investigation_id"]),
        attack_kb_version=knowledge.attack_kb_version,
        active_groups=groups_total,
        observed=observed,
        total_weight=round(total, _ROUND),
        matches=tuple(rows),
        clusters=clusters,
        mitigations=mitigations,
        techniques_without_mitigation=without,
        candidates_without_technique_overlap=without_overlap,
    )


def profile_match_to_json(record: ProfileMatchRecord) -> dict[str, Any]:
    return dict(_to_json(record))


def persist_profile_match(client: ElasticClient, record: ProfileMatchRecord) -> None:
    _persist(
        client,
        PROFILE_MATCH_INDEX,
        PROFILE_MATCH_MAPPING,
        record.investigation_id,
        profile_match_to_json(record),
    )


def load_profile_match(client: ElasticClient, investigation_id: str) -> Mapping[str, Any] | None:
    return _load(client, PROFILE_MATCH_INDEX, investigation_id)


__all__ = [
    "PROFILE_MATCH_INDEX",
    "PROFILE_MATCH_METHOD_VERSION",
    "Mitigation",
    "ProfileCluster",
    "ProfileMatch",
    "ProfileMatchRecord",
    "WeightedTechnique",
    "load_profile_match",
    "match_profiles",
    "persist_profile_match",
    "profile_match_to_json",
]
