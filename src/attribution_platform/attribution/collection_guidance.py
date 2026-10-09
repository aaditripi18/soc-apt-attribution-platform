"""Evidence-collection guidance for one attribution unit (ADR-0005 Amendment E).

Answers CLAUDE.md's "what additional evidence would improve confidence" before a
``calibration_version`` exists, without ranking hypotheses: it orders
**questions**, never candidates.

For the unit's candidate set ``C`` (``n`` Groups / Campaigns) and every technique
``t`` that some candidate is recorded in ATT&CK as using but the unit has not
observed, the guidance states only facts:

- ``candidates_using`` — the candidates whose ATT&CK profile includes ``t``
  (``k`` of ``n``): observing ``t`` would be consistent with exactly those;
- ``split`` = ``min(k, n - k)`` — how many candidates the answer would set apart
  *whichever way it falls* (observed → the ``n - k`` others lose the support
  ``t`` would give; adequately absent → the ``k`` users are contradicted,
  ADR-0005 §D11). It is a count, never a score or probability;
- ``data_components`` — the ATT&CK data components that observe ``t`` (MITRE's
  own detection model);
- ``detectability`` — whether **this** platform can detect ``t``: the Sigma
  logsources of its imported rules, or why not (the coverage report's status and
  blockers).

Questions are ordered by ``split`` (descending), then by whether the platform can
detect the technique, then by ATT&CK id — a deterministic, inspectable order.
A technique every candidate uses (``k = n``) or none uses separates nothing and is
not listed. Sub-techniques are matched exactly as ATT&CK records them (no
parent / child inference), the same rule the ACH matrix applies.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    required_data_components,
    techniques_used_by,
)

COLLECTION_GUIDANCE_METHOD_VERSION = "1.0"
#: Questions kept per unit (the full candidate split is always reproducible).
DEFAULT_MAX_QUESTIONS = 10


@dataclass(frozen=True)
class Detectability:
    """Whether the platform can detect one technique, from its own generated
    content (the Sigma import and coverage reports of the loaded pack)."""

    status: str  # coverage-report status: covered / telemetry_gap / ... / no_sigma_rule
    logsources: tuple[str, ...] = ()  # Sigma logsources of imported rules, when covered
    blocked_by: tuple[str, ...] = ()  # telemetry blockers of rejected rules

    @property
    def detectable(self) -> bool:
        return self.status == "covered"


@dataclass(frozen=True)
class CollectionQuestion:
    technique_stix_id: str
    technique_id: str
    technique_name: str
    candidates_using: tuple[str, ...]  # candidate ids (sorted)
    candidates_total: int
    split: int
    data_components: tuple[str, ...]
    detectability: Detectability | None

    @property
    def rationale(self) -> str:
        k, n = len(self.candidates_using), self.candidates_total
        detect = (
            f"this platform detects it ({', '.join(self.detectability.logsources)})"
            if self.detectability is not None and self.detectability.detectable
            else "this platform cannot detect it yet"
            + (
                f" ({self.detectability.status}"
                + (
                    f": {', '.join(self.detectability.blocked_by)}"
                    if self.detectability.blocked_by
                    else ""
                )
                + ")"
                if self.detectability is not None
                else ""
            )
        )
        return (
            f"{k} of {n} candidates use {self.technique_id}: observing it is consistent with "
            f"those {k}; finding it adequately absent contradicts them — either answer sets "
            f"{self.split} candidate(s) apart; {detect}."
        )


@dataclass(frozen=True)
class CollectionGuidance:
    method_version: str
    candidates_total: int
    questions_considered: int
    questions: tuple[CollectionQuestion, ...]


def _external(knowledge: AttackKnowledge, stix_id: str) -> tuple[str, str]:
    obj: Mapping[str, Any] = knowledge.get_by_id(stix_id) or {}
    for ref in obj.get("external_references") or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]), str(obj.get("name", ""))
    return stix_id, str(obj.get("name", ""))


def _component_names(knowledge: AttackKnowledge, technique_stix_id: str) -> tuple[str, ...]:
    names = set()
    for component_id in required_data_components(knowledge, technique_stix_id):
        obj = knowledge.get_by_id(component_id)
        names.add(str(obj.get("name")) if obj is not None else component_id)
    return tuple(sorted(names))


def compute_collection_guidance(
    knowledge: AttackKnowledge,
    *,
    candidates: Iterable[tuple[str, str]],
    observed_technique_stix_ids: Iterable[str],
    detectability: Mapping[str, Detectability] | None = None,
    max_questions: int = DEFAULT_MAX_QUESTIONS,
) -> CollectionGuidance:
    """Guidance for one unit (module docstring).

    ``candidates`` are ``(candidate_id, ATT&CK stix id)`` pairs (Group or
    Campaign); ``detectability`` is keyed by ATT&CK technique id (``T1059.002``)."""
    if max_questions < 1:
        raise ValueError("max_questions must be >= 1")
    pairs = sorted(set(candidates))
    observed = set(observed_technique_stix_ids)
    users: dict[str, set[str]] = {}
    for candidate_id, stix_id in pairs:
        for technique in techniques_used_by(knowledge, stix_id):
            if technique not in observed:
                users.setdefault(technique, set()).add(candidate_id)
    n = len(pairs)
    considered = []
    for technique, using in users.items():
        k = len(using)
        split = min(k, n - k)
        if split == 0:
            continue
        technique_id, name = _external(knowledge, technique)
        considered.append(
            CollectionQuestion(
                technique_stix_id=technique,
                technique_id=technique_id,
                technique_name=name,
                candidates_using=tuple(sorted(using)),
                candidates_total=n,
                split=split,
                data_components=(),  # filled for the kept questions only (below)
                detectability=(detectability or {}).get(technique_id),
            )
        )
    considered.sort(
        key=lambda q: (
            -q.split,
            not (q.detectability is not None and q.detectability.detectable),
            q.technique_id,
        )
    )
    kept = tuple(
        CollectionQuestion(
            **{
                **q.__dict__,
                "data_components": _component_names(knowledge, q.technique_stix_id),
            }
        )
        for q in considered[:max_questions]
    )
    return CollectionGuidance(
        method_version=COLLECTION_GUIDANCE_METHOD_VERSION,
        candidates_total=n,
        questions_considered=len(considered),
        questions=kept,
    )


__all__ = [
    "COLLECTION_GUIDANCE_METHOD_VERSION",
    "DEFAULT_MAX_QUESTIONS",
    "CollectionGuidance",
    "CollectionQuestion",
    "Detectability",
    "compute_collection_guidance",
]
