"""Reviewed decisions on which of a rule's declared techniques its logic
establishes (ADR-0025).

By default a rule that declares alternative techniques establishes none of the
alternatives (:func:`attribution_platform.detection.evidence.ambiguous_technique_ids`).
A reviewer who has read the rule can record, with a reason, the techniques
every match of it establishes. The file is tracked, so each decision is
versioned and its hash can be cited.

A decision may add techniques **conditioned on the matched event**
(ADR-0025 Amendment K): each ``when`` clause is one detection-engine field
condition, evaluated on the Observation the rule matched with the engine's
own semantics, and the techniques it names are established only for matches
that satisfy it. Conditions may not read PowerShell script-block text: a block
holds code that was compiled, not code shown to run (Amendment J).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from attribution_platform.detection.errors import DetectionError
from attribution_platform.detection.rules import FieldCondition
from attribution_platform.domain import Observation

_ATTACK_ID = re.compile(r"\AT\d{4}(?:\.\d{3})?\Z")
REVIEW_VERSION = "technique-support-review/2"
#: Text a condition may not read (ADR-0025 Amendment K).
_UNCONDITIONABLE = ("script_block",)


class TechniqueSupportError(ValueError):
    """The review file is malformed (fail closed)."""


@dataclass(frozen=True)
class ConditionalSupport:
    """Techniques established by the matches whose event satisfies ``condition``."""

    condition: FieldCondition
    establishes: frozenset[str]


@dataclass(frozen=True)
class TechniqueSupportReview:
    #: ``DetectionResult.detection_source`` (e.g. ``sigma:<id>``) -> ATT&CK ids
    supported: Mapping[str, frozenset[str]]
    sha256: str
    #: low-level rules whose technique counts once linked into a cluster
    linked: frozenset[str] = frozenset()
    #: rule source -> techniques established only when the matched event satisfies a condition
    conditional: Mapping[str, tuple[ConditionalSupport, ...]] = MappingProxyType({})

    def for_source(self, detection_source: str) -> frozenset[str] | None:
        """What every match establishes (``None``: not reviewed)."""
        return self.supported.get(detection_source)

    def for_match(self, detection_source: str, observation: Observation) -> frozenset[str] | None:
        """What this match establishes: every match's techniques plus those of
        each ``when`` clause the matched event satisfies (``None``: not reviewed)."""
        base = self.supported.get(detection_source)
        if base is None:
            return None
        added = (
            clause.establishes
            for clause in self.conditional.get(detection_source, ())
            if clause.condition.matches(observation)
        )
        return base.union(*added)

    def counts_when_linked(self, detection_source: str) -> bool:
        return detection_source in self.linked


EMPTY_REVIEW = TechniqueSupportReview(MappingProxyType({}), hashlib.sha256(b"").hexdigest())


def load_technique_support_review(path: Path) -> TechniqueSupportReview:
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if data.get("version") != REVIEW_VERSION:
        raise TechniqueSupportError(f"{path}: version must be {REVIEW_VERSION}")
    supported: dict[str, frozenset[str]] = {}
    linked: set[str] = set()
    conditional: dict[str, tuple[ConditionalSupport, ...]] = {}
    for entry in data.get("decisions", []):
        source = str(entry.get("rule_source", ""))
        ids = entry.get("establishes")
        if not source.strip() or source in supported:
            raise TechniqueSupportError(f"{path}: missing or duplicate rule_source {source!r}")
        if not isinstance(ids, list) or not all(
            isinstance(i, str) and _ATTACK_ID.match(i) for i in ids
        ):
            raise TechniqueSupportError(f"{path}: {source}: 'establishes' must list ATT&CK ids")
        if not str(entry.get("reason", "")).strip() or not str(entry.get("rule_name", "")).strip():
            raise TechniqueSupportError(f"{path}: {source}: a rule_name and a reason are required")
        supported[source] = frozenset(ids)
        clauses = _clauses(path, source, entry.get("when", []))
        if clauses:
            conditional[source] = clauses
        flag = entry.get("counts_when_linked", False)
        if not isinstance(flag, bool) or (flag and not ids and not clauses):
            raise TechniqueSupportError(
                f"{path}: {source}: 'counts_when_linked' must be a boolean, and needs a technique "
                "(for every match or in a 'when' clause)"
            )
        if flag:
            linked.add(source)
    return TechniqueSupportReview(
        MappingProxyType(supported),
        hashlib.sha256(raw).hexdigest(),
        frozenset(linked),
        MappingProxyType(conditional),
    )


def _clauses(path: Path, source: str, raw: object) -> tuple[ConditionalSupport, ...]:
    if not isinstance(raw, list):
        raise TechniqueSupportError(f"{path}: {source}: 'when' must be a list")
    clauses = []
    for clause in raw:
        if not isinstance(clause, dict) or set(clause) != {
            "field",
            "operator",
            "value",
            "establishes",
            "reason",
        }:
            raise TechniqueSupportError(
                f"{path}: {source}: a 'when' clause has exactly field, operator, value, "
                "establishes and reason"
            )
        field = str(clause["field"])
        if any(word in field for word in _UNCONDITIONABLE):
            raise TechniqueSupportError(
                f"{path}: {source}: a condition may not read {field!r} "
                "(code that was compiled, not shown to run)"
            )
        ids = clause["establishes"]
        if (
            not isinstance(ids, list)
            or not ids
            or not all(isinstance(i, str) and _ATTACK_ID.match(i) for i in ids)
        ):
            raise TechniqueSupportError(
                f"{path}: {source}: a 'when' clause must establish ATT&CK ids"
            )
        if not str(clause["reason"]).strip():
            raise TechniqueSupportError(f"{path}: {source}: a 'when' clause needs a reason")
        value = clause["value"]
        try:
            condition = FieldCondition(
                field_path=field,
                operator=str(clause["operator"]),
                value=tuple(value) if isinstance(value, list) else value,
                case_insensitive=True,
            )
        except DetectionError as error:
            raise TechniqueSupportError(f"{path}: {source}: {error}") from error
        clauses.append(ConditionalSupport(condition, frozenset(ids)))
    return tuple(clauses)


def established_ids(declared: frozenset[str], reviewed: frozenset[str] | None) -> frozenset[str]:
    """The ATT&CK technique ids a rule declaring ``declared`` establishes when it
    fires - the same rule as
    :func:`attribution_platform.detection.evidence.ambiguous_technique_ids`,
    stated on ids, for reports over rule packs (tested to agree)."""
    parents = {i.split(".")[0] for i in declared}
    subs = {i for i in declared if "." in i}
    alternatives = len(parents) > 1
    ambiguous = set(declared) if alternatives else (subs if len(subs) > 1 else set())
    if reviewed is not None:
        # a review is authoritative: exactly what it names, which may be nothing
        return frozenset(declared & reviewed)
    return frozenset(declared - ambiguous)


__all__ = [
    "ConditionalSupport",
    "established_ids",
    "EMPTY_REVIEW",
    "REVIEW_VERSION",
    "TechniqueSupportError",
    "TechniqueSupportReview",
    "load_technique_support_review",
]
