"""Reviewed decisions on which of a rule's declared techniques its logic
establishes (ADR-0025).

By default a rule that declares alternative techniques establishes none of the
alternatives (:func:`attribution_platform.detection.evidence.ambiguous_technique_ids`).
A reviewer who has read the rule can record, with a reason, the techniques
every match of it establishes. The file is tracked, so each decision is
versioned and its hash can be cited.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

_ATTACK_ID = re.compile(r"\AT\d{4}(?:\.\d{3})?\Z")
REVIEW_VERSION = "technique-support-review/1"


class TechniqueSupportError(ValueError):
    """The review file is malformed (fail closed)."""


@dataclass(frozen=True)
class TechniqueSupportReview:
    #: ``DetectionResult.detection_source`` (e.g. ``sigma:<id>``) -> ATT&CK ids
    supported: Mapping[str, frozenset[str]]
    sha256: str

    def for_source(self, detection_source: str) -> frozenset[str] | None:
        return self.supported.get(detection_source)


EMPTY_REVIEW = TechniqueSupportReview(MappingProxyType({}), hashlib.sha256(b"").hexdigest())


def load_technique_support_review(path: Path) -> TechniqueSupportReview:
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if data.get("version") != REVIEW_VERSION:
        raise TechniqueSupportError(f"{path}: version must be {REVIEW_VERSION}")
    supported: dict[str, frozenset[str]] = {}
    for entry in data.get("decisions", []):
        source = str(entry.get("rule_source", ""))
        ids = entry.get("establishes")
        if not source.strip() or source in supported:
            raise TechniqueSupportError(f"{path}: missing or duplicate rule_source {source!r}")
        if (
            not isinstance(ids, list)
            or not ids
            or not all(isinstance(i, str) and _ATTACK_ID.match(i) for i in ids)
        ):
            raise TechniqueSupportError(f"{path}: {source}: 'establishes' must list ATT&CK ids")
        if not str(entry.get("reason", "")).strip() or not str(entry.get("rule_name", "")).strip():
            raise TechniqueSupportError(f"{path}: {source}: a rule_name and a reason are required")
        supported[source] = frozenset(ids)
    return TechniqueSupportReview(MappingProxyType(supported), hashlib.sha256(raw).hexdigest())


def established_ids(declared: frozenset[str], reviewed: frozenset[str] | None) -> frozenset[str]:
    """The ATT&CK technique ids a rule declaring ``declared`` establishes when it
    fires - the same rule as
    :func:`attribution_platform.detection.evidence.ambiguous_technique_ids`,
    stated on ids, for reports over rule packs (tested to agree)."""
    parents = {i.split(".")[0] for i in declared}
    subs = {i for i in declared if "." in i}
    alternatives = len(parents) > 1
    ambiguous = set(declared) if alternatives else (subs if len(subs) > 1 else set())
    return frozenset(declared - (ambiguous - (reviewed or frozenset())))


__all__ = [
    "established_ids",
    "EMPTY_REVIEW",
    "REVIEW_VERSION",
    "TechniqueSupportError",
    "TechniqueSupportReview",
    "load_technique_support_review",
]
