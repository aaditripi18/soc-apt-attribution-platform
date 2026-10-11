"""Which ATT&CK Group a Sigma rule is *associated with* — the candidates the
actor review must decide (ADR-0018 Amendment B).

A Group tag (``attack.gNNNN``) is one way a rule points at a Group. SigmaHQ
also files rules written from reporting on one actor or one malware family
under a directory named after it (``rules-emerging-threats/<year>/TA/<name>/``,
``.../Malware/<name>/``), often without a Group tag, and tags rules with ATT&CK
software ids. Each of these is a *candidate* association only; none is trusted.
This module derives them mechanically from the rule and the pinned ATT&CK
version — nothing is looked up by hand:

- ``group_tag``           the rule carries ``attack.gNNNN``;
- ``directory_alias``     the directory name contains a name or alias of exactly
  one active Group;
- ``directory_software``  the directory name contains a name or alias of exactly
  one active software entry that exactly one active Group is recorded using;
- ``software_tag``        the rule carries ``attack.sNNNN`` for such an entry.

"Used by exactly one Group in ATT&CK" is a statement about ATT&CK's records,
not about the world: commodity malware is often recorded for a single Group.
That is why every association still needs an accepted decision in the review
before it becomes evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver, external_id
from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    groups_using_software,
    is_active,
)

GROUP_TAG = "group_tag"
DIRECTORY_ALIAS = "directory_alias"
DIRECTORY_SOFTWARE = "directory_software"
SOFTWARE_TAG = "software_tag"
#: Strongest first; a Group reached several ways lists every basis in this order.
BASES = (GROUP_TAG, DIRECTORY_ALIAS, DIRECTORY_SOFTWARE, SOFTWARE_TAG)

_SOFTWARE_TYPES = ("malware", "tool")
_ACTOR_DIRECTORY = re.compile(r"(?:^|/)rules-emerging-threats/[^/]+/(?:TA|Malware)/([^/]+)/")
_GROUP_TAG = re.compile(r"attack\.g\d{4}")
_SOFTWARE_TAG = re.compile(r"attack\.s\d{4}")
#: Shorter directory-name fragments are too likely to be an accident.
_MIN_NAME_LENGTH = 4


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.casefold())


def _names(obj: object) -> set[str]:
    names: set[str] = set()
    get = obj.get  # type: ignore[attr-defined]
    if isinstance(get("name"), str):
        names.add(get("name"))
    for field in ("aliases", "x_mitre_aliases"):
        values = get(field)
        if isinstance(values, tuple | list):
            names.update(v for v in values if isinstance(v, str))
    return names


@dataclass(frozen=True)
class GroupAssociation:
    """One candidate Group for one rule."""

    tag: str  #: ``attack.gNNNN`` — the review's key
    bases: tuple[str, ...]
    #: What was matched, per basis: the tag, the alias, or "software id name".
    matched: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {"tag": self.tag, "bases": list(self.bases), "matched": list(self.matched)}


class ActorAssociationIndex:
    """Derives the candidate Groups of a rule from the pinned ATT&CK version."""

    def __init__(self, knowledge: AttackKnowledge) -> None:
        self._software_ids = ExternalIdResolver(knowledge, _SOFTWARE_TYPES)
        group_tag = {
            str(g["id"]): f"attack.{str(external_id(g)).lower()}" for g in active_groups(knowledge)
        }
        by_group_name: dict[str, set[str]] = {}
        for group in active_groups(knowledge):
            for name in _names(group):
                by_group_name.setdefault(_key(name), set()).add(str(group["id"]))
        #: normalised Group name or alias -> (tag, the name as ATT&CK writes it)
        self._group_names: dict[str, tuple[str, str]] = {}
        for group in active_groups(knowledge):
            for name in sorted(_names(group)):
                key = _key(name)
                if len(key) >= _MIN_NAME_LENGTH and len(by_group_name[key]) == 1:
                    self._group_names[key] = (group_tag[str(group["id"])], name)
        #: software stix id -> (tag of its single Group, "Sxxxx name")
        self._single_group_software: dict[str, tuple[str, str]] = {}
        by_software_name: dict[str, set[str]] = {}
        for object_type in _SOFTWARE_TYPES:
            for software in knowledge.objects_of_type(object_type):
                if not is_active(software):
                    continue
                stix_id = str(software["id"])
                for name in _names(software):
                    by_software_name.setdefault(_key(name), set()).add(stix_id)
                users = groups_using_software(knowledge, stix_id)
                if len(users) == 1 and users[0] in group_tag:
                    self._single_group_software[stix_id] = (
                        group_tag[users[0]],
                        f"{external_id(software)} {software.get('name')}",
                    )
        #: normalised software name or alias -> the one software entry it names
        self._software_names = {
            key: next(iter(ids))
            for key, ids in by_software_name.items()
            if len(key) >= _MIN_NAME_LENGTH and len(ids) == 1
        }

    def associations(self, member_path: str, tags: Iterable[str]) -> tuple[GroupAssociation, ...]:
        """The candidate Groups of the rule at ``member_path`` with ``tags``,
        sorted by Group tag."""
        found: dict[str, dict[str, str]] = {}

        def add(tag: str, basis: str, matched: str) -> None:
            found.setdefault(tag, {}).setdefault(basis, matched)

        lowered = sorted({str(t).lower() for t in tags})
        for tag in lowered:
            if _GROUP_TAG.fullmatch(tag):
                add(tag, GROUP_TAG, tag)
            elif _SOFTWARE_TAG.fullmatch(tag):
                resolved = self._software_ids.resolve(tag.split(".", 1)[1].upper())
                single = (
                    self._single_group_software.get(str(resolved[0]["id"])) if resolved else None
                )
                if single is not None:
                    add(single[0], SOFTWARE_TAG, single[1])
        directory = _ACTOR_DIRECTORY.search(member_path)
        if directory is not None:
            tokens = [t for t in re.split(r"[-_ ]", directory.group(1)) if t]
            for start in range(len(tokens)):
                for end in range(start + 1, len(tokens) + 1):
                    key = _key("".join(tokens[start:end]))
                    group = self._group_names.get(key)
                    if group is not None:
                        add(group[0], DIRECTORY_ALIAS, group[1])
                    software = self._single_group_software.get(self._software_names.get(key, ""))
                    if software is not None:
                        add(software[0], DIRECTORY_SOFTWARE, software[1])
        return tuple(
            GroupAssociation(
                tag=tag,
                bases=tuple(b for b in BASES if b in bases),
                matched=tuple(bases[b] for b in BASES if b in bases),
            )
            for tag, bases in sorted(found.items())
        )


__all__ = [
    "BASES",
    "DIRECTORY_ALIAS",
    "DIRECTORY_SOFTWARE",
    "GROUP_TAG",
    "SOFTWARE_TAG",
    "ActorAssociationIndex",
    "GroupAssociation",
]
