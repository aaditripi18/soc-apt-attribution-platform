"""ATT&CK external ids (``T1562.004``, ``S0002``) → the object the pinned KB says
is current, following the KB's own ``revoked-by`` relationships.

Shared by the Sigma importer (rule tags) and the telemetry reports (dataset
labels), so an older id is resolved once, the same way everywhere, and only
through what the pinned bundle itself records. Fails closed (``None``) on an
unknown id, an id naming several active objects, a deprecated object, a
revocation cycle, or a revocation chain that ends at an inactive object —
never a guess.
"""

from __future__ import annotations

from collections.abc import Iterable

from attribution_platform.attack_knowledge.loader import AttackKnowledge, FrozenStixObject
from attribution_platform.attack_knowledge.traversal import is_active


def external_id(obj: FrozenStixObject) -> str | None:
    """The object's ``mitre-attack`` external id, or ``None``."""
    for ref in obj.get("external_references") or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


class ExternalIdResolver:
    """An index over the pinned KB's objects of ``object_types``."""

    def __init__(self, knowledge: AttackKnowledge, object_types: Iterable[str]) -> None:
        self._knowledge = knowledge
        self._by_external_id: dict[str, list[FrozenStixObject]] = {}
        for obj_type in sorted(set(object_types)):
            for obj in knowledge.objects_of_type(obj_type):
                for ref in obj.get("external_references") or ():
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        self._by_external_id.setdefault(str(ref["external_id"]), []).append(obj)
        self._revoked_by: dict[str, str] = {}
        for rel in knowledge.relationships():
            if rel.get("relationship_type") == "revoked-by":
                self._revoked_by[str(rel["source_ref"])] = str(rel["target_ref"])

    def resolve(self, external_id_: str) -> tuple[FrozenStixObject, str | None] | None:
        """``(current object, the revoked id it came from or None)``, or ``None``."""
        candidates = self._by_external_id.get(external_id_, [])
        active = [o for o in candidates if is_active(o)]
        if len(active) == 1:
            return active[0], None
        if active:
            return None  # ambiguous: never pick arbitrarily
        revoked = [o for o in candidates if o.get("revoked") is True]
        if len(revoked) != 1:
            return None
        current_id = str(revoked[0]["id"])
        seen = {current_id}
        while current_id in self._revoked_by:
            current_id = self._revoked_by[current_id]
            if current_id in seen:
                return None
            seen.add(current_id)
        target = self._knowledge.get_by_id(current_id)
        if target is None or not is_active(target):
            return None
        return target, external_id_

    def current_external_id(self, external_id_: str) -> str | None:
        """The external id of the current object, or ``None`` if unresolvable."""
        resolved = self.resolve(external_id_)
        return external_id(resolved[0]) if resolved is not None else None


__all__ = ["ExternalIdResolver", "external_id"]
