"""Validate a domain ``AttackRef`` against loaded pinned ATT&CK knowledge (gate G0.6).

A small, deterministic KB query: given a loaded
:class:`~attribution_platform.attack_knowledge.loader.AttackKnowledge` and a
:class:`~attribution_platform.domain.AttackRef`, confirm the reference points
to a real object of the claimed type in that exact KB version. This is the
one place a *pure pointer* ``AttackRef`` (which by G0.3 design never touches
the KB) is checked against the actual pinned knowledge.

It performs a bounded lookup only — no alias resolution, no relationship
traversal, no candidate generation, no scoring. It lives in
``attack_knowledge`` (not the domain layer) because it queries the KB;
``domain`` never imports this. This layer may import ``domain`` (the
one-directional dependency: domain is foundational).
"""

from __future__ import annotations

from attribution_platform.attack_knowledge.loader import AttackKnowledge, FrozenStixObject
from attribution_platform.domain import AttackRef


class AttackReferenceError(ValueError):
    """Raised when an ``AttackRef`` does not resolve in the loaded ATT&CK KB.

    Fail-closed: the reference's KB version disagrees with the loaded KB, the
    ``stix_id`` is absent, or the resolved object's STIX ``type`` does not
    match the reference's declared ``object_type``.
    """


def resolve_attack_ref(knowledge: AttackKnowledge, ref: AttackRef) -> FrozenStixObject:
    """Return the pinned ATT&CK object the ``ref`` points to, or fail closed.

    Checks, in order (raising :class:`AttackReferenceError` on the first
    failure):

    1. ``ref.attack_kb_version`` matches ``knowledge.attack_kb_version`` — a
       reference is only interpretable against the KB version that produced
       it (docs/architecture/11 §I).
    2. ``ref.stix_id`` resolves to an object via ``knowledge.get_by_id``.
    3. the resolved object's STIX ``type`` equals ``ref.object_type``.

    Returns the resolved (deeply-immutable) STIX object on success — no copy,
    no second schema; the domain layer keeps only the pointer.
    """
    if ref.attack_kb_version != knowledge.attack_kb_version:
        raise AttackReferenceError(
            f"AttackRef.attack_kb_version={ref.attack_kb_version!r} does not match the loaded "
            f"KB version {knowledge.attack_kb_version!r}"
        )

    obj = knowledge.get_by_id(ref.stix_id)
    if obj is None:
        raise AttackReferenceError(
            f"AttackRef.stix_id={ref.stix_id!r} does not exist in ATT&CK "
            f"{knowledge.attack_kb_version}"
        )

    actual_type = obj.get("type")
    if actual_type != ref.object_type:
        raise AttackReferenceError(
            f"AttackRef.stix_id={ref.stix_id!r} resolves to a {actual_type!r} object, "
            f"but AttackRef.object_type is {ref.object_type!r}"
        )

    return obj
