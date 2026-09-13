"""Minimal, immutable ATT&CK reference contract (gate G0.3).

An :class:`AttackRef` is a *stable pointer* to a single ATT&CK object in the
pinned knowledge base loaded by gate G0.2 — nothing more. It deliberately
does **not**:

- duplicate the full ATT&CK STIX object into the domain layer,
- hard-code any technique IDs or APT group names,
- resolve the reference against the loaded KB,
- resolve aliases or traverse ATT&CK relationships,
- perform candidate generation or any attribution.

Keeping it a pure pointer keeps the domain layer decoupled from the ~50 MB
ATT&CK artifact and from the ``attack_knowledge`` package: constructing an
``AttackRef`` never loads the bundle. Whether a given ``stix_id`` actually
resolves in a specific loaded KB is a *later*-gate concern (checked where a
loaded ``AttackKnowledge`` is available), not a domain-construction concern.

The reference validates its own *shape* only (STIX-id well-formedness,
non-empty type, non-empty kb version). ``stix_id`` is the primary key
because that is exactly what G0.2's ``AttackKnowledge.get_by_id`` uses;
``external_id`` (the human-facing ``Txxxx`` for techniques) is optional
because not every ATT&CK object type has one.
"""

from __future__ import annotations

from dataclasses import dataclass

from attribution_platform.domain.errors import DomainContractError, ensure_nonempty_str

#: STIX 2.1 ids are ``<type>--<uuid>``; we validate that structural shape
#: (a real STIX invariant), not any ATT&CK *content*.
_STIX_ID_SEPARATOR = "--"


@dataclass(frozen=True)
class AttackRef:
    """A stable reference to one pinned ATT&CK object.

    - ``stix_id``: the object's STIX 2.1 id, e.g.
      ``attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22`` (the key
      resolvable via ``AttackKnowledge.get_by_id`` in G0.2).
    - ``object_type``: the STIX/ATT&CK object type, e.g. ``attack-pattern``,
      ``intrusion-set``, ``malware``, ``tool``, ``campaign``,
      ``x-mitre-tactic``. Supplied by the caller; not enumerated here.
    - ``attack_kb_version``: the pinned KB version this id belongs to
      (e.g. ``enterprise-attack-19.0``), so a reference is reproducible and
      only interpreted against the KB version that produced it.
    - ``external_id``: optional human-facing ATT&CK id (``Txxxx`` /
      ``Txxxx.yyy`` for techniques); absent for objects without one.

    Validation (shape only, fail closed): ``object_type`` and
    ``attack_kb_version`` non-empty; ``stix_id`` non-empty and of the form
    ``<object_type>--<rest>`` (its STIX id prefix must match ``object_type``).
    """

    stix_id: str
    object_type: str
    attack_kb_version: str
    external_id: str | None = None

    def __post_init__(self) -> None:
        ensure_nonempty_str(self.stix_id, "AttackRef.stix_id")
        ensure_nonempty_str(self.object_type, "AttackRef.object_type")
        ensure_nonempty_str(self.attack_kb_version, "AttackRef.attack_kb_version")

        if _STIX_ID_SEPARATOR not in self.stix_id:
            raise DomainContractError(
                f"AttackRef.stix_id {self.stix_id!r} is not a well-formed STIX id "
                f"(expected '<type>{_STIX_ID_SEPARATOR}<uuid>')"
            )
        prefix = self.stix_id.split(_STIX_ID_SEPARATOR, 1)[0]
        if prefix != self.object_type:
            raise DomainContractError(
                f"AttackRef.stix_id type-prefix {prefix!r} does not match "
                f"object_type {self.object_type!r}"
            )

        if self.external_id is not None:
            ensure_nonempty_str(self.external_id, "AttackRef.external_id")
