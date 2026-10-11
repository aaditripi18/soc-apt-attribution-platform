"""Deterministic ATT&CK knowledge traversal and entity resolution (gate G3.1).

Implements the knowledge-boundary capabilities ADR-0005 §D6 named as a Phase-3
prerequisite ("extend ``attack_knowledge/``, additively") and the entity/alias/
active-filtering/combination-query requirements Gate 3.1 adds on top of it.
This module is pure, read-only knowledge infrastructure: it never creates or
mutates a Phase 0-2 object, never generates a ``Candidate``, and never
computes a diagnosticity value (``g(x)``/``D(x)``) — it only exposes the raw,
authoritative queries a later Attribution Engine gate will use to compute
those. See the module-level "Deliberately out of scope" note below.

Built entirely on top of the existing, unmodified, frozen G0.2 loader
(:mod:`attribution_platform.attack_knowledge.loader`) — this module adds a new
sibling capability rather than reopening ``loader.py``, mirroring this
project's own repeated "additive sibling module, never reopen a frozen gate"
precedent (``structural.py`` -> ``contextual.py`` -> ... each Phase-2 gate).

What this module provides:

- **Entity resolution** (:func:`resolve_entity`): fail-closed lookup of a
  canonical STIX id, optionally asserting the object's STIX type.
- **Alias resolution** (:func:`aliases_for`, :func:`resolve_alias`): the
  known alias strings for a canonical entity, and the reverse — resolving an
  alias name back to exactly one canonical, *active* entity id, or failing
  closed (:class:`UnknownAttackEntityError`) when none match, or
  (:class:`AmbiguousAliasError`) when the alias is genuinely shared by two or
  more distinct active entities. No identity is ever arbitrarily chosen.
- **Active-object filtering** (:func:`is_active`, :func:`active_groups`,
  :func:`active_campaigns`): distinguishes active from ``revoked``/
  ``x_mitre_deprecated`` objects. Filtering is a read-time semantic view over
  the same immutable, loaded bundle — nothing is deleted from it.
- **Relationship traversal**: forward (:func:`group_profile`,
  :func:`techniques_used_by`, :func:`software_used_by`) and reverse
  (:func:`groups_using_technique`, :func:`campaigns_using_technique`,
  :func:`groups_using_software`, :func:`campaigns_using_software`,
  :func:`software_using_technique`) queries over real STIX ``uses``
  relationships only — no relationship is inferred or fabricated.
- **Combination/profile queries** (:func:`groups_using_all_techniques`,
  :func:`campaigns_using_all_techniques`): "which active Group/Campaign
  profiles are a superset of this technique/software id set" — the exact
  population query ADR-0005 §D3's (not-yet-implemented) combination
  diagnosticity will need, exposed here as a plain set query.
- **Campaign attribution traversal** (:func:`groups_attributed_to_campaign`,
  :func:`campaigns_attributed_to_group`): the additive ADR-0005 Amendment B
  prerequisite — deterministic lookup over real STIX ``attributed-to``
  relationships (``Campaign --attributed-to--> Group``), where the edge
  itself and the target Group must both be active. Read-only knowledge
  context: it never infers, scores, or implies a case-specific attribution.

Deliberately out of scope (see ADR-0005 and the Gate 3.1 task boundary —
building any of this is a later gate's job, not this module's):

- No ``g(x)``/``D(x)``/``g(C)``/``D(C)`` computation of any kind.
- No ``Candidate``/``Hypothesis`` construction or candidate generation (D7).
- No ACH matrix, likelihood, confidence, abstention, or calibration.
- No TI enrichment, no live/network ATT&CK access.

Determinism: every function here operates only on the one pinned, already-
verified, deeply-immutable :class:`~attribution_platform.attack_knowledge.loader.AttackKnowledge`
passed in by the caller — never a version string, never a path, never a
network call. Every returned collection of ids is a ``tuple[str, ...]``
sorted by the ids themselves (never a bare ``frozenset`` iteration order,
never insertion/dict order) — the same "sorted by id before returned"
discipline ADR-0005 §D16 requires of the attribution layer, applied here one
gate early since this is exactly the kind of collection that discipline
exists to protect.
"""

from __future__ import annotations

import weakref
from collections.abc import Callable, Mapping
from types import MappingProxyType

from attribution_platform.attack_knowledge.loader import AttackKnowledge, FrozenStixObject

# STIX object "type" values this module reasons about. Each layer in this
# codebase owns its own local type constants rather than importing another
# submodule's private names (the same convention correlation/*.py already
# established) — these deliberately duplicate loader.py's own private
# _TYPE_* constants rather than importing them.
_TYPE_GROUP = "intrusion-set"
_TYPE_CAMPAIGN = "campaign"
_TYPE_TECHNIQUE = "attack-pattern"
_TYPE_MALWARE = "malware"
_TYPE_TOOL = "tool"

_SOFTWARE_TYPES: frozenset[str] = frozenset({_TYPE_MALWARE, _TYPE_TOOL})
_ALIAS_BEARING_TYPES: frozenset[str] = frozenset(
    {_TYPE_GROUP, _TYPE_CAMPAIGN, _TYPE_MALWARE, _TYPE_TOOL}
)

_RELATIONSHIP_USES = "uses"
_RELATIONSHIP_ATTRIBUTED_TO = "attributed-to"
_RELATIONSHIP_DETECTS = "detects"

# ATT&CK v19 detection-graph object types (the "detections overhaul" model,
# ATT&CK ≥ v17): a technique's telemetry requirement is reached through
# detection-strategy -> analytic -> log-source-reference -> data-component,
# not the legacy per-technique `x_mitre_data_sources` field (absent in the
# pinned enterprise-attack-19.0 bundle). See ADR-0005 Amendment C (2026-09-21)
# and docs/architecture/11-coverage-model.md.
_TYPE_DETECTION_STRATEGY = "x-mitre-detection-strategy"
_TYPE_ANALYTIC = "x-mitre-analytic"
_TYPE_DATA_COMPONENT = "x-mitre-data-component"


class UnknownAttackEntityError(LookupError):
    """Raised when a STIX id (or alias, or object-type expectation) does not
    resolve against the loaded ATT&CK knowledge base.

    Fail-closed: this is never a signal to fabricate, guess, or silently
    substitute a different object — callers must treat it as fatal for the
    query being made.
    """


class AmbiguousAliasError(ValueError):
    """Raised when an alias string resolves to more than one distinct
    *active* ATT&CK entity.

    Fail-closed: no identity is ever arbitrarily chosen between candidates —
    this is a genuine data ambiguity (two active entities documented under
    the same alias) that only a caller with additional context can resolve.
    """


class InvalidCombinationQueryError(ValueError):
    """Raised when a combination/profile query is malformed (e.g. an empty
    technique/software id set) — a caller-usage error, not a knowledge-base
    gap.
    """


# ===========================================================================
# A. Entity resolution
# ===========================================================================


def resolve_entity(
    knowledge: AttackKnowledge, stix_id: str, *, expected_type: str | None = None
) -> FrozenStixObject:
    """Resolve ``stix_id`` to its pinned ATT&CK object, or fail closed.

    Never fabricates an object for an unknown id — raises
    :class:`UnknownAttackEntityError` instead. When ``expected_type`` is
    given, the resolved object's own STIX ``type`` field must match it
    exactly, or the same error is raised (never a silent type coercion).
    """
    obj = knowledge.get_by_id(stix_id)
    if obj is None:
        raise UnknownAttackEntityError(
            f"{stix_id!r} does not exist in ATT&CK {knowledge.attack_kb_version}"
        )
    actual_type = obj.get("type")
    if expected_type is not None and actual_type != expected_type:
        raise UnknownAttackEntityError(
            f"{stix_id!r} resolves to a {actual_type!r} object in "
            f"{knowledge.attack_kb_version}, expected {expected_type!r}"
        )
    return obj


# ===========================================================================
# C. Active-object filtering
# ===========================================================================


def is_active(obj: FrozenStixObject) -> bool:
    """True iff ``obj`` is neither ``revoked`` nor ``x_mitre_deprecated``.

    Both STIX fields are optional/absent on most objects; per STIX
    convention, absence (or any value other than the literal ``True``) means
    the flag does not apply — only an explicit ``True`` marks an object
    revoked/deprecated.
    """
    return obj.get("revoked") is not True and obj.get("x_mitre_deprecated") is not True


def active_groups(knowledge: AttackKnowledge) -> tuple[FrozenStixObject, ...]:
    """Every non-revoked, non-deprecated ``intrusion-set`` object, sorted by
    STIX id. This is the exact "active Group" population ADR-0005 §D3's
    (not computed here) prevalence denominator is defined over."""
    return tuple(
        sorted((g for g in knowledge.groups() if is_active(g)), key=lambda o: str(o["id"]))
    )


def active_campaigns(knowledge: AttackKnowledge) -> tuple[FrozenStixObject, ...]:
    """Every non-revoked, non-deprecated ``campaign`` object, sorted by STIX id."""
    return tuple(
        sorted((c for c in knowledge.campaigns() if is_active(c)), key=lambda o: str(o["id"]))
    )


# ===========================================================================
# B. Alias resolution
# ===========================================================================


def _alias_strings(obj: FrozenStixObject) -> frozenset[str]:
    """The object's own ATT&CK name plus every string in its ``aliases``
    (Group/Campaign) or ``x_mitre_aliases`` (Software) STIX field."""
    names: set[str] = set()
    name = obj.get("name")
    if isinstance(name, str) and name:
        names.add(name)
    for field in ("aliases", "x_mitre_aliases"):
        values = obj.get(field)
        if isinstance(values, tuple):
            for value in values:
                if isinstance(value, str) and value:
                    names.add(value)
    return frozenset(names)


def aliases_for(knowledge: AttackKnowledge, stix_id: str) -> frozenset[str]:
    """The canonical ATT&CK name plus every known alias string for
    ``stix_id`` — read directly from that object's own ``aliases``/
    ``x_mitre_aliases`` STIX field. Fails closed on an unknown id.

    This performs no cross-object collapsing beyond what the pinned bundle
    itself already records: when MITRE merges one group's identity into
    another's (a STIX ``revoked-by`` relationship), the surviving object's
    own ``aliases`` field already carries the retired object's alias names —
    this function reads that field as-is, never re-deriving or second-
    guessing it.
    """
    obj = resolve_entity(knowledge, stix_id)
    return _alias_strings(obj)


def _normalize_alias(alias: str) -> str:
    """Deterministic normalization key for alias comparison: trims
    surrounding whitespace and case-folds. The same key for the same
    logical alias, regardless of casing/incidental whitespace."""
    return alias.strip().casefold()


def resolve_alias(
    knowledge: AttackKnowledge,
    alias: str,
    *,
    object_types: frozenset[str] = _ALIAS_BEARING_TYPES,
) -> str:
    """Resolve an alias name (case/whitespace-insensitive) to exactly one
    canonical STIX id among the *active* entities of ``object_types``.

    Fails closed in both directions:

    - :class:`UnknownAttackEntityError` if no active entity of the requested
      types carries this alias.
    - :class:`AmbiguousAliasError` if two or more *distinct* active entities
      carry the identical normalized alias — this genuinely occurs in the
      pinned v19.0 bundle (two different active Groups documented under the
      same public alias); no identity is ever arbitrarily chosen.

    Multiple alias strings belonging to the SAME STIX object always resolve
    to that one object's id without ambiguity — this only raises when the
    normalized alias is shared by *different* canonical entities.
    """
    normalized = _normalize_alias(alias)
    if not normalized:
        raise UnknownAttackEntityError("alias must be a non-empty string")

    matches: set[str] = set()
    for stix_type in object_types:
        for obj in knowledge.objects_of_type(stix_type):
            if not is_active(obj):
                continue
            if any(_normalize_alias(name) == normalized for name in _alias_strings(obj)):
                matches.add(str(obj["id"]))

    if not matches:
        raise UnknownAttackEntityError(
            f"alias {alias!r} does not resolve to any active ATT&CK entity "
            f"in {knowledge.attack_kb_version}"
        )
    if len(matches) > 1:
        raise AmbiguousAliasError(
            f"alias {alias!r} is ambiguous across active entities in "
            f"{knowledge.attack_kb_version}: {tuple(sorted(matches))!r}"
        )
    return next(iter(matches))


# ===========================================================================
# D. Relationship traversal (forward + reverse), over real STIX "uses" edges
# ===========================================================================


_Index = Mapping[str, frozenset[str]]
#: ``(id(knowledge), index name) -> (weak reference to that knowledge, index)``.
_INDEXES: dict[tuple[int, str], tuple[weakref.ref[AttackKnowledge], _Index]] = {}


def _index(
    knowledge: AttackKnowledge, name: str, build: Callable[[AttackKnowledge], _Index]
) -> _Index:
    """``build(knowledge)``, computed once per loaded knowledge base.

    An :class:`AttackKnowledge` is deeply frozen, so an index over its
    relationships is a pure function of that one object: remembering it changes
    no result, only the cost (each build walks every relationship — ~10 ms on
    the pinned bundle — and the exact combination search asks for ``g`` tens of
    thousands of times; ADR-0009 Amendment D). The entry is keyed by object
    identity, checked against a weak reference so a recycled ``id`` can never
    return another knowledge base's index, and dropped when the object is
    collected. The index itself is read-only.
    """
    key = (id(knowledge), name)
    hit = _INDEXES.get(key)
    if hit is not None and hit[0]() is knowledge:
        return hit[1]
    built = MappingProxyType(dict(build(knowledge)))

    def forget(_reference: weakref.ref[AttackKnowledge]) -> None:
        _INDEXES.pop(key, None)

    _INDEXES[key] = (weakref.ref(knowledge, forget), built)
    return built


def _uses_index_by_source(knowledge: AttackKnowledge) -> _Index:
    """``source_ref -> {target_ref, ...}`` over every ``uses`` relationship of
    the loaded (already frozen, already verified) knowledge base — a pure
    function of ``knowledge`` (see :func:`_index`)."""
    return _index(knowledge, "uses_by_source", _build_uses_index_by_source)


def _build_uses_index_by_source(knowledge: AttackKnowledge) -> dict[str, frozenset[str]]:
    index: dict[str, set[str]] = {}
    for rel in knowledge.relationships():
        if rel.get("relationship_type") != _RELATIONSHIP_USES:
            continue
        source = rel.get("source_ref")
        target = rel.get("target_ref")
        if isinstance(source, str) and isinstance(target, str):
            index.setdefault(source, set()).add(target)
    return {key: frozenset(value) for key, value in index.items()}


def _uses_index_by_target(knowledge: AttackKnowledge) -> _Index:
    """``target_ref -> {source_ref, ...}`` over every ``uses`` relationship —
    the reverse of :func:`_uses_index_by_source`."""
    return _index(knowledge, "uses_by_target", _build_uses_index_by_target)


def _build_uses_index_by_target(knowledge: AttackKnowledge) -> dict[str, frozenset[str]]:
    index: dict[str, set[str]] = {}
    for rel in knowledge.relationships():
        if rel.get("relationship_type") != _RELATIONSHIP_USES:
            continue
        source = rel.get("source_ref")
        target = rel.get("target_ref")
        if isinstance(source, str) and isinstance(target, str):
            index.setdefault(target, set()).add(source)
    return {key: frozenset(value) for key, value in index.items()}


def _object_type(knowledge: AttackKnowledge, stix_id: str) -> str | None:
    obj = knowledge.get_by_id(stix_id)
    return str(obj["type"]) if obj is not None else None


def _filter_by_type(
    knowledge: AttackKnowledge, stix_ids: frozenset[str], stix_type: str
) -> tuple[str, ...]:
    return tuple(sorted(sid for sid in stix_ids if _object_type(knowledge, sid) == stix_type))


def _filter_active_by_type(
    knowledge: AttackKnowledge, stix_ids: frozenset[str], stix_type: str
) -> tuple[str, ...]:
    result = []
    for sid in stix_ids:
        obj = knowledge.get_by_id(sid)
        if obj is not None and obj.get("type") == stix_type and is_active(obj):
            result.append(sid)
    return tuple(sorted(result))


def _active_uses_targets(knowledge: AttackKnowledge, stix_id: str) -> frozenset[str]:
    """The one authoritative **active-target** view of a source's ``uses``
    profile: its ``uses`` target ids filtered to *active* (non-``revoked``,
    non-``x_mitre_deprecated``) objects only, using the existing :func:`is_active`
    semantics — never a second definition of "active".

    This enforces the accepted active-target policy (ADR-0005 Amendment B
    "Active-target policy for ``ProfileBreadth`` and every prevalence/traversal
    quantity"; ADR-0006 §Decision-path scale): revoked/deprecated **target**
    techniques/software MUST NOT contribute to a profile (and therefore not to
    profile breadth). A target id that does not resolve in the pinned KB (a
    dangling ``uses`` edge) is excluded fail-closed. Reverse lookups
    (:func:`groups_using_technique` etc.) and the combination superset queries
    (:func:`groups_using_all_techniques`) already restrict the **source**
    population to active Groups/Campaigns via :func:`_filter_active_by_type` /
    :func:`active_groups`, so only these forward-profile helpers needed the
    target-side filter added here."""
    return frozenset(
        target
        for target in _uses_index_by_source(knowledge).get(stix_id, frozenset())
        if (obj := knowledge.get_by_id(target)) is not None and is_active(obj)
    )


def group_profile(knowledge: AttackKnowledge, stix_id: str) -> tuple[str, ...]:
    """The full **active** technique+software ``uses`` set for one Group or
    Campaign, sorted by STIX id — revoked/deprecated target techniques/software
    are excluded (active-target policy, via :func:`_active_uses_targets`). This
    is the exact set ``len(group_profile(...))`` = ``ProfileBreadth`` consumes
    (ADR-0005 Amendment B). Fails closed on an unknown id or an id that is not a
    Group/Campaign."""
    obj = resolve_entity(knowledge, stix_id)
    if obj.get("type") not in (_TYPE_GROUP, _TYPE_CAMPAIGN):
        raise UnknownAttackEntityError(
            f"{stix_id!r} is a {obj.get('type')!r} object; group_profile() requires a "
            f"{_TYPE_GROUP!r} or {_TYPE_CAMPAIGN!r}"
        )
    return tuple(sorted(_active_uses_targets(knowledge, stix_id)))


def techniques_used_by(knowledge: AttackKnowledge, stix_id: str) -> tuple[str, ...]:
    """The **active** technique-only subset of this entity's ``uses`` profile
    (every *active* ``attack-pattern`` id it is recorded as using), sorted by id.
    Works for any ``uses``-source entity (Group, Campaign, or Software). Applies
    the same active-target policy as :func:`group_profile`, so the invariant
    ``group_profile == techniques_used_by ∪ software_used_by`` is preserved.
    Fails closed on an unknown id."""
    resolve_entity(knowledge, stix_id)
    return _filter_by_type(knowledge, _active_uses_targets(knowledge, stix_id), _TYPE_TECHNIQUE)


def software_used_by(knowledge: AttackKnowledge, stix_id: str) -> tuple[str, ...]:
    """The **active** software-only subset (``malware``/``tool``) of this
    entity's ``uses`` profile, sorted by id — revoked/deprecated target software
    excluded (active-target policy, via :func:`_active_uses_targets`). Fails
    closed on an unknown id."""
    resolve_entity(knowledge, stix_id)
    targets = _active_uses_targets(knowledge, stix_id)
    return tuple(sorted(t for t in targets if _object_type(knowledge, t) in _SOFTWARE_TYPES))


def groups_using_technique(knowledge: AttackKnowledge, technique_stix_id: str) -> tuple[str, ...]:
    """Every *active* Group recorded as using this technique, sorted by id —
    the reverse lookup ADR-0005 §D3's ``g(x)`` (not computed here) needs.
    Fails closed on an unknown/non-technique id."""
    resolve_entity(knowledge, technique_stix_id, expected_type=_TYPE_TECHNIQUE)
    sources = _uses_index_by_target(knowledge).get(technique_stix_id, frozenset())
    return _filter_active_by_type(knowledge, sources, _TYPE_GROUP)


def campaigns_using_technique(
    knowledge: AttackKnowledge, technique_stix_id: str
) -> tuple[str, ...]:
    """Every *active* Campaign recorded as using this technique, sorted by
    id. Fails closed on an unknown/non-technique id."""
    resolve_entity(knowledge, technique_stix_id, expected_type=_TYPE_TECHNIQUE)
    sources = _uses_index_by_target(knowledge).get(technique_stix_id, frozenset())
    return _filter_active_by_type(knowledge, sources, _TYPE_CAMPAIGN)


def software_using_technique(knowledge: AttackKnowledge, technique_stix_id: str) -> tuple[str, ...]:
    """Every Software (``malware``/``tool``) object related to this
    technique via a real ``uses`` relationship, sorted by id — unfiltered by
    active/revoked status (callers needing only active software may filter
    the result with :func:`is_active` themselves; this query answers "which
    Software objects are related to technique X", not "which active
    Software"). Fails closed on an unknown/non-technique id."""
    resolve_entity(knowledge, technique_stix_id, expected_type=_TYPE_TECHNIQUE)
    sources = _uses_index_by_target(knowledge).get(technique_stix_id, frozenset())
    result = [s for s in sources if _object_type(knowledge, s) in _SOFTWARE_TYPES]
    return tuple(sorted(result))


def groups_using_software(knowledge: AttackKnowledge, software_stix_id: str) -> tuple[str, ...]:
    """Every *active* Group recorded as using this software, sorted by id —
    the reverse lookup ADR-0005 §D3's software-extended ``g(x)`` (not
    computed here) needs. Fails closed on an unknown/non-software id."""
    obj = resolve_entity(knowledge, software_stix_id)
    if obj.get("type") not in _SOFTWARE_TYPES:
        raise UnknownAttackEntityError(
            f"{software_stix_id!r} is a {obj.get('type')!r} object, expected "
            f"{_TYPE_MALWARE!r} or {_TYPE_TOOL!r}"
        )
    sources = _uses_index_by_target(knowledge).get(software_stix_id, frozenset())
    return _filter_active_by_type(knowledge, sources, _TYPE_GROUP)


def campaigns_using_software(knowledge: AttackKnowledge, software_stix_id: str) -> tuple[str, ...]:
    """Every *active* Campaign recorded as using this software, sorted by
    id. Fails closed on an unknown/non-software id."""
    obj = resolve_entity(knowledge, software_stix_id)
    if obj.get("type") not in _SOFTWARE_TYPES:
        raise UnknownAttackEntityError(
            f"{software_stix_id!r} is a {obj.get('type')!r} object, expected "
            f"{_TYPE_MALWARE!r} or {_TYPE_TOOL!r}"
        )
    sources = _uses_index_by_target(knowledge).get(software_stix_id, frozenset())
    return _filter_active_by_type(knowledge, sources, _TYPE_CAMPAIGN)


# ===========================================================================
# E. Campaign attribution traversal, over real STIX "attributed-to" edges
#    (ADR-0005 Amendment B "ATT&CK attributed-to traversal prerequisite")
# ===========================================================================


def _active_attributed_to_index(
    knowledge: AttackKnowledge, *, by_target: bool
) -> dict[str, frozenset[str]]:
    """Index over every *active* ``attributed-to`` relationship object
    (``Campaign --attributed-to--> Group``): ``source_ref -> {target_ref}``,
    or the reverse (``target_ref -> {source_ref}``) when ``by_target``.

    A revoked/deprecated relationship object is skipped here — unlike the
    ``uses`` indexes, edge activeness is part of this query's contract. Built
    fresh from the loaded relationships on every call (a pure function of
    ``knowledge``; no cached or global state)."""
    index: dict[str, set[str]] = {}
    for rel in knowledge.relationships():
        if rel.get("relationship_type") != _RELATIONSHIP_ATTRIBUTED_TO or not is_active(rel):
            continue
        source = rel.get("source_ref")
        target = rel.get("target_ref")
        if isinstance(source, str) and isinstance(target, str):
            key, value = (target, source) if by_target else (source, target)
            index.setdefault(key, set()).add(value)
    return {key: frozenset(value) for key, value in index.items()}


def groups_attributed_to_campaign(
    knowledge: AttackKnowledge, campaign_stix_id: str
) -> tuple[str, ...]:
    """Every *active* Group this Campaign is recorded as attributed to via a
    real, *active* STIX ``attributed-to`` relationship, sorted by id.

    ADR-0005 Amendment B B6 context only: this is ATT&CK knowledge context,
    never case-specific proof. Fails closed
    (:class:`UnknownAttackEntityError`) on an unknown or non-``campaign`` id;
    returns an empty tuple (not an error) when no active edge to an active
    Group exists."""
    resolve_entity(knowledge, campaign_stix_id, expected_type=_TYPE_CAMPAIGN)
    targets = _active_attributed_to_index(knowledge, by_target=False).get(
        campaign_stix_id, frozenset()
    )
    return _filter_active_by_type(knowledge, targets, _TYPE_GROUP)


def campaigns_attributed_to_group(
    knowledge: AttackKnowledge, group_stix_id: str
) -> tuple[str, ...]:
    """Every Campaign recorded as attributed to this Group via a real,
    *active* STIX ``attributed-to`` relationship, sorted by id (the reverse of
    :func:`groups_attributed_to_campaign`; STIX direction is
    ``Campaign --attributed-to--> Group``).

    The target Group must itself be active: an edge to a revoked/deprecated
    Group never qualifies, so querying an inactive Group returns an empty
    tuple. Fails closed (:class:`UnknownAttackEntityError`) on an unknown or
    non-``intrusion-set`` id."""
    group = resolve_entity(knowledge, group_stix_id, expected_type=_TYPE_GROUP)
    if not is_active(group):
        return ()
    sources = _active_attributed_to_index(knowledge, by_target=True).get(group_stix_id, frozenset())
    return _filter_by_type(knowledge, sources, _TYPE_CAMPAIGN)


# ===========================================================================
# Combination/profile queries — the population lookups ADR-0005 §D3's
# combination diagnosticity (g(C)/D(C), NOT computed here) will consume.
# ===========================================================================


def groups_using_all_techniques(
    knowledge: AttackKnowledge, technique_stix_ids: frozenset[str]
) -> tuple[str, ...]:
    """Every *active* Group whose ``uses`` profile is a superset of
    ``technique_stix_ids``, sorted by id.

    ``technique_stix_ids`` must be non-empty and every id must resolve to a
    real ``attack-pattern`` in this KB — fails closed
    (:class:`InvalidCombinationQueryError` / :class:`UnknownAttackEntityError`)
    otherwise. Returns an empty tuple (not an error) when the combination is
    well-formed but no active Group's profile satisfies it — that is a
    legitimate, deterministic "no matches" result, not a failure.
    """
    if not technique_stix_ids:
        raise InvalidCombinationQueryError("technique_stix_ids must be non-empty")
    for technique_stix_id in technique_stix_ids:
        resolve_entity(knowledge, technique_stix_id, expected_type=_TYPE_TECHNIQUE)

    index = _uses_index_by_source(knowledge)
    matches = [
        str(group["id"])
        for group in active_groups(knowledge)
        if technique_stix_ids <= index.get(str(group["id"]), frozenset())
    ]
    return tuple(sorted(matches))


def campaigns_using_all_techniques(
    knowledge: AttackKnowledge, technique_stix_ids: frozenset[str]
) -> tuple[str, ...]:
    """Every *active* Campaign whose ``uses`` profile is a superset of
    ``technique_stix_ids``, sorted by id. Same fail-closed/empty-result
    contract as :func:`groups_using_all_techniques`."""
    if not technique_stix_ids:
        raise InvalidCombinationQueryError("technique_stix_ids must be non-empty")
    for technique_stix_id in technique_stix_ids:
        resolve_entity(knowledge, technique_stix_id, expected_type=_TYPE_TECHNIQUE)

    index = _uses_index_by_source(knowledge)
    matches = [
        str(campaign["id"])
        for campaign in active_campaigns(knowledge)
        if technique_stix_ids <= index.get(str(campaign["id"]), frozenset())
    ]
    return tuple(sorted(matches))


# ===========================================================================
# F. Coverage-required derivation, over the ATT&CK v19 detection graph
#    (ADR-0005 §D2 as clarified by Amendment C (2026-09-21);
#     docs/architecture/11-coverage-model.md — Phase-3 prerequisite B3).
#
#    STIX direction:  detection-strategy --detects--> attack-pattern
#    Forward refs:     detection-strategy.x_mitre_analytic_refs -> analytic
#                      analytic.x_mitre_log_source_references[]
#                          .x_mitre_data_component_ref -> x-mitre-data-component
#    Required value:   the active data-component's `name`.
# ===========================================================================


def _detection_strategies_by_technique(knowledge: AttackKnowledge) -> dict[str, frozenset[str]]:
    """``technique target_ref -> {detection-strategy source_ref, ...}`` over
    every *active* ``detects`` relationship (STIX direction:
    ``detection-strategy --detects--> attack-pattern``).

    Edge activeness is part of this query's contract (like the
    ``attributed-to`` index, unlike the ``uses`` indexes): a revoked/deprecated
    ``detects`` relationship contributes nothing. Built fresh from the loaded
    relationships on every call (a pure function of ``knowledge``; no cached or
    global state)."""
    index: dict[str, set[str]] = {}
    for rel in knowledge.relationships():
        if rel.get("relationship_type") != _RELATIONSHIP_DETECTS or not is_active(rel):
            continue
        source = rel.get("source_ref")
        target = rel.get("target_ref")
        if isinstance(source, str) and isinstance(target, str):
            index.setdefault(target, set()).add(source)
    return {key: frozenset(value) for key, value in index.items()}


def required_data_components(knowledge: AttackKnowledge, technique_stix_id: str) -> tuple[str, ...]:
    """The **active** ``x-mitre-data-component`` NAMES required to observe a
    technique, sorted-unique — the ADR-0005 §D2 ``data_sources_required`` set
    under the pinned ATT&CK v19 detection graph (Amendment C (2026-09-21);
    ``docs/architecture/11-coverage-model.md`` — Phase-3 prerequisite B3).

    Derivation (pinned ``AttackKnowledge`` only; no network): every active
    ``x-mitre-data-component`` reachable via ``technique ← active detects ←
    active detection-strategy → active analytic →
    x_mitre_log_source_references[].x_mitre_data_component_ref → active
    data-component``. Active filtering (:func:`is_active`, the accepted P2
    active-object policy) is applied at **every** hop; a revoked/deprecated
    object at any hop, or a dangling/unresolved/malformed reference, contributes
    nothing (fail closed, never raises for a missing hop, never fabricates).

    Fails closed (:class:`UnknownAttackEntityError`) on an unknown id or an id
    that is not an ``attack-pattern``. An **inactive** technique, or an active
    technique with no resolvable active data-component (≈7% of active
    techniques — predominantly Reconnaissance/Resource-Development), yields an
    **empty** tuple; per §D2/doc 11 the caller maps that to
    :attr:`~attribution_platform.attribution.contracts.CoverageState.UNKNOWN`.
    This function computes only the required set; it makes no coverage-state
    decision and reads no attribution output. Deterministic and
    ``PYTHONHASHSEED``-independent; never mutates ``knowledge``."""
    technique = resolve_entity(knowledge, technique_stix_id, expected_type=_TYPE_TECHNIQUE)
    if not is_active(technique):
        return ()

    strategy_ids = _detection_strategies_by_technique(knowledge).get(technique_stix_id, frozenset())
    names: set[str] = set()
    for strategy_id in strategy_ids:
        strategy = knowledge.get_by_id(strategy_id)
        if (
            strategy is None
            or strategy.get("type") != _TYPE_DETECTION_STRATEGY
            or not is_active(strategy)
        ):
            continue
        analytic_refs = strategy.get("x_mitre_analytic_refs", ())
        if not isinstance(analytic_refs, tuple):
            continue
        for analytic_id in analytic_refs:
            if not isinstance(analytic_id, str):
                continue
            analytic = knowledge.get_by_id(analytic_id)
            if (
                analytic is None
                or analytic.get("type") != _TYPE_ANALYTIC
                or not is_active(analytic)
            ):
                continue
            log_source_refs = analytic.get("x_mitre_log_source_references", ())
            if not isinstance(log_source_refs, tuple):
                continue
            for ref in log_source_refs:
                if not isinstance(ref, MappingProxyType):
                    continue
                component_id = ref.get("x_mitre_data_component_ref")
                if not isinstance(component_id, str):
                    continue
                component = knowledge.get_by_id(component_id)
                if (
                    component is None
                    or component.get("type") != _TYPE_DATA_COMPONENT
                    or not is_active(component)
                ):
                    continue
                name = component.get("name")
                if isinstance(name, str) and name:
                    names.add(name)
    return tuple(sorted(names))
