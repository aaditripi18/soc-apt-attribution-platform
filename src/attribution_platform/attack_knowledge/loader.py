"""Deterministic runtime loader for the pinned MITRE ATT&CK v19.0 bundle.

Scope (gate G0.2 — see docs/architecture/13-phase-0-implementation-plan.md):
loads the already-vendored, already-verified (gate G0.1) Enterprise ATT&CK
v19.0 STIX 2.1 bundle into an in-memory, deterministic, **deeply read-only**
representation — indexed by STIX id and by STIX object type. This is
deliberately NOT a re-typed domain model: it preserves the authoritative
STIX object fields as-is (each object becomes a recursively-frozen mapping,
field-for-field identical to the source JSON) rather than inventing a
second ATT&CK schema. Later gates (G0.3+) build typed domain contracts on
top of this raw, verified access layer.

Runtime constraints (hard requirements, not suggestions):

- Loads **only** the one pinned, versioned local artifact
  (``data/attack/enterprise/v19.0/enterprise-attack-19.0.json``). The public
  entrypoint, :func:`load_attack_knowledge`, takes **no path argument** —
  there is no way for a caller to redirect it to an arbitrary bundle.
- **No network access anywhere in this module.** No MITRE/TAXII calls, no
  "latest" discovery, no silent fallback to a different ATT&CK version.
- Integrity is verified (gate G0.1's :func:`verify_artifact`) **before**
  any object is exposed. A failed/mismatched/tampered artifact raises
  :class:`~attribution_platform.attack_knowledge.verification.ArtifactIntegrityError`
  and nothing is silently repaired or substituted.
- Loading is deterministic: the same pinned artifact always yields the same
  logical object set (same ids, same counts, same fields). No timestamps,
  randomness, or network/host state are ever mixed into the loaded data.
- **Immutability is genuine, not just at the top level.** Every exposed
  object is recursively frozen (see :func:`_deep_freeze`): dicts become
  ``types.MappingProxyType``, lists become ``tuple``, at every nesting
  depth. ``knowledge.objects_by_id[some_id]["name"] = "x"`` raises
  ``TypeError`` — as does mutating a nested list/dict inside that object.
  Scalars (``str``/``int``/``float``/``bool``/``None``) are already
  immutable in Python and are returned as-is.

Deliberately narrow — scope decisions recorded here (see
docs/architecture/13-phase-0-implementation-plan.md, G0.2, for the full
rationale):

- No ``mitreattack-python`` (or any other new runtime dependency). This
  module is stdlib-only (``json``, ``pathlib``, ``dataclasses``,
  ``types.MappingProxyType``), reusing gate G0.1's verification module from
  within this same package. Doc 13's original G0.2 sketch mentioned
  ``mitreattack-python``; this gate's explicit "minimal dependencies" and
  "deliberately narrow" constraints take precedence, and
  ``mitreattack-python``'s own object-model wrapper would itself risk
  "inventing a second ATT&CK schema" — deferred.
- No alias resolution and no relationship traversal (e.g. "which
  techniques does group G use"). Both are candidate-generation-adjacent
  machinery (ADR-0002: candidate generation collapses aliases and walks
  ``uses`` edges) and are explicitly out of scope for this gate. Raw
  ``relationship`` objects are exposed as data via
  :meth:`AttackKnowledge.relationships`; building traversal *logic* on top
  of them is deferred to whichever later gate actually needs it.
- No hard-coded ATT&CK vocabulary anywhere in this module: every
  technique/tactic/group/software/campaign/relationship comes from the
  loaded bundle. The only project-owned constant this module relies on is
  the *pin identifier* (``EXPECTED_ATTACK_KB_VERSION`` etc., defined in
  ``verification.py``) — analogous to a lockfile version pin, not ATT&CK
  content.
- No ``calibration_version``. Calibration does not exist yet (no
  attribution engine, no scoring); this module never fabricates one, and
  keeps ``attack_kb_version`` and any future ``calibration_version``
  conceptually and structurally distinct (ADR-0002 D12/D22,
  docs/architecture/11-attack-knowledge-versioning.md §I).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from attribution_platform.attack_knowledge.verification import (
    ArtifactManifest,
    ObjectFingerprint,
    StixCollectionInfo,
    load_bundle_objects,
    verify_artifact,
)

#: The one true pinned artifact location, resolved relative to this module's
#: own location on disk. This works for an editable/dev install run from
#: within the repository (the only supported mode at this gate); it is not
#: designed for a built/installed distribution, which is out of scope for
#: Phase 0.
_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ATTACK_ARTIFACT_DIR = _REPO_ROOT / "data" / "attack" / "enterprise" / "v19.0"

# STIX object "type" values that carry ATT&CK content, grouped the same way
# verification.compute_object_fingerprint() already categorizes them, so the
# two stay consistent by construction rather than by convention.
_TYPE_TACTIC = "x-mitre-tactic"
_TYPE_TECHNIQUE = "attack-pattern"
_TYPE_GROUP = "intrusion-set"
_TYPE_MALWARE = "malware"
_TYPE_TOOL = "tool"
_TYPE_CAMPAIGN = "campaign"
_TYPE_MITIGATION = "course-of-action"
_TYPE_RELATIONSHIP = "relationship"

#: A recursively-frozen STIX object: a read-only mapping whose values are
#: themselves frozen (nested mappings become FrozenStixObject, nested lists
#: become tuples of frozen values, scalars are returned as-is). See
#: _deep_freeze().
type FrozenStixObject = MappingProxyType[str, Any]


def _deep_freeze(value: Any) -> Any:
    """Recursively freeze a JSON-shaped value into an immutable equivalent.

    - ``dict`` -> ``MappingProxyType`` with every value recursively frozen.
    - ``list`` -> ``tuple`` with every element recursively frozen.
    - anything else (``str``/``int``/``float``/``bool``/``None``) -> returned
      unchanged (already immutable in Python).

    This preserves the raw STIX field structure semantically — field names
    and values are untouched; only the *container types* become immutable,
    at every nesting depth. Input is expected to be the output of
    ``json.load`` (i.e. only JSON-representable types occur), matching
    ``verification.load_bundle_objects``'s "safe json.load only" contract.
    """
    if isinstance(value, dict):
        return MappingProxyType({k: _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(v) for v in value)
    return value


@dataclass(frozen=True)
class AttackKnowledge:
    """A verified, deterministic, **deeply** read-only view of the pinned
    ATT&CK bundle.

    Every exposed STIX object — and every nested dict/list inside it, at
    any depth — is recursively frozen (see :func:`_deep_freeze`): dicts are
    ``MappingProxyType``, lists are ``tuple``. There is no level at which a
    caller can mutate loaded ATT&CK data; ``knowledge.objects_by_id[id]["x"] = y``
    and any nested equivalent raise ``TypeError``.
    """

    attack_kb_version: str
    attack_kb_sha256: str
    attack_domain: str
    stix_spec: str
    stix_collection: StixCollectionInfo
    object_fingerprint: ObjectFingerprint
    objects_by_id: MappingProxyType[str, FrozenStixObject]
    objects_by_type: MappingProxyType[str, tuple[FrozenStixObject, ...]]

    def get_by_id(self, stix_id: str) -> FrozenStixObject | None:
        """Look up a single STIX object by its id. Returns ``None`` if absent."""
        return self.objects_by_id.get(stix_id)

    def objects_of_type(self, stix_type: str) -> tuple[FrozenStixObject, ...]:
        """All STIX objects of a given ``type`` (empty tuple if none)."""
        return self.objects_by_type.get(stix_type, ())

    # Thin, STIX-vocabulary-matching accessors — data access only, no
    # resolution/traversal logic. See the module docstring for what is
    # deliberately NOT included here (aliases, relationship traversal).

    def tactics(self) -> tuple[FrozenStixObject, ...]:
        return self.objects_of_type(_TYPE_TACTIC)

    def techniques(self) -> tuple[FrozenStixObject, ...]:
        """Base techniques only (excludes sub-techniques)."""
        return tuple(
            o
            for o in self.objects_of_type(_TYPE_TECHNIQUE)
            if o.get("x_mitre_is_subtechnique") is not True
        )

    def sub_techniques(self) -> tuple[FrozenStixObject, ...]:
        return tuple(
            o
            for o in self.objects_of_type(_TYPE_TECHNIQUE)
            if o.get("x_mitre_is_subtechnique") is True
        )

    def groups(self) -> tuple[FrozenStixObject, ...]:
        return self.objects_of_type(_TYPE_GROUP)

    def software(self) -> tuple[FrozenStixObject, ...]:
        """Both ``malware`` and ``tool`` STIX objects, combined."""
        return self.objects_of_type(_TYPE_MALWARE) + self.objects_of_type(_TYPE_TOOL)

    def campaigns(self) -> tuple[FrozenStixObject, ...]:
        return self.objects_of_type(_TYPE_CAMPAIGN)

    def mitigations(self) -> tuple[FrozenStixObject, ...]:
        return self.objects_of_type(_TYPE_MITIGATION)

    def relationships(self) -> tuple[FrozenStixObject, ...]:
        """Raw ``relationship`` objects (source_ref/target_ref/relationship_type).

        Exposed as data only — no traversal helpers (e.g. "techniques used
        by group G") are provided at this gate; see the module docstring.
        """
        return self.objects_of_type(_TYPE_RELATIONSHIP)


def _freeze_and_index(
    objects: list[dict[str, Any]],
) -> tuple[
    MappingProxyType[str, FrozenStixObject],
    MappingProxyType[str, tuple[FrozenStixObject, ...]],
]:
    """Recursively freeze every object once, then index the SAME frozen
    instances by id and by type (so ``get_by_id(x)`` and the matching entry
    in ``objects_of_type(t)`` are identical objects, not separately-frozen
    copies)."""
    by_id: dict[str, FrozenStixObject] = {}
    by_type: dict[str, list[FrozenStixObject]] = {}

    for raw_obj in objects:
        frozen_obj: FrozenStixObject = _deep_freeze(raw_obj)

        stix_id = frozen_obj.get("id")
        if isinstance(stix_id, str) and stix_id:
            by_id[stix_id] = frozen_obj

        stix_type = frozen_obj.get("type")
        if isinstance(stix_type, str):
            by_type.setdefault(stix_type, []).append(frozen_obj)

    return (
        MappingProxyType(by_id),
        MappingProxyType({k: tuple(v) for k, v in by_type.items()}),
    )


def _load_from_dir(artifact_dir: Path) -> AttackKnowledge:
    """Internal, path-parameterized loader.

    Used by the public :func:`load_attack_knowledge` (always with the one
    pinned directory) and by tests (with small synthetic fixtures, mirroring
    gate G0.1's own testing pattern) to exercise failure paths without
    touching the real 50MB artifact. This function is intentionally NOT
    part of the public runtime surface — see the module docstring's note on
    "must not accept an arbitrary external bundle path".
    """
    manifest: ArtifactManifest = verify_artifact(
        artifact_dir
    )  # fail-closed integrity gate — first, always
    objects = load_bundle_objects(artifact_dir / manifest.artifact_filename)
    objects_by_id, objects_by_type = _freeze_and_index(objects)

    return AttackKnowledge(
        attack_kb_version=manifest.attack_kb_version,
        attack_kb_sha256=manifest.artifact_sha256,
        attack_domain=manifest.attack_domain,
        stix_spec=manifest.stix_spec,
        stix_collection=manifest.stix_collection,
        object_fingerprint=manifest.object_fingerprint,
        objects_by_id=objects_by_id,
        objects_by_type=objects_by_type,
    )


def load_attack_knowledge() -> AttackKnowledge:
    """Load the one pinned, verified MITRE ATT&CK v19.0 bundle.

    This is the runtime entrypoint: it takes no arguments and always
    resolves to :data:`DEFAULT_ATTACK_ARTIFACT_DIR` — there is no way to
    redirect it to a different artifact, a different version, or a live
    service. Integrity is verified before any object is returned; on
    failure this raises
    :class:`~attribution_platform.attack_knowledge.verification.ArtifactIntegrityError`
    and returns nothing.
    """
    return _load_from_dir(DEFAULT_ATTACK_ARTIFACT_DIR)
