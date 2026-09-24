"""Calibration corpus manifest + ``calibration_corpus_version`` (gate B1.3,
ADR-0006 §D12/§D13).

**Corpus *identity* only — no fitting, no ``calibration_version``, no split
validation, no scoring.** This module defines the deterministic **identity of
a calibration corpus**: a frozen :class:`CalibrationCorpusManifest` over the
per-case content hashes (``case_id``), a corpus-level source registry, the
(passive) split assignment, and the version stamps — plus its single derived
identity, :func:`compute_calibration_corpus_version`. The dependency chain is
strictly one-way and acyclic::

    CalibrationCase -> case_id -> Corpus Manifest -> calibration_corpus_version
                                                     -> (future) calibration_version

**This module creates ONLY ``calibration_corpus_version``.** It contains **no**
``calibration_version``, **no** fitted parameter set / fitting procedure, **no**
threshold / WEP cutoff / confidence cutoff / likelihood / ranking / abstention,
and **no** leakage / scenario-family-disjointness / near-duplicate /
blind-actor / ATT&CK-ablation validation (all B1.4+). It records the split
*assignment* (role -> families) but never *validates* it.

**Reuse, never re-invent.** It imports only its own package
(:mod:`~attribution_platform.calibration.contracts` /
:mod:`~attribution_platform.calibration.errors`), the already-shared
:func:`attribution_platform.domain.serialization.to_canonical_json`
(sorted-key, byte-stable, ``PYTHONHASHSEED``-independent), and the standard
library. No ATT&CK loader/traversal, no attribution scoring, no new serializer
or hashing scheme. A local ``_sha256_hex`` mirrors the B1.2 inlined-helper
convention (each contracts module owns its helpers).

**Self-excluded version (no hash-of-hash).** ``calibration_corpus_version`` is
a ``field(init=False)`` computed in ``__post_init__`` over the canonical JSON
of **every manifest field except the version field itself** — so it never
includes itself, never includes ``calibration_version``, and never depends on
any volatile value (timestamp, path beyond ``source_ref``, UUID, memory
address). Every semantically-unordered collection is canonicalized
(sorted-unique) on construction, so identity is order-independent.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field

from attribution_platform.calibration.contracts import (
    CalibrationCase,
    CaseRole,
    SourceKind,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.domain.serialization import to_canonical_json

#: Schema version of the B1.3 manifest contract — deliberately **distinct**
#: from ``CalibrationCase.corpus_schema_version`` (the case-contract schema).
#: Both participate in the corpus-version hash; they version different things.
CALIBRATION_MANIFEST_SCHEMA_VERSION = "calibration-corpus-manifest/1"

#: The deterministic identity prefix, mirroring B1.2's ``"calibration-case::"``
#: and the project-wide ``"::"``-join convention.
CALIBRATION_CORPUS_VERSION_PREFIX = "calibration-corpus-version"


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one string — a local copy of the identical helper
    every prior contracts layer owns (never a new hashing algorithm)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Non-empty-string check (raises :class:`CalibrationError`) — a local copy
    of the identical check the B1.2 contracts module owns."""
    if not isinstance(value, str) or not value.strip():
        raise CalibrationError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


# ===========================================================================
# CorpusCaseEntry (ADR-0006 §D13 "per-case content hashes" + split/role)
# ===========================================================================


@dataclass(frozen=True)
class CorpusCaseEntry:
    """One case's manifest entry (ADR-0006 §D13). Records the case's content
    identity (``case_id``) plus the two corpus-assignment fields B1.2's
    ``case_id`` deliberately **excludes** (``case_role`` / ``scenario_family_id``),
    plus a small human-readable/consistency-check mirror of source metadata
    (``source_ref`` / ``source_kind`` / ``license`` / ``attack_kb_version``,
    all already bound into ``case_id`` — kept for readability and the
    manifest's structural checks, never a second source of truth).

    A manifest records **case references, not embedded ``CalibrationCase``
    objects** — ``case_id`` (a content hash of the case's frozen inputs)
    reproducibly identifies the case content on its own.
    """

    case_id: str
    scenario_family_id: str
    case_role: CaseRole
    attack_kb_version: str
    source_ref: str
    source_kind: SourceKind
    license: str

    def __post_init__(self) -> None:
        _require_nonempty_str(self.case_id, "CorpusCaseEntry.case_id")
        _require_nonempty_str(self.scenario_family_id, "CorpusCaseEntry.scenario_family_id")
        if not isinstance(self.case_role, CaseRole):
            raise CalibrationError(
                f"CorpusCaseEntry.case_role must be a CaseRole, "
                f"got {type(self.case_role).__name__}"
            )
        _require_nonempty_str(self.attack_kb_version, "CorpusCaseEntry.attack_kb_version")
        _require_nonempty_str(self.source_ref, "CorpusCaseEntry.source_ref")
        if not isinstance(self.source_kind, SourceKind):
            raise CalibrationError(
                f"CorpusCaseEntry.source_kind must be a SourceKind, "
                f"got {type(self.source_kind).__name__}"
            )
        _require_nonempty_str(self.license, "CorpusCaseEntry.license")

    @classmethod
    def from_case(cls, case: CalibrationCase) -> CorpusCaseEntry:
        """Derive an entry from a :class:`CalibrationCase` (never modifying or
        reconstructing it) — the mirrored fields are read straight off the
        case, so an entry can never silently disagree with its case."""
        if not isinstance(case, CalibrationCase):
            raise CalibrationError(
                f"CorpusCaseEntry.from_case: expected a CalibrationCase, "
                f"got {type(case).__name__}"
            )
        return cls(
            case_id=case.case_id,
            scenario_family_id=case.scenario_family_id,
            case_role=case.case_role,
            attack_kb_version=case.attack_kb_version,
            source_ref=case.source_ref,
            source_kind=case.source_kind,
            license=case.license,
        )


# ===========================================================================
# CorpusSourceEntry (ADR-0006 §D13 corpus-level source registry)
# ===========================================================================


@dataclass(frozen=True)
class CorpusSourceEntry:
    """One corpus-level source-registry entry (ADR-0006 §D13). Carries the
    dataset's licensing and provenance at corpus level — including the
    ``transformation_provenance`` that has no per-case home in B1.2.

    B1.3 **stores** provenance; it does **not** validate its truth or infer it
    (the provenance-validation engine is B1.5). ``acquisition_provenance`` and
    ``transformation_provenance`` are required, non-empty, author-supplied
    strings. Exactly one entry per distinct ``source_ref`` (enforced by
    :class:`CalibrationCorpusManifest`).
    """

    source_ref: str
    source_kind: SourceKind
    license: str
    acquisition_provenance: str
    transformation_provenance: str

    def __post_init__(self) -> None:
        _require_nonempty_str(self.source_ref, "CorpusSourceEntry.source_ref")
        if not isinstance(self.source_kind, SourceKind):
            raise CalibrationError(
                f"CorpusSourceEntry.source_kind must be a SourceKind, "
                f"got {type(self.source_kind).__name__}"
            )
        _require_nonempty_str(self.license, "CorpusSourceEntry.license")
        _require_nonempty_str(
            self.acquisition_provenance, "CorpusSourceEntry.acquisition_provenance"
        )
        _require_nonempty_str(
            self.transformation_provenance, "CorpusSourceEntry.transformation_provenance"
        )


# ===========================================================================
# Deterministic corpus identity (ADR-0006 §D12/§D13; audit §4/§8)
# ===========================================================================

#: The manifest fields that participate in ``calibration_corpus_version``, in a
#: fixed key set (``to_canonical_json`` sorts keys, so key order is irrelevant
#: and the digest is ``PYTHONHASHSEED``-independent). The version field itself
#: is deliberately **absent** (self-exclusion — no hash-of-hash), as are
#: ``calibration_version``, any fitted parameter/threshold, and any volatile
#: timestamp/path/UUID (none appears in the manifest at all).
CORPUS_VERSION_INPUT_FIELDS: tuple[str, ...] = (
    "manifest_schema_version",
    "corpus_schema_version",
    "attack_kb_version",
    "case_entries",
    "source_entries",
    "split_assignment",
)


def compute_calibration_corpus_version(
    *,
    manifest_schema_version: str,
    corpus_schema_version: str,
    attack_kb_version: str,
    case_entries: tuple[CorpusCaseEntry, ...],
    source_entries: tuple[CorpusSourceEntry, ...],
    split_assignment: tuple[tuple[str, tuple[str, ...]], ...],
) -> str:
    """Deterministically compose ``calibration_corpus_version`` from the fixed,
    documented identity boundary (:data:`CORPUS_VERSION_INPUT_FIELDS`) — a
    SHA-256 over the canonical JSON of the manifest **without** its own version
    field. Reuses ``to_canonical_json`` (sorted-key, byte-stable) and the
    SHA-256/``"::"``-join convention; never includes ``calibration_version`` or
    any volatile value.

    Callers normally do not call this directly:
    :class:`CalibrationCorpusManifest` computes and stores it. Exposed for
    tests and a future consumer. The collections passed here must already be
    canonicalized (the manifest guarantees this before calling).
    """
    identity: dict[str, object] = {
        "manifest_schema_version": manifest_schema_version,
        "corpus_schema_version": corpus_schema_version,
        "attack_kb_version": attack_kb_version,
        "case_entries": list(case_entries),
        "source_entries": list(source_entries),
        "split_assignment": [
            {"case_role": role, "scenario_family_ids": list(families)}
            for role, families in split_assignment
        ],
    }
    return "::".join([CALIBRATION_CORPUS_VERSION_PREFIX, _sha256_hex(to_canonical_json(identity))])


# ===========================================================================
# CalibrationCorpusManifest (ADR-0006 §D13)
# ===========================================================================


@dataclass(frozen=True)
class CalibrationCorpusManifest:
    """The deterministic identity of one calibration corpus (ADR-0006 §D13).

    Frozen and canonical: ``case_entries`` are sorted-by-``case_id`` and must be
    unique; ``source_entries`` are sorted-by-``source_ref`` and unique;
    ``split_assignment`` is derived from ``case_entries`` (role -> sorted-unique
    ``scenario_family_id``s) so it can never silently disagree with the cases.
    ``calibration_corpus_version`` is computed (``field(init=False)``), never
    supplied, and self-excluded from its own hash.

    Consistency invariants (fail closed): every entry's ``attack_kb_version``
    equals the manifest's single corpus-level ``attack_kb_version`` (a mixed-KB
    corpus is rejected — the methodology is ATT&CK-version-specific); every
    ``case_id`` is unique; every entry's ``source_ref`` has exactly one matching
    ``CorpusSourceEntry`` whose ``source_kind``/``license`` agree with the entry.
    An **empty corpus is structurally valid** and receives a deterministic
    version (calibration *sufficiency* is a later gate's concern, never a
    minimum-case-count threshold here).

    Prefer :meth:`from_cases` to build from real :class:`CalibrationCase`
    objects; the direct constructor is for tests / a future consumer that
    already holds entries.
    """

    corpus_schema_version: str
    attack_kb_version: str
    case_entries: tuple[CorpusCaseEntry, ...]
    source_entries: tuple[CorpusSourceEntry, ...]
    manifest_schema_version: str = field(default=CALIBRATION_MANIFEST_SCHEMA_VERSION)
    split_assignment: tuple[tuple[str, tuple[str, ...]], ...] = field(init=False)
    calibration_corpus_version: str = field(init=False)

    def __post_init__(self) -> None:
        _require_nonempty_str(
            self.manifest_schema_version, "CalibrationCorpusManifest.manifest_schema_version"
        )
        _require_nonempty_str(
            self.corpus_schema_version, "CalibrationCorpusManifest.corpus_schema_version"
        )
        _require_nonempty_str(self.attack_kb_version, "CalibrationCorpusManifest.attack_kb_version")

        for entry in self.case_entries:
            if not isinstance(entry, CorpusCaseEntry):
                raise CalibrationError(
                    "CalibrationCorpusManifest.case_entries must contain only CorpusCaseEntry "
                    f"objects, got {type(entry).__name__}"
                )
        for source in self.source_entries:
            if not isinstance(source, CorpusSourceEntry):
                raise CalibrationError(
                    "CalibrationCorpusManifest.source_entries must contain only CorpusSourceEntry "
                    f"objects, got {type(source).__name__}"
                )

        # Duplicate case_id -> fail closed (never silently dedup): a case_id is
        # a content hash, so two identical ids are the same case listed twice.
        seen_case_ids: set[str] = set()
        for entry in self.case_entries:
            if entry.case_id in seen_case_ids:
                raise CalibrationError(
                    f"CalibrationCorpusManifest: duplicate case_id {entry.case_id!r} in "
                    "case_entries (per-case content hashes must be unique)"
                )
            seen_case_ids.add(entry.case_id)

        # Source registry uniqueness by source_ref.
        seen_source_refs: set[str] = set()
        for source in self.source_entries:
            if source.source_ref in seen_source_refs:
                raise CalibrationError(
                    f"CalibrationCorpusManifest: duplicate source_ref {source.source_ref!r} in "
                    "source_entries (the registry has one entry per distinct source)"
                )
            seen_source_refs.add(source.source_ref)
        source_by_ref = {s.source_ref: s for s in self.source_entries}

        # Single corpus-level ATT&CK KB version + source-registry agreement.
        for entry in self.case_entries:
            if entry.attack_kb_version != self.attack_kb_version:
                raise CalibrationError(
                    f"CalibrationCorpusManifest: case {entry.case_id!r} has attack_kb_version "
                    f"{entry.attack_kb_version!r} but the corpus is pinned to "
                    f"{self.attack_kb_version!r} — a mixed-KB corpus is rejected (the methodology "
                    "is ATT&CK-version-specific)"
                )
            matched_source = source_by_ref.get(entry.source_ref)
            if matched_source is None:
                raise CalibrationError(
                    f"CalibrationCorpusManifest: case {entry.case_id!r} references source_ref "
                    f"{entry.source_ref!r} with no matching CorpusSourceEntry"
                )
            if entry.source_kind is not matched_source.source_kind:
                raise CalibrationError(
                    f"CalibrationCorpusManifest: case {entry.case_id!r} source_kind "
                    f"{entry.source_kind.value!r} disagrees with the source registry "
                    f"({matched_source.source_kind.value!r}) for source_ref {entry.source_ref!r}"
                )
            if entry.license != matched_source.license:
                raise CalibrationError(
                    f"CalibrationCorpusManifest: case {entry.case_id!r} license {entry.license!r} "
                    f"disagrees with the source registry ({matched_source.license!r}) for "
                    f"source_ref {entry.source_ref!r}"
                )

        # Canonicalize collections (sorted, deterministic) -- identity is
        # therefore independent of the caller's input ordering.
        object.__setattr__(
            self,
            "case_entries",
            tuple(sorted(self.case_entries, key=lambda e: e.case_id)),
        )
        object.__setattr__(
            self,
            "source_entries",
            tuple(sorted(self.source_entries, key=lambda s: s.source_ref)),
        )

        # split_assignment is DERIVED from case_entries (never supplied), so it
        # cannot silently disagree with the case metadata: role -> sorted-unique
        # scenario_family_ids, roles emitted in a fixed (value-sorted) order.
        families_by_role: dict[str, set[str]] = {}
        for entry in self.case_entries:
            families_by_role.setdefault(entry.case_role.value, set()).add(entry.scenario_family_id)
        split_assignment = tuple(
            (role, tuple(sorted(families_by_role[role]))) for role in sorted(families_by_role)
        )
        object.__setattr__(self, "split_assignment", split_assignment)

        object.__setattr__(
            self,
            "calibration_corpus_version",
            compute_calibration_corpus_version(
                manifest_schema_version=self.manifest_schema_version,
                corpus_schema_version=self.corpus_schema_version,
                attack_kb_version=self.attack_kb_version,
                case_entries=self.case_entries,
                source_entries=self.source_entries,
                split_assignment=self.split_assignment,
            ),
        )

    @classmethod
    def from_cases(
        cls,
        cases: Iterable[CalibrationCase],
        source_entries: Iterable[CorpusSourceEntry],
        *,
        attack_kb_version: str,
        corpus_schema_version: str | None = None,
        manifest_schema_version: str = CALIBRATION_MANIFEST_SCHEMA_VERSION,
    ) -> CalibrationCorpusManifest:
        """Build a manifest from real :class:`CalibrationCase` objects (derives
        each :class:`CorpusCaseEntry` from its case, never modifying the case)
        and the corpus source registry.

        ``attack_kb_version`` is the required single corpus-level pin; every
        case must match it (else fail closed). ``corpus_schema_version`` defaults
        to the shared value all cases must carry — if omitted it is taken from
        the cases and every case is verified to agree (a mixed
        ``corpus_schema_version`` fails closed); if given, every case must equal
        it. Source ``kind``/``license`` agreement, ``case_id`` uniqueness, and KB
        agreement are all enforced by the constructor.
        """
        case_list = list(cases)
        entries = tuple(CorpusCaseEntry.from_case(c) for c in case_list)

        resolved_corpus_schema_version = corpus_schema_version
        for case in case_list:
            if resolved_corpus_schema_version is None:
                resolved_corpus_schema_version = case.corpus_schema_version
            elif case.corpus_schema_version != resolved_corpus_schema_version:
                raise CalibrationError(
                    f"CalibrationCorpusManifest.from_cases: case {case.case_id!r} has "
                    f"corpus_schema_version {case.corpus_schema_version!r} but the corpus expects "
                    f"{resolved_corpus_schema_version!r} — all cases must share one corpus schema"
                )
        if resolved_corpus_schema_version is None:
            # Empty corpus + no explicit version: fall back to the case-contract
            # default so an empty corpus is still deterministically versioned.
            from attribution_platform.calibration.contracts import (
                CALIBRATION_CASE_SCHEMA_VERSION,
            )

            resolved_corpus_schema_version = CALIBRATION_CASE_SCHEMA_VERSION

        return cls(
            corpus_schema_version=resolved_corpus_schema_version,
            attack_kb_version=attack_kb_version,
            case_entries=entries,
            source_entries=tuple(source_entries),
            manifest_schema_version=manifest_schema_version,
        )
