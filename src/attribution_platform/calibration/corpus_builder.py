"""C3.2 golden-corpus builder — **first implementation slice** (ADR-0006 §D5/§D6/
§D13; B1-M/B1-D locks).

Turns **labeled replay fixtures** (raw telemetry) + **separately-authored
annotations** (ground truth, expected-output shape, coverage, provenance) into
frozen :class:`~attribution_platform.calibration.contracts.CalibrationCase`
objects and a :class:`~attribution_platform.calibration.manifest.CalibrationCorpusManifest`
carrying the existing ``calibration_corpus_version`` identity.

**Scope (first slice).** This module only *assembles* cases from what the real,
unmodified replay pipeline produces. It performs **no** fitting, produces **no**
``calibration_version``, computes **no** scoring, and creates **no** attribution
decision. It introduces **no** second hashing/versioning mechanism — corpus
identity is delegated wholly to
:func:`~attribution_platform.calibration.manifest.compute_calibration_corpus_version`
(via :meth:`CalibrationCorpusManifest.from_cases`).

**Anti-circular authorship boundary.** Raw telemetry lives in the replay
fixtures; ground-truth labels and expected-output shapes live in the *separate*
annotations. This module never derives a label or an expected shape from ATT&CK
``uses`` relationships — it copies the annotation's authored values verbatim and
records only the ids the replay pipeline actually produced
(``correlation_group_id`` / ``sequence_id`` / telemetry provenance) and the
``BehavioralStep.evidence_types`` the pipeline already carried (B4). Nothing here
fabricates evidence types.

**Units per family (doc 15 DC-4, T5).** A real scenario produces several
attribution units (hosts / process trees), so a family may declare several
**units**. Correlation group ids are content hashes the author cannot know in
advance, so each authored unit names one or more **anchor scenarios** — replay
scenarios (telemetry records) the unit must contain. The builder maps every
produced group to exactly one declared unit, and fails closed when a unit's
anchors land in no group or in more than one, when two units claim one group,
or when a group is claimed by no unit (an undeclared unit means the annotation
is incomplete — never silently dropped or guessed). Each unit carries its own
expected-output shape (a sparse unit of an attributable family may be expected
to abstain) and optional unit-level coverage assumptions; all units share the
family's ground truth and split. An annotation without units keeps the
original single-unit contract: the fixture must replay to exactly one group,
so corpus v1 rebuilds byte-identically.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.calibration.contracts import (
    ActorLabelSource,
    CalibrationCase,
    CaseRole,
    ExpectedOutcome,
    ExpectedOutputShape,
    GroundTruth,
    LabelConfidence,
    LabelSemantics,
    SourceKind,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.calibration.manifest import (
    CalibrationCorpusManifest,
    CorpusSourceEntry,
)
from attribution_platform.calibration.units import (
    CorpusSource,
    UnitAnalysis,
    analyze_source,
    source_id,
)
from attribution_platform.correlation.contracts import CorrelationGroup
from attribution_platform.correlation.sequence import BehavioralSequence
from attribution_platform.dataplane import ElasticClient
from attribution_platform.detection import DetectionEngine
from attribution_platform.replay import (
    DetectionReplayFixture,
    load_detection_replay_fixture_file,
)

#: Identity of this corpus-build method (first slice). Recorded for provenance;
#: this module never fabricates a case/corpus identity of its own.
CORPUS_BUILDER_METHOD = "c3.2-corpus-builder"
CORPUS_BUILDER_METHOD_VERSION = "0.2"  # 0.2: multiple units per family


@dataclass(frozen=True)
class UnitAnnotation:
    """One authored attribution unit of a family: the replay scenarios it must
    contain (``anchor_scenario_ids``, non-empty), its expected-output shape, and
    unit-specific coverage assumptions (added to the family's)."""

    unit_id: str
    anchor_scenario_ids: tuple[str, ...]
    expected_output_shape: ExpectedOutputShape | None
    coverage_assumptions: tuple[str, ...] = ()
    #: A declared unit that is *not* part of the corpus (e.g. background
    #: activity in a real recording that is not the emulated actor's). It must
    #: still be anchored and claimed — never silently dropped — and carries the
    #: author's reason; no case is built from it.
    exclusion_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.unit_id, str) or not self.unit_id.strip():
            raise CalibrationError("UnitAnnotation.unit_id must be a non-empty string")
        anchors = tuple(sorted(set(self.anchor_scenario_ids)))
        if not anchors or any(not isinstance(a, str) or not a.strip() for a in anchors):
            raise CalibrationError(
                f"UnitAnnotation {self.unit_id!r}: anchor_scenario_ids must be non-empty strings"
            )
        object.__setattr__(self, "anchor_scenario_ids", anchors)
        if self.exclusion_reason is not None:
            if not self.exclusion_reason.strip() or self.expected_output_shape is not None:
                raise CalibrationError(
                    f"UnitAnnotation {self.unit_id!r}: an excluded unit needs a non-empty "
                    "exclusion_reason and no expected_output_shape"
                )
        elif not isinstance(self.expected_output_shape, ExpectedOutputShape):
            raise CalibrationError(
                f"UnitAnnotation {self.unit_id!r}: expected_output_shape must be an "
                "ExpectedOutputShape"
            )


@dataclass(frozen=True)
class CorpusScenarioAnnotation:
    """The separately-authored, non-telemetry labels for one scenario family
    (ADR-0006 §D6). Physically/logically distinct from the raw-telemetry replay
    fixture, so expected-output authorship stays independent of ATT&CK
    inference.

    Exactly one of ``expected_output_shape`` (single-unit family) and ``units``
    (multi-unit family, see the module docstring) is given."""

    scenario_family_id: str
    case_role: CaseRole
    source_kind: SourceKind
    source_ref: str
    license: str
    acquisition_provenance: str
    transformation_provenance: str
    ground_truth: GroundTruth
    expected_output_shape: ExpectedOutputShape | None = None
    coverage_assumptions: tuple[str, ...] = ()
    units: tuple[UnitAnnotation, ...] = ()

    def __post_init__(self) -> None:
        if (self.expected_output_shape is None) == (not self.units):
            raise CalibrationError(
                f"CorpusScenarioAnnotation {self.scenario_family_id!r}: give exactly one of "
                "expected_output_shape (single unit) or units (several units)"
            )
        unit_ids = [u.unit_id for u in self.units]
        if len(unit_ids) != len(set(unit_ids)):
            raise CalibrationError(
                f"CorpusScenarioAnnotation {self.scenario_family_id!r}: duplicate unit_id"
            )


@dataclass(frozen=True)
class CorpusBuildResult:
    """The built corpus: the frozen cases (sorted by ``case_id``) and their
    manifest. ``calibration_corpus_version`` is the manifest's own, computed by
    the existing identity mechanism — never recomputed here."""

    cases: tuple[CalibrationCase, ...]
    manifest: CalibrationCorpusManifest

    @property
    def calibration_corpus_version(self) -> str:
        return self.manifest.calibration_corpus_version


def _telemetry_provenance(group: CorrelationGroup) -> tuple[str, ...]:
    """The immutable Phase 0-2 id chain backing this attribution unit —
    the group's member Observation + Evidence ids, canonicalized sorted-unique
    (§D6 ``telemetry_provenance``). Non-empty for any real group."""
    return tuple(sorted(set(group.member_observation_ids) | set(group.member_evidence_ids)))


def _unit_groups(
    annotation: CorpusScenarioAnnotation,
    result: UnitAnalysis,
    fixture_id: str,
) -> list[tuple[UnitAnnotation | None, CorrelationGroup, BehavioralSequence]]:
    """Pair each produced attribution unit with its authored unit (``None`` for
    a single-unit annotation). Fails closed on any ambiguity (module docstring)."""
    groups = {g.group_id: g for g in result.groups}
    pairs: list[tuple[CorrelationGroup, BehavioralSequence]] = []
    for sequence in result.sequences:
        group = groups.get(sequence.group_id)
        if group is None:  # pragma: no cover - structural guarantee of the replay pipeline
            raise CalibrationError(
                f"build_calibration_cases: sequence {sequence.sequence_id!r} references group "
                f"{sequence.group_id!r} not present in the replay result"
            )
        pairs.append((group, sequence))
    family = annotation.scenario_family_id

    if not annotation.units:
        if len(pairs) != 1:
            raise CalibrationError(
                f"build_calibration_cases: fixture {fixture_id!r} produced {len(pairs)} "
                f"attribution units (groups); a single-unit annotation requires exactly one "
                f"(family {family!r}) — declare units to build several"
            )
        return [(None, pairs[0][0], pairs[0][1])]

    observations_by_scenario = result.anchor_observations
    claimed: dict[str, str] = {}
    out: list[tuple[UnitAnnotation | None, CorrelationGroup, BehavioralSequence]] = []
    for unit in annotation.units:
        matched: set[str] = set()
        for anchor in unit.anchor_scenario_ids:
            if anchor not in observations_by_scenario:
                raise CalibrationError(
                    f"build_calibration_cases: unit {unit.unit_id!r} of family {family!r} "
                    f"names anchor scenario {anchor!r}, which the fixture does not contain"
                )
            anchor_groups = {
                g.group_id
                for g, _ in pairs
                if observations_by_scenario[anchor] & set(g.member_observation_ids)
            }
            if not anchor_groups:
                raise CalibrationError(
                    f"build_calibration_cases: anchor scenario {anchor!r} of unit "
                    f"{unit.unit_id!r} (family {family!r}) is in no attribution unit — it "
                    f"produced no correlated evidence"
                )
            matched |= anchor_groups
        if len(matched) != 1:
            raise CalibrationError(
                f"build_calibration_cases: the anchors of unit {unit.unit_id!r} (family "
                f"{family!r}) fall in {len(matched)} different attribution units; a unit "
                f"is exactly one"
            )
        (group_id,) = matched
        if group_id in claimed:
            raise CalibrationError(
                f"build_calibration_cases: units {claimed[group_id]!r} and {unit.unit_id!r} "
                f"of family {family!r} both claim attribution unit {group_id!r}"
            )
        claimed[group_id] = unit.unit_id
        group, sequence = next((g, s) for g, s in pairs if g.group_id == group_id)
        out.append((unit, group, sequence))
    unclaimed = sorted(g.group_id for g, _ in pairs if g.group_id not in claimed)
    if unclaimed:
        raise CalibrationError(
            f"build_calibration_cases: fixture {fixture_id!r} (family {family!r}) produced "
            f"{len(unclaimed)} attribution unit(s) no authored unit declares: {unclaimed!r}"
        )
    return out


def build_calibration_cases(
    annotation: CorpusScenarioAnnotation,
    fixture: CorpusSource,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
) -> tuple[CalibrationCase, ...]:
    """Replay one labeled source (a fixture or a real recording) through the
    real, unmodified pipeline and assemble one :class:`CalibrationCase` per
    attribution unit, from the produced unit plus the authored annotation
    (module docstring). Declared excluded units produce no case."""
    result = analyze_source(fixture, client=client, engine=engine, knowledge=knowledge)
    cases: list[CalibrationCase] = []
    for unit, group, sequence in _unit_groups(annotation, result, result.source_id):
        if unit is not None and unit.exclusion_reason is not None:
            continue
        if unit is None:
            assert annotation.expected_output_shape is not None
            shape = annotation.expected_output_shape
            assumptions = annotation.coverage_assumptions
        else:
            assert unit.expected_output_shape is not None
            shape = unit.expected_output_shape
            assumptions = tuple(
                sorted(set(annotation.coverage_assumptions) | set(unit.coverage_assumptions))
            )
        cases.append(
            CalibrationCase(
                scenario_family_id=annotation.scenario_family_id,
                source_kind=annotation.source_kind,
                source_ref=annotation.source_ref,
                license=annotation.license,
                attack_kb_version=knowledge.attack_kb_version,
                correlation_group_id=group.group_id,
                sequence_id=sequence.sequence_id,
                telemetry_provenance=_telemetry_provenance(group),
                ground_truth=annotation.ground_truth,
                expected_output_shape=shape,
                case_role=annotation.case_role,
                coverage_assumptions=assumptions,
            )
        )
    return tuple(sorted(cases, key=lambda c: c.case_id))


def build_calibration_case(
    annotation: CorpusScenarioAnnotation,
    fixture: CorpusSource,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
) -> CalibrationCase:
    """Single-unit form of :func:`build_calibration_cases` (fails closed unless
    the fixture yields exactly one attribution unit)."""
    cases = build_calibration_cases(
        annotation, fixture, client=client, engine=engine, knowledge=knowledge
    )
    if len(cases) != 1:
        raise CalibrationError(
            f"build_calibration_case: source {source_id(fixture)!r} produced {len(cases)} "
            f"cases; use build_calibration_cases for a multi-unit family"
        )
    return cases[0]


def build_corpus(
    entries: Sequence[tuple[CorpusScenarioAnnotation, CorpusSource]],
    *,
    client_factory: Callable[[], ElasticClient],
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    corpus_schema_version: str | None = None,
) -> CorpusBuildResult:
    """Build a corpus from ``(annotation, fixture)`` pairs. Each fixture replays
    into a **fresh** client from ``client_factory`` (isolation + determinism).
    The manifest and ``calibration_corpus_version`` are produced by the existing
    :meth:`CalibrationCorpusManifest.from_cases` — no second hashing mechanism.

    Deterministic: cases are sorted by ``case_id``, source entries by
    ``source_ref``; a ``source_ref`` reused with disagreeing provenance/kind/
    license fails closed. Inputs are never mutated."""
    cases: list[CalibrationCase] = []
    source_by_ref: dict[str, CorpusSourceEntry] = {}
    families: set[str] = set()
    for annotation, fixture in entries:
        if annotation.scenario_family_id in families:
            raise CalibrationError(
                f"build_corpus: family {annotation.scenario_family_id!r} appears twice; one "
                "annotation (with all its units) per family"
            )
        families.add(annotation.scenario_family_id)
        cases.extend(
            build_calibration_cases(
                annotation, fixture, client=client_factory(), engine=engine, knowledge=knowledge
            )
        )
        source_entry = CorpusSourceEntry(
            source_ref=annotation.source_ref,
            source_kind=annotation.source_kind,
            license=annotation.license,
            acquisition_provenance=annotation.acquisition_provenance,
            transformation_provenance=annotation.transformation_provenance,
        )
        prior = source_by_ref.get(annotation.source_ref)
        if prior is not None and prior != source_entry:
            raise CalibrationError(
                f"build_corpus: source_ref {annotation.source_ref!r} used with two disagreeing "
                f"source/provenance descriptions — a source's identity must be consistent"
            )
        source_by_ref[annotation.source_ref] = source_entry

    source_entries = tuple(source_by_ref[ref] for ref in sorted(source_by_ref))
    manifest = CalibrationCorpusManifest.from_cases(
        tuple(cases),
        source_entries,
        attack_kb_version=knowledge.attack_kb_version,
        corpus_schema_version=corpus_schema_version,
    )
    return CorpusBuildResult(
        cases=tuple(sorted(cases, key=lambda c: c.case_id)),
        manifest=manifest,
    )


# ---------------------------------------------------------------------------
# File-driven loading (seed corpus on disk)
# ---------------------------------------------------------------------------


def load_scenario_annotation(path: Path) -> CorpusScenarioAnnotation:
    """Parse one authored annotation JSON file into a
    :class:`CorpusScenarioAnnotation`. Enum values must be members of the
    existing closed vocabularies (fail closed via the enum constructors); the
    value objects' own ``__post_init__`` invariants still apply when the case is
    built."""
    data = json.loads(path.read_text(encoding="utf-8"))
    gt = data["ground_truth"]
    ground_truth = GroundTruth(
        actor_label_source=ActorLabelSource(gt["actor_label_source"]),
        label_semantics=LabelSemantics(gt["label_semantics"]),
        label_confidence=LabelConfidence(gt["label_confidence"]),
        actor_label=gt.get("actor_label"),
        campaign_context=tuple(gt.get("campaign_context", ())),
    )
    units = tuple(
        UnitAnnotation(
            unit_id=u["unit_id"],
            anchor_scenario_ids=tuple(u["anchor_scenario_ids"]),
            expected_output_shape=(
                _expected_output_shape(u["expected_output_shape"])
                if u.get("expected_output_shape") is not None
                else None
            ),
            coverage_assumptions=tuple(u.get("coverage_assumptions", ())),
            exclusion_reason=u.get("exclusion_reason"),
        )
        for u in data.get("units", ())
    )
    eos = data.get("expected_output_shape")
    return CorpusScenarioAnnotation(
        scenario_family_id=data["scenario_family_id"],
        case_role=CaseRole(data["case_role"]),
        source_kind=SourceKind(data["source_kind"]),
        source_ref=data["source_ref"],
        license=data["license"],
        acquisition_provenance=data["acquisition_provenance"],
        transformation_provenance=data["transformation_provenance"],
        ground_truth=ground_truth,
        expected_output_shape=_expected_output_shape(eos) if eos is not None else None,
        coverage_assumptions=tuple(data.get("coverage_assumptions", ())),
        units=units,
    )


def _expected_output_shape(eos: dict[str, Any]) -> ExpectedOutputShape:
    return ExpectedOutputShape(
        outcome=ExpectedOutcome(eos["outcome"]),
        authorship_provenance=eos["authorship_provenance"],
        expected_likelihood_band=eos.get("expected_likelihood_band"),
        expected_confidence_band=eos.get("expected_confidence_band"),
        discriminating_evidence=tuple(eos.get("discriminating_evidence", ())),
        expected_contradiction=tuple(eos.get("expected_contradiction", ())),
        expected_next_evidence=tuple(eos.get("expected_next_evidence", ())),
    )


def load_corpus_entries_from_dir(
    root: Path,
) -> tuple[tuple[CorpusScenarioAnnotation, DetectionReplayFixture], ...]:
    """Load ``(annotation, fixture)`` pairs from a seed-corpus directory laid out
    as ``<root>/annotations/<family>.annotation.json`` +
    ``<root>/scenarios/<family>.fixture.json``. Deterministic (sorted by family);
    fails closed on a missing paired fixture."""
    annotations_dir = root / "annotations"
    scenarios_dir = root / "scenarios"
    suffix = ".annotation.json"
    entries: list[tuple[CorpusScenarioAnnotation, DetectionReplayFixture]] = []
    for annotation_path in sorted(annotations_dir.glob(f"*{suffix}")):
        family = annotation_path.name[: -len(suffix)]
        fixture_path = scenarios_dir / f"{family}.fixture.json"
        if not fixture_path.is_file():
            raise CalibrationError(
                f"load_corpus_entries_from_dir: annotation {annotation_path.name!r} has no paired "
                f"fixture at {fixture_path}"
            )
        entries.append(
            (
                load_scenario_annotation(annotation_path),
                load_detection_replay_fixture_file(fixture_path),
            )
        )
    return tuple(entries)


def build_corpus_from_dir(
    root: Path,
    *,
    client_factory: Callable[[], ElasticClient],
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    corpus_schema_version: str | None = None,
) -> CorpusBuildResult:
    """Convenience: load a seed-corpus directory and build it (see
    :func:`load_corpus_entries_from_dir` + :func:`build_corpus`)."""
    entries = load_corpus_entries_from_dir(root)
    return build_corpus(
        entries,
        client_factory=client_factory,
        engine=engine,
        knowledge=knowledge,
        corpus_schema_version=corpus_schema_version,
    )


__all__ = [
    "CORPUS_BUILDER_METHOD",
    "CORPUS_BUILDER_METHOD_VERSION",
    "CorpusScenarioAnnotation",
    "UnitAnnotation",
    "CorpusBuildResult",
    "build_calibration_case",
    "build_calibration_cases",
    "build_corpus",
    "load_scenario_annotation",
    "load_corpus_entries_from_dir",
    "build_corpus_from_dir",
]
