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

**First-slice constraint.** Each fixture must replay to **exactly one**
attribution unit (one ``CorrelationGroup`` + its one ``BehavioralSequence``) —
one family, one case. A fixture producing zero or several groups fails closed;
the general multi-group mapping belongs to the later full C3.2 gate.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

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
from attribution_platform.correlation.contracts import CorrelationGroup
from attribution_platform.dataplane import ElasticClient
from attribution_platform.detection import DetectionEngine
from attribution_platform.replay import (
    DetectionReplayFixture,
    load_detection_replay_fixture_file,
    replay_fixture_through_behavioral_sequences,
)

#: Identity of this corpus-build method (first slice). Recorded for provenance;
#: this module never fabricates a case/corpus identity of its own.
CORPUS_BUILDER_METHOD = "c3.2-corpus-builder"
CORPUS_BUILDER_METHOD_VERSION = "0.1"


@dataclass(frozen=True)
class CorpusScenarioAnnotation:
    """The separately-authored, non-telemetry labels for one scenario family
    (ADR-0006 §D6). Physically/logically distinct from the raw-telemetry replay
    fixture, so expected-output authorship stays independent of ATT&CK
    inference."""

    scenario_family_id: str
    case_role: CaseRole
    source_kind: SourceKind
    source_ref: str
    license: str
    acquisition_provenance: str
    transformation_provenance: str
    ground_truth: GroundTruth
    expected_output_shape: ExpectedOutputShape
    coverage_assumptions: tuple[str, ...] = ()


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


def build_calibration_case(
    annotation: CorpusScenarioAnnotation,
    fixture: DetectionReplayFixture,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
) -> CalibrationCase:
    """Replay one labeled fixture through the real, unmodified pipeline and
    assemble one :class:`CalibrationCase` from the produced attribution unit plus
    the authored annotation. Fails closed unless the fixture yields exactly one
    group/sequence."""
    result = replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    if len(result.sequences) != 1:
        raise CalibrationError(
            f"build_calibration_case: fixture {fixture.fixture_id!r} produced "
            f"{len(result.sequences)} attribution units (groups); the first-slice builder "
            f"requires exactly one per fixture (family {annotation.scenario_family_id!r})"
        )
    sequence = result.sequences[0]
    groups = {g.group_id: g for g in result.correlation_result.contextual_result.groups}
    group = groups.get(sequence.group_id)
    if group is None:  # pragma: no cover - structural guarantee of the replay pipeline
        raise CalibrationError(
            f"build_calibration_case: sequence {sequence.sequence_id!r} references group "
            f"{sequence.group_id!r} not present in the replay result"
        )
    return CalibrationCase(
        scenario_family_id=annotation.scenario_family_id,
        source_kind=annotation.source_kind,
        source_ref=annotation.source_ref,
        license=annotation.license,
        attack_kb_version=knowledge.attack_kb_version,
        correlation_group_id=group.group_id,
        sequence_id=sequence.sequence_id,
        telemetry_provenance=_telemetry_provenance(group),
        ground_truth=annotation.ground_truth,
        expected_output_shape=annotation.expected_output_shape,
        case_role=annotation.case_role,
        coverage_assumptions=annotation.coverage_assumptions,
    )


def build_corpus(
    entries: Sequence[tuple[CorpusScenarioAnnotation, DetectionReplayFixture]],
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
    for annotation, fixture in entries:
        case = build_calibration_case(
            annotation, fixture, client=client_factory(), engine=engine, knowledge=knowledge
        )
        cases.append(case)
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
    eos = data["expected_output_shape"]
    expected_output_shape = ExpectedOutputShape(
        outcome=ExpectedOutcome(eos["outcome"]),
        authorship_provenance=eos["authorship_provenance"],
        expected_likelihood_band=eos.get("expected_likelihood_band"),
        expected_confidence_band=eos.get("expected_confidence_band"),
        discriminating_evidence=tuple(eos.get("discriminating_evidence", ())),
        expected_contradiction=tuple(eos.get("expected_contradiction", ())),
        expected_next_evidence=tuple(eos.get("expected_next_evidence", ())),
    )
    return CorpusScenarioAnnotation(
        scenario_family_id=data["scenario_family_id"],
        case_role=CaseRole(data["case_role"]),
        source_kind=SourceKind(data["source_kind"]),
        source_ref=data["source_ref"],
        license=data["license"],
        acquisition_provenance=data["acquisition_provenance"],
        transformation_provenance=data["transformation_provenance"],
        ground_truth=ground_truth,
        expected_output_shape=expected_output_shape,
        coverage_assumptions=tuple(data.get("coverage_assumptions", ())),
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
    "CorpusBuildResult",
    "build_calibration_case",
    "build_corpus",
    "load_scenario_annotation",
    "load_corpus_entries_from_dir",
    "build_corpus_from_dir",
]
