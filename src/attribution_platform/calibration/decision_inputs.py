"""Corpus → decision-quantity harness (B1-M fitting input; ADR-0006 §D8/§D9/§D16,
ADR-0005 Amendment B §B2/§B5).

Replays each frozen :class:`~attribution_platform.calibration.contracts.CalibrationCase`'s
own fixture through the real, unmodified pipeline and the real Gate 3.3–3.5
attribution stages (candidate generation → ACH matrix → comparative analysis),
plus the Amendment-B candidate-independent ``Unattributed`` baseline, and pairs
the result with the case's **authored** labels. This is the per-case input the
later fitting sub-gate consumes.

**Boundary.** Fits nothing, chooses no numeric value, produces no
``calibration_version``, and emits no likelihood/confidence/WEP/abstention
decision. Authored labels (``actor_label``, ``label_semantics``,
``expected_outcome``) are copied verbatim and never compared against, mapped
onto, or inferred from ATT&CK candidates here (§D9 anti-circularity).

**Floor independence.** ``min_profile_floor`` is a fitted parameter, so it is
**not** fixed here. The comparative analysis is computed once at the structural
lower bound ``1``; the fields the decision layer reads (each
``EvidenceContribution``'s ``d_value``/``g_value`` and each summary's
``profile_breadth``) do not depend on the floor, so
:func:`compute_case_decision_quantities` can evaluate any candidate floor over
the same input without re-replaying. Only ``support_value`` (never consumed by
the decision layer) reflects the floor-``1`` computation.

**Population control.** The caller names the roles to evaluate explicitly;
``EXCLUDED`` (the final-test-reserved population, C3.2 Stage 2 D2) is refused —
it is consumed only by a later one-time final evaluation, never by this tooling.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attribution.ach_matrix import build_ach_matrix
from attribution_platform.attribution.candidate_generation import generate_candidates
from attribution_platform.attribution.comparative_analysis import (
    ComparativeEvidenceResult,
    UnattributedBaseline,
    compute_comparative_evidence,
    compute_unattributed_decision_support,
)
from attribution_platform.attribution.contracts import Candidate
from attribution_platform.attribution.decision_quantities import (
    DecisionQuantitiesResult,
    compute_decision_quantities,
)
from attribution_platform.calibration.contracts import (
    CalibrationCase,
    CaseRole,
    ExpectedOutcome,
    LabelSemantics,
)
from attribution_platform.calibration.corpus_builder import (
    CorpusBuildResult,
    CorpusScenarioAnnotation,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.dataplane import ElasticClient
from attribution_platform.detection import DetectionEngine
from attribution_platform.replay import (
    DetectionReplayFixture,
    replay_fixture_through_behavioral_sequences,
)

DECISION_INPUTS_METHOD = "c3.2-corpus-decision-inputs"
DECISION_INPUTS_METHOD_VERSION = "0.1"

#: The structural lower bound of ``min_profile_floor`` (ADR-0005 §D16). Used
#: only so ``compute_comparative_evidence`` can run; see the module docstring
#: for why no fitted value is implied.
_STRUCTURAL_MIN_PROFILE_FLOOR = 1


@dataclass(frozen=True)
class CaseDecisionInput:
    """One case's authored labels plus the real attribution-stage outputs it
    replays to. ``actor_label`` is the authored (emulation-plan) identity,
    opaque here — never matched against ``candidates``."""

    case_id: str
    scenario_family_id: str
    case_role: CaseRole
    label_semantics: LabelSemantics
    expected_outcome: ExpectedOutcome
    actor_label: str | None
    group_id: str
    sequence_id: str
    attack_kb_version: str
    candidates: tuple[Candidate, ...]
    comparative: ComparativeEvidenceResult
    unattributed_baseline: UnattributedBaseline


@dataclass(frozen=True)
class CorpusDecisionInputs:
    """Decision inputs for the requested roles of one built corpus, sorted by
    ``case_id``, carrying the corpus identity they were derived from."""

    calibration_corpus_version: str
    attack_kb_version: str
    roles: tuple[CaseRole, ...]
    cases: tuple[CaseDecisionInput, ...] = ()


def build_case_decision_input(
    case: CalibrationCase,
    fixture: DetectionReplayFixture,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
) -> CaseDecisionInput:
    """Replay ``fixture`` and run the attribution stages over its single
    attribution unit. Fails closed unless the replay reproduces exactly the
    ``correlation_group_id``/``sequence_id`` frozen on ``case`` under the same
    ``attack_kb_version`` — a drifted pipeline must never silently feed
    fitting."""
    if case.attack_kb_version != knowledge.attack_kb_version:
        raise CalibrationError(
            f"build_case_decision_input: case {case.case_id!r} was built under "
            f"attack_kb_version {case.attack_kb_version!r}, but the loaded knowledge is "
            f"{knowledge.attack_kb_version!r}"
        )
    replay = replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    if len(replay.sequences) != 1:
        raise CalibrationError(
            f"build_case_decision_input: fixture {fixture.fixture_id!r} produced "
            f"{len(replay.sequences)} attribution units; exactly one is required "
            f"(case {case.case_id!r})"
        )
    sequence = replay.sequences[0]
    groups = {g.group_id: g for g in replay.correlation_result.contextual_result.groups}
    group = groups.get(sequence.group_id)
    if group is None:  # pragma: no cover - structural guarantee of the replay pipeline
        raise CalibrationError(
            f"build_case_decision_input: sequence {sequence.sequence_id!r} references "
            f"group {sequence.group_id!r} not present in the replay result"
        )
    if group.group_id != case.correlation_group_id or sequence.sequence_id != case.sequence_id:
        raise CalibrationError(
            f"build_case_decision_input: replay of case {case.case_id!r} produced "
            f"group/sequence ({group.group_id!r}, {sequence.sequence_id!r}) but the frozen "
            f"case records ({case.correlation_group_id!r}, {case.sequence_id!r}) — the "
            "pipeline no longer reproduces this corpus"
        )

    candidate_result = generate_candidates(group, sequence, knowledge)
    matrix = build_ach_matrix(group, sequence, candidate_result, knowledge)
    comparative = compute_comparative_evidence(
        matrix,
        knowledge,
        candidate_result,
        min_profile_floor=_STRUCTURAL_MIN_PROFILE_FLOOR,
    )
    baseline = compute_unattributed_decision_support(matrix, knowledge)

    return CaseDecisionInput(
        case_id=case.case_id,
        scenario_family_id=case.scenario_family_id,
        case_role=case.case_role,
        label_semantics=case.ground_truth.label_semantics,
        expected_outcome=case.expected_output_shape.outcome,
        actor_label=case.ground_truth.actor_label,
        group_id=group.group_id,
        sequence_id=sequence.sequence_id,
        attack_kb_version=knowledge.attack_kb_version,
        candidates=candidate_result.candidates,
        comparative=comparative,
        unattributed_baseline=baseline,
    )


def build_corpus_decision_inputs(
    corpus: CorpusBuildResult,
    entries: Sequence[tuple[CorpusScenarioAnnotation, DetectionReplayFixture]],
    *,
    roles: Iterable[CaseRole],
    client_factory: Callable[[], ElasticClient],
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
) -> CorpusDecisionInputs:
    """Build decision inputs for every case of ``corpus`` whose role is in
    ``roles``. ``entries`` are the same ``(annotation, fixture)`` pairs the
    corpus was built from (e.g. ``load_corpus_entries_from_dir``); each fixture
    replays into a fresh client. Deterministic: output sorted by ``case_id``."""
    requested = tuple(sorted(set(roles), key=lambda r: r.value))
    if not requested:
        raise CalibrationError("build_corpus_decision_inputs: roles must name at least one role")
    if CaseRole.EXCLUDED in requested:
        raise CalibrationError(
            "build_corpus_decision_inputs: the EXCLUDED (final-test-reserved) population "
            "is never consumed by calibration/validation tooling"
        )
    if corpus.manifest.attack_kb_version != knowledge.attack_kb_version:
        raise CalibrationError(
            f"build_corpus_decision_inputs: corpus attack_kb_version "
            f"{corpus.manifest.attack_kb_version!r} does not match the loaded knowledge "
            f"{knowledge.attack_kb_version!r}"
        )

    fixture_by_family: dict[str, DetectionReplayFixture] = {}
    for annotation, fixture in entries:
        if annotation.scenario_family_id in fixture_by_family:
            raise CalibrationError(
                f"build_corpus_decision_inputs: duplicate entry for family "
                f"{annotation.scenario_family_id!r}"
            )
        fixture_by_family[annotation.scenario_family_id] = fixture

    inputs: list[CaseDecisionInput] = []
    for case in corpus.cases:
        if case.case_role not in requested:
            continue
        case_fixture = fixture_by_family.get(case.scenario_family_id)
        if case_fixture is None:
            raise CalibrationError(
                f"build_corpus_decision_inputs: no fixture supplied for family "
                f"{case.scenario_family_id!r} (case {case.case_id!r})"
            )
        inputs.append(
            build_case_decision_input(
                case, case_fixture, client=client_factory(), engine=engine, knowledge=knowledge
            )
        )

    return CorpusDecisionInputs(
        calibration_corpus_version=corpus.calibration_corpus_version,
        attack_kb_version=knowledge.attack_kb_version,
        roles=requested,
        cases=tuple(sorted(inputs, key=lambda i: i.case_id)),
    )


def compute_case_decision_quantities(
    case_input: CaseDecisionInput, *, min_profile_floor: int
) -> DecisionQuantitiesResult:
    """The Amendment-B decision quantities for one case at an explicitly
    supplied ``min_profile_floor`` (a fitting-grid value; never chosen here)."""
    return compute_decision_quantities(
        case_input.comparative,
        min_profile_floor=min_profile_floor,
        unattributed_baseline=case_input.unattributed_baseline,
    )


__all__ = [
    "DECISION_INPUTS_METHOD",
    "DECISION_INPUTS_METHOD_VERSION",
    "CaseDecisionInput",
    "CorpusDecisionInputs",
    "build_case_decision_input",
    "build_corpus_decision_inputs",
    "compute_case_decision_quantities",
]
