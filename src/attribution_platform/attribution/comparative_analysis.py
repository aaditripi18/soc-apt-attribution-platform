"""Comparative ACH analysis / `support(h)` (gate G3.5, ADR-0005 §D3/§D4/§D8/§D9).

**Internal comparative evidence aggregation only — no attribution decision
is made here.** This module transforms the Gate 3.4 ``ACHMatrix`` into,
for each hypothesis, a deterministic `support(h)` value and the itemized
per-feature contributions that produced it. It does not select a winner, it
does not compute a likelihood/WEP band, it does not compute confidence, it
does not abstain, and it does not calibrate. Those are later, separately
gated pieces of Phase 3 built *on top of* this module's output, never
inside it.

**Input boundary — the Gate 3.4 carry-forward decision, honored exactly.**
Gate 3.4's own post-implementation audit found ``Hypothesis.evidence_assessment_ids``
is never populated (Gate 3.4 preserves Gate 3.3's hypotheses unchanged).
This module therefore consumes :attr:`ACHMatrix.assessments` directly,
grouping/filtering by ``hypothesis_id`` — it never reads
``Hypothesis.evidence_assessment_ids``. Beyond ``(ACHMatrix, AttackKnowledge)``
it also takes the Gate 3.3 ``CandidateGenerationResult`` — required only so
that ADR-0005 Amendment A's `ProfileBreadth(h)` can reach each candidate's
canonical ATT&CK STIX id (`actor_ref`/`campaign_ref`), which a ``Hypothesis``
does not carry (its ``candidate_id`` is an irreversible hash) and which
``ACHMatrix`` does not forward. That mapping is read explicitly; no hash is
ever reversed and candidates are never re-generated. Everything else
(``group_id``, ``attack_kb_version``, the full hypothesis set) is already
carried on the matrix.

**`support(h)` — ADR-0005 §D9's formula, profile-breadth-normalized per
Amendment A, implemented exactly.** The pre-normalization aggregate is:

    raw_support(h) = Σ_supporting (D · relevance) − Σ_contradicting (D · contradiction_strength)

and the reported support is normalized **once** by candidate profile breadth
(ADR-0002 D16, operationalized in ADR-0005 Amendment A):

    ProfileBreadth(h)           = len(group_profile(knowledge, candidate_stix_id(h)))
    ProfileBreadth_effective(h) = max(ProfileBreadth(h), min_profile_floor)
    support(h)                  = raw_support(h) / ProfileBreadth_effective(h)

Normalization is applied exactly once, to the aggregate, **after** all
per-feature / combination / multiplicity contributions are summed — the
per-feature ``EvidenceContribution.contribution_value``\\ s are unchanged
(they remain *raw* `D`-based values), so `raw_support(h)` is exactly their
sum. The ``Unattributed`` sentinel has no candidate STIX id and is outside
the normalization domain: its support is left the neutral, un-normalized
aggregate (`0.0`), with no ``group_profile`` lookup and no division.
`support(h)` is **never bounded to `[0, 1]`** and is never a probability.
`min_profile_floor`'s numeric value is a `calibration_version` parameter
(Amendment A / §D17), defaulted to a documented placeholder here
(:data:`DEFAULT_MIN_PROFILE_FLOOR`), never a claimed calibrated value. The
per-term breakdown of `raw_support(h)` below is unchanged by Amendment A:

- **`Σ_contradicting (D · contradiction_strength)` is always exactly `0`
  today, and this module enforces that rather than assumes it.** Gate 3.4's
  own module docstring proves ``EvidenceRole.CONTRADICTING`` cells are never
  produced by the current pipeline (genuine contradiction requires
  ``CoverageProfile``, explicitly out of scope through Gate 3.4). ADR-0005
  never defines what numeric value `contradiction_strength` actually takes
  — it appears exactly once in the ADR's text, with no further
  specification. Rather than fabricate a weight for a term that cannot
  currently be exercised, this module **fails closed** (raises
  :class:`~attribution_platform.attribution.errors.AttributionError`) if it
  ever encounters a `CONTRADICTING` cell, instead of silently inventing a
  `contradiction_strength` value.
- **`relevance` in `Σ_supporting (D · relevance)` is an implicit `1` for
  every cell this module ever processes.** A `SUPPORTING`-role cell only
  ever exists with `relevance = CONSISTENT` (Gate 3.4's own construction
  invariant — see `ach_matrix.py`); ADR-0005 defines no distinct numeric
  weight for `CONSISTENT` versus any other relevance value. `D · relevance`
  therefore reduces to `D` for every real cell today — implemented as such,
  not as an invented weighting scale.
- **Repeated evidence for one technique genuinely multiplies its
  contribution (ADR-0005 §D4).** Two distinct `BehavioralStep`s asserting
  the same technique are "genuinely two independent behavioral acts... both
  contribute independently to `support(h)`" — so an atomic feature's
  contribution is `(number of distinct SUPPORTING cells for it) × D(x)`,
  never deduplicated to a single `D(x)`. (§D4 is equally explicit this can
  never, by itself, satisfy the later single-technique abstention guard —
  that is a downstream concern, unaffected by how this module sums.)
- **A combination contributes `D(C)` exactly once per attribution unit**,
  regardless of how many times each of its member features was
  individually observed — a combination is the *co-occurrence* itself
  (ADR-0005 §D3: "a set `C`... genuinely co-occurring within one
  attribution unit"), a unit-level fact, not a per-repetition-multiplied
  one. ADR-0005 does not address multiplicity for combinations whose
  members have differing repeat-counts; this is the smallest, most literal
  reading consistent with the ADR's own "co-occurrence" framing, and is
  named explicitly here as an interpretive completion, not a silent one.

**Diagnosticity (`g(x)`/`D(x)`/`g(C)`/`D(C)`) — ADR-0005 §D3, implemented
exactly:**

- `g(x) = |active groups using x| / |active groups|` — **always relative to
  the active *Group* population only, never Campaigns** (§D3's literal
  formula), via :func:`~attribution_platform.attack_knowledge.traversal.active_groups`/
  :func:`~attribution_platform.attack_knowledge.traversal.groups_using_technique`.
  Every `feature_stix_id` this module ever sees comes from
  `EvidenceAssessment.technique_stix_id`, which the frozen Gate 3.2 contract
  already restricts to `attack-pattern`-prefixed ids only — software-
  extended `g(x)` (ADR-0005 §D3's own "software-extended" clause) is
  therefore structurally unreachable here too, for the identical, already-
  accepted Gate 3.4 reason (see `ach_matrix.py`'s own module docstring),
  not a new limitation introduced by this module.
- `D(x) = 1 − g(x)`; `g(C)`/`D(C)` identically, via
  :func:`~attribution_platform.attack_knowledge.traversal.groups_using_all_techniques`.
- **Candidate-type invariance**: `g`/`D` are computed as a pure function of
  the feature id(s) and the pinned KB — never of which candidate/hypothesis
  is being scored. The identical value is reused verbatim whether the
  hypothesis names a Group or a Campaign candidate.
- **`g(x)=0`/undefined fail-closed behavior**: when a feature has zero
  active-group matches, `g`/`D` are **not** computed from the formula —
  the feature is marked :attr:`DiagnosticityOutcome.OUTSIDE_CALIBRATED_REGIME`
  and contributes exactly `0.0` to `support(h)`, never a fabricated
  substitute value. ADR-0005 §D3 states this must trigger identically
  regardless of the underlying cause (sparse documentation vs. a malformed
  relationship vs. a genuinely-zero-active-match technique) — this module
  does not attempt to distinguish them, matching that instruction exactly.
- **The "below minimum-support count" half of the fallback is deliberately
  NOT implemented.** ADR-0005 §D3 names a second undefined-diagnosticity
  trigger — support below a minimum-count threshold — but states plainly
  that the threshold itself is "a `calibration_version` constant; not
  chosen here." No `calibration_version` exists anywhere in this codebase
  yet (Gate 3.5 does not implement calibration). Inventing a numeric
  threshold here would be fabricating a calibration parameter this ADR
  explicitly reserves for later. This module therefore implements only the
  unconditionally-required zero-match case; the below-threshold-but-nonzero
  case is left to whichever gate first has an actual `calibration_version`
  to compare against.
- **Never described, exposed, or usable as a probability.** `g`/`D`/
  `support(h)` are internal, documentation-relative construction values —
  see the module's own field/type docstrings for the exact "never a
  probability, never a headline score" framing repeated at every exposure
  point.

**Combination diagnosticity and the deterministic partition-selection
rule (ADR-0005 §D3) — implemented exactly for the admissibility test and
the tie-break; the underlying combinatorial *search* procedure is an
explicitly-flagged interpretive completion (see "Architectural note"
below):**

- Admissibility: a candidate combination `C` (`len(C) >= 2`) is valid iff
  `g(C) < min(g(x) for x in C)` — genuinely narrower than every one of its
  parts, verbatim from ADR-0005 §D3.
- Tie-break (verbatim, ADR-0005 §D3's own "Deterministic partition
  selection"): among competing valid, maximal partitions, prefer the one
  minimizing `Σ g(C)` over its combination blocks; if still tied, the
  partition whose combination blocks — each canonicalized as a sorted tuple
  of member ids — sort first lexicographically as a tuple of those tuples.
- **Architectural note — search procedure, explicitly flagged.** ADR-0005
  precisely defines admissibility and the tie-break *between* already-
  identified candidate maximal partitions, but does not specify the search
  algorithm for *finding* candidate partitions, nor an operational
  definition of "maximal" as a hard, checkable constraint. This module
  implements: (1) exhaustive enumeration of every set-partition of a
  hypothesis's own distinct supporting-feature set, safety-bounded at
  :data:`_MAX_COMBINATION_FEATURES` distinct features (beyond which this
  module fails closed rather than guess a bounded/approximate algorithm —
  Bell-number growth makes unbounded exhaustive search genuinely
  intractable, and the ADR names no truncation rule); (2) a validity filter
  (every multi-element block passes admissibility); (3) a **local-
  maximality filter**: a valid partition is discarded if any two of its
  blocks (combination or atomic) could be merged into a single, still-
  admissible block — i.e. no pairwise "further grouping" is available; (4)
  the ADR's own exact tie-break among the survivors. This four-step
  procedure is the smallest, most literal completion of "maximal, non-
  overlapping partition" consistent with the admissibility test and tie-
  break ADR-0005 *does* specify — it is named here explicitly as an
  interpretive completion of an underspecified algorithmic detail, not a
  silent invention of new scoring semantics, and is fully covered by
  hand-verified tests.
- **No maximum combination size is specified by ADR-0005, and none is
  invented here** beyond the computational safety bound above (a
  fail-closed limit on the *search*, not a redefinition of what counts as
  a valid combination).

**Unattributed.** Never receives a fabricated ATT&CK-derived contribution:
it has zero materialized `EvidenceAssessment` cells (Gate 3.4's own
guarantee), so its `support_value` is the empty sum, `0.0` — an accurate,
neutral representation, never a forced win or forced loss. Its later
comparison against real candidates is explicitly out of scope here (§D13's
abstention decision, a later gate).

**No mutation.** `ACHMatrix`/`Hypothesis`/`EvidenceAssessment`/
`AttackKnowledge` are only ever read; this module's own output types are
freshly constructed, immutable, and hold no reference back that a caller
could use to mutate the inputs.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import Enum

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    group_profile,
    groups_using_all_techniques,
    groups_using_technique,
)
from attribution_platform.attribution.ach_matrix import ACHMatrix
from attribution_platform.attribution.candidate_generation import CandidateGenerationResult
from attribution_platform.attribution.contracts import UNATTRIBUTED_CANDIDATE_ID, EvidenceRole
from attribution_platform.attribution.errors import AttributionError

#: Method identity for this engine, mirroring every prior gate's own
#: constant-pair convention.
COMPARATIVE_ANALYSIS_METHOD = "comparative-ach-analysis"
COMPARATIVE_ANALYSIS_METHOD_VERSION = "1.0"

#: Placeholder value for ADR-0005 Amendment A's `min_profile_floor`
#: (`ProfileBreadth_effective(h) = max(ProfileBreadth(h), min_profile_floor)`).
#: **This is NOT the eventual calibrated value.** Amendment A fixes the
#: `max(…)` floor *structure* as structural methodology but leaves the
#: numeric floor a `calibration_version` parameter, and no `calibration_version`
#: artifact exists in this codebase yet (§D17). ``1`` is the smallest
#: deterministic, division-safe default: it guarantees a denominator of at
#: least 1 (so `support(h)` is always well-defined, even for the degenerate
#: zero-profile case a real generated candidate cannot actually reach), while
#: being the identity floor for every candidate with a non-empty profile. A
#: later calibration round MAY raise it to dampen small-profile amplification;
#: callers (and tests) may pass an explicit ``min_profile_floor`` to override.
DEFAULT_MIN_PROFILE_FLOOR = 1

#: Safety bound on exhaustive combination-partition search (see the module
#: docstring's "Architectural note"). Bell(8) = 4140 set-partitions, with
#: at most 2**8 = 256 distinct blocks ever needing a real KB query
#: (memoized) — comfortably fast. This is a computational fail-closed
#: limit, never a redefinition of combination admissibility.
_MAX_COMBINATION_FEATURES = 8


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Local non-empty-string check (raises ``AttributionError``) — a local
    copy of the identical check every other layer in this project owns
    independently."""
    if not isinstance(value, str) or not value.strip():
        raise AttributionError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one caller-supplied, free-text identity
    component — local copy of every prior layer's own helper."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DiagnosticityOutcome(Enum):
    """Whether a feature's `g`/`D` value was resolvable from the baseline
    formula (ADR-0005 §D3), or fell back to the "outside calibrated regime"
    state (undefined/zero-active-match `g`) — never a probability, never a
    third numeric value invented in place of an unresolved one."""

    RESOLVED = "resolved"
    OUTSIDE_CALIBRATED_REGIME = "outside_calibrated_regime"


@dataclass(frozen=True)
class EvidenceContribution:
    """One atomic-or-combination feature's contribution to one hypothesis's
    `support(h)` — the smallest explainable provenance unit ("why does this
    hypothesis have the support value it has").

    - ``feature_stix_ids``: sorted tuple of technique ids; length 1 for an
      atomic feature, length >= 2 for a combination.
    - ``diagnosticity_outcome`` / ``g_value`` / ``d_value``: ADR-0005 §D3's
      own inspectable, documentation-relative values — ``g_value``/
      ``d_value`` are ``None`` iff ``diagnosticity_outcome`` is
      ``OUTSIDE_CALIBRATED_REGIME``. **Never a probability, never a
      headline score.**
    - ``assessment_ids``: the grounding ``EvidenceAssessment`` id(s) this
      contribution traces back to — non-empty, canonicalized.
    - ``contribution_value``: this feature's numeric addition to
      `support(h)` — `0.0` when outside the calibrated regime, otherwise
      `d_value` for a combination, or `d_value * (number of supporting
      cells for this atomic feature)` for an atomic feature (ADR-0005 §D4's
      independent-repetition rule).
    """

    feature_stix_ids: tuple[str, ...]
    diagnosticity_outcome: DiagnosticityOutcome
    g_value: float | None
    d_value: float | None
    assessment_ids: tuple[str, ...]
    contribution_value: float

    def __post_init__(self) -> None:
        if not self.feature_stix_ids:
            raise AttributionError("EvidenceContribution.feature_stix_ids must be non-empty")
        for feature_id in self.feature_stix_ids:
            _require_nonempty_str(feature_id, "EvidenceContribution.feature_stix_ids[]")
        object.__setattr__(self, "feature_stix_ids", tuple(sorted(self.feature_stix_ids)))

        if not isinstance(self.diagnosticity_outcome, DiagnosticityOutcome):
            raise AttributionError(
                "EvidenceContribution.diagnosticity_outcome must be a DiagnosticityOutcome, "
                f"got {type(self.diagnosticity_outcome).__name__}"
            )
        if self.diagnosticity_outcome is DiagnosticityOutcome.OUTSIDE_CALIBRATED_REGIME:
            if self.g_value is not None or self.d_value is not None:
                raise AttributionError(
                    "EvidenceContribution: g_value/d_value must be None when "
                    "diagnosticity_outcome is OUTSIDE_CALIBRATED_REGIME"
                )
            if self.contribution_value != 0.0:
                raise AttributionError(
                    "EvidenceContribution: contribution_value must be 0.0 when "
                    "diagnosticity_outcome is OUTSIDE_CALIBRATED_REGIME"
                )
        else:
            if self.g_value is None or self.d_value is None:
                raise AttributionError(
                    "EvidenceContribution: g_value/d_value must be set when "
                    "diagnosticity_outcome is RESOLVED"
                )
            if not (0.0 <= self.g_value <= 1.0):
                raise AttributionError(
                    f"EvidenceContribution.g_value must be in [0, 1], got {self.g_value!r}"
                )
            if not (0.0 <= self.d_value <= 1.0):
                raise AttributionError(
                    f"EvidenceContribution.d_value must be in [0, 1], got {self.d_value!r}"
                )

        if not self.assessment_ids:
            raise AttributionError("EvidenceContribution.assessment_ids must be non-empty")
        for assessment_id in self.assessment_ids:
            _require_nonempty_str(assessment_id, "EvidenceContribution.assessment_ids[]")
        object.__setattr__(self, "assessment_ids", tuple(sorted(set(self.assessment_ids))))

        if self.contribution_value < 0.0:
            raise AttributionError(
                f"EvidenceContribution.contribution_value must be >= 0, "
                f"got {self.contribution_value!r}"
            )


@dataclass(frozen=True)
class HypothesisSupportSummary:
    """`support(h)` and its itemized contributions for one hypothesis
    (ADR-0005 §D8/§D9, profile-breadth-normalized per Amendment A) — an
    internal comparative evidence aggregate, never an analyst-facing
    verdict, never a likelihood/confidence/probability/percentage.

    - ``support_value``: the **profile-breadth-normalized** support (ADR-0005
      Amendment A) — `raw_support_value / max(profile_breadth,
      min_profile_floor)`. Not bounded to `[0, 1]` (it is an ordering
      statistic, never a probability): repeated-technique multiplicity and
      multiple high-`D` contributions can legitimately produce values above
      `1`.
    - ``raw_support_value``: the pre-normalization aggregate (`Σ` atomic +
      combination − contradicting contributions) — exactly the sum of the
      per-feature ``EvidenceContribution.contribution_value``\\ s, which are
      themselves unchanged by Amendment A.
    - ``profile_breadth``: the raw `ProfileBreadth(h)` — the count of distinct
      technique/software STIX ids in the candidate's own `uses` profile
      (`len(group_profile(...))`). ``None`` iff this hypothesis names the
      `Unattributed` sentinel, which has no candidate STIX id and is outside
      the normalization domain (Amendment A) — its support is left the
      neutral, un-normalized aggregate.
    - ``profile_breadth_floor_applied``: ``True`` iff `profile_breadth <
      min_profile_floor` (so the effective denominator was clamped up to the
      floor). Always ``False`` when ``profile_breadth`` is ``None``.
    """

    hypothesis_id: str
    candidate_id: str
    support_value: float
    raw_support_value: float
    profile_breadth: int | None
    profile_breadth_floor_applied: bool
    contributions: tuple[EvidenceContribution, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty_str(self.hypothesis_id, "HypothesisSupportSummary.hypothesis_id")
        _require_nonempty_str(self.candidate_id, "HypothesisSupportSummary.candidate_id")
        if self.support_value < 0.0:
            raise AttributionError(
                f"HypothesisSupportSummary.support_value must be >= 0, "
                f"got {self.support_value!r}"
            )
        if self.raw_support_value < 0.0:
            raise AttributionError(
                f"HypothesisSupportSummary.raw_support_value must be >= 0, "
                f"got {self.raw_support_value!r}"
            )
        if self.profile_breadth is not None:
            if isinstance(self.profile_breadth, bool) or not isinstance(self.profile_breadth, int):
                raise AttributionError(
                    "HypothesisSupportSummary.profile_breadth must be an int or None, got "
                    f"{type(self.profile_breadth).__name__}"
                )
            if self.profile_breadth < 0:
                raise AttributionError(
                    f"HypothesisSupportSummary.profile_breadth must be >= 0, "
                    f"got {self.profile_breadth!r}"
                )
        if not isinstance(self.profile_breadth_floor_applied, bool):
            raise AttributionError(
                "HypothesisSupportSummary.profile_breadth_floor_applied must be a bool, got "
                f"{type(self.profile_breadth_floor_applied).__name__}"
            )
        if self.profile_breadth is None and self.profile_breadth_floor_applied:
            raise AttributionError(
                "HypothesisSupportSummary: profile_breadth_floor_applied must be False when "
                "profile_breadth is None (the Unattributed / outside-normalization-domain case)"
            )
        for contribution in self.contributions:
            if not isinstance(contribution, EvidenceContribution):
                raise AttributionError(
                    "HypothesisSupportSummary.contributions must contain only "
                    f"EvidenceContribution objects, got {type(contribution).__name__}"
                )
        object.__setattr__(
            self,
            "contributions",
            tuple(sorted(self.contributions, key=lambda c: (c.feature_stix_ids, c.assessment_ids))),
        )


@dataclass(frozen=True)
class ComparativeEvidenceResult:
    """What :func:`compute_comparative_evidence` produced for one
    attribution unit (ADR-0005 §D8/§D9) — a derived, computation-time
    structure, mirroring :class:`~attribution_platform.attribution.ach_matrix.ACHMatrix`'s
    own "derived result, never independently persisted" shape."""

    group_id: str
    attack_kb_version: str
    hypothesis_summaries: tuple[HypothesisSupportSummary, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty_str(self.group_id, "ComparativeEvidenceResult.group_id")
        _require_nonempty_str(self.attack_kb_version, "ComparativeEvidenceResult.attack_kb_version")
        for summary in self.hypothesis_summaries:
            if not isinstance(summary, HypothesisSupportSummary):
                raise AttributionError(
                    "ComparativeEvidenceResult.hypothesis_summaries must contain only "
                    f"HypothesisSupportSummary objects, got {type(summary).__name__}"
                )
        object.__setattr__(
            self,
            "hypothesis_summaries",
            tuple(sorted(self.hypothesis_summaries, key=lambda s: s.hypothesis_id)),
        )


def _enumerate_set_partitions(items: tuple[str, ...]) -> Iterator[tuple[frozenset[str], ...]]:
    """Yield every partition of ``items`` into non-empty, disjoint blocks
    (the standard restricted-growth-string recursive generation) — the
    caller is responsible for bounding ``len(items)`` first."""
    n = len(items)
    if n == 0:
        return

    def helper(i: int, blocks: list[list[str]]) -> Iterator[tuple[frozenset[str], ...]]:
        if i == n:
            yield tuple(frozenset(b) for b in blocks)
            return
        for block in blocks:
            block.append(items[i])
            yield from helper(i + 1, blocks)
            block.pop()
        blocks.append([items[i]])
        yield from helper(i + 1, blocks)
        blocks.pop()

    yield from helper(0, [])


def _find_combination_partition(
    features: tuple[str, ...], g_of: Callable[[frozenset[str]], float | None]
) -> tuple[frozenset[str], ...]:
    """Select the deterministic combination partition for one hypothesis's
    own distinct supporting-feature set (ADR-0005 §D3) — see the module
    docstring's "Architectural note" for the exact four-step procedure and
    why it is an explicitly-flagged interpretive completion, not an
    invented formula. Returns the tuple of chosen multi-element combination
    blocks; features not covered by any returned block are atomic.
    """
    n = len(features)
    if n < 2:
        return ()
    if n > _MAX_COMBINATION_FEATURES:
        raise AttributionError(
            f"_find_combination_partition: {n} distinct supporting features exceeds the "
            f"{_MAX_COMBINATION_FEATURES}-feature bounded-search safety limit — ADR-0005 §D3 "
            "does not specify a bounded/approximate combination-partition search algorithm "
            "for this case, so this gate fails closed rather than guessing one (see this "
            "module's own docstring)"
        )

    atomic_g: dict[str, float | None] = {x: g_of(frozenset({x})) for x in features}

    def is_admissible(block: frozenset[str]) -> bool:
        if len(block) < 2:
            return False
        member_gs = [atomic_g[x] for x in block]
        if any(g is None for g in member_gs):
            return False
        combo_g = g_of(block)
        if combo_g is None:
            return False
        return combo_g < min(g for g in member_gs if g is not None)

    valid_partitions: list[tuple[frozenset[str], ...]] = []
    for partition in _enumerate_set_partitions(features):
        multi_blocks = tuple(b for b in partition if len(b) >= 2)
        if all(is_admissible(b) for b in multi_blocks):
            valid_partitions.append(multi_blocks)

    feature_set = frozenset(features)

    def has_improving_merge(multi_blocks: tuple[frozenset[str], ...]) -> bool:
        covered: frozenset[str] = (
            frozenset[str]().union(*multi_blocks) if multi_blocks else frozenset()
        )
        atomics = feature_set - covered
        blocks = list(multi_blocks) + [frozenset({x}) for x in atomics]
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                if is_admissible(blocks[i] | blocks[j]):
                    return True
        return False

    maximal_partitions = [p for p in valid_partitions if not has_improving_merge(p)]
    if not maximal_partitions:
        return ()

    def sum_g(multi_blocks: tuple[frozenset[str], ...]) -> float:
        total = 0.0
        for block in multi_blocks:
            value = g_of(block)
            if value is None:
                raise AttributionError(
                    "_find_combination_partition: internal inconsistency — an admissible "
                    "block's g(C) resolved to None during scoring"
                )
            total += value
        return total

    def canonical_key(multi_blocks: tuple[frozenset[str], ...]) -> tuple[tuple[str, ...], ...]:
        return tuple(sorted(tuple(sorted(b)) for b in multi_blocks))

    best = min(maximal_partitions, key=lambda p: (sum_g(p), canonical_key(p)))
    # Canonicalize the returned block ORDER itself (sorted by each block's own
    # canonical sorted-tuple form) -- the chosen partition's *content* is
    # already deterministic via the tie-break above, but the tuple order it
    # was discovered in depends on `features`' own input order (via
    # `_enumerate_set_partitions`); every caller must see the same order for
    # identical logical input regardless of how `features` was supplied.
    return tuple(sorted(best, key=lambda b: tuple(sorted(b))))


def _make_hypothesis_summary(
    *,
    hypothesis_id: str,
    candidate_id: str,
    raw_support_value: float,
    contributions: tuple[EvidenceContribution, ...],
    profile_breadth: int | None,
    min_profile_floor: int,
) -> HypothesisSupportSummary:
    """Apply ADR-0005 Amendment A profile-breadth normalization **once** to
    the already-aggregated ``raw_support_value``, and assemble the summary.

    ``profile_breadth is None`` marks the Unattributed / outside-normalization-
    domain case (Amendment A): no ``group_profile`` lookup and no division —
    ``support_value`` is left equal to ``raw_support_value`` (the neutral
    aggregate). Otherwise ``support(h) = raw_support(h) /
    max(profile_breadth, min_profile_floor)`` — division only, applied once,
    never per-contribution (the per-feature ``EvidenceContribution`` values
    are already summed into ``raw_support_value`` unchanged).
    """
    if profile_breadth is None:
        return HypothesisSupportSummary(
            hypothesis_id=hypothesis_id,
            candidate_id=candidate_id,
            support_value=raw_support_value,
            raw_support_value=raw_support_value,
            profile_breadth=None,
            profile_breadth_floor_applied=False,
            contributions=contributions,
        )
    effective_breadth = max(profile_breadth, min_profile_floor)
    floor_applied = profile_breadth < min_profile_floor
    support_value = raw_support_value / effective_breadth
    return HypothesisSupportSummary(
        hypothesis_id=hypothesis_id,
        candidate_id=candidate_id,
        support_value=support_value,
        raw_support_value=raw_support_value,
        profile_breadth=profile_breadth,
        profile_breadth_floor_applied=floor_applied,
        contributions=contributions,
    )


def _summarize_hypothesis(
    hypothesis_id: str,
    candidate_id: str,
    cells: tuple[tuple[str, str], ...],
    g_of: Callable[[frozenset[str]], float | None],
    profile_breadth: int | None,
    min_profile_floor: int,
) -> HypothesisSupportSummary:
    """``cells`` is a tuple of ``(technique_stix_id, assessment_id)`` pairs
    for this one hypothesis's SUPPORTING cells only (CONTRADICTING is
    rejected by the caller before this function is ever reached).

    Computes the raw per-feature/per-combination contributions and their
    aggregate ``raw_support(h)`` exactly as before (unchanged by Amendment
    A), then delegates the single profile-breadth normalization step to
    :func:`_make_hypothesis_summary`."""
    if not cells:
        return _make_hypothesis_summary(
            hypothesis_id=hypothesis_id,
            candidate_id=candidate_id,
            raw_support_value=0.0,
            contributions=(),
            profile_breadth=profile_breadth,
            min_profile_floor=min_profile_floor,
        )

    assessment_ids_by_feature: dict[str, list[str]] = {}
    for feature_id, assessment_id in cells:
        assessment_ids_by_feature.setdefault(feature_id, []).append(assessment_id)
    for feature_id in assessment_ids_by_feature:
        assessment_ids_by_feature[feature_id].sort()

    distinct_features = tuple(sorted(assessment_ids_by_feature))
    combination_blocks = (
        _find_combination_partition(distinct_features, g_of) if len(distinct_features) >= 2 else ()
    )

    contributions: list[EvidenceContribution] = []
    covered: set[str] = set()

    for block in combination_blocks:
        covered |= set(block)
        block_assessment_ids = tuple(
            sorted(aid for feature_id in block for aid in assessment_ids_by_feature[feature_id])
        )
        g_value = g_of(frozenset(block))
        if g_value is None:
            contributions.append(
                EvidenceContribution(
                    feature_stix_ids=tuple(sorted(block)),
                    diagnosticity_outcome=DiagnosticityOutcome.OUTSIDE_CALIBRATED_REGIME,
                    g_value=None,
                    d_value=None,
                    assessment_ids=block_assessment_ids,
                    contribution_value=0.0,
                )
            )
        else:
            d_value = 1.0 - g_value
            contributions.append(
                EvidenceContribution(
                    feature_stix_ids=tuple(sorted(block)),
                    diagnosticity_outcome=DiagnosticityOutcome.RESOLVED,
                    g_value=g_value,
                    d_value=d_value,
                    assessment_ids=block_assessment_ids,
                    contribution_value=d_value,
                )
            )

    for feature_id in distinct_features:
        if feature_id in covered:
            continue
        feature_assessment_ids = tuple(assessment_ids_by_feature[feature_id])
        g_value = g_of(frozenset({feature_id}))
        if g_value is None:
            contributions.append(
                EvidenceContribution(
                    feature_stix_ids=(feature_id,),
                    diagnosticity_outcome=DiagnosticityOutcome.OUTSIDE_CALIBRATED_REGIME,
                    g_value=None,
                    d_value=None,
                    assessment_ids=feature_assessment_ids,
                    contribution_value=0.0,
                )
            )
        else:
            d_value = 1.0 - g_value
            occurrence_count = len(feature_assessment_ids)
            contributions.append(
                EvidenceContribution(
                    feature_stix_ids=(feature_id,),
                    diagnosticity_outcome=DiagnosticityOutcome.RESOLVED,
                    g_value=g_value,
                    d_value=d_value,
                    assessment_ids=feature_assessment_ids,
                    contribution_value=d_value * occurrence_count,
                )
            )

    raw_support_value = sum(c.contribution_value for c in contributions)
    return _make_hypothesis_summary(
        hypothesis_id=hypothesis_id,
        candidate_id=candidate_id,
        raw_support_value=raw_support_value,
        contributions=tuple(contributions),
        profile_breadth=profile_breadth,
        min_profile_floor=min_profile_floor,
    )


def compute_comparative_evidence(
    matrix: ACHMatrix,
    knowledge: AttackKnowledge,
    candidate_result: CandidateGenerationResult,
    *,
    min_profile_floor: int = DEFAULT_MIN_PROFILE_FLOOR,
) -> ComparativeEvidenceResult:
    """Compute the deterministic, profile-breadth-normalized `support(h)`
    comparative evidence aggregate for every hypothesis in ``matrix``
    (ADR-0005 §D3/§D4/§D8/§D9, normalized per Amendment A) — comparative
    evidence aggregation only, no attribution decision.

    ``candidate_result`` is the Gate 3.3
    :class:`~attribution_platform.attribution.candidate_generation.CandidateGenerationResult`
    that produced ``matrix``'s hypotheses. It is required because
    ``ProfileBreadth(h)`` needs the candidate's canonical ATT&CK STIX id
    (`actor_ref`/`campaign_ref`), which lives on the ``Candidate`` objects
    here and is **not** recoverable from a ``Hypothesis`` (whose
    ``candidate_id`` is an irreversible hash) or from ``ACHMatrix``. This
    reads the mapping explicitly; it never reverses a hash, never
    re-generates candidates, and never mutates any input.

    ``min_profile_floor`` is ADR-0005 Amendment A's calibration-deferred
    floor (see :data:`DEFAULT_MIN_PROFILE_FLOOR`) — the numeric value is a
    ``calibration_version`` parameter, exposed here so a future calibrated
    value (or a test) can supply it explicitly.

    Fails closed on a structural mismatch between ``matrix``,
    ``candidate_result`` and ``knowledge``, on an out-of-range
    ``min_profile_floor``, and on encountering a `CONTRADICTING` cell (see
    the module docstring — `contradiction_strength` is not yet defined by
    the accepted architecture).
    """
    if not isinstance(matrix, ACHMatrix):
        raise AttributionError(
            f"compute_comparative_evidence: matrix must be an ACHMatrix, "
            f"got {type(matrix).__name__}"
        )
    if not isinstance(knowledge, AttackKnowledge):
        raise AttributionError(
            "compute_comparative_evidence: knowledge must be an AttackKnowledge, "
            f"got {type(knowledge).__name__}"
        )
    if not isinstance(candidate_result, CandidateGenerationResult):
        raise AttributionError(
            "compute_comparative_evidence: candidate_result must be a "
            f"CandidateGenerationResult, got {type(candidate_result).__name__}"
        )
    if isinstance(min_profile_floor, bool) or not isinstance(min_profile_floor, int):
        raise AttributionError(
            "compute_comparative_evidence: min_profile_floor must be an int, got "
            f"{type(min_profile_floor).__name__}"
        )
    if min_profile_floor < 1:
        raise AttributionError(
            "compute_comparative_evidence: min_profile_floor must be >= 1 (a support "
            f"denominator), got {min_profile_floor!r}"
        )
    if matrix.attack_kb_version != knowledge.attack_kb_version:
        raise AttributionError(
            f"compute_comparative_evidence: matrix.attack_kb_version "
            f"{matrix.attack_kb_version!r} does not match the loaded "
            f"knowledge.attack_kb_version {knowledge.attack_kb_version!r}"
        )
    if candidate_result.group_id != matrix.group_id:
        raise AttributionError(
            f"compute_comparative_evidence: candidate_result.group_id "
            f"{candidate_result.group_id!r} does not match matrix.group_id "
            f"{matrix.group_id!r}"
        )
    if candidate_result.attack_kb_version != matrix.attack_kb_version:
        raise AttributionError(
            "compute_comparative_evidence: candidate_result.attack_kb_version "
            f"{candidate_result.attack_kb_version!r} does not match matrix.attack_kb_version "
            f"{matrix.attack_kb_version!r}"
        )

    # candidate_id -> the candidate's canonical ATT&CK STIX id (actor_ref for a
    # Group, campaign_ref for a Campaign). Exactly one is set (Candidate's own
    # invariant). The Unattributed sentinel is deliberately absent from this
    # map — it names no ATT&CK entity and is outside the normalization domain.
    candidate_stix_by_id: dict[str, str] = {}
    for candidate in candidate_result.candidates:
        stix_id = candidate.actor_ref if candidate.actor_ref is not None else candidate.campaign_ref
        if stix_id is None:  # pragma: no cover - Candidate guarantees exactly one is set
            raise AttributionError(
                f"compute_comparative_evidence: candidate {candidate.candidate_id!r} has "
                "neither actor_ref nor campaign_ref set"
            )
        candidate_stix_by_id[candidate.candidate_id] = stix_id

    cells_by_hypothesis: dict[str, list[tuple[str, str]]] = {}
    for assessment in matrix.assessments:
        if assessment.role is EvidenceRole.CONTRADICTING:
            raise AttributionError(
                f"compute_comparative_evidence: encountered a CONTRADICTING "
                f"EvidenceAssessment ({assessment.assessment_id!r}) — ADR-0005's "
                "'contradiction_strength' term is not yet defined by the accepted "
                "architecture (see this module's own docstring); refusing to fabricate "
                "a weight rather than guess one"
            )
        cells_by_hypothesis.setdefault(assessment.hypothesis_id, []).append(
            (assessment.technique_stix_id, assessment.assessment_id)
        )

    active_group_count = len(active_groups(knowledge))
    g_cache: dict[frozenset[str], float | None] = {}

    def g_of(features: frozenset[str]) -> float | None:
        if features in g_cache:
            return g_cache[features]
        if active_group_count == 0:
            result: float | None = None
        elif len(features) == 1:
            (feature_id,) = features
            matching = groups_using_technique(knowledge, feature_id)
            result = (len(matching) / active_group_count) if matching else None
        else:
            matching = groups_using_all_techniques(knowledge, features)
            result = (len(matching) / active_group_count) if matching else None
        g_cache[features] = result
        return result

    profile_breadth_cache: dict[str, int] = {}

    def profile_breadth_of(candidate_id: str) -> int | None:
        """`ProfileBreadth(h)` (Amendment A) — `len(group_profile(...))` for a
        real candidate, or ``None`` for the Unattributed sentinel (outside the
        normalization domain). Deterministic and memoized; never reverses a
        hash and never mutates the KB."""
        if candidate_id == UNATTRIBUTED_CANDIDATE_ID:
            return None
        if candidate_id in profile_breadth_cache:
            return profile_breadth_cache[candidate_id]
        stix_id = candidate_stix_by_id.get(candidate_id)
        if stix_id is None:
            raise AttributionError(
                f"compute_comparative_evidence: hypothesis candidate_id {candidate_id!r} is "
                "not the Unattributed sentinel and has no matching Candidate in "
                "candidate_result — cannot resolve its ATT&CK profile breadth"
            )
        breadth = len(group_profile(knowledge, stix_id))
        profile_breadth_cache[candidate_id] = breadth
        return breadth

    summaries = tuple(
        _summarize_hypothesis(
            hypothesis.hypothesis_id,
            hypothesis.candidate_id,
            tuple(cells_by_hypothesis.get(hypothesis.hypothesis_id, ())),
            g_of,
            profile_breadth_of(hypothesis.candidate_id),
            min_profile_floor,
        )
        for hypothesis in matrix.hypotheses
    )

    return ComparativeEvidenceResult(
        group_id=matrix.group_id,
        attack_kb_version=matrix.attack_kb_version,
        hypothesis_summaries=summaries,
    )
