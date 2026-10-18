"""The Evidence contract: a derived, analyst-meaningful claim (gate G0.3).

An :class:`Evidence` is a **derived** object — a claim backed by one or more
:class:`~attribution_platform.domain.observation.Observation` s — not merely
another telemetry event. It always retains provenance to the Observation(s)
it was derived from (via :class:`~attribution_platform.domain.provenance.DerivationProvenance`),
satisfying the gate's core requirement that every derived object trace back to
its supporting normalized telemetry.

Explicitly out of scope at this gate (contract only — no derivation logic,
and, per ADR-0002 / the G0.3 gate, **no attribution semantics**):

- No attribution score, likelihood, attribution confidence, ACH, candidate
  generation, or scoring of any kind.
- ``quality`` (optional :class:`~attribution_platform.domain.enums.EvidenceQuality`)
  is descriptive metadata about *this evidence item's own trustworthiness* —
  it is **not** attribution likelihood/confidence and carries no numeric
  score; no combination/derivation operates on it here.
- ``attack_ref`` is optional ("where applicable"): evidentiary/contextual
  evidence need not map to a technique. Per-evidence-type mapping rules
  (e.g. "behavioral evidence should map to a technique") are *derivation*
  rules for a later gate, not universal contract invariants — encoding them
  here would be a business heuristic the gate forbids.

Deeply immutable and value-equal by construction (scalars, ``tuple``, and
frozen dataclasses only).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from attribution_platform.domain.attack import AttackRef
from attribution_platform.domain.entities import HostRef, TimeSpan, UserRef
from attribution_platform.domain.enums import EvidenceQuality, EvidenceType
from attribution_platform.domain.errors import ensure_nonempty_str
from attribution_platform.domain.provenance import DerivationProvenance

#: Version of THIS Evidence contract (our schema).
EVIDENCE_SCHEMA_VERSION = "evidence/1"


@dataclass(frozen=True)
class Evidence:
    """A derived, analyst-meaningful claim backed by supporting Observations.

    Required:
    - ``evidence_id``: stable, opaque identifier **supplied upstream** by the
      derivation layer (never generated here — G0.3 §5).
    - ``evidence_type``: the claim's category (closed vocabulary).
    - ``claim``: a human-readable summary of what is being claimed.
    - ``provenance``: :class:`DerivationProvenance` — which rule/version
      produced it and which Observation(s) support it (non-empty). This is
      the mandatory link back to normalized telemetry.

    Optional:
    - ``attack_ref`` — an ATT&CK object reference, where applicable.
    - ``quality`` — descriptive trustworthiness of the evidence item (NOT
      attribution likelihood/confidence).
    - ``time_span`` — the interval the claim covers (may span observations).
    - ``host`` / ``user`` — entity scope of the claim, where applicable.

    ``schema_version`` defaults to the current contract version.

    Note: ``provenance.source_observation_ids`` being non-empty is enforced by
    :class:`DerivationProvenance` itself, so "Evidence without supporting
    Observation references" is structurally impossible.
    """

    evidence_id: str
    evidence_type: EvidenceType
    claim: str
    provenance: DerivationProvenance
    attack_ref: AttackRef | None = None
    quality: EvidenceQuality | None = None
    time_span: TimeSpan | None = None
    host: HostRef | None = None
    user: UserRef | None = None
    #: ADR-0025: the technique in ``attack_ref`` is one of several its rule declares
    #: and the match does not say which. Declared, shown, never compared.
    technique_ambiguous: bool = False
    #: ADR-0025 Amendment I: low-level Evidence of a rule whose review says its
    #: technique counts once the detection is part of an activity cluster.
    counted_when_linked: bool = False
    schema_version: str = field(default=EVIDENCE_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        ensure_nonempty_str(self.evidence_id, "Evidence.evidence_id")
        ensure_nonempty_str(self.claim, "Evidence.claim")
        ensure_nonempty_str(self.schema_version, "Evidence.schema_version")
        if not isinstance(self.evidence_type, EvidenceType):
            # Guards against a raw string slipping in past a non-strict caller.
            raise TypeError(
                f"Evidence.evidence_type must be an EvidenceType, got "
                f"{type(self.evidence_type).__name__}"
            )
        # provenance / attack_ref / entity groups are typed frozen dataclasses
        # already validated at their own construction.
