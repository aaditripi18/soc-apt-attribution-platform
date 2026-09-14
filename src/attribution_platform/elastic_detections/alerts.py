"""Elastic Detection Engine alert -> DetectionResult (gate G1.1).

Two functions, deliberately kept apart:

- :func:`fetch_recent_alerts` — the only I/O in this module: a bounded,
  read-only query against Elastic's alerts index via the G0.8
  :class:`~attribution_platform.dataplane.client.ElasticClient` abstraction
  (never a concrete client). Returns raw alert documents; does no
  normalization.
- :func:`normalize_elastic_alert` — pure, offline, deterministic: one
  already-fetched Elastic Security alert document (the real
  ``kibana.alert.*``/``@timestamp`` field shape Elastic's Detection Engine
  writes to its ``.alerts-security.alerts-*`` indices) in, one
  :class:`~attribution_platform.detection.DetectionResult` out. No network,
  no ATT&CK-KB network access (the KB is already loaded and in memory), no
  randomness, no wall-clock.

**Elastic-specific field names are confined to this module.** Nothing in
:mod:`attribution_platform.detection` (the core rule engine, gate G1.0) is
touched or imported here in the wrong direction — this module imports
*from* ``detection`` (to build its output contract) and from
``attack_knowledge``/``dataplane``/``domain``, never the reverse; a guard
test enforces that ``detection/`` never imports this package or
``dataplane`` (see ``tests/test_elastic_detection_alerts.py``).

**No parallel telemetry-ingestion path.** This module never builds an
``Observation`` and never parses raw source-event fields (that remains the
:mod:`attribution_platform.sources` boundary's job, unchanged). An alert's
underlying triggering event is referenced — not re-derived — via
``kibana.alert.ancestors[0].id``, Elastic's own real field naming the
Elasticsearch document id of the event that produced the alert. When that
event was itself normalized into one of our ``Observation``s through the
existing ``SourceAdapter``/extraction boundary (so its ``observation_id``
matches), this becomes exactly
``DetectionResult.supporting_observation_ids`` — a pointer, not a copy.
Resolving that Observation (e.g. via
:func:`attribution_platform.dataplane.load_observation`) and calling
:func:`attribution_platform.detection.derive_evidence_from_detection` with
it is the caller's job, using existing, unmodified functions — this module
does not do it itself and does not implement a second Evidence-derivation
path.

**Single-event alerts only.** An alert whose ``kibana.alert.ancestors`` has
more than one entry represents multiple underlying events — that is
correlation, explicitly Phase 2 and out of scope — and is rejected
fail-closed rather than silently narrowed to "the first one".

**ATT&CK mappings are validated, never trusted.** Elastic detection rules
declare their own ATT&CK mapping via ``kibana.alert.rule.threat[].technique``
(and nested ``.subtechnique``), using MITRE's human-facing ``Txxxx`` ids —
*not* our pinned KB's STIX ids. Each declared id is looked up in the loaded
:class:`~attribution_platform.attack_knowledge.loader.AttackKnowledge` (by
its ``external_references`` — the same authoritative source
:mod:`attribution_platform.attack_knowledge` always uses) and the resulting
reference is validated with the existing, unmodified
:func:`attribution_platform.attack_knowledge.resolution.resolve_attack_ref`
— the same function G1.0's rule-pack loader and G0.6's ``derive_evidence``
already use. A ``Txxxx`` Elastic declares that does not resolve in our
pinned v19.0 KB (wrong id, retired technique, KB-version drift) fails the
whole alert closed with :class:`~attribution_platform.detection.DetectionError`
— it is never silently dropped or replaced with a fabricated reference. An
alert declaring the same technique twice (directly, or via a technique and
its own sub-technique resolving to the same KB object) is also rejected —
this module does not duplicate that check itself; it relies on
:class:`~attribution_platform.detection.DetectionResult`'s own structural
``attack_ref.stix_id``-uniqueness invariant (a G1.1 provenance-review
finding: that invariant belongs on the contract, since G1.1 is a second
producer of ``DetectionResult`` that does not go through ``DetectionRule``).

**Matched-field information is best-effort.** Elastic does not expose one
uniform "which fields matched" structure across every detection-rule type
(query, threshold, EQL, ML, ...). Where an alert carries the common ECS
entity fields Elastic's query/threshold rule types copy onto the alert
document, this module records their presence as ``MatchedField(...,
operator="exists", ...)`` entries — an honest "this field was part of what
matched," not a fabricated claim about which specific predicate fired. If
none of those fields are present, a single fallback ``MatchedField`` naming
the firing rule id is used, so ``MatchBasis``'s non-empty invariant is
always satisfiable without inventing data Elastic did not provide.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.resolution import (
    AttackReferenceError,
    resolve_attack_ref,
)
from attribution_platform.dataplane.client import ElasticClient
from attribution_platform.dataplane.errors import ElasticIntegrationError
from attribution_platform.detection import (
    DetectionError,
    DetectionResult,
    MatchBasis,
    MatchedField,
    TechniqueMapping,
)
from attribution_platform.domain import AttackRef, DomainContractError, EvidenceType, TimeSpan
from attribution_platform.extraction.detection_match import RuleRef

#: DetectionResult.detection_source for every alert this module normalizes.
ELASTIC_ALERT_SOURCE = "elastic"

#: Elastic Security's default Detection-Engine alerts index for the default
#: Kibana space. A real, documented index pattern -- not invented here.
DEFAULT_ALERTS_INDEX = ".alerts-security.alerts-default"

#: A small, explicit bound. Callers may lower it; there is deliberately no
#: way to request "all" alerts (see the ``ElasticClient.search`` docstring).
DEFAULT_ALERT_FETCH_SIZE = 50

#: The common ECS entity leaf fields Elastic's query/threshold detection
#: rules typically copy onto the alert document alongside ``kibana.alert.*``
#: -- the same entity-group vocabulary the G1.0 rule engine itself uses
#: (see ``detection.rules._ALLOWED_TOP_LEVEL_FIELDS``), kept independent
#: here since this module reads plain nested dicts, not an ``Observation``.
_MATCHED_FIELD_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("process", "name"),
    ("process", "command_line"),
    ("process", "executable"),
    ("host", "name"),
    ("user", "name"),
    ("network", "transport"),
    ("file", "path"),
    ("file", "name"),
)


def fetch_recent_alerts(
    client: ElasticClient,
    *,
    index: str = DEFAULT_ALERTS_INDEX,
    size: int = DEFAULT_ALERT_FETCH_SIZE,
) -> tuple[Mapping[str, Any], ...]:
    """Bounded, read-only fetch of up to ``size`` alerts from ``index``.

    Uses the existing G0.8 ``ElasticClient.search`` (a ``match_all`` query --
    this module does not build rule/time-range filters; that is a later
    gate's concern if ever needed). Returns raw alert documents, unmodified
    and unnormalized. Never mutates anything.
    """
    if size <= 0:
        raise DetectionError(f"fetch_recent_alerts: size must be positive, got {size}")
    try:
        return client.search(index, {"match_all": {}}, size=size)
    except ElasticIntegrationError as exc:
        raise DetectionError(f"failed to fetch alerts from {index!r}: {exc}") from exc


def _require(alert: Mapping[str, Any], key: str, *, where: str) -> Any:
    value = alert.get(key)
    if value is None:
        raise DetectionError(f"{where}: alert missing required field {key!r}")
    return value


def _require_nonempty_str(value: Any, *, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DetectionError(f"{where} must be a non-empty string, got {value!r}")
    return value


def normalize_elastic_alert(
    alert: Mapping[str, Any], *, knowledge: AttackKnowledge
) -> DetectionResult:
    """Normalize one already-fetched Elastic Security alert document into a
    :class:`~attribution_platform.detection.DetectionResult`.

    Pure and deterministic: no I/O, no generated ids, no wall-clock. Fails
    closed (:class:`~attribution_platform.detection.DetectionError`) on any
    missing/malformed required field, a multi-event alert, or an ATT&CK
    mapping that does not resolve against the pinned KB. See the module
    docstring for the exact field mapping and validation rules.
    """
    if not isinstance(alert, Mapping):
        raise DetectionError(
            f"normalize_elastic_alert requires a Mapping, got {type(alert).__name__}"
        )

    where = "elastic alert"

    alert_uuid = _require_nonempty_str(
        _require(alert, "kibana.alert.uuid", where=where), where=f"{where}.kibana.alert.uuid"
    )

    timestamp_raw = _require(alert, "@timestamp", where=where)
    if not isinstance(timestamp_raw, str):
        raise DetectionError(
            f"{where}: '@timestamp' must be a string, got {type(timestamp_raw).__name__}"
        )
    try:
        timestamp = datetime.fromisoformat(timestamp_raw)
    except ValueError as exc:
        raise DetectionError(
            f"{where}: '@timestamp' {timestamp_raw!r} is not a valid ISO-8601 timestamp"
        ) from exc

    rule_id = _require_nonempty_str(
        _require(alert, "kibana.alert.rule.rule_id", where=where),
        where=f"{where}.kibana.alert.rule.rule_id",
    )
    rule_version_raw = _require(alert, "kibana.alert.rule.version", where=where)
    rule_version = str(rule_version_raw).strip()
    if not rule_version:
        raise DetectionError(f"{where}: 'kibana.alert.rule.version' must not be empty")
    try:
        rule_ref = RuleRef(rule_id=rule_id, rule_version=rule_version)
    except ValueError as exc:  # ExtractionError, also a ValueError
        raise DetectionError(f"{where}: invalid rule identity: {exc}") from exc

    ancestors = _require(alert, "kibana.alert.ancestors", where=where)
    if not isinstance(ancestors, list) or not ancestors:
        raise DetectionError(f"{where}: 'kibana.alert.ancestors' must be a non-empty list")
    if len(ancestors) != 1:
        raise DetectionError(
            f"{where}: alert has {len(ancestors)} ancestor events; this adapter supports only "
            "single-event alerts (multi-event correlation is Phase 2, out of scope)"
        )
    ancestor = ancestors[0]
    if not isinstance(ancestor, Mapping):
        raise DetectionError(f"{where}: 'kibana.alert.ancestors[0]' must be an object")
    observation_id = _require_nonempty_str(
        ancestor.get("id"), where=f"{where}.kibana.alert.ancestors[0].id"
    )

    match_basis = _match_basis_from_alert(alert, rule_id=rule_id)
    technique_mappings = _technique_mappings_from_alert(alert, knowledge=knowledge, where=where)

    # Preserve our own rule-pack content hash only if an upstream step
    # explicitly attached it (e.g. a rule we authored and provisioned into
    # Elastic, with its provenance carried along) -- never fabricated for a
    # genuinely Elastic-native rule, which has no rule pack of ours at all.
    # A missing/blank value becomes None here -- the same "not known, not
    # fabricated" representation gate G1.0 already uses for a DetectionRule
    # built without a rule pack (see DetectionResult.rule_pack_content_hash's
    # own docstring) -- which flows unchanged onto
    # Evidence.provenance.method_content_hash (derive_evidence_from_detection)
    # and always serializes as an explicit `"method_content_hash": null`
    # (domain.to_serializable emits every dataclass field by name, never
    # omits one), so a caller reading canonical JSON sees "no rule-pack hash
    # is known for this detection" as a visible fact, not a silently missing
    # key that could be misread as "reproducible against our native pack".
    content_hash_raw = alert.get("rule_pack_content_hash")
    rule_pack_content_hash = (
        content_hash_raw if isinstance(content_hash_raw, str) and content_hash_raw.strip() else None
    )

    return DetectionResult(
        detection_id=f"elastic::{alert_uuid}",
        rule_ref=rule_ref,
        detection_source=ELASTIC_ALERT_SOURCE,
        supporting_observation_ids=(observation_id,),
        match_basis=match_basis,
        technique_mappings=technique_mappings,
        evidence_type=EvidenceType.BEHAVIORAL,
        time_span=TimeSpan(start=timestamp, end=timestamp),
        rule_pack_content_hash=rule_pack_content_hash,
    )


def _match_basis_from_alert(alert: Mapping[str, Any], *, rule_id: str) -> MatchBasis:
    matched: list[MatchedField] = []
    for top, leaf in _MATCHED_FIELD_CANDIDATES:
        group = alert.get(top)
        if isinstance(group, Mapping) and group.get(leaf) is not None:
            matched.append(
                MatchedField(
                    field_path=f"{top}.{leaf}", operator="exists", observed=str(group[leaf])
                )
            )
    if not matched:
        # Honest fallback: we know the rule that fired, even if Elastic gave
        # us no field-level detail for this rule type -- never fabricate
        # more precision than we actually have.
        matched.append(
            MatchedField(
                field_path="kibana.alert.rule.rule_id", operator="exists", observed=rule_id
            )
        )
    return MatchBasis(matched_fields=tuple(matched))


def _technique_mappings_from_alert(
    alert: Mapping[str, Any], *, knowledge: AttackKnowledge, where: str
) -> tuple[TechniqueMapping, ...]:
    threat = alert.get("kibana.alert.rule.threat")
    if threat is None:
        return ()
    if not isinstance(threat, list):
        raise DetectionError(f"{where}: 'kibana.alert.rule.threat' must be a list if present")

    external_ids: list[str] = []
    for i, entry in enumerate(threat):
        entry_where = f"{where}.kibana.alert.rule.threat[{i}]"
        if not isinstance(entry, Mapping):
            raise DetectionError(f"{entry_where} must be an object")
        techniques = entry.get("technique", [])
        if not isinstance(techniques, list):
            raise DetectionError(f"{entry_where}.technique must be a list")
        for j, technique in enumerate(techniques):
            technique_where = f"{entry_where}.technique[{j}]"
            if not isinstance(technique, Mapping):
                raise DetectionError(f"{technique_where} must be an object")
            external_ids.append(
                _require_nonempty_str(technique.get("id"), where=f"{technique_where}.id")
            )
            subtechniques = technique.get("subtechnique", [])
            if subtechniques:
                if not isinstance(subtechniques, list):
                    raise DetectionError(
                        f"{technique_where}.subtechnique must be a list if present"
                    )
                for k, sub in enumerate(subtechniques):
                    sub_where = f"{technique_where}.subtechnique[{k}]"
                    if not isinstance(sub, Mapping):
                        raise DetectionError(f"{sub_where} must be an object")
                    external_ids.append(
                        _require_nonempty_str(sub.get("id"), where=f"{sub_where}.id")
                    )

    return tuple(
        _mapping_for_external_id(external_id, knowledge=knowledge, where=where)
        for external_id in external_ids
    )


def _mapping_for_external_id(
    external_id: str, *, knowledge: AttackKnowledge, where: str
) -> TechniqueMapping:
    attack_ref = _resolve_external_id(knowledge, external_id, where=where)
    return TechniqueMapping(
        attack_ref=attack_ref,
        mapping_basis=f"Elastic detection rule declared ATT&CK technique {external_id}",
        mapping_source=ELASTIC_ALERT_SOURCE,
    )


def _resolve_external_id(knowledge: AttackKnowledge, external_id: str, *, where: str) -> AttackRef:
    """Look up Elastic's human-facing ``Txxxx`` id in the pinned KB and
    return a validated ``AttackRef`` -- never trust Elastic's id blindly;
    look it up ourselves, in our own pinned bundle, and re-validate with the
    same :func:`resolve_attack_ref` every other gate uses."""
    for obj in (*knowledge.techniques(), *knowledge.sub_techniques()):
        for ref in obj.get("external_references", ()):
            if (
                isinstance(ref, Mapping)
                and ref.get("source_name") == "mitre-attack"
                and ref.get("external_id") == external_id
            ):
                try:
                    attack_ref = AttackRef(
                        stix_id=obj["id"],
                        object_type=obj["type"],
                        attack_kb_version=knowledge.attack_kb_version,
                        external_id=external_id,
                    )
                except DomainContractError as exc:
                    raise DetectionError(
                        f"{where}: technique {external_id!r} resolved to an invalid "
                        f"reference: {exc}"
                    ) from exc
                try:
                    resolve_attack_ref(knowledge, attack_ref)  # defence-in-depth, matches G1.0
                except AttackReferenceError as exc:
                    raise DetectionError(
                        f"{where}: technique {external_id!r} failed re-validation: {exc}"
                    ) from exc
                return attack_ref

    raise DetectionError(
        f"{where}: ATT&CK technique {external_id!r} (declared by Elastic) does not exist in the "
        f"pinned KB {knowledge.attack_kb_version} — refusing to fabricate a reference"
    )
