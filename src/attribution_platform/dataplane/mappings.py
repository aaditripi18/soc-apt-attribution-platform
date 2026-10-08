"""Pinned index names and field mappings for the Observation/Evidence indices
(gate G0.8).

"Explicit, pinned index names/mappings" (docs/architecture/13-phase-0-implementation-plan.md
G0.8) means two things here:

1. **Index names are derived from the domain contract's own schema version**
   (``OBSERVATION_SCHEMA_VERSION`` / ``EVIDENCE_SCHEMA_VERSION`` — gate G0.3),
   not a separately hand-maintained literal that could drift out of sync with
   it. A future deliberate contract change (a bumped schema version) produces
   a new index name automatically, rather than silently writing
   old-and-new-shape documents into the same index.
2. **Mappings are hand-written, not left fully dynamic**, for every field
   this gate is explicitly required to preserve with correct types:
   ``*_id`` fields (``keyword`` — exact match, never analyzed), timestamps
   (``date``), the ATT&CK reference, and the derivation-provenance object.
   The larger, more variable entity groups inherited from ECS-aligned domain
   entities (``host``/``user``/``process``/``network``/``file`` —
   :mod:`attribution_platform.domain.entities`) are mapped as ``object``:
   Elasticsearch still indexes their sub-fields dynamically, but this gate
   does not hand-curate every leaf type for them. Hand-curating those is a
   reasonable later refinement (once real query patterns exist to drive it),
   not a G0.8 requirement — over-specifying now would be speculative.

ECS-compatible naming, not an ECS redesign: field *names* here are exactly
the domain dataclasses' own field names (``observation_id``, ``timestamp``,
``host``, ...) — the same names
:func:`attribution_platform.domain.serialization.to_serializable` already
produces. Nothing is renamed to ECS's dotted form (e.g. ``@timestamp``,
``host.name``) — doing so would mean maintaining a second, ECS-shaped schema
alongside the G0.3 domain contracts, which the gate explicitly forbids. What
*is* ECS-compatible is the choice of Elasticsearch field types (``keyword``
vs ``date`` vs ``text``) and reuse of ECS's own top-level entity-group names,
which the domain layer already aligned with ECS at G0.3.
"""

from __future__ import annotations

from typing import Any

from attribution_platform.correlation import (
    BEHAVIORAL_SEQUENCE_SCHEMA_VERSION,
    CORRELATION_GROUP_SCHEMA_VERSION,
    CORRELATION_LINK_SCHEMA_VERSION,
)
from attribution_platform.domain import EVIDENCE_SCHEMA_VERSION, OBSERVATION_SCHEMA_VERSION


def _index_name(prefix: str, schema_version: str) -> str:
    # schema_version is e.g. "observation/1" -> index suffix "v1".
    _, _, version = schema_version.partition("/")
    return f"attribution-platform-{prefix}-v{version}"


#: Pinned, schema-version-derived index names (never hand-typed elsewhere).
OBSERVATIONS_INDEX = _index_name("observations", OBSERVATION_SCHEMA_VERSION)
EVIDENCE_INDEX = _index_name("evidence", EVIDENCE_SCHEMA_VERSION)

#: G2.3: pinned, schema-version-derived index names for the two G2.0
#: correlation contracts — same convention as OBSERVATIONS_INDEX/EVIDENCE_INDEX.
CORRELATION_LINKS_INDEX = _index_name("correlation-links", CORRELATION_LINK_SCHEMA_VERSION)
CORRELATION_GROUPS_INDEX = _index_name("correlation-groups", CORRELATION_GROUP_SCHEMA_VERSION)

#: G2.4.2: pinned, schema-version-derived index name for the G2.4.0
#: BehavioralSequence contract — same convention, one document per sequence
#: (ADR-0004 D18), never one per step/edge/gap/parallel-group.
BEHAVIORAL_SEQUENCES_INDEX = _index_name("behavioral-sequences", BEHAVIORAL_SEQUENCE_SCHEMA_VERSION)

#: Explicit field mappings for the Observation index (Elasticsearch "properties").
OBSERVATIONS_MAPPING: dict[str, Any] = {
    "observation_id": {"type": "keyword"},
    "timestamp": {"type": "date"},
    "timestamp_precision": {"type": "keyword"},
    "schema_version": {"type": "keyword"},
    "raw_reference": {
        "properties": {
            "source_type": {"type": "keyword"},
            "source_event_id": {"type": "keyword"},
            "dataset_ref": {"type": "keyword"},
            "raw_payload_ref": {"type": "keyword"},
        }
    },
    # Entity groups: dynamic objects (see module docstring) — their sub-fields
    # are still indexed and searchable, just not hand-typed at this gate.
    "event": {"type": "object"},
    "host": {"type": "object"},
    "user": {"type": "object"},
    "process": {"type": "object"},
    "network": {"type": "object"},
    "file": {"type": "object"},
    "dll": {"type": "object"},
    "registry": {"type": "object"},
    "target_process": {"type": "object"},
    "process_access": {"type": "object"},
    "remote_thread": {"type": "object"},
    "dns": {"type": "object"},
    "file_stream": {"type": "object"},
    "pipe": {"type": "object"},
    "wmi": {"type": "object"},
    "powershell": {"type": "object"},
    "target_user": {"type": "object"},
    "logon": {"type": "object"},
    "object_access": {"type": "object"},
    "share": {"type": "object"},
    "service": {"type": "object"},
    "kerberos": {"type": "object"},
    "scheduled_task": {"type": "object"},
    "privilege": {"type": "object"},
    "account_change": {"type": "object"},
    "credential_read": {"type": "object"},
    "wfp_filter": {"type": "object"},
    "audit": {"type": "object"},
    "cloud": {"type": "object"},
    "user_agent": {"type": "object"},
    "entra": {"type": "object"},
    "o365": {"type": "object"},
    "aws_cloudtrail": {"type": "object"},
    "okta": {"type": "object"},
    "github": {"type": "object"},
    "kubernetes_audit": {"type": "object"},
    "azure_activity": {"type": "object"},
    "observer": {"type": "object"},
    "zeek": {"type": "object"},
}

#: Explicit field mappings for the Evidence index (Elasticsearch "properties").
EVIDENCE_MAPPING: dict[str, Any] = {
    "evidence_id": {"type": "keyword"},
    "evidence_type": {"type": "keyword"},
    "claim": {"type": "text"},
    "schema_version": {"type": "keyword"},
    "provenance": {
        "properties": {
            "method": {"type": "keyword"},
            "method_version": {"type": "keyword"},
            "source_observation_ids": {"type": "keyword"},
            "derived_at": {"type": "date"},
        }
    },
    "attack_ref": {
        "properties": {
            "stix_id": {"type": "keyword"},
            "object_type": {"type": "keyword"},
            "attack_kb_version": {"type": "keyword"},
            "external_id": {"type": "keyword"},
        }
    },
    "quality": {"type": "keyword"},
    "time_span": {
        "properties": {
            "start": {"type": "date"},
            "end": {"type": "date"},
        }
    },
    "host": {"type": "object"},
    "user": {"type": "object"},
}

#: G2.3: explicit field mappings for the CorrelationLink index. Mirrors
#: EVIDENCE_MAPPING's convention exactly: every ``*_id``/enum-valued field is
#: ``keyword``, the nested ``basis``/``provenance`` objects get their own
#: hand-typed ``properties`` (the entire field set G2.0's ``CorrelationLink``/
#: ``CorrelationBasis``/``CorrelationProvenance`` contracts define — nothing
#: more, since this layer persists no attribution/likelihood/confidence
#: field, and none exists on these contracts to omit).
CORRELATION_LINKS_MAPPING: dict[str, Any] = {
    "link_id": {"type": "keyword"},
    "anchor_a": {"type": "keyword"},
    "anchor_b": {"type": "keyword"},
    "link_class": {"type": "keyword"},
    "schema_version": {"type": "keyword"},
    "basis": {
        "properties": {
            "link_class": {"type": "keyword"},
            "field_path": {"type": "keyword"},
            "observed_value": {"type": "keyword"},
            "observation_id_a": {"type": "keyword"},
            "observation_id_b": {"type": "keyword"},
            "uncertainty_note": {"type": "text"},
        }
    },
    "provenance": {
        "properties": {
            "method": {"type": "keyword"},
            "method_version": {"type": "keyword"},
            "source_evidence_ids": {"type": "keyword"},
            "source_observation_ids": {"type": "keyword"},
            "method_content_hash": {"type": "keyword"},
        }
    },
}

#: G2.3: explicit field mappings for the CorrelationGroup index — the entire
#: field set G2.0's ``CorrelationGroup`` contract defines (see that module's
#: docstring: group_id, member ids, link ids, provenance, schema_version —
#: deliberately no likelihood/confidence/APT-candidate field exists to map).
CORRELATION_GROUPS_MAPPING: dict[str, Any] = {
    "group_id": {"type": "keyword"},
    "member_evidence_ids": {"type": "keyword"},
    "member_observation_ids": {"type": "keyword"},
    "structural_link_ids": {"type": "keyword"},
    "contextual_link_ids": {"type": "keyword"},
    "schema_version": {"type": "keyword"},
    "provenance": {
        "properties": {
            "method": {"type": "keyword"},
            "method_version": {"type": "keyword"},
            "source_evidence_ids": {"type": "keyword"},
            "source_observation_ids": {"type": "keyword"},
            "method_content_hash": {"type": "keyword"},
        }
    },
}

#: G2.4.2: explicit field mappings for the BehavioralSequence index
#: (ADR-0004 D18 — one document per sequence, steps/edges/gaps/
#: parallel_groups all embedded). Mirrors CORRELATION_GROUPS_MAPPING's
#: convention: every top-level ``*_id``/schema-version field is ``keyword``,
#: ``provenance`` gets the same hand-typed ``properties`` block every other
#: index already uses for ``CorrelationProvenance``. ``steps``/``edges``/
#: ``gaps``/``parallel_groups`` are left as dynamic ``object`` (mirroring how
#: OBSERVATIONS_MAPPING leaves the larger, more variable entity groups
#: dynamic) — hand-curating every leaf of four new nested shapes is a
#: reasonable later refinement, not a G2.4.2 requirement; no
#: likelihood/confidence/APT-candidate field exists on the underlying
#: contracts to map.
BEHAVIORAL_SEQUENCES_MAPPING: dict[str, Any] = {
    "sequence_id": {"type": "keyword"},
    "group_id": {"type": "keyword"},
    "schema_version": {"type": "keyword"},
    "steps": {"type": "object"},
    "edges": {"type": "object"},
    "gaps": {"type": "object"},
    "parallel_groups": {"type": "object"},
    "provenance": {
        "properties": {
            "method": {"type": "keyword"},
            "method_version": {"type": "keyword"},
            "source_evidence_ids": {"type": "keyword"},
            "source_observation_ids": {"type": "keyword"},
            "method_content_hash": {"type": "keyword"},
        }
    },
}
