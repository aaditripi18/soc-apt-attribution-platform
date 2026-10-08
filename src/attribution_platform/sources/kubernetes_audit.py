"""The Kubernetes API-server audit SourceAdapter (ADR-0011 batch C).

One Observation per audit **event** (``apiVersion`` ``audit.k8s.io/v1``,
``kind`` ``Event``): one request produces one event per stage it reaches
(``RequestReceived``, ``ResponseStarted``, ``ResponseComplete``, ``Panic``), all
sharing its ``auditID``. The Observation id is ``auditID`` + ``stage``.

**Event time:** ``requestReceivedTimestamp`` (when the API server received the
request — the time of the behaviour, identical across its stages), ISO 8601
with a zone; without one it is refused.

**Exact values:** the ``kubernetes_audit`` group holds the fields Sigma's
``kubernetes`` rules read (``verb``, ``requestURI``, ``objectRef.*``,
``responseStatus.code``), as logged. ECS: ``user.name`` = ``user.username``;
``network.source.ip`` = ``sourceIPs[0]`` (the API documents the list as starting
with the originating client) when it is an IP address; ``user_agent.original``
= ``userAgent``; ``event.action`` = ``verb``. The event names no cluster, so no
host or ``cloud`` group is set (none is invented).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    KubernetesAuditRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    SourceRef,
    UserAgentRef,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import at_path, ip_or_none, zoned_iso_time

KUBERNETES_AUDIT_SOURCE_TYPE = "kubernetes_audit"
KUBERNETES_AUDIT_DATASET = "kubernetes.audit_logs"
_ADAPTER = "KubernetesAuditSourceAdapter"


def is_kubernetes_audit_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is one ``audit.k8s.io`` audit event."""
    return (
        record.get("kind") == "Event"
        and str(record.get("apiVersion", "")).startswith("audit.k8s.io/")
        and "auditID" in record
    )


def _at(record: Mapping[str, Any], *path: str) -> str | None:
    return at_path(record, path, _ADAPTER)


class KubernetesAuditSourceAdapter:
    """Kubernetes audit events -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return KUBERNETES_AUDIT_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_kubernetes_audit_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not a Kubernetes audit event")
        timestamp, precision = zoned_iso_time(
            raw_record.get("requestReceivedTimestamp"), "requestReceivedTimestamp", _ADAPTER
        )
        audit_id, stage = _at(raw_record, "auditID"), _at(raw_record, "stage")
        if audit_id is None or stage is None:
            raise SourceAdapterError(f"{_ADAPTER}: auditID and stage are required")
        verb = _at(raw_record, "verb")
        audit = KubernetesAuditRef(
            audit_id=audit_id,
            stage=stage,
            level=_at(raw_record, "level"),
            verb=verb,
            request_uri=_at(raw_record, "requestURI"),
            response_code=_at(raw_record, "responseStatus", "code"),
            response_status=_at(raw_record, "responseStatus", "status"),
            response_reason=_at(raw_record, "responseStatus", "reason"),
            object_resource=_at(raw_record, "objectRef", "resource"),
            object_subresource=_at(raw_record, "objectRef", "subresource"),
            object_namespace=_at(raw_record, "objectRef", "namespace"),
            object_name=_at(raw_record, "objectRef", "name"),
            object_api_group=_at(raw_record, "objectRef", "apiGroup"),
            object_api_version=_at(raw_record, "objectRef", "apiVersion"),
            authorization_decision=_at(raw_record, "annotations", "authorization.k8s.io/decision"),
        )
        source_ips = raw_record.get("sourceIPs")
        first_ip = (
            ip_or_none(source_ips[0])
            if isinstance(source_ips, list) and source_ips and isinstance(source_ips[0], str)
            else None
        )
        username = _at(raw_record, "user", "username")
        agent = _at(raw_record, "userAgent")
        observation_id = f"k8s-audit:{audit_id}:{stage}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(
                    source_type=KUBERNETES_AUDIT_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(kind="event", action=verb, dataset=KUBERNETES_AUDIT_DATASET),
                user=UserRef(name=username) if username else None,
                network=NetworkInfo(source=NetworkEndpoint(ip=first_ip)) if first_ip else None,
                user_agent=UserAgentRef(original=agent) if agent else None,
                kubernetes_audit=audit,
            ),
        )


__all__ = [
    "KUBERNETES_AUDIT_DATASET",
    "KUBERNETES_AUDIT_SOURCE_TYPE",
    "KubernetesAuditSourceAdapter",
    "is_kubernetes_audit_record",
]
