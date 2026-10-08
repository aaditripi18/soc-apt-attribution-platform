"""The GitHub audit-log SourceAdapter (ADR-0011 batch C).

One Observation per GitHub enterprise / organization audit-log event in the
export / streaming JSON form: ``@timestamp`` and ``created_at`` (milliseconds
since the Unix epoch), ``_document_id``, ``action``, ``actor``, ``org``,
``business``, ``repo``, … (webhook payloads are a different schema and are not
read).

**Event time:** ``@timestamp`` — integer epoch milliseconds, UTC by definition.

**Exact values:** the ``github`` group holds the event's fields as logged
(Sigma's ``github/audit`` rules read ``action``). ECS: ``user.name`` / ``user.id``
= ``actor`` / ``actor_id``; ``user_agent.original`` = ``user_agent``;
``event.action`` = ``action``. ``actor_ip`` is present only when the enterprise
enables IP disclosure; when it is an IP address it becomes ``network.source.ip``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    GitHubAuditRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    SourceRef,
    TimePrecision,
    UserAgentRef,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import epoch_millis_time, ip_or_none, scalar_text

GITHUB_SOURCE_TYPE = "github_audit"
GITHUB_DATASET = "github.audit"
_ADAPTER = "GitHubAuditSourceAdapter"


def is_github_audit_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is one GitHub audit-log event."""
    return all(key in record for key in ("@timestamp", "_document_id", "action"))


def _text(value: Any) -> str | None:
    return scalar_text(value, _ADAPTER)


class GitHubAuditSourceAdapter:
    """GitHub audit-log events -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return GITHUB_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_github_audit_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not a GitHub audit-log event")
        timestamp = epoch_millis_time(raw_record["@timestamp"], "@timestamp", _ADAPTER)
        document_id = _text(raw_record["_document_id"])
        if document_id is None:
            raise SourceAdapterError(f"{_ADAPTER}: _document_id is required")
        action = _text(raw_record["action"])
        github = GitHubAuditRef(
            document_id=document_id,
            action=action,
            operation_type=_text(raw_record.get("operation_type")),
            actor=_text(raw_record.get("actor")),
            actor_id=_text(raw_record.get("actor_id")),
            actor_is_bot=_text(raw_record.get("actor_is_bot")),
            user=_text(raw_record.get("user")),
            org=_text(raw_record.get("org")),
            org_id=_text(raw_record.get("org_id")),
            business=_text(raw_record.get("business")),
            business_id=_text(raw_record.get("business_id")),
            repo=_text(raw_record.get("repo")),
            visibility=_text(raw_record.get("visibility")),
        )
        agent = _text(raw_record.get("user_agent"))
        ip = ip_or_none(_text(raw_record.get("actor_ip")))
        observation_id = f"github:{document_id}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=TimePrecision.MILLISECOND,
                raw_reference=SourceRef(
                    source_type=GITHUB_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(kind="event", action=action, dataset=GITHUB_DATASET),
                user=(
                    UserRef(id=github.actor_id, name=github.actor)
                    if github.actor or github.actor_id
                    else None
                ),
                network=NetworkInfo(source=NetworkEndpoint(ip=ip)) if ip else None,
                user_agent=UserAgentRef(original=agent) if agent else None,
                github=github,
            ),
        )


__all__ = [
    "GITHUB_DATASET",
    "GITHUB_SOURCE_TYPE",
    "GitHubAuditSourceAdapter",
    "is_github_audit_record",
]
