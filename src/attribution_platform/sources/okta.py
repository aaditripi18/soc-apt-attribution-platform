"""The Okta System Log SourceAdapter (ADR-0011 batch C).

One Observation per Okta System Log event (the ``/api/v1/logs`` JSON object:
``uuid``, ``published``, ``eventType``, ``legacyEventType``, ``displayMessage``,
``actor``, ``client``, ``outcome``, ``securityContext``, ``debugContext``, …).

**Event time:** ``published`` (ISO 8601, ``Z``); without a zone it is refused.

**Exact values:** the ``okta`` group holds the fields Sigma's ``okta/okta`` rules
read, as logged. ECS: ``user.id`` / ``user.name`` = ``actor.id`` /
``actor.alternateId`` when the actor is a ``User``; ``network.source.ip`` =
``client.ipAddress`` when it is an IP address; ``user_agent.original`` =
``client.userAgent.rawUserAgent``; ``event.action`` = ``eventType``;
``event.outcome`` = ``success`` / ``failure`` for Okta's ``SUCCESS`` / ``FAILURE``
(other results — ``ALLOW``, ``DENY``, ``CHALLENGE``, ``UNKNOWN`` — are kept in
``okta.outcome_result`` only). The event names no Okta org, so no ``cloud``
group is set (none is invented).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    OktaRef,
    SourceRef,
    UserAgentRef,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import at_path, ip_or_none, zoned_iso_time

OKTA_SOURCE_TYPE = "okta_system_log"
OKTA_DATASET = "okta.system"
_ADAPTER = "OktaSourceAdapter"
_OUTCOMES = {"SUCCESS": "success", "FAILURE": "failure"}


def is_okta_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is one Okta System Log event."""
    return all(key in record for key in ("uuid", "published", "eventType", "actor"))


def _at(record: Mapping[str, Any], *path: str) -> str | None:
    return at_path(record, path, _ADAPTER)


class OktaSourceAdapter:
    """Okta System Log events -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return OKTA_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_okta_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not an Okta System Log event")
        timestamp, precision = zoned_iso_time(raw_record["published"], "published", _ADAPTER)
        uuid = _at(raw_record, "uuid")
        if uuid is None:
            raise SourceAdapterError(f"{_ADAPTER}: uuid is required")
        event_type = _at(raw_record, "eventType")
        result = _at(raw_record, "outcome", "result")
        okta = OktaRef(
            uuid=uuid,
            event_type=event_type,
            legacy_event_type=_at(raw_record, "legacyEventType"),
            display_message=_at(raw_record, "displayMessage"),
            severity=_at(raw_record, "severity"),
            outcome_result=result,
            outcome_reason=_at(raw_record, "outcome", "reason"),
            actor_id=_at(raw_record, "actor", "id"),
            actor_type=_at(raw_record, "actor", "type"),
            actor_alternate_id=_at(raw_record, "actor", "alternateId"),
            actor_display_name=_at(raw_record, "actor", "displayName"),
            transaction_id=_at(raw_record, "transaction", "id"),
            external_session_id=_at(raw_record, "authenticationContext", "externalSessionId"),
            security_is_proxy=_at(raw_record, "securityContext", "isProxy"),
            debug_behaviors=_at(raw_record, "debugContext", "debugData", "behaviors"),
            debug_log_only_security_data=_at(
                raw_record, "debugContext", "debugData", "logOnlySecurityData"
            ),
        )
        user = (
            UserRef(id=okta.actor_id, name=okta.actor_alternate_id)
            if okta.actor_type == "User"
            else None
        )
        ip = ip_or_none(_at(raw_record, "client", "ipAddress"))
        agent = _at(raw_record, "client", "userAgent", "rawUserAgent")
        observation_id = f"okta:{uuid}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(
                    source_type=OKTA_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(
                    kind="event",
                    action=event_type,
                    outcome=_OUTCOMES.get(result or ""),
                    dataset=OKTA_DATASET,
                ),
                user=user,
                network=NetworkInfo(source=NetworkEndpoint(ip=ip)) if ip else None,
                user_agent=UserAgentRef(original=agent) if agent else None,
                okta=okta,
            ),
        )


__all__ = ["OKTA_DATASET", "OKTA_SOURCE_TYPE", "OktaSourceAdapter", "is_okta_record"]
