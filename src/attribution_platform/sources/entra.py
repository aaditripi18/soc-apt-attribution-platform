"""The Microsoft Entra ID SourceAdapter (ADR-0011 batch A).

One Observation per Entra ID record from an **Azure Monitor diagnostic-setting
export** (Event Hub / storage account): a JSON object with the common top-level
fields (``time``, ``resourceId`` under ``/providers/Microsoft.aadiam``,
``operationName``, ``category``, ``tenantId``, ``resultType``, ``callerIpAddress``,
``correlationId``) and the category's record in ``properties``.

**Supported categories** (Sigma ``azure/*`` logsource → ``event.dataset``,
Elastic's own data-stream names):

- ``SignInLogs``, ``NonInteractiveUserSignInLogs``, ``ServicePrincipalSignInLogs``,
  ``ManagedIdentitySignInLogs`` → ``azure.signinlogs``; event time
  ``properties.createdDateTime`` (Graph *signIn*: when the sign-in was initiated).
- ``AuditLogs`` → ``azure.auditlogs``; event time ``properties.activityDateTime``.
- ``UserRiskEvents``, ``ServicePrincipalRiskEvents`` → ``azure.identity_protection``
  (Sigma ``azure/riskdetection``); event time ``properties.activityDateTime``
  (when the risky activity happened, not when it was detected).

Any other category (Graph activity, risky-user state, provisioning, …) has no
imported Sigma logsource and is refused, counted by the caller. An event time
without a zone is refused (ADR-0011 D5) — never assumed UTC.

**Exact values** (ADR-0011 D2): every field is copied as logged into the ``entra``
group; JSON booleans become ``"true"`` / ``"false"``. ECS fields are filled only
where the value means the same thing: ``user`` (the signed-in user, the audit
initiator or the at-risk user: object id and UPN), ``network.source.ip``
(``callerIpAddress``, when it is an IP address), ``user_agent.original`` (``properties.userAgent``),
``cloud.provider`` = ``azure`` and ``cloud.account.id`` = ``tenantId``,
``event.action`` = ``operationName``, and ``event.outcome`` where Microsoft defines
it (sign-in ``resultType`` ``0`` = success, otherwise failure; audit
``properties.result``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attribution_platform.domain import (
    CloudRef,
    EntraRef,
    EventMetadata,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    SourceRef,
    UserAgentRef,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import ip_or_none, scalar_text, zoned_iso_time

ENTRA_SOURCE_TYPE = "entra_id"
_ADAPTER = "EntraIdSourceAdapter"
_SIGN_IN = "azure.signinlogs"
_AUDIT = "azure.auditlogs"
_RISK = "azure.identity_protection"
#: diagnostic ``category`` -> (``event.dataset``, the ``properties`` event-time field).
CATEGORIES: Mapping[str, tuple[str, str]] = {
    "SignInLogs": (_SIGN_IN, "createdDateTime"),
    "NonInteractiveUserSignInLogs": (_SIGN_IN, "createdDateTime"),
    "ServicePrincipalSignInLogs": (_SIGN_IN, "createdDateTime"),
    "ManagedIdentitySignInLogs": (_SIGN_IN, "createdDateTime"),
    "AuditLogs": (_AUDIT, "activityDateTime"),
    "UserRiskEvents": (_RISK, "activityDateTime"),
    "ServicePrincipalRiskEvents": (_RISK, "activityDateTime"),
}


def is_entra_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is an Entra ID diagnostic-export record (any category)."""
    resource = record.get("resourceId")
    return (
        isinstance(resource, str)
        and "/providers/microsoft.aadiam" in resource.casefold()
        and "category" in record
        and "operationName" in record
        and isinstance(record.get("properties"), Mapping)
    )


def _text(value: Any) -> str | None:
    return scalar_text(value, _ADAPTER)


class EntraIdSourceAdapter:
    """Entra ID diagnostic-export records -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return ENTRA_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_entra_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not an Entra ID diagnostic-export record")
        category = raw_record["category"]
        if category not in CATEGORIES:
            raise SourceAdapterError(f"{_ADAPTER}: category {category!r} is not supported")
        dataset, time_field = CATEGORIES[category]
        props: Mapping[str, Any] = raw_record["properties"]
        timestamp, precision = zoned_iso_time(
            props.get(time_field), f"properties.{time_field}", _ADAPTER
        )
        tenant = _text(raw_record.get("tenantId"))
        record_id = _text(props.get("id"))
        if tenant is None or record_id is None:
            raise SourceAdapterError(f"{_ADAPTER}: tenantId and properties.id are required")
        operation = _text(raw_record.get("operationName"))
        result_type = _text(raw_record.get("resultType"))

        outcome: str | None = None
        user: UserRef | None = None
        if dataset == _SIGN_IN:
            if result_type is not None:
                outcome = "success" if result_type == "0" else "failure"
            if props.get("userId") or props.get("userPrincipalName"):
                user = UserRef(
                    id=_text(props.get("userId")), name=_text(props.get("userPrincipalName"))
                )
        elif dataset == _AUDIT:
            result = _text(props.get("result"))
            outcome = result if result in ("success", "failure") else None
            initiated = props.get("initiatedBy")
            actor = initiated.get("user") if isinstance(initiated, Mapping) else None
            if isinstance(actor, Mapping) and (actor.get("id") or actor.get("userPrincipalName")):
                user = UserRef(
                    id=_text(actor.get("id")), name=_text(actor.get("userPrincipalName"))
                )
        elif props.get("userId") or props.get("userPrincipalName"):
            user = UserRef(
                id=_text(props.get("userId")), name=_text(props.get("userPrincipalName"))
            )

        device = props.get("deviceDetail")
        entra = EntraRef(
            log_category=category,
            operation_name=operation,
            record_id=record_id,
            correlation_id=_text(raw_record.get("correlationId")),
            result_type=result_type,
            result_description=_text(raw_record.get("resultDescription")),
            result=_text(props.get("result")),
            audit_category=_text(props.get("category")) if dataset == _AUDIT else None,
            activity_display_name=_text(props.get("activityDisplayName")),
            logged_by_service=_text(props.get("loggedByService")),
            operation_type=_text(props.get("operationType")),
            authentication_requirement=_text(props.get("authenticationRequirement")),
            conditional_access_status=_text(props.get("conditionalAccessStatus")),
            client_app_used=_text(props.get("clientAppUsed")),
            app_id=_text(props.get("appId")),
            app_display_name=_text(props.get("appDisplayName")),
            resource_display_name=_text(props.get("resourceDisplayName")),
            home_tenant_id=_text(props.get("homeTenantId")),
            resource_tenant_id=_text(props.get("resourceTenantId")),
            device_is_compliant=(
                _text(device.get("isCompliant")) if isinstance(device, Mapping) else None
            ),
            risk_state=_text(props.get("riskState")),
            risk_level=_text(props.get("riskLevel")),
            risk_detail=_text(props.get("riskDetail")),
            risk_event_type=_text(props.get("riskEventType")),
        )
        caller_ip = ip_or_none(_text(raw_record.get("callerIpAddress")))
        agent = _text(props.get("userAgent"))
        observation_id = f"entra:{tenant}:{category}:{record_id}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(
                    source_type=ENTRA_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(
                    kind="event", action=operation, outcome=outcome, dataset=dataset
                ),
                user=user,
                network=(NetworkInfo(source=NetworkEndpoint(ip=caller_ip)) if caller_ip else None),
                cloud=CloudRef(provider="azure", account_id=tenant),
                user_agent=UserAgentRef(original=agent) if agent else None,
                entra=entra,
            ),
        )


__all__ = ["CATEGORIES", "ENTRA_SOURCE_TYPE", "EntraIdSourceAdapter", "is_entra_record"]
