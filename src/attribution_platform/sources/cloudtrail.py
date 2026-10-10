"""The AWS CloudTrail SourceAdapter (ADR-0011 batch B).

One Observation per CloudTrail record in CloudTrail's **native** JSON form (one
event object, as delivered to S3 inside ``Records`` or exported one per line):
``eventVersion``, ``eventTime``, ``eventSource``, ``eventName``, ``awsRegion``,
``userIdentity``, ``sourceIPAddress``, … Amazon Security Lake's OCSF form of the
same events is a different schema and is not read here (ADR-0011 D1).

**Event time:** ``eventTime`` (UTC, ``Z``-suffixed in every observed record); a
value without a zone is refused (D5).

**Exact values** (D2): the ``aws_cloudtrail`` group holds CloudTrail's own
fields and the nested values Sigma's ``aws/cloudtrail`` rules read, as logged.
ECS: ``cloud.provider`` = ``aws``, ``cloud.account.id`` = ``recipientAccountId``
(the account the event was delivered to), ``cloud.region`` = ``awsRegion``,
``cloud.service.name`` = ``eventSource``; ``event.action`` = ``eventName``,
``event.outcome`` = ``failure`` when ``errorCode`` is present (CloudTrail
records an error code only for a failed request), or a sign-in's own result
(``responseElements.ConsoleLogin`` ``Success`` / ``Failure``), otherwise absent —
success is not claimed from silence; ``user.id`` = ``userIdentity.principalId``,
``user.name`` = ``userIdentity.userName`` (only where CloudTrail states one);
``network.source.ip`` = ``sourceIPAddress`` only when it is an IP address (it is
often an AWS service name); ``user_agent.original`` = ``userAgent``. The
``requestParameters`` object is kept whole, as compact JSON text in logged key
order (ADR-0015).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from attribution_platform.domain import (
    AwsCloudTrailRef,
    CloudRef,
    EventMetadata,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    SourceRef,
    UserAgentRef,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import (
    at_path,
    ip_or_none,
    scalar_text,
    zoned_iso_time,
)

CLOUDTRAIL_SOURCE_TYPE = "aws_cloudtrail"
CLOUDTRAIL_DATASET = "aws.cloudtrail"
_ADAPTER = "CloudTrailSourceAdapter"
_REQUIRED = ("eventVersion", "eventTime", "eventSource", "eventName", "eventID")


def is_cloudtrail_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is one native CloudTrail event."""
    return all(key in record for key in _REQUIRED) and "class_uid" not in record


def _text(value: Any) -> str | None:
    return scalar_text(value, _ADAPTER)


def _at(record: Mapping[str, Any], *path: str) -> str | None:
    return at_path(record, path, _ADAPTER)


def _object_text(value: Any) -> str | None:
    """A JSON object exactly as logged: compact JSON text, key order kept. A
    record without the object (or with JSON ``null``) has none."""
    if not isinstance(value, Mapping):
        return None
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


class CloudTrailSourceAdapter:
    """Native CloudTrail records -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return CLOUDTRAIL_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_cloudtrail_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not a native CloudTrail record")
        timestamp, precision = zoned_iso_time(raw_record["eventTime"], "eventTime", _ADAPTER)
        event_id = _text(raw_record["eventID"])
        account = _text(raw_record.get("recipientAccountId"))
        if event_id is None or account is None:
            raise SourceAdapterError(f"{_ADAPTER}: eventID and recipientAccountId are required")
        event_source = _text(raw_record["eventSource"])
        event_name = _text(raw_record["eventName"])
        error_code = _text(raw_record.get("errorCode"))
        source_ip = _text(raw_record.get("sourceIPAddress"))
        agent = _text(raw_record.get("userAgent"))
        principal = _at(raw_record, "userIdentity", "principalId")
        user_name = _at(raw_record, "userIdentity", "userName")

        trail = AwsCloudTrailRef(
            event_id=event_id,
            event_source=event_source,
            event_name=event_name,
            event_type=_text(raw_record.get("eventType")),
            event_category=_text(raw_record.get("eventCategory")),
            error_code=error_code,
            error_message=_text(raw_record.get("errorMessage")),
            source_ip_address=source_ip,
            read_only=_text(raw_record.get("readOnly")),
            request_id=_text(raw_record.get("requestID")),
            shared_event_id=_text(raw_record.get("sharedEventID")),
            user_identity_type=_at(raw_record, "userIdentity", "type"),
            user_identity_arn=_at(raw_record, "userIdentity", "arn"),
            user_identity_principal_id=principal,
            user_identity_account_id=_at(raw_record, "userIdentity", "accountId"),
            user_identity_access_key_id=_at(raw_record, "userIdentity", "accessKeyId"),
            user_identity_invoked_by=_at(raw_record, "userIdentity", "invokedBy"),
            mfa_used=_at(raw_record, "additionalEventData", "MFAUsed"),
            console_login=_at(raw_record, "responseElements", "ConsoleLogin"),
            request_attribute=_at(raw_record, "requestParameters", "attribute"),
            request_enable=_at(raw_record, "requestParameters", "enable"),
            response_publicly_accessible=_at(raw_record, "responseElements", "publiclyAccessible"),
            response_pending_master_user_password=_at(
                raw_record, "responseElements", "pendingModifiedValues", "masterUserPassword"
            ),
            request_parameters=_object_text(raw_record.get("requestParameters")),
        )
        ip = ip_or_none(source_ip)
        observation_id = f"cloudtrail:{account}:{event_id}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=precision,
                raw_reference=SourceRef(
                    source_type=CLOUDTRAIL_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(
                    kind="event",
                    action=event_name,
                    outcome=(
                        "failure"
                        if error_code is not None
                        else {"Success": "success", "Failure": "failure"}.get(
                            trail.console_login or ""
                        )
                    ),
                    dataset=CLOUDTRAIL_DATASET,
                ),
                user=UserRef(id=principal, name=user_name) if principal or user_name else None,
                network=NetworkInfo(source=NetworkEndpoint(ip=ip)) if ip else None,
                cloud=CloudRef(
                    provider="aws",
                    account_id=account,
                    region=_text(raw_record.get("awsRegion")),
                    service_name=event_source,
                ),
                user_agent=UserAgentRef(original=agent) if agent else None,
                aws_cloudtrail=trail,
            ),
        )


__all__ = [
    "CLOUDTRAIL_DATASET",
    "CLOUDTRAIL_SOURCE_TYPE",
    "CloudTrailSourceAdapter",
    "is_cloudtrail_record",
]
