"""Derived ECS views for cloud / SaaS audit streams (ADR-0015 D2).

Each view set reproduces, from this platform's Observation of one audit record,
the fields Elastic's integration pipeline for that data stream produces — pinned
to ``elastic/integrations`` commit ``ff5328128a30`` and checked field by field
against that integration's own pipeline test fixtures
(``tests/test_elastic_cloud_conformance.py``). Only fields whose pipeline value
follows from what the adapter keeps *exactly as logged* are offered; anything
else (GeoIP / ASN enrichment, flattened request bodies the adapter does not
keep, parsed user-agent parts) is absent from the view set, so a rule branch
reading it is reported as a gap rather than approximated.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from importlib.resources import files
from types import MappingProxyType
from typing import Any

from attribution_platform.detection.derived_json import flattened_leaves, java_to_string
from attribution_platform.detection.derived_views import (
    UNDETERMINED,
    ViewSet,
    attr,
    build_view_set,
)
from attribution_platform.domain import Observation


def _table(name: str) -> Mapping[str, Any]:
    """A lookup table extracted from Elastic's pinned pipeline
    (``scripts/extract_elastic_pipeline_tables.py``)."""
    text = (
        files("attribution_platform.detection")
        .joinpath(f"pipeline_tables/{name}")
        .read_text(encoding="utf-8")
    )
    return MappingProxyType(json.loads(text))


# ---------------------------------------------------------------------------
# AWS CloudTrail (packages/aws/data_stream/cloudtrail)
# ---------------------------------------------------------------------------


#: ``script_remove_nulls_before_renames``: the pipeline's first step drops, from
#: the whole record, ``null``, these scalar strings, and containers left empty.
_CLOUDTRAIL_REMOVED = frozenset({"", "-", "none"})


def _trail(obs: Observation, name: str) -> Any:
    value = attr(obs, "aws_cloudtrail", name)
    return None if value in _CLOUDTRAIL_REMOVED else value


def _user_agent(obs: Observation) -> str | None:
    value = attr(obs, "user_agent", "original")
    return None if value in _CLOUDTRAIL_REMOVED else value


def _cloudtrail_outcome(obs: Observation) -> str | None:
    """``failure`` when the record has an error code or message, else ``success``;
    a ``ConsoleLogin`` takes its own ``responseElements.ConsoleLogin``, lower-cased."""
    if attr(obs, "aws_cloudtrail") is None:
        return None
    outcome = (
        "failure"
        if _trail(obs, "error_code") is not None or _trail(obs, "error_message") is not None
        else "success"
    )
    console_login = _trail(obs, "console_login")
    if _trail(obs, "event_name") == "ConsoleLogin" and console_login is not None:
        outcome = str(console_login).lower()
    return outcome


#: ``script_add_ecs_categorization``: event name -> ``event.category`` / ``event.type``.
_CLOUDTRAIL_CATEGORIZATION = _table("cloudtrail_categorization.json")
#: A flattened copy is kept only while the object's string form is shorter than this.
_FLATTENED_LIMIT = 32766


def _cloudtrail_category(obs: Observation, key: str) -> tuple[str, ...] | None:
    """The pipeline sets ``event.type = [info]`` for every record, then overlays
    the table entry of the event name (``event.category`` only comes from it)."""
    if attr(obs, "aws_cloudtrail") is None:
        return None
    entry = _CLOUDTRAIL_CATEGORIZATION.get(str(_trail(obs, "event_name")))
    if entry is not None and key in entry:
        return tuple(entry[key])
    return ("info",) if key == "type" else None


def _request_parameters(obs: Observation) -> str | None:
    return java_to_string(attr(obs, "aws_cloudtrail", "request_parameters"), _CLOUDTRAIL_REMOVED)


def _request_parameters_flattened(obs: Observation, sub_path: str) -> tuple[str, ...] | None:
    rendered = _request_parameters(obs)
    if rendered is None or len(rendered) >= _FLATTENED_LIMIT:
        return None
    return flattened_leaves(
        attr(obs, "aws_cloudtrail", "request_parameters"), sub_path, _CLOUDTRAIL_REMOVED
    )


def _cloudtrail_account(obs: Observation) -> str | None:
    """``userIdentity.accountId`` when the record has one, else
    ``recipientAccountId`` (the pipeline renames the first into
    ``cloud.account.id`` and copies the second only into an empty field)."""
    if attr(obs, "aws_cloudtrail") is None:
        return None
    acting = _trail(obs, "user_identity_account_id")
    return str(acting) if acting is not None else attr(obs, "cloud", "account_id")


def _cloudtrail_user_id(obs: Observation) -> Any:
    """``userIdentity.principalId``. For an ``IdentityCenterUser`` without one the
    pipeline falls back to ``onBehalfOf.userId``, which the adapter does not keep."""
    if attr(obs, "aws_cloudtrail") is None:
        return None
    principal = _trail(obs, "user_identity_principal_id")
    if principal is None and _trail(obs, "user_identity_type") == "IdentityCenterUser":
        return UNDETERMINED
    return principal


CLOUDTRAIL_VIEWS: ViewSet = build_view_set(
    "elastic_cloudtrail",
    {
        "cloud.account.id": _cloudtrail_account,
        "user.id": _cloudtrail_user_id,
        "event.category": lambda o: _cloudtrail_category(o, "category"),
        "event.type": lambda o: _cloudtrail_category(o, "type"),
        "aws.cloudtrail.request_parameters": _request_parameters,
        "event.action": lambda o: _trail(o, "event_name"),
        "event.provider": lambda o: _trail(o, "event_source"),
        "event.outcome": _cloudtrail_outcome,
        "source.address": lambda o: _trail(o, "source_ip_address"),
        "user_agent.original": _user_agent,
        "aws.cloudtrail.error_code": lambda o: _trail(o, "error_code"),
        "aws.cloudtrail.error_message": lambda o: _trail(o, "error_message"),
        "aws.cloudtrail.event_type": lambda o: _trail(o, "event_type"),
        "aws.cloudtrail.event_category": lambda o: _trail(o, "event_category"),
        "aws.cloudtrail.user_identity.type": lambda o: _trail(o, "user_identity_type"),
        "aws.cloudtrail.user_identity.arn": lambda o: _trail(o, "user_identity_arn"),
        "aws.cloudtrail.user_identity.access_key_id": lambda o: _trail(
            o, "user_identity_access_key_id"
        ),
        "aws.cloudtrail.user_identity.invoked_by": lambda o: _trail(o, "user_identity_invoked_by"),
    },
    arrays=frozenset({"event.category", "event.type"}),
    ignore_above={"aws.cloudtrail.request_parameters": 8191},
    dynamic={"aws.cloudtrail.flattened.request_parameters.": _request_parameters_flattened},
)

# ---------------------------------------------------------------------------
# Microsoft 365 unified audit log (packages/o365/data_stream/audit)
# ---------------------------------------------------------------------------

#: ``RecordType`` -> ``event.code`` (the audit schema's name).
_O365_RECORD_TYPES = _table("o365_record_types.json")
#: The operations the pipeline renames, per audit schema (``event.code``).
_O365_RENAMED_ACTIONS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        "AzureActiveDirectory": {
            "Add user.": "added-user-account",
            "Update user.": "modified-user-account",
            "Delete user.": "deleted-user-account",
        },
        "MicrosoftTeams": {
            "TeamCreated": "added-group-account-to",
            "MemberAdded": "added-users-to-group",
            "Delete user.": "deleted-user-account",
        },
    }
)
#: For the DLP schemas the pipeline recomputes ``event.outcome`` from the record's
#: ``PolicyDetails`` (DLP rule actions) and reworks the operation; the adapter
#: does not keep those details, so both are undetermined for these records.
_O365_DLP_CODES = frozenset({"ComplianceDLPSharePoint", "ComplianceDLPExchange"})


def _o365(obs: Observation, name: str) -> Any:
    return attr(obs, "o365", name)


def _o365_code(obs: Observation) -> str | None:
    record_type = _o365(obs, "record_type")
    if record_type is None:
        return None
    code = _O365_RECORD_TYPES.get(str(record_type))
    return None if code is None else str(code)


def _o365_action(obs: Observation) -> Any:
    operation = _o365(obs, "operation")
    if operation is None:
        return None
    code = _o365_code(obs)
    if code in _O365_DLP_CODES:
        return UNDETERMINED
    return _O365_RENAMED_ACTIONS.get(str(code), {}).get(str(operation), str(operation))


def _o365_outcome(obs: Observation) -> Any:
    """``ResultStatus`` decides (case-insensitively); anything else is ``success``."""
    if attr(obs, "o365") is None:
        return None
    if _o365_code(obs) in _O365_DLP_CODES:
        return UNDETERMINED
    status = _o365(obs, "result_status")
    if status is not None and str(status).lower() in ("failed", "false"):
        return "failure"
    return "success"


O365_VIEWS: ViewSet = build_view_set(
    "elastic_o365",
    {
        "event.action": _o365_action,
        "event.provider": lambda o: _o365(o, "workload"),
        "event.code": _o365_code,
        "event.outcome": _o365_outcome,
        "o365.audit.ApplicationId": lambda o: _o365(o, "application_id"),
    },
)

# ---------------------------------------------------------------------------
# Microsoft Entra ID via Azure Monitor (packages/azure): audit logs, sign-in logs
# (Azure activity logs are not offered: the adapter reads the REST API record
# shape, Elastic's pipeline the diagnostic-export shape, so nothing can be checked.)
# ---------------------------------------------------------------------------


def _lower_if(value: Any, allowed: tuple[str, ...]) -> str | None:
    """``value`` lower-cased when it is one of ``allowed`` (case-insensitively)."""
    if isinstance(value, str) and value.lower() in allowed:
        return value.lower()
    return None


AZURE_AUDIT_VIEWS: ViewSet = build_view_set(
    "elastic_azure_audit",
    {
        "azure.auditlogs.operation_name": lambda o: attr(o, "entra", "operation_name"),
        "event.action": lambda o: attr(o, "entra", "operation_name"),
        "event.outcome": lambda o: _lower_if(attr(o, "entra", "result"), ("success", "failure")),
        "azure.auditlogs.properties.category": lambda o: attr(o, "entra", "audit_category"),
    },
)


def _signin_outcome(obs: Observation) -> Any:
    """``success`` when the sign-in's error code is 0 (or absent), ``failure`` when
    it is positive. The adapter keeps the record's ``resultType``, which Azure
    Monitor documents as that same error code; a non-numeric one is undetermined."""
    if attr(obs, "entra") is None:
        return None
    code = attr(obs, "entra", "result_type")
    if code is None:
        return UNDETERMINED
    if not str(code).isdigit():
        return UNDETERMINED
    return "success" if int(str(code)) == 0 else "failure"


AZURE_SIGNIN_VIEWS: ViewSet = build_view_set(
    "elastic_azure_signin",
    {
        "event.action": lambda o: attr(o, "entra", "operation_name"),
        "event.outcome": _signin_outcome,
        "azure.signinlogs.properties.app_id": lambda o: attr(o, "entra", "app_id"),
        "azure.signinlogs.properties.app_display_name": lambda o: attr(
            o, "entra", "app_display_name"
        ),
        "azure.signinlogs.properties.resource_display_name": lambda o: attr(
            o, "entra", "resource_display_name"
        ),
        "azure.signinlogs.properties.risk_state": lambda o: attr(o, "entra", "risk_state"),
    },
)

# ---------------------------------------------------------------------------
# Okta System Log (packages/okta/data_stream/system)
# ---------------------------------------------------------------------------


def _okta(obs: Observation, name: str) -> Any:
    return attr(obs, "okta", name)


def _okta_outcome(obs: Observation) -> str | None:
    """``success`` / ``allow`` -> success, ``failure`` / ``deny`` -> failure
    (case-insensitively); any other record is ``unknown``."""
    if attr(obs, "okta") is None:
        return None
    result = _okta(obs, "outcome_result")
    lowered = str(result).lower() if result is not None else None
    if lowered in ("success", "allow"):
        return "success"
    if lowered in ("failure", "deny"):
        return "failure"
    return "unknown"


OKTA_VIEWS: ViewSet = build_view_set(
    "elastic_okta",
    {
        "event.action": lambda o: _okta(o, "event_type"),
        "okta.event_type": lambda o: _okta(o, "event_type"),
        "event.outcome": _okta_outcome,
        "okta.outcome.result": lambda o: _okta(o, "outcome_result"),
        "okta.outcome.reason": lambda o: _okta(o, "outcome_reason"),
        "okta.display_message": lambda o: _okta(o, "display_message"),
        "okta.actor.id": lambda o: _okta(o, "actor_id"),
        "okta.actor.type": lambda o: _okta(o, "actor_type"),
        "okta.actor.alternate_id": lambda o: _okta(o, "actor_alternate_id"),
        "okta.actor.display_name": lambda o: _okta(o, "actor_display_name"),
    },
)

# ---------------------------------------------------------------------------
# GitHub audit log (packages/github/data_stream/audit)
# ---------------------------------------------------------------------------

_GITHUB_CATEGORY = re.compile(r"^([a-z_]+)\.")


def _github(obs: Observation, name: str) -> Any:
    return attr(obs, "github", name)


def _github_category(obs: Observation) -> str | None:
    """The pipeline's grok: the ``[a-z_]+`` prefix of the action before its first dot."""
    action = _github(obs, "action")
    match = _GITHUB_CATEGORY.match(str(action)) if action is not None else None
    return match.group(1) if match else None


def _github_event_category(obs: Observation) -> tuple[str, ...] | None:
    """``[configuration, web]`` for every record, plus ``iam`` for ``team`` / ``org``."""
    if attr(obs, "github") is None:
        return None
    base = ("configuration", "web")
    return (*base, "iam") if _github_category(obs) in ("team", "org") else base


def _github_event_type(obs: Observation) -> tuple[str, ...] | None:
    """``group, user`` for ``team`` / ``org``; ``creation`` / ``deletion`` by the
    words in the action after its category; ``change`` when nothing else applies."""
    if attr(obs, "github") is None:
        return None
    types: list[str] = []
    category = _github_category(obs)
    if category in ("team", "org"):
        types += ["group", "user"]
    rest = str(_github(obs, "action"))[len(category) + 1 :] if category is not None else None
    if rest is not None and ("create" in rest or "add" in rest):
        types.append("creation")
    if rest is not None and ("delete" in rest or "remove" in rest):
        types.append("deletion")
    return tuple(types) if types else ("change",)


GITHUB_VIEWS: ViewSet = build_view_set(
    "elastic_github",
    {
        "event.category": _github_event_category,
        "event.type": _github_event_type,
        "event.action": lambda o: _github(o, "action"),
        "github.category": _github_category,
        "github.operation_type": lambda o: _github(o, "operation_type"),
        "github.visibility": lambda o: _github(o, "visibility"),
        "github.repo": lambda o: _github(o, "repo"),
        "github.org": lambda o: _github(o, "org"),
    },
    arrays=frozenset({"event.category", "event.type"}),
)

# ---------------------------------------------------------------------------
# Kubernetes audit log (packages/kubernetes/data_stream/audit_logs)
# ---------------------------------------------------------------------------


def _k8s(obs: Observation, name: str) -> Any:
    return attr(obs, "kubernetes_audit", name)


def _k8s_outcome(obs: Observation) -> str | None:
    """Set only from the ``authorization.k8s.io/decision`` annotation."""
    return {"allow": "success", "forbid": "failure"}.get(str(_k8s(obs, "authorization_decision")))


def _k8s_user(obs: Observation) -> str | None:
    return attr(obs, "user", "name") if attr(obs, "kubernetes_audit") is not None else None


KUBERNETES_VIEWS: ViewSet = build_view_set(
    "elastic_kubernetes",
    {
        "event.action": lambda o: _k8s(o, "verb"),
        "event.outcome": _k8s_outcome,
        "user.name": _k8s_user,
        "kubernetes.audit.user.username": _k8s_user,
        "user_agent.original": lambda o: (
            attr(o, "user_agent", "original") if attr(o, "kubernetes_audit") else None
        ),
        "kubernetes.audit.verb": lambda o: _k8s(o, "verb"),
        "kubernetes.audit.stage": lambda o: _k8s(o, "stage"),
        "kubernetes.audit.level": lambda o: _k8s(o, "level"),
        "kubernetes.audit.requestURI": lambda o: _k8s(o, "request_uri"),
        "kubernetes.audit.objectRef.resource": lambda o: _k8s(o, "object_resource"),
        "kubernetes.audit.objectRef.subresource": lambda o: _k8s(o, "object_subresource"),
        "kubernetes.audit.objectRef.namespace": lambda o: _k8s(o, "object_namespace"),
        "kubernetes.audit.objectRef.name": lambda o: _k8s(o, "object_name"),
        "kubernetes.audit.objectRef.apiGroup": lambda o: _k8s(o, "object_api_group"),
        "kubernetes.audit.objectRef.apiVersion": lambda o: _k8s(o, "object_api_version"),
        "kubernetes.audit.annotations.authorization_k8s_io/decision": lambda o: _k8s(
            o, "authorization_decision"
        ),
    },
)

# ---------------------------------------------------------------------------
# Azure Activity Log, diagnostic export (packages/azure/data_stream/activitylogs)
# ---------------------------------------------------------------------------

#: ``category`` (lower-cased) -> ``event.type``, the pipeline's own table.
_ACTIVITY_EVENT_TYPE: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {"write": ("change",), "read": ("access",), "delete": ("deletion",), "action": ("change",)}
)


def _activity(obs: Observation, name: str) -> Any:
    """A field of an exported Activity Log event. Elastic's integration reads
    only that layout: for the REST form of the same log (same dataset here) what
    its pipeline would produce is unknown, so every view is undetermined."""
    if attr(obs, "azure_activity") is None:
        return None
    if obs.raw_reference.source_type != "azure_activity_export":
        return UNDETERMINED
    return attr(obs, "azure_activity", name)


def _activity_outcome(obs: Observation) -> Any:
    """``resultType`` as logged when it is success / failure in any case; else
    ``properties.result`` when it is exactly success / failure / unknown."""
    result_type = _activity(obs, "result_type")
    if result_type is UNDETERMINED:
        return UNDETERMINED
    if result_type is not None and str(result_type).lower() in ("success", "failure"):
        return result_type
    fallback = _activity(obs, "properties_result")
    return fallback if fallback in ("success", "failure", "unknown") else None


def _activity_type(obs: Observation) -> Any:
    category = _activity(obs, "category")
    if category is None or category is UNDETERMINED:
        return category
    return _ACTIVITY_EVENT_TYPE.get(str(category).lower())


AZURE_ACTIVITY_VIEWS: ViewSet = build_view_set(
    "elastic_azure_activity",
    {
        "azure.activitylogs.operation_name": lambda o: _activity(o, "operation_name"),
        "event.action": lambda o: _activity(o, "operation_name"),
        "azure.activitylogs.result_type": lambda o: _activity(o, "result_type"),
        "azure.activitylogs.category": lambda o: _activity(o, "category"),
        "event.outcome": _activity_outcome,
        "event.type": _activity_type,
    },
    arrays=frozenset({"event.type"}),
)


__all__ = [
    "AZURE_ACTIVITY_VIEWS",
    "AZURE_AUDIT_VIEWS",
    "AZURE_SIGNIN_VIEWS",
    "CLOUDTRAIL_VIEWS",
    "GITHUB_VIEWS",
    "KUBERNETES_VIEWS",
    "O365_VIEWS",
    "OKTA_VIEWS",
]
