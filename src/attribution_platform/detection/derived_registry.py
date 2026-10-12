"""Every derived view set the rule engine can read (ADR-0015 D2).

A ``field_path`` whose first segment is a view-set namespace
(``elastic_sysmon.process.args``, ``elastic_cloudtrail.event.outcome``, …) is
resolved here; an unknown field of a known namespace is a hard error.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from attribution_platform.detection.derived_cloud import (
    AZURE_ACTIVITY_VIEWS,
    AZURE_AUDIT_VIEWS,
    AZURE_SIGNIN_VIEWS,
    CLOUDTRAIL_VIEWS,
    GITHUB_VIEWS,
    KUBERNETES_VIEWS,
    O365_VIEWS,
    OKTA_VIEWS,
)
from attribution_platform.detection.derived_fields import SYSMON_VIEWS
from attribution_platform.detection.derived_powershell import POWERSHELL_VIEWS
from attribution_platform.detection.derived_security import SECURITY_VIEWS
from attribution_platform.detection.derived_views import ViewSet
from attribution_platform.domain import Observation

VIEW_SETS: Mapping[str, ViewSet] = MappingProxyType(
    {
        views.namespace: views
        for views in (
            SYSMON_VIEWS,
            SECURITY_VIEWS,
            POWERSHELL_VIEWS,
            CLOUDTRAIL_VIEWS,
            O365_VIEWS,
            AZURE_AUDIT_VIEWS,
            AZURE_SIGNIN_VIEWS,
            AZURE_ACTIVITY_VIEWS,
            OKTA_VIEWS,
            GITHUB_VIEWS,
            KUBERNETES_VIEWS,
        )
    }
)


class UnknownDerivedField(LookupError):
    """A namespace is known but has no such field."""


def resolve_derived(observation: Observation, field_path: str) -> tuple[bool, Any]:
    """``(True, value)`` for a derived ``field_path``, else ``(False, None)``."""
    namespace, _, ecs_field = field_path.partition(".")
    views = VIEW_SETS.get(namespace)
    if views is None:
        return False, None
    try:
        return True, views.resolve(ecs_field, observation)
    except KeyError:
        raise UnknownDerivedField(field_path) from None


__all__ = ["VIEW_SETS", "UnknownDerivedField", "resolve_derived"]
