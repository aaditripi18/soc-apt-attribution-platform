"""ADR-0015 Amendment D: Activity Log events in the diagnostic-export layout.
Elastic's Azure rules read only that layout, so they fire on it and never on the
REST form of the same log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection.derived_cloud import AZURE_ACTIVITY_VIEWS
from attribution_platform.detection.derived_views import UNDETERMINED
from attribution_platform.replay.recording_pipeline import (
    AZURE_ACTIVITY_CHANNEL,
    AZURE_ACTIVITY_EXPORT_CHANNEL,
    DEFAULT_CHANNEL_ADAPTERS,
    channel_of,
)
from attribution_platform.sources.azure_activity import (
    AzureActivityExportSourceAdapter,
    AzureActivitySourceAdapter,
    is_azure_activity_export_record,
)
from attribution_platform.sources.errors import SourceAdapterError

REPO = Path(__file__).resolve().parents[1]
PACK = (
    REPO
    / "data"
    / "detection"
    / "elastic"
    / "195f15c0bac8"
    / "generated"
    / "elastic-195f15c0bac8.rules.json"
)
DELETE = "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"
RESOURCE = "/SUBSCRIPTIONS/0000/RESOURCEGROUPS/RG"
#: "Azure Resource Group Deleted"
RULE = "bb4fe8d2-7ae2-475c-8b5d-55b449e4264f"


def _export(**changes: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "time": "2026-03-01T10:00:00.1234567Z",
        "resourceId": RESOURCE,
        "operationName": DELETE,
        "category": "Administrative",
        "resultType": "Success",
        "correlationId": "c-1",
        "callerIpAddress": "203.0.113.7",
        "level": "Information",
        "properties": {"statusCode": "OK"},
    }
    record.update(changes)
    return {k: v for k, v in record.items() if v is not None}


def _rest() -> dict[str, Any]:
    return {
        "eventDataId": "e-1",
        "eventTimestamp": "2026-03-01T10:00:00Z",
        "subscriptionId": "0000",
        "operationName": {"value": DELETE, "localizedValue": "Delete resource group"},
        "status": {"value": "Succeeded"},
        "resourceId": RESOURCE,
    }


def _observe(record: dict[str, Any]) -> Any:
    (observation,) = AzureActivityExportSourceAdapter().to_observations(record)
    return observation


def _view(name: str, record: dict[str, Any]) -> Any:
    return AZURE_ACTIVITY_VIEWS.resolve(name, _observe(record))


def test_an_exported_event_is_read_as_logged() -> None:
    observation = _observe(_export())
    activity = observation.azure_activity
    assert activity.operation_name == DELETE and activity.result_type == "Success"
    assert activity.category == "Administrative" and activity.resource_id == RESOURCE
    assert activity.status is None  # the REST form's vocabulary is not filled in
    assert observation.event.dataset == "azure.activitylogs"
    assert observation.network.source.ip == "203.0.113.7"
    assert observation.raw_reference.source_type == "azure_activity_export"
    # no event id in this layout: the id is the record's content, so it is stable
    assert observation.observation_id.startswith("azure-activity-export:sha256:")
    reordered = dict(reversed(list(_export().items())))
    assert _observe(reordered).observation_id == observation.observation_id
    assert _observe(_export(correlationId="c-2")).observation_id != observation.observation_id


@pytest.mark.parametrize(
    "record",
    [
        _export(time="2026-03-01T10:00:00"),  # no zone
        _export(operationName="  "),
        _export(category="NonInteractiveUserSignInLogs"),  # another log's category
        _export(resourceId="/tenants/t/providers/Microsoft.aadiam"),  # Entra ID
        _export(time=None),
        _rest(),
    ],
)
def test_other_records_are_refused(record: dict[str, Any]) -> None:
    with pytest.raises(SourceAdapterError):
        AzureActivityExportSourceAdapter().to_observations(record)


def test_the_two_layouts_are_routed_apart() -> None:
    assert is_azure_activity_export_record(_export())
    assert channel_of(_export()) == AZURE_ACTIVITY_EXPORT_CHANNEL
    assert channel_of(_rest()) == AZURE_ACTIVITY_CHANNEL
    assert isinstance(
        DEFAULT_CHANNEL_ADAPTERS[AZURE_ACTIVITY_EXPORT_CHANNEL], AzureActivityExportSourceAdapter
    )


def test_the_outcome_follows_the_pipeline() -> None:
    # resultType as logged, when it is success / failure in any case
    assert _view("event.outcome", _export(resultType="Success")) == "Success"
    assert _view("event.outcome", _export(resultType="failure")) == "failure"
    # any other resultType: properties.result, only if exactly one of three words
    started = _export(resultType="Start", properties={"result": "success"})
    assert _view("event.outcome", started) == "success"
    assert _view("event.outcome", _export(resultType="Start")) is None
    text = _export(resultType=None, properties=json.dumps({"result": "unknown"}))
    assert _view("event.outcome", text) == "unknown"
    assert (
        _view("event.outcome", _export(resultType=None, properties={"result": "Success"})) is None
    )
    assert _view("event.outcome", _export(resultType=None, properties="not json")) is None
    assert _view("event.type", _export(category="Delete")) == ("deletion",)
    assert _view("event.type", _export(category="Administrative")) is None
    assert _view("event.action", _export()) == DELETE


def test_an_elastic_rule_fires_on_the_export_and_never_on_the_rest_form() -> None:
    engine = DetectionEngine(rules=load_rule_pack(PACK, knowledge=load_attack_knowledge()).rules)

    def fired(observation: Any) -> set[str]:
        return {d.rule_ref.rule_id.split(":")[1] for d in engine.evaluate([observation])}

    assert RULE in fired(_observe(_export()))
    assert RULE not in fired(_observe(_export(resultType="Failure")))
    assert RULE not in fired(_observe(_export(operationName=DELETE.lower())))
    # the REST form of the same operation: what Elastic's pipeline would make of it
    # is unknown, so every view is undetermined and no Elastic rule fires
    (rest,) = AzureActivitySourceAdapter().to_observations(_rest())
    assert all(view(rest) is UNDETERMINED for view in AZURE_ACTIVITY_VIEWS.views.values())
    assert not {r for r in fired(rest) if r == RULE}
    assert not [d for d in engine.evaluate([rest]) if d.detection_source.startswith("elastic:")]
