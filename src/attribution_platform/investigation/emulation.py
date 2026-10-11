"""Ran versus detected: an emulation report beside what the platform found (ADR-0019).

When a recording comes from a lab run, the emulation tool's own report says what
was executed: which step, which ATT&CK technique, on which host, when, and in
which process. That is ground truth the platform never saw — it is given the
telemetry only — so setting the two side by side measures detection honestly.

This module reads a MITRE CALDERA operation report and compares each step with
the investigation's Evidence:

- **the step's own process**: Evidence grounded in an Observation of the step's
  process (its pid, or a child of it) on the step's host inside the step's time
  window — what the platform saw *of that step*;
- **the step's technique anywhere**: Evidence for the technique the report
  names, wherever in the investigation it was found.

Only descriptive fields of the report are read (step name, technique, tactic,
host, status, times, pid). The report's command text and command output are
**never** read, stored or served: the comparison does not need them, and a
read model has no business carrying attack commands.

The outcome per step is a closed vocabulary, decided by fixed rules below. It is
a statement about detection, never about attribution.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from attribution_platform.dataplane import ElasticClient
from attribution_platform.domain import Evidence, EvidenceQuality, Observation
from attribution_platform.investigation.records import _load, _persist, _to_json

EMULATION_METHOD_VERSION = "1.0"
EMULATION_SCHEMA_VERSION = "emulation-comparison/1"
EMULATION_INDEX = "attribution-platform-emulation-comparisons-v1"
EMULATION_MAPPING: Mapping[str, Any] = {"investigation_id": {"type": "keyword"}}

#: Slack around a step's [issued, collected] interval when matching its process.
STEP_WINDOW_SLACK = timedelta(seconds=10)
#: CALDERA link status codes with a documented meaning.
_STATUS = {0: "success", 1: "failed", 124: "timeout", -2: "discarded", -3: "collected"}
_TECHNIQUE_TYPE = "attack-pattern"

#: Outcomes, strongest first.
TECHNIQUE_DETECTED_IN_STEP = "technique_detected_in_step"
STEP_ACTIVITY_DETECTED = "step_activity_detected"
TECHNIQUE_DETECTED_ELSEWHERE = "technique_detected_elsewhere"
NOT_DETECTED = "not_detected"
OUTCOMES = (
    TECHNIQUE_DETECTED_IN_STEP,
    STEP_ACTIVITY_DETECTED,
    TECHNIQUE_DETECTED_ELSEWHERE,
    NOT_DETECTED,
)


class EmulationReportError(ValueError):
    """The report is not a CALDERA operation report this module can read."""


@dataclass(frozen=True)
class EmulationStep:
    order: int
    name: str
    ability_id: str
    technique_id: str | None
    technique_name: str | None
    tactic: str | None
    host: str | None
    executor: str | None
    status: str
    issued_at: datetime | None
    collected_at: datetime | None
    pid: int | None


@dataclass(frozen=True)
class EmulationRun:
    tool: str
    operation_name: str
    profile_name: str | None
    started_at: datetime | None
    finished_at: datetime | None
    report_sha256: str
    steps: tuple[EmulationStep, ...]


@dataclass(frozen=True)
class StepComparison:
    order: int
    name: str
    technique_id: str | None
    technique_name: str | None
    tactic: str | None
    host: str | None
    status: str
    issued_at: str | None
    collected_at: str | None
    pid: int | None
    #: Evidence grounded in the step's own process, inside its time window.
    step_evidence: int
    step_technique_ids: tuple[str, ...]
    step_unit_ids: tuple[str, ...]
    #: Evidence for the step's technique anywhere in the investigation.
    technique_evidence_core: int
    technique_evidence_context: int
    outcome: str


@dataclass(frozen=True)
class EmulationComparisonRecord:
    investigation_id: str
    tool: str
    operation_name: str
    profile_name: str | None
    started_at: str | None
    finished_at: str | None
    report_sha256: str
    steps: tuple[StepComparison, ...]
    outcome_counts: Mapping[str, int]
    distinct_techniques: int
    distinct_techniques_with_evidence: int
    window_slack_seconds: int = int(STEP_WINDOW_SLACK.total_seconds())
    method_version: str = EMULATION_METHOD_VERSION
    schema_version: str = field(default=EMULATION_SCHEMA_VERSION)


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _text(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def parse_caldera_report(raw: bytes, *, sha256: str) -> EmulationRun:
    """A CALDERA "Full Report" (operation report JSON). Fails closed on another
    shape. Command and output fields are not read."""
    try:
        report = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EmulationReportError(f"the emulation report is not JSON: {exc}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("steps"), dict):
        raise EmulationReportError("not a CALDERA operation report: no 'steps' by agent")
    host_of = {
        str(agent.get("paw")): _text(agent.get("host"))
        for agent in report.get("host_group") or ()
        if isinstance(agent, dict)
    }
    collected: list[tuple[datetime | None, str, int, Mapping[str, Any], str | None]] = []
    for paw, block in sorted(report["steps"].items()):
        if not isinstance(block, dict) or not isinstance(block.get("steps"), list):
            raise EmulationReportError(f"agent {paw!r}: no step list")
        for position, step in enumerate(block["steps"]):
            if not isinstance(step, dict) or not step.get("ability_id"):
                raise EmulationReportError(f"agent {paw!r}: step {position} has no ability id")
            collected.append(
                (_time(step.get("delegated")), str(paw), position, step, host_of.get(str(paw)))
            )
    collected.sort(key=lambda item: (item[0] is None, item[0] or datetime.min, item[1], item[2]))
    steps = []
    for order, (issued, _paw, _position, step, host) in enumerate(collected, start=1):
        raw_attack = step.get("attack")
        attack: Mapping[str, Any] = raw_attack if isinstance(raw_attack, dict) else {}
        status = step.get("status")
        pid = step.get("pid")
        steps.append(
            EmulationStep(
                order=order,
                name=str(step.get("name") or step["ability_id"]),
                ability_id=str(step["ability_id"]),
                technique_id=_text(attack.get("technique_id")),
                technique_name=_text(attack.get("technique_name")),
                tactic=_text(attack.get("tactic")),
                host=host,
                executor=_text(step.get("executor")),
                status=_STATUS.get(status, f"status {status}")
                if isinstance(status, int)
                else "unknown",
                issued_at=issued,
                collected_at=_time(step.get("run")),
                pid=pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
            )
        )
    raw_adversary = report.get("adversary")
    adversary: Mapping[str, Any] = raw_adversary if isinstance(raw_adversary, dict) else {}
    return EmulationRun(
        tool="MITRE CALDERA",
        operation_name=str(report.get("name") or ""),
        profile_name=_text(adversary.get("name")),
        started_at=_time(report.get("start")),
        finished_at=_time(report.get("finish")),
        report_sha256=sha256,
        steps=tuple(steps),
    )


def load_caldera_report(path: Path) -> EmulationRun:
    import hashlib

    raw = path.read_bytes()
    return parse_caldera_report(raw, sha256=hashlib.sha256(raw).hexdigest())


def _same_host(observation: Observation, host: str | None) -> bool:
    if host is None:
        return True
    name = observation.host.name if observation.host is not None else None
    if not name:
        return False
    # the report holds the short computer name; telemetry may hold the FQDN
    return name.lower() == host.lower() or name.lower().split(".")[0] == host.lower()


def _of_step(observation: Observation, step: EmulationStep) -> bool:
    """Is this Observation of the step's own process (or a child of it), on the
    step's host, inside the step's time window?"""
    if step.pid is None or step.issued_at is None or observation.process is None:
        return False
    if step.pid not in (observation.process.pid, observation.process.parent_pid):
        return False
    end = (step.collected_at or step.issued_at) + STEP_WINDOW_SLACK
    if not step.issued_at - STEP_WINDOW_SLACK <= observation.timestamp <= end:
        return False
    return _same_host(observation, step.host)


def compare_emulation(
    run: EmulationRun,
    investigation_id: str,
    members: Mapping[str, tuple[Evidence, Observation]],
    unit_of: Mapping[str, str],
) -> EmulationComparisonRecord:
    """``members``: every Evidence of the investigation with its Observation;
    ``unit_of``: evidence id -> the unit it belongs to (absent: in no unit)."""
    by_technique: dict[str, list[Evidence]] = {}
    for evidence, _ in members.values():
        ref = evidence.attack_ref
        if ref is not None and ref.object_type == _TECHNIQUE_TYPE and ref.external_id:
            by_technique.setdefault(ref.external_id, []).append(evidence)

    compared = []
    for step in run.steps:
        own = [
            evidence for evidence, observation in members.values() if _of_step(observation, step)
        ]
        own_techniques = sorted(
            {
                e.attack_ref.external_id
                for e in own
                if e.attack_ref is not None
                and e.attack_ref.object_type == _TECHNIQUE_TYPE
                and e.attack_ref.external_id
            }
        )
        named = by_technique.get(step.technique_id or "", [])
        core = sum(1 for e in named if e.quality is not EvidenceQuality.LOW)
        if step.technique_id is not None and step.technique_id in own_techniques:
            outcome = TECHNIQUE_DETECTED_IN_STEP
        elif own:
            outcome = STEP_ACTIVITY_DETECTED
        elif named:
            outcome = TECHNIQUE_DETECTED_ELSEWHERE
        else:
            outcome = NOT_DETECTED
        compared.append(
            StepComparison(
                order=step.order,
                name=step.name,
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                tactic=step.tactic,
                host=step.host,
                status=step.status,
                issued_at=step.issued_at.isoformat() if step.issued_at else None,
                collected_at=step.collected_at.isoformat() if step.collected_at else None,
                pid=step.pid,
                step_evidence=len(own),
                step_technique_ids=tuple(own_techniques),
                step_unit_ids=tuple(
                    sorted({unit_of[e.evidence_id] for e in own if e.evidence_id in unit_of})
                ),
                technique_evidence_core=core,
                technique_evidence_context=len(named) - core,
                outcome=outcome,
            )
        )
    techniques = {s.technique_id for s in run.steps if s.technique_id}
    return EmulationComparisonRecord(
        investigation_id=investigation_id,
        tool=run.tool,
        operation_name=run.operation_name,
        profile_name=run.profile_name,
        started_at=run.started_at.isoformat() if run.started_at else None,
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
        report_sha256=run.report_sha256,
        steps=tuple(compared),
        outcome_counts={o: sum(1 for s in compared if s.outcome == o) for o in OUTCOMES},
        distinct_techniques=len(techniques),
        distinct_techniques_with_evidence=sum(1 for t in techniques if by_technique.get(t)),
    )


def comparison_to_json(record: EmulationComparisonRecord) -> dict[str, Any]:
    return dict(_to_json(record))


def persist_emulation_comparison(client: ElasticClient, record: EmulationComparisonRecord) -> None:
    _persist(
        client,
        EMULATION_INDEX,
        EMULATION_MAPPING,
        record.investigation_id,
        comparison_to_json(record),
    )


def load_emulation_comparison(
    client: ElasticClient, investigation_id: str
) -> Mapping[str, Any] | None:
    return _load(client, EMULATION_INDEX, investigation_id)


__all__ = [
    "EMULATION_INDEX",
    "EmulationComparisonRecord",
    "EmulationReportError",
    "EmulationRun",
    "EmulationStep",
    "OUTCOMES",
    "compare_emulation",
    "comparison_to_json",
    "load_caldera_report",
    "load_emulation_comparison",
    "parse_caldera_report",
    "persist_emulation_comparison",
]
