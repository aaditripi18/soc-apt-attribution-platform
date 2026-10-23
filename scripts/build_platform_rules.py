"""Build the platform's own rule pack (ADR-0026).

The platform's detection content is translated from published rules (Sigma,
Elastic). This pack holds the few rules written here, for behaviour measured as
undetected on recordings of known content that no pinned rule expresses: two-stage
sequences (ADR-0026), and single events ATT&CK's own description of a technique names
(Amendment C). Every rule is listed below with what it matches; the pack is generated
deterministically so the tracked file can be reproduced byte for byte:

    python scripts/build_platform_rules.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver  # noqa: E402
from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402

OUT = REPO / "data" / "detection" / "platform" / "platform-rules.json"
VERSION = "1.0"
#: Programs that save files a user fetched from the network.
BROWSERS = ("msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe")
#: Document, image, archive and media extensions that an executable's name may
#: carry before ``.exe`` to pass for that kind of file.
DECOY_EXTENSIONS = (
    "doc", "docx", "gif", "jpeg", "jpg", "mp3", "mp4", "pdf", "png", "ppt", "pptx", "rtf", "txt",
    "xls", "xlsx", "zip",
)  # fmt: skip
#: A file is "then run" if it starts within a day of being saved.
SPAN_SECONDS = 86_400
DECEPTIVE = "platform:deceptive-download-run"
DOWNLOADED = "platform:browser-download-run"
NETWORK_EXECUTABLE = "platform:executable-received-over-http"
#: Zeek's MIME types for Windows executables (its own file-type signatures).
EXECUTABLE_MIME_TYPES = ("application/x-dosexec",)
#: Disabling or stopping the Windows Event Log (ADR-0026 Amendment C), each by a procedure
#: ATT&CK's own description of T1685.001 names.
EVENTLOG_REGISTRY = "platform:eventlog-service-disabled-registry"
EVENTLOG_POWERSHELL = "platform:eventlog-service-stopped-powershell"
EVENTLOG_SC = "platform:eventlog-service-disabled-sc"
CMDLINE_AUDIT = "platform:command-line-auditing-disabled"
#: Script text that stops the service or sets it disabled or stopped; matched without case.
EVENTLOG_SCRIPT_BRANCHES = (
    ("Stop-Service -Name EventLog",),
    ("Stop-Service EventLog",),
    ("Set-Service -Name EventLog", "Disabled"),
    ("Set-Service -Name EventLog", "Stopped"),
    ("Set-Service EventLog", "Disabled"),
    ("Set-Service EventLog", "Stopped"),
)


def _sequence(stage: int, name: str, field_path: str) -> dict[str, object]:
    return {
        "kind": "sequence",
        "stage": stage,
        "span_seconds": SPAN_SECONDS,
        "key_form": "windows_path",
        "fields": [{"name": name, "field_path": field_path}],
    }


def _condition(field_path: str, operator: str, value: str | None = None) -> dict[str, object]:
    condition: dict[str, object] = {"field_path": field_path, "operator": operator}
    if value is not None:
        condition.update(value=value, case_insensitive=True)
    return condition


def build() -> dict[str, object]:
    knowledge = load_attack_knowledge()
    resolver = ExternalIdResolver(knowledge, ("attack-pattern",))

    def mapping(external_id: str, basis: str) -> dict[str, str]:
        resolved = resolver.resolve(external_id)
        if resolved is None or resolved[1] is not None:
            raise SystemExit(
                f"{external_id} is not an active technique of the pinned knowledge base"
            )
        return {
            "stix_id": str(resolved[0]["id"]),
            "object_type": "attack-pattern",
            "attack_kb_version": knowledge.attack_kb_version,
            "external_id": external_id,
            "mapping_basis": basis,
            "mapping_source": "platform-rules",
        }

    run_basis = "a file saved by a web browser was started as a process on the same host"
    user_execution = mapping("T1204.002", run_basis)
    double_extension = mapping(
        "T1036.007", "the started file's name carries a document or media extension before .exe"
    )
    rules: list[dict[str, object]] = []

    def saved_by_browser(family: str) -> None:
        for browser in BROWSERS:
            rules.append(
                {
                    "rule_id": f"{family}:saved:{browser}",
                    "rule_version": VERSION,
                    "conditions": [
                        _condition("event.category", "has_element", "file"),
                        _condition("process.executable", "endswith", "\\" + browser),
                        _condition("file.path", "exists"),
                    ],
                    "technique_mappings": [],
                    "evidence_type": "behavioral",
                    "rule_source": family,
                    "rule_family": family,
                    "aggregation": _sequence(1, "file.path", "file.path"),
                }
            )

    # 1. A browser saves a file whose name passes for a document and ends in .exe;
    #    that file is then run. Core tier.
    saved_by_browser(DECEPTIVE)
    for extension in DECOY_EXTENSIONS:
        rules.append(
            {
                "rule_id": f"{DECEPTIVE}:run:{extension}",
                "rule_version": VERSION,
                "conditions": [
                    _condition("event.category", "has_element", "process"),
                    _condition("event.type", "has_element", "start"),
                    _condition("process.executable", "endswith", f".{extension}.exe"),
                ],
                "technique_mappings": [double_extension, user_execution],
                "evidence_type": "behavioral",
                "rule_source": DECEPTIVE,
                "rule_family": DECEPTIVE,
                "aggregation": _sequence(2, "process.executable", "process.executable"),
            }
        )
    # 2. A browser saves any file that is then run. Ordinary installers do this too:
    #    enrich tier (context, never compared; ADR-0003 Amendment H).
    saved_by_browser(DOWNLOADED)
    rules.append(
        {
            "rule_id": f"{DOWNLOADED}:run",
            "rule_version": VERSION,
            "conditions": [
                _condition("event.category", "has_element", "process"),
                _condition("event.type", "has_element", "start"),
                _condition("process.executable", "exists"),
            ],
            "technique_mappings": [user_execution],
            "evidence_type": "behavioral",
            "rule_source": DOWNLOADED,
            "rule_family": DOWNLOADED,
            "evidence_quality": "low",
            "aggregation": _sequence(2, "process.executable", "process.executable"),
        }
    )
    # 3. An executable received over HTTP, from Zeek's file analysis. Ordinary
    #    software downloads do this too: enrich tier (context, never compared).
    rules.append(
        {
            "rule_id": f"{NETWORK_EXECUTABLE}:files",
            "rule_version": VERSION,
            "conditions": [
                {"field_path": "event.dataset", "operator": "equals", "value": "zeek.files"},
                {"field_path": "zeek.file_source", "operator": "equals", "value": "HTTP"},
                {
                    "field_path": "zeek.mime_type",
                    "operator": "in",
                    "value": list(EXECUTABLE_MIME_TYPES),
                },
                # the originator received it: a download, not an upload
                # Zeek writes a boolean as T / F in its TSV logs and true / false in JSON
                {"field_path": "zeek.file_is_orig", "operator": "in", "value": ["F", "false"]},
            ],
            "technique_mappings": [
                mapping(
                    "T1105",
                    "network file analysis saw a Windows executable delivered to a host over HTTP",
                )
            ],
            "evidence_type": "behavioral",
            "rule_source": NETWORK_EXECUTABLE,
            "rule_family": NETWORK_EXECUTABLE,
            "evidence_quality": "low",
        }
    )

    # 4. The Windows Event Log disabled or stopped, and process command lines dropped from
    #    the Security log. Core tier: one technique each, so every match establishes it.
    def single(family: str, suffix: str, conditions: list[dict[str, object]], basis: str) -> None:
        rules.append(
            {
                "rule_id": f"{family}:{suffix}",
                "rule_version": VERSION,
                "conditions": conditions,
                "technique_mappings": [mapping("T1685.001", basis)],
                "evidence_type": "behavioral",
                "rule_source": family,
                "rule_family": family,
            }
        )

    registry_set = [
        _condition("event.category", "has_element", "registry"),
        _condition("event.type", "has_element", "change"),
    ]
    single(
        EVENTLOG_REGISTRY,
        "start-disabled",
        [
            *registry_set,
            _condition("registry.path", "endswith", "\\Services\\EventLog\\Start"),
            _condition("registry.data", "equals", "DWORD (0x00000004)"),
        ],
        "the Event Log service's Start value was set to 4 (disabled)",
    )
    single(
        CMDLINE_AUDIT,
        "include-cmdline-off",
        [
            *registry_set,
            _condition(
                "registry.path",
                "endswith",
                "\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled",
            ),
            _condition("registry.data", "equals", "DWORD (0x00000000)"),
        ],
        "the audit policy that writes command lines into process-creation events was turned off",
    )
    script_block = [
        _condition("event.category", "has_element", "process"),
        _condition("event.action", "equals", "powershell_script_block"),
    ]
    for index, phrases in enumerate(EVENTLOG_SCRIPT_BRANCHES):
        single(
            EVENTLOG_POWERSHELL,
            f"{index:03d}",
            [
                *script_block,
                *(_condition("powershell.script_block_text", "contains", p) for p in phrases),
            ],
            "a PowerShell script block stopped the Event Log service or set it disabled or stopped",
        )
    process_start = [
        _condition("event.category", "has_element", "process"),
        _condition("event.type", "has_element", "start"),
        _condition("process.executable", "endswith", "\\sc.exe"),
        _condition("process.command_line", "contains", "eventlog"),
    ]
    single(
        EVENTLOG_SC,
        "config-disabled",
        [
            *process_start,
            _condition("process.command_line", "contains", " config "),
            _condition("process.command_line", "contains", "disabled"),
        ],
        "sc.exe set the Event Log service's start type to disabled",
    )
    single(
        EVENTLOG_SC,
        "stop",
        [*process_start, _condition("process.command_line", "contains", " stop ")],
        "sc.exe stopped the Event Log service",
    )
    return {
        "pack_id": f"platform-rules-{VERSION}",
        "description": (
            "Rules written for this platform (ADR-0026). Generated by "
            "scripts/build_platform_rules.py; do not edit by hand."
        ),
        "attack_kb_version": knowledge.attack_kb_version,
        # what each rule is called wherever its detections are shown
        "titles": {
            DECEPTIVE: "Deceptively named download run by the user",
            DOWNLOADED: "File saved by a browser, then run",
            NETWORK_EXECUTABLE: "Executable received over HTTP",
            EVENTLOG_REGISTRY: "Event Log service disabled in the registry",
            EVENTLOG_POWERSHELL: "Event Log service stopped or disabled with PowerShell",
            EVENTLOG_SC: "Event Log service stopped or disabled with sc.exe",
            CMDLINE_AUDIT: "Command lines removed from process-creation auditing",
        },
        "rules": rules,
    }


def render() -> str:
    return json.dumps(build(), indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"Wrote {OUT} ({len(build()['rules'])} rules)")  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    sys.exit(main())
