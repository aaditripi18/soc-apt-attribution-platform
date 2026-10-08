#!/usr/bin/env python3
"""Extract a small, fixed set of real cloud records from the ``splunk/attack_data``
cache into a tracked golden file (ADR-0011 D7).

Selection is deterministic: for each golden id, the first record (in file order,
logs taken in sorted cache-path order) that its predicate accepts. Records are
written verbatim (the original JSON line) with their source path to
``data/telemetry-samples/splunk-attack-data-cloud/golden-records.jsonl``.
Re-running on the verified cache reproduces the file byte-for-byte. Apache-2.0
data (see the NOTICE beside it).

    python scripts/extract_cloud_golden_records.py
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-cloud"
OUT = SAMPLES / "golden-records.jsonl"


def _entra(category: str, operation: str | None = None) -> Callable[[Mapping[str, Any]], bool]:
    return lambda r: r.get("category") == category and (
        operation is None or r.get("operationName") == operation
    )


def _ct(record: Mapping[str, Any], *path: str) -> Any:
    node: Any = record
    for key in path:
        node = node.get(key) if isinstance(node, Mapping) else None
    return node


def _o365(workload: str, operation: str) -> Callable[[Mapping[str, Any]], bool]:
    return lambda r: r.get("Workload") == workload and r.get("Operation") == operation


#: golden id -> predicate over one parsed record (batch A: Entra ID, Office 365;
#: batch B: AWS CloudTrail; batch C: Azure Activity, Okta, GitHub, Kubernetes).
GOLDEN: Mapping[str, Callable[[Mapping[str, Any]], bool]] = {
    "entra-signin": _entra("SignInLogs"),
    "entra-signin-mfa-interrupted": lambda r: (
        r.get("category") == "SignInLogs" and r.get("resultType") == "500121"
    ),
    "entra-signin-noninteractive": _entra("NonInteractiveUserSignInLogs"),
    "entra-signin-service-principal": _entra("ServicePrincipalSignInLogs"),
    "entra-audit-security-info": _entra("AuditLogs", "User registered security info"),
    "entra-audit-disable-strong-auth": _entra("AuditLogs", "Disable Strong Authentication"),
    "entra-audit-add-member-to-role": _entra("AuditLogs", "Add member to role"),
    "entra-risk-event": _entra("UserRiskEvents"),
    "entra-graph-activity": _entra("MicrosoftGraphActivityLogs"),  # refused: no logsource
    "entra-risky-user": _entra("RiskyUsers"),  # refused: a state record, zone-less time
    "o365-aad-user-logged-in": _o365("AzureActiveDirectory", "UserLoggedIn"),
    "o365-aad-disable-strong-auth": _o365("AzureActiveDirectory", "Disable Strong Authentication."),
    "o365-aad-add-domain": lambda r: (
        r.get("Workload") == "AzureActiveDirectory"
        and "domain" in str(r.get("Operation", "")).casefold()
        and str(r.get("Operation", "")).casefold().startswith(("add", "new"))
    ),
    "o365-ti-mail-data": _o365("ThreatIntelligence", "TIMailData"),
    "o365-exchange-client-ip-port": lambda r: (
        r.get("Workload") == "Exchange" and str(r.get("ClientIP", "")).count(":") == 1
    ),
    "o365-sharepoint-user-agent": lambda r: (
        r.get("Workload") == "SharePoint" and bool(r.get("UserAgent"))
    ),
    "o365-invalid-time": lambda r: str(r.get("CreationTime", "")).endswith(":65"),  # refused
    # batch B: AWS CloudTrail (native)
    "aws-console-login-root": lambda r: (
        r.get("eventName") == "ConsoleLogin"
        and _ct(r, "userIdentity", "type") == "Root"
        and _ct(r, "responseElements", "ConsoleLogin") == "Success"
    ),
    "aws-console-login-failed": lambda r: (
        r.get("eventName") == "ConsoleLogin" and r.get("errorMessage") == "Failed authentication"
    ),
    "aws-stop-logging": lambda r: (
        r.get("eventSource") == "cloudtrail.amazonaws.com"
        and r.get("eventName") in ("StopLogging", "DeleteTrail")
    ),
    "aws-access-denied": lambda r: ("eventVersion" in r and r.get("errorCode") == "AccessDenied"),
    "aws-service-source": lambda r: (
        "eventVersion" in r and r.get("sourceIPAddress") == "eks.amazonaws.com"
    ),
    "aws-ocsf": lambda r: "class_uid" in r and "api" in r,  # Security Lake OCSF: not read
    # batch C: Azure Activity (REST form), Okta, GitHub audit, Kubernetes audit
    "azure-activity-runbook-write": lambda r: (
        _ct(r, "operationName", "value") == "Microsoft.Automation/automationAccounts/runbooks/write"
        and _ct(r, "status", "value") == "Succeeded"
    ),
    "okta-mfa-deactivate": lambda r: r.get("eventType") == "user.mfa.factor.deactivate",
    "okta-account-lock": lambda r: r.get("displayMessage") == "Max sign in attempts exceeded",
    "okta-session-start": lambda r: r.get("eventType") == "user.session.start",
    "github-dependabot-disable": lambda r: (
        "_document_id" in r and r.get("action") == "repository_vulnerability_alerts.disable"
    ),
    "github-repo-destroy": lambda r: "_document_id" in r and r.get("action") == "repo.destroy",
    "k8s-anonymous-get": lambda r: (
        r.get("kind") == "Event" and _ct(r, "user", "username") == "system:anonymous"
    ),
    "k8s-create-pod": lambda r: (
        r.get("kind") == "Event"
        and r.get("verb") == "create"
        and _ct(r, "objectRef", "resource") == "pods"
    ),
}


def main() -> int:
    manifest = json.loads((SAMPLES / "manifest.json").read_text(encoding="utf-8"))
    logs = sorted(
        e["cache_path"] for e in manifest["files"] if not e["cache_path"].endswith(".yml")
    )
    found: dict[str, tuple[str, str]] = {}
    for cache_path in logs:
        pending = [g for g in GOLDEN if g not in found]
        if not pending:
            break
        path = REPO_ROOT / cache_path
        with path.open(encoding="utf-8", errors="replace", newline="\n") as handle:
            for raw in handle:
                line = raw.rstrip("\r\n")
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, Mapping):
                    continue
                for golden_id in list(pending):
                    if GOLDEN[golden_id](record):
                        found[golden_id] = (path.relative_to(CACHE).as_posix(), line)
                        pending.remove(golden_id)
                if not pending:
                    break
    missing = sorted(set(GOLDEN) - set(found))
    if missing:
        raise RuntimeError(f"no record for {missing}")
    with OUT.open("w", encoding="utf-8", newline="\n") as handle:
        for golden_id in GOLDEN:
            source, record = found[golden_id]
            row = {"golden_id": golden_id, "source": source, "record": record}
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(found)} records to {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
