"""Derived ECS views for Windows Security events (ADR-0015 D2).

Elastic's System integration indexes the Security channel in
``logs-system.security-*``; its pipeline
(``packages/system/data_stream/security``, ``elastic/integrations`` @
``ff5328128a30``) differs from the Sysmon one in ways a rule can observe — most
visibly, a 4688 command line is split on whitespace outside double quotes and
**keeps the quotes** in ``process.args``. Each view below reproduces that
pipeline and is checked against its own test fixtures
(``tests/test_elastic_security_conformance.py``).

The pipeline's first step removes every event-data value that is ``null``,
``""``, ``"-"`` or the null GUID, so a placeholder and an absent field are the
same thing to a rule; the views apply the same removal. Where the adapter does
not read a field the pipeline would (an acting process on some events, the
subject of a filtering-platform event), the view answers
:data:`~attribution_platform.detection.derived_views.UNDETERMINED`, which makes
every condition on it a non-match.
"""

from __future__ import annotations

import re
from typing import Any

from attribution_platform.detection.derived_views import (
    UNDETERMINED,
    ViewSet,
    attr,
    build_view_set,
)
from attribution_platform.domain import Observation

SECURITY_DATASET = "system.security"
PROCESS_CREATION_CODE = "4688"


def _is_security(obs: Observation) -> bool:
    return bool(attr(obs, "event", "dataset") == SECURITY_DATASET)


def _is_4688(obs: Observation) -> bool:
    return _is_security(obs) and attr(obs, "event", "code") == PROCESS_CREATION_CODE


#: ``remove_empty_values_from_event_data``: values the pipeline drops first.
_REMOVED = frozenset({"", "-", "{00000000-0000-0000-0000-000000000000}"})
#: Filtering-platform events name their account ``UserSid`` / ``UserName``; the
#: adapter records it as the acting user, so the ``Subject*`` fields are unknown.
_NO_SUBJECT_CODES = frozenset({"5441", "5447"})
#: Event codes whose ``PrivilegeList`` the pipeline splits on whitespace.
_PRIVILEGE_SPLIT_CODES = frozenset(
    {"4672", "4673", "4674", "4704", "4705", "4741", "4742", "4743", "4659"}
)


def _ed(value: Any) -> Any:
    return None if value is None or value in _REMOVED else value


def _raw(*path: str) -> Any:
    """A ``winlog.event_data`` value the pipeline leaves in place."""

    def view(obs: Observation) -> Any:
        return _ed(attr(obs, *path)) if _is_security(obs) else None

    return view


def _subject(field: str) -> Any:
    def view(obs: Observation) -> Any:
        if not _is_security(obs):
            return None
        if attr(obs, "event", "code") in _NO_SUBJECT_CODES:
            return UNDETERMINED
        return _ed(attr(obs, "user", field))

    return view


def _privilege_list(obs: Observation) -> tuple[str, ...] | None:
    """A string for most events; split on ``\\s+`` (Java ``split``: trailing empty
    strings dropped) for the privilege-use and account events."""
    value = _ed(attr(obs, "privilege", "privilege_list")) if _is_security(obs) else None
    if value is None:
        return None
    if attr(obs, "event", "code") not in _PRIVILEGE_SPLIT_CODES:
        return (str(value),)
    parts = re.split(r"\s+", str(value))
    while parts and parts[-1] == "":
        parts.pop()
    return tuple(parts) or None


def security_argv(command_line: str) -> tuple[str, ...]:
    """The pipeline's 4688 split: break on whitespace outside double quotes; a
    quote toggles the state and stays in the argument; empty pieces are dropped."""
    args: list[str] = []
    start = 0
    in_quote = False
    last = len(command_line) - 1
    for i, char in enumerate(command_line):
        end = i
        if char == '"':
            in_quote = not in_quote
        if _java_whitespace(char) and not in_quote:
            if end > start:
                args.append(command_line[start:end])
            start = i + 1
        if i == last and start <= end:
            args.append(command_line[start : end + 1])
    return tuple(args)


def _java_whitespace(char: str) -> bool:
    """``Character.isWhitespace``: Unicode space separators except the no-break
    spaces, plus tab, LF, VT, FF, CR and the four ASCII separators."""
    if char in "\t\n\u000b\f\r\u001c\u001d\u001e\u001f":
        return True
    if char in "   ":
        return False
    return char == " " or (char.isspace() and ord(char) > 0x7F)


def _process(field: str) -> Any:
    def view(obs: Observation) -> Any:
        if not _is_security(obs):
            return None
        if not _is_4688(obs) and attr(obs, "process") is None:
            # Other Security events may carry an acting process the adapter does
            # not read for that event; without it the value is unknown.
            return UNDETERMINED
        if not _is_4688(obs) and field != "executable":
            return UNDETERMINED
        return _ed(attr(obs, "process", field))

    return view


def _process_name(field: str) -> Any:
    def view(obs: Observation) -> Any:
        executable = _process(field)(obs)
        if not isinstance(executable, str):
            return executable
        return executable.split("\\")[-1]  # splitOnToken("\\")[-1]

    return view


def _process_args(obs: Observation) -> Any:
    if not _is_security(obs):
        return None
    if not _is_4688(obs):
        return UNDETERMINED
    command_line = _ed(attr(obs, "process", "command_line"))
    if command_line is None:
        return None
    return security_argv(str(command_line)) or None


SECURITY_VIEWS: ViewSet = build_view_set(
    "elastic_security",
    {
        "process.executable": _process("executable"),
        "process.name": _process_name("executable"),
        "process.command_line": _process("command_line"),
        "process.args": _process_args,
        "process.parent.executable": _process("parent_executable"),
        "process.parent.name": _process_name("parent_executable"),
        "event.outcome": lambda o: attr(o, "event", "outcome") if _is_security(o) else None,
        "winlog.event_data.SubjectUserSid": _subject("id"),
        "winlog.event_data.SubjectUserName": _subject("name"),
        "winlog.event_data.SubjectDomainName": _subject("domain"),
        "winlog.event_data.ObjectServer": _raw("object_access", "server"),
        "winlog.event_data.ObjectType": _raw("object_access", "type"),
        "winlog.event_data.ObjectName": _raw("object_access", "name"),
        "winlog.event_data.HandleId": _raw("object_access", "handle_id"),
        "winlog.event_data.Properties": _raw("object_access", "properties"),
        "winlog.event_data.AdditionalInfo": _raw("object_access", "additional_info"),
        "winlog.event_data.OperationType": _raw("object_access", "operation_type"),
        "winlog.event_data.ShareName": _raw("share", "name"),
        "winlog.event_data.ShareLocalPath": _raw("share", "local_path"),
        "winlog.event_data.RelativeTargetName": _raw("share", "relative_target_name"),
        "winlog.event_data.ServiceName": _raw("service", "name"),
        "winlog.event_data.ServiceFileName": _raw("service", "file_name"),
        "winlog.event_data.ServiceType": _raw("service", "type"),
        "winlog.event_data.ServiceStartType": _raw("service", "start_type"),
        "winlog.event_data.ServiceAccount": _raw("service", "account"),
        "winlog.event_data.TaskName": _raw("scheduled_task", "name"),
        "winlog.event_data.PrivilegeList": _privilege_list,
        "winlog.event_data.LogonType": _raw("logon", "logon_type"),
        "winlog.event_data.LogonProcessName": _raw("logon", "logon_process"),
        "winlog.event_data.AuthenticationPackageName": _raw("logon", "authentication_package"),
        "winlog.event_data.TicketOptions": _raw("kerberos", "ticket_options"),
        "winlog.event_data.TicketEncryptionType": _raw("kerberos", "ticket_encryption_type"),
        "winlog.event_data.PreAuthType": _raw("kerberos", "pre_auth_type"),
        "winlog.event_data.SamAccountName": _raw("account_change", "sam_account_name"),
        "winlog.event_data.MemberName": _raw("account_change", "member_name"),
        "winlog.event_data.MemberSid": _raw("account_change", "member_sid"),
        "winlog.event_data.NewUacValue": _raw("account_change", "new_uac_value"),
        "winlog.event_data.OldUacValue": _raw("account_change", "old_uac_value"),
        "winlog.event_data.TargetUserName": _raw("target_user", "name"),
        "winlog.event_data.TargetDomainName": _raw("target_user", "domain"),
    },
    non_keyword={"process.command_line": "wildcard"},
    arrays=frozenset({"process.args", "winlog.event_data.PrivilegeList"}),
)

__all__ = ["SECURITY_VIEWS", "security_argv"]
