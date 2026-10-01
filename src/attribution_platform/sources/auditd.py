"""The Linux Audit (auditd) SourceAdapter (ADR-0010 D4).

One Observation per audit **record** — Sigma's ``linux/auditd`` rules match single
records by ``type`` — carrying the record's fields in the ``audit`` entity group.
Records of one audit event share ``audit.event_serial``; ADR-0003 Amendment G
links them structurally.

**Accepted shape:** a raw ``audit.log`` line, optionally prefixed by ``node=<host>``,
optionally followed by the ENRICHED format's interpreted suffix after a
group-separator byte (``\\x1d``)::

    [node=H ]type=T msg=audit(<epoch>.<ms>:<serial>): k=v k="v" msg='k=v ...'[\\x1dK=V ...]

**Event time:** the epoch seconds and milliseconds of ``msg=audit(...)`` — UTC by
definition, exact to the millisecond. A record printed by ``ausearch -i``
(``msg=audit(MM/DD/YYYY hh:mm:ss.mmm:serial)``) carries local time with no zone:
it is refused, as the zone-less round-1 Windows exports were (ADR-0008).

**Host:** ``node=`` when the record has it; otherwise the host the recording's
source declaration states produced the log (given to the adapter); otherwise the
record is refused. A host is never guessed (the ``hostname=`` inside some
records describes the operation's peer, not the logging host, and is not used).

**Exact values:** every field as logged, except auditd's own encoding of
*untrusted strings* (EXECVE arguments, ``name``, ``comm``, ``exe``): quoted is
literal, unquoted is hex and is decoded exactly (UTF-8), ``(null)`` is absent;
anything else fails closed. EXECVE arguments split by auditd into
``aN_len`` / ``aN[i]`` pieces are refused, not reassembled. ``a0``–``a7`` keep the
meaning the record type gives them (argv in EXECVE, raw hex syscall arguments in
SYSCALL). The syscall *name* and account names come only from the ENRICHED
suffix — never from a syscall table.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from attribution_platform.domain import (
    AuditRef,
    EventMetadata,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
    UserRef,
)
from attribution_platform.sources.errors import SourceAdapterError

AUDITD_SOURCE_TYPE = "auditd"
#: ``event.dataset`` for Linux Audit records (Elastic's auditd module dataset name).
AUDITD_DATASET = "auditd.log"
_ADAPTER = "AuditdSourceAdapter"

_GROUP_SEPARATOR = "\x1d"
_HEADER = re.compile(
    r"\A(?:node=(?P<node>\S+) )?type=(?P<type>[A-Z0-9_]+) "
    r"msg=audit\((?P<stamp>[^)]*)\) ?:\s?(?P<body>.*)\Z",
    re.DOTALL,
)
_EPOCH = re.compile(r"\A(?P<sec>\d+)\.(?P<ms>\d{3}):(?P<serial>\d+)\Z")
_INTERPRETED = re.compile(r"\A\d\d/\d\d/\d{4} \d\d:\d\d:\d\d\.\d{3}:\d+\Z")
#: A bare value runs to the next whitespace that is followed by another
#: ``key=`` — auditd writes some values with spaces unquoted inside ``msg='…'``
#: (e.g. ``op=adding user id=1002``), as ``ausearch`` itself accounts for. Raw
#: top-level values never contain spaces (auditd encodes them), so they are
#: unaffected.
_TOKEN = re.compile(
    r"(?P<key>[A-Za-z0-9_\-\[\]]+)=(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'"
    r"|(?P<bare>.*?)(?=\s+[A-Za-z0-9_\-\[\]]+=|\s*\Z))",
    re.DOTALL,
)
_HEX = re.compile(r"\A(?:[0-9A-Fa-f]{2})+\Z")
_SPLIT_ARG = re.compile(r"\Aa\d+(?:_len|\[\d+\])\Z")
#: auditd's untrusted-string fields (quoted literal, else hex, ``(null)`` absent).
_UNTRUSTED = frozenset({"name", "comm", "exe", "cwd"})
_MAX_ARGS = 8  # a0–a7: what Sigma's auditd content reads


def is_audit_record(text: str) -> bool:
    """Whether a log line looks like one auditd record (cheap prefix test)."""
    stripped = text.lstrip()
    return stripped.startswith("type=") or stripped.startswith("node=")


def _tokens(text: str) -> list[tuple[str, str, bool, bool]]:
    """``(key, value, quoted, nested)`` for every ``key=value`` in ``text``."""
    out = []
    for match in _TOKEN.finditer(text):
        if match["dq"] is not None:
            out.append((match["key"], match["dq"], True, False))
        elif match["sq"] is not None:
            out.append((match["key"], match["sq"], True, True))
        else:
            out.append((match["key"], match["bare"] or "", False, False))
    return out


def _untrusted(key: str, value: str, quoted: bool) -> str | None:
    if quoted:
        return value
    if value == "(null)":
        return None
    if not _HEX.match(value):
        raise SourceAdapterError(f"{_ADAPTER}: {key}={value!r} is neither quoted nor hex")
    try:
        return bytes.fromhex(value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceAdapterError(f"{_ADAPTER}: {key} is hex but not UTF-8") from exc


class AuditdSourceAdapter:
    """auditd records -> one ``Observation`` each.

    ``host`` is the host the recording's source declaration states produced the
    log; it is used only for records without ``node=``."""

    def __init__(self, host: HostRef | None = None) -> None:
        self._host = host

    @property
    def source_type(self) -> str:
        return AUDITD_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, str):
            raise SourceAdapterError(
                f"{_ADAPTER} expects one audit.log line, got {type(raw_record).__name__}"
            )
        line = raw_record.strip()
        raw_part, _, enriched_part = line.partition(_GROUP_SEPARATOR)
        header = _HEADER.match(raw_part)
        if header is None:
            raise SourceAdapterError(f"{_ADAPTER}: not an audit record")
        stamp = header["stamp"]
        if _INTERPRETED.match(stamp):
            raise SourceAdapterError(
                f"{_ADAPTER}: ausearch -i interpreted record — local time with no zone is "
                f"not a trustworthy UTC event time"
            )
        epoch = _EPOCH.match(stamp)
        if epoch is None:
            raise SourceAdapterError(f"{_ADAPTER}: unrecognised audit timestamp {stamp!r}")
        timestamp = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
            seconds=int(epoch["sec"]), milliseconds=int(epoch["ms"])
        )

        record_type = header["type"]
        fields: dict[str, str | None] = {}
        for key, value, quoted, nested in _tokens(header["body"]):
            if nested and key == "msg":
                for inner_key, inner_value, inner_quoted, _ in _tokens(value):
                    if inner_key not in fields:
                        fields[inner_key] = (
                            _untrusted(inner_key, inner_value, inner_quoted)
                            if inner_key in _UNTRUSTED
                            else inner_value
                        )
                continue
            if record_type == "EXECVE" and _SPLIT_ARG.match(key):
                raise SourceAdapterError(f"{_ADAPTER}: split EXECVE argument {key!r} refused")
            if key in fields:
                raise SourceAdapterError(f"{_ADAPTER}: duplicate field {key!r}")
            if key in _UNTRUSTED or (record_type == "EXECVE" and re.fullmatch(r"a\d+", key)):
                fields[key] = _untrusted(key, value, quoted)
            else:
                fields[key] = value
        enriched = {key: value for key, value, _, _ in _tokens(enriched_part)}

        if header["node"]:
            host = HostRef(name=header["node"], os_type="linux")
        elif self._host is not None:
            host = self._host
        else:
            raise SourceAdapterError(
                f"{_ADAPTER}: no node= in the record and no declared host for the recording"
            )
        host_key = host.name or host.id
        if not host_key:
            raise SourceAdapterError(f"{_ADAPTER}: the declared host has neither name nor id")

        def pid(key: str) -> int | None:
            value = fields.get(key)
            if value is None or value == "":
                return None
            if not value.isdigit():
                raise SourceAdapterError(f"{_ADAPTER}: {key}={value!r} is not a process id")
            return int(value)

        executable = fields.get("exe")
        process = None
        if executable is not None or fields.get("pid") is not None:
            process = ProcessRef(
                pid=pid("pid"),
                parent_pid=pid("ppid"),
                executable=executable,
                name=executable.rsplit("/", 1)[-1] or None if executable else None,
            )
        uid = fields.get("uid")
        user = UserRef(id=uid, name=enriched.get("UID")) if uid is not None else None
        args = {f"a{i}": fields.get(f"a{i}") for i in range(_MAX_ARGS)}
        audit = AuditRef(
            record_type=record_type,
            event_serial=epoch["serial"],
            syscall=fields.get("syscall"),
            syscall_name=enriched.get("SYSCALL"),
            success=fields.get("success"),
            exit=fields.get("exit"),
            argc=fields.get("argc"),
            item=fields.get("item"),
            name=fields.get("name"),
            nametype=fields.get("nametype"),
            comm=fields.get("comm"),
            unit=fields.get("unit"),
            op=fields.get("op"),
            res=fields.get("res"),
            key=fields.get("key"),
            auid=fields.get("auid"),
            uid=uid,
            euid=fields.get("euid"),
            ses=fields.get("ses"),
            tty=fields.get("tty"),
            **args,
        )
        item = fields.get("item")
        observation_id = f"auditd:{host_key}:{epoch['serial']}:{record_type}" + (
            f":{item}" if item is not None else ""
        )
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=TimePrecision.MILLISECOND,
                raw_reference=SourceRef(
                    source_type=AUDITD_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(kind="event", action=record_type, dataset=AUDITD_DATASET),
                host=host,
                user=user,
                process=process,
                audit=audit,
            ),
        )


__all__ = [
    "AUDITD_DATASET",
    "AUDITD_SOURCE_TYPE",
    "AuditdSourceAdapter",
    "is_audit_record",
]
