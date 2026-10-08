"""The Zeek SourceAdapter and log readers (ADR-0012).

**Readers.** Zeek writes each log in one of two documented forms, both read
exactly into Zeek's own field names:

- **JSON**, one object per line — Zeek's native names (``id.orig_h``) or the
  ``Log::default_field_name_map`` variant that replaces ``.`` with ``_``
  (``id_orig_h``); only the ``id.*`` connection fields carry a dot, so only they
  are read under both spellings. A SimpleRock / RockNSM envelope adds
  ``@stream`` (the log), ``@system`` (the sensor) and ``@proc`` (``zeek``).
- **TSV** (:func:`iter_zeek_tsv`), Zeek's default ASCII writer: ``#separator``,
  ``#set_separator``, ``#empty_field``, ``#unset_field``, ``#path`` and
  ``#fields`` headers; ``\\xHH`` escapes are undone, the unset marker is absent,
  the empty marker is an empty value. The log is the ``#path`` header.

Every record handed to the adapter therefore carries its log under ``@stream``.

**Observations.** One per record of a *traffic* log — ``conn``, ``dns``,
``http``, ``ssl``, ``kerberos``, ``smb_files``, ``smb_mapping``, ``dce_rpc``,
``files``, ``notice``. Sensor housekeeping logs (``loaded_scripts``, ``stats``,
``capture_loss``, ``packet_filter``, ``reporter``) and logs no rule reads
(``x509``, ``weird``, ``dpd``, ``pe``) are refused, counted by the caller.

**Event time:** ``ts`` — epoch seconds (UTC by definition) with Zeek's
microsecond fraction, converted exactly from its decimal text.

**Values:** the ``zeek`` group holds the fields as logged; ``network.source`` /
``destination`` = ``id.orig_*`` / ``id.resp_*`` (the connection's originator and
responder — Zeek's definition), ``network.transport`` = ``proto``;
``user_agent.original`` = HTTP ``user_agent``; ``observer.product`` = ``zeek``
and ``observer.hostname`` = the sensor (``@system``) when stated. No ``host``:
a sensor sees traffic, it is not the host (ADR-0012 D5). ``event.dataset`` is
Elastic's name for the log (``zeek.connection``, ``zeek.dns``, …).

**Identity:** the Observation id is a digest of the log name and the record's
mapped content, so one record present in several published files (a combined
log and a per-host archive) is one Observation, whichever form it was read in.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from attribution_platform.domain import (
    EventMetadata,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    ObserverRef,
    SourceRef,
    TimePrecision,
    UserAgentRef,
    ZeekRef,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.json_values import ip_or_none, scalar_text

ZEEK_SOURCE_TYPE = "zeek"
_ADAPTER = "ZeekSourceAdapter"
#: Zeek log -> ``event.dataset`` (Elastic's Zeek integration data-stream names).
DATASETS: Mapping[str, str] = {
    "conn": "zeek.connection",
    "dns": "zeek.dns",
    "http": "zeek.http",
    "ssl": "zeek.ssl",
    "kerberos": "zeek.kerberos",
    "smb_files": "zeek.smb_files",
    "smb_mapping": "zeek.smb_mapping",
    "dce_rpc": "zeek.dce_rpc",
    "files": "zeek.files",
    "notice": "zeek.notice",
}
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_TS = re.compile(r"\A\d+(?:\.\d{1,6})?\Z")
_HEX_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")


def is_zeek_record(record: Mapping[str, Any]) -> bool:
    """Whether ``record`` is a Zeek log record as the readers yield it."""
    return isinstance(record.get("@stream"), str) and record.get("@proc") in (None, "zeek")


def _unescape(value: str) -> str:
    return _HEX_ESCAPE.sub(lambda m: chr(int(m[1], 16)), value)


def iter_zeek_tsv(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Records of one Zeek TSV log, as ``{field: value}`` with ``@stream`` = the
    ``#path`` header and ``@proc`` = ``zeek``. Unset values are omitted; set /
    vector values become lists. A data line before the headers, or with the
    wrong number of columns, fails closed."""
    separator, set_separator = "\t", ","
    empty, unset = "(empty)", "-"
    path: str | None = None
    fields: list[str] | None = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#"):
            key, _, value = line[1:].partition(separator if fields is not None else "\t")
            if line.startswith("#separator "):
                separator = _unescape(line.split(" ", 1)[1])
            elif key == "set_separator":
                set_separator = _unescape(value)
            elif key == "empty_field":
                empty = value
            elif key == "unset_field":
                unset = value
            elif key == "path":
                path = value
            elif key == "fields":
                fields = value.split(separator)
            continue
        if path is None or fields is None:
            raise SourceAdapterError(f"{_ADAPTER}: TSV data before its #path / #fields headers")
        values = line.split(separator)
        if len(values) != len(fields):
            raise SourceAdapterError(
                f"{_ADAPTER}: TSV line has {len(values)} columns, #fields declares {len(fields)}"
            )
        record: dict[str, Any] = {"@stream": path, "@proc": "zeek"}
        for name, value in zip(fields, values, strict=True):
            if value == unset:
                continue
            if value == empty:
                record[name] = ""
            elif set_separator in value and name in _LIST_FIELDS:
                record[name] = [_unescape(v) for v in value.split(set_separator)]
            else:
                record[name] = _unescape(value)
        yield record


#: Fields whose Zeek type is a set / vector in the logs read here.
_LIST_FIELDS = frozenset({"answers", "TTLs", "conn_uids", "tx_hosts", "rx_hosts", "analyzers"})


def iter_zeek_lines(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Records of one Zeek log file in either form: TSV when it starts with
    Zeek's ``#separator`` header, otherwise JSON lines (non-object lines are
    not records and are skipped)."""
    iterator = iter(lines)
    first = next(iterator, None)
    if first is None:
        return
    if first.startswith("#separator"):
        yield from iter_zeek_tsv([first, *iterator])
        return
    for line in [first, *iterator]:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            yield record


def _text(value: Any) -> str | None:
    if isinstance(value, list):
        if not all(isinstance(v, str | int | float) for v in value):
            raise SourceAdapterError(f"{_ADAPTER}: a list of non-scalars")
        return ",".join(str(v) for v in value) or None
    return scalar_text(value, _ADAPTER)


def _ts(value: Any) -> datetime:
    """``ts`` exactly: JSON numbers are read from their shortest round-trip text."""
    text = repr(value) if isinstance(value, float) else value if isinstance(value, str) else None
    if isinstance(value, int) and not isinstance(value, bool):
        text = str(value)
    if text is None or not _TS.match(text):
        raise SourceAdapterError(f"{_ADAPTER}: ts={value!r} is not epoch seconds")
    try:
        micros = int(Decimal(text) * 1_000_000)
    except InvalidOperation as exc:  # pragma: no cover - guarded by the pattern
        raise SourceAdapterError(f"{_ADAPTER}: ts={value!r} is not a number") from exc
    return _EPOCH + timedelta(microseconds=micros)


def _id(record: Mapping[str, Any], name: str) -> Any:
    """A connection ``id.*`` field under Zeek's name or the ``_`` field-name map."""
    return record.get(f"id.{name}", record.get(f"id_{name}"))


def _port(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value)
    if not text.isdigit() or int(text) > 65535:
        raise SourceAdapterError(f"{_ADAPTER}: {value!r} is not a port")
    return int(text)


class ZeekSourceAdapter:
    """Zeek traffic-log records -> one ``Observation`` each."""

    @property
    def source_type(self) -> str:
        return ZEEK_SOURCE_TYPE

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        if not isinstance(raw_record, Mapping) or not is_zeek_record(raw_record):
            raise SourceAdapterError(f"{_ADAPTER}: not a Zeek log record")
        log = raw_record["@stream"]
        if log not in DATASETS:
            raise SourceAdapterError(f"{_ADAPTER}: log {log!r} is not a traffic log read here")
        r = raw_record
        timestamp = _ts(r.get("ts"))
        zeek = ZeekRef(
            log=log,
            uid=_text(r.get("uid")),
            fuid=_text(r.get("fuid")),
            service=_text(r.get("service")) if log == "conn" else None,
            conn_state=_text(r.get("conn_state")),
            history=_text(r.get("history")),
            duration=_text(r.get("duration")),
            orig_bytes=_text(r.get("orig_bytes")),
            resp_bytes=_text(r.get("resp_bytes")),
            query=_text(r.get("query")),
            qtype_name=_text(r.get("qtype_name")),
            rcode_name=_text(r.get("rcode_name")),
            z=_text(r.get("Z")),
            answers=_text(r.get("answers")),
            method=_text(r.get("method")),
            http_host=_text(r.get("host")) if log == "http" else None,
            uri=_text(r.get("uri")),
            status_code=_text(r.get("status_code")),
            server_name=_text(r.get("server_name")),
            ssl_version=_text(r.get("version")) if log == "ssl" else None,
            ssl_subject=_text(r.get("subject")) if log == "ssl" else None,
            ssl_issuer=_text(r.get("issuer")) if log == "ssl" else None,
            ja3=_text(r.get("ja3")),
            ja3s=_text(r.get("ja3s")),
            request_type=_text(r.get("request_type")),
            krb_client=_text(r.get("client")) if log == "kerberos" else None,
            krb_service=_text(r.get("service")) if log == "kerberos" else None,
            cipher=_text(r.get("cipher")) if log == "kerberos" else None,
            success=_text(r.get("success")),
            smb_action=_text(r.get("action")) if log == "smb_files" else None,
            smb_path=_text(r.get("path")) if log.startswith("smb_") else None,
            smb_name=_text(r.get("name")) if log == "smb_files" else None,
            share_type=_text(r.get("share_type")),
            named_pipe=_text(r.get("named_pipe")),
            endpoint=_text(r.get("endpoint")),
            operation=_text(r.get("operation")),
            filename=_text(r.get("filename")),
            mime_type=_text(r.get("mime_type")),
            file_source=_text(r.get("source")) if log == "files" else None,
            md5=_text(r.get("md5")),
            sha1=_text(r.get("sha1")),
            conn_uids=_text(r.get("conn_uids")),
            note=_text(r.get("note")),
            msg=_text(r.get("msg")),
        )
        orig_h, resp_h = _text(_id(r, "orig_h")), _text(_id(r, "resp_h"))
        source = NetworkEndpoint(ip=ip_or_none(orig_h), port=_port(_id(r, "orig_p")))
        destination = NetworkEndpoint(ip=ip_or_none(resp_h), port=_port(_id(r, "resp_p")))
        has_endpoints = any(
            v is not None for v in (*vars(source).values(), *vars(destination).values())
        )
        network = (
            NetworkInfo(
                source=source,
                destination=destination,
                transport=_text(r.get("proto")),
            )
            if has_endpoints
            else None
        )
        agent = _text(r.get("user_agent")) if log == "http" else None
        sensor = _text(r.get("@system"))
        content = {k: v for k, v in vars(zeek).items() if v is not None}
        content.update(
            {
                "ts": timestamp.isoformat(),
                "src": [source.ip, source.port],
                "dst": [destination.ip, destination.port],
                "trans_id": _text(r.get("trans_id")),
                "trans_depth": _text(r.get("trans_depth")),
            }
        )
        digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode("utf-8")).hexdigest()
        observation_id = f"zeek:{log}:{digest[:32]}"
        return (
            Observation(
                observation_id=observation_id,
                timestamp=timestamp,
                timestamp_precision=TimePrecision.MICROSECOND,
                raw_reference=SourceRef(
                    source_type=ZEEK_SOURCE_TYPE, source_event_id=observation_id
                ),
                event=EventMetadata(kind="event", action=log, dataset=DATASETS[log]),
                network=network,
                user_agent=UserAgentRef(original=agent) if agent else None,
                observer=ObserverRef(product="zeek", hostname=sensor),
                zeek=zeek,
            ),
        )


__all__ = [
    "DATASETS",
    "ZEEK_SOURCE_TYPE",
    "ZeekSourceAdapter",
    "is_zeek_record",
    "iter_zeek_lines",
    "iter_zeek_tsv",
]
