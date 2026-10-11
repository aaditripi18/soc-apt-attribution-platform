"""Derived ECS views for PowerShell script-block events (ADR-0015 Amendment B).

Elastic's Windows integration indexes ``Microsoft-Windows-PowerShell/Operational``
in ``logs-windows.powershell_operational-*``. Its pipeline
(``packages/windows/_dev/shared/ingest_pipeline/powershell_operational.yml``,
``elastic/integrations`` @ ``ff5328128a30``, SHA-256 ``e07f1bff…8948`` as the
data stream's pinned ``default.yml.link`` states) and index settings are
reproduced here for event **4104** only — the event that carries script text,
which every Elastic PowerShell rule reads.

**The text field.** ``powershell.file.script_block_text`` is not a keyword: the
data stream's manifest gives it the analyzer ::

    powershell_script_analyzer: {type: pattern, pattern: '[\\W&&[^-]]+'}

An Elasticsearch ``pattern`` analyzer splits the text wherever the pattern
matches, drops empty pieces, and lower-cases what is left. The pattern is a Java
regular expression without the Unicode flag, so ``\\W`` is "not ``[A-Za-z0-9_]``"
and the separators are every run of characters other than ASCII letters, digits,
``_`` and ``-``. A token is therefore a run of exactly those characters, and
lower-casing it is ASCII lower-casing. :func:`powershell_script_tokens` is that
analyzer.

A KQL query on such a field does not compare strings. A quoted value is a
*phrase*: the value is analysed the same way, and the document matches when the
value's tokens occur in the text consecutively and in order. The view below
returns the text as its tokens joined and enclosed by single spaces
(``" invoke-mimikatz -dumpcreds "``); a phrase is the same form of its own
tokens, and — because no token contains a space — "the phrase's form is a
substring of the text's form" is exactly "its tokens occur consecutively". So
the rule engine's plain ``contains`` decides phrase matches exactly, and no new
operator is needed.

Checked against Elastic's own pipeline fixtures for the fields below
(``tests/test_elastic_powershell_conformance.py``).
"""

from __future__ import annotations

import re
from typing import Any

from attribution_platform.detection.derived_views import ViewSet, attr, build_view_set
from attribution_platform.domain import Observation

#: The adapter's ``event.action`` for a 4104 script-block event.
SCRIPT_BLOCK_ACTION = "powershell_script_block"
SCRIPT_BLOCK_CODE = "4104"
POWERSHELL_PROVIDER = "Microsoft-Windows-PowerShell"

#: ``[\W&&[^-]]+`` as Java reads it without UNICODE_CHARACTER_CLASS.
_SEPARATORS = re.compile(r"[^A-Za-z0-9_\-]+")


def powershell_script_tokens(text: str) -> tuple[str, ...]:
    """``powershell_script_analyzer`` applied to ``text``."""
    return tuple(piece.lower() for piece in _SEPARATORS.split(text) if piece)


def token_form(tokens: tuple[str, ...]) -> str | None:
    """Tokens as one string in which a phrase match is a substring match;
    ``None`` when there is no token (nothing can match)."""
    return " " + " ".join(tokens) + " " if tokens else None


def _is_script_block(obs: Observation) -> bool:
    return bool(attr(obs, "event", "action") == SCRIPT_BLOCK_ACTION)


def _script_block_text(obs: Observation) -> Any:
    text = attr(obs, "powershell", "script_block_text") if _is_script_block(obs) else None
    return token_form(powershell_script_tokens(text)) if isinstance(text, str) else None


def _script_path(obs: Observation) -> str | None:
    path = attr(obs, "powershell", "script_path") if _is_script_block(obs) else None
    return path if isinstance(path, str) and path != "" else None


def _file_part(part: str) -> Any:
    """``file.name`` / ``file.directory`` / ``file.extension`` exactly as the
    pipeline's script sets them: only for a path longer than one character that
    contains a backslash; the extension only if the path contains a dot."""

    def view(obs: Observation) -> Any:
        path = _script_path(obs)
        if path is None or len(path) <= 1:
            return None
        index = path.rfind("\\")
        if index < 0:
            return None
        if part == "name":
            return path[index + 1 :]
        if part == "directory":
            return path[:index]
        dot = path.rfind(".")
        return path[dot + 1 :] if dot > -1 else None

    return view


def _when_script_block(*path: str) -> Any:
    return lambda obs: attr(obs, *path) if _is_script_block(obs) else None


POWERSHELL_VIEWS: ViewSet = build_view_set(
    "elastic_powershell",
    {
        "powershell.file.script_block_text": _script_block_text,
        "powershell.file.script_block_id": _when_script_block("powershell", "script_block_id"),
        "file.path": _script_path,
        "file.name": _file_part("name"),
        "file.directory": _file_part("directory"),
        "file.extension": _file_part("extension"),
        "user.id": _when_script_block("user", "id"),
        "process.pid": lambda obs: (
            str(pid) if (pid := _when_script_block("process", "pid")(obs)) is not None else None
        ),
    },
    non_keyword={"powershell.file.script_block_text": "text", "process.pid": "long"},
    analyzers={
        "powershell.file.script_block_text": lambda value: token_form(
            powershell_script_tokens(value)
        )
    },
)

__all__ = [
    "POWERSHELL_PROVIDER",
    "POWERSHELL_VIEWS",
    "SCRIPT_BLOCK_ACTION",
    "SCRIPT_BLOCK_CODE",
    "powershell_script_tokens",
    "token_form",
]
