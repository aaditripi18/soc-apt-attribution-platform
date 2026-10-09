r"""Every Python source compiles without a SyntaxWarning.

An invalid escape such as ``"C:\Windows\v1.0"`` written with single backslashes
compiles with only a warning, yet ``\v`` is a vertical tab and ``\n`` a newline:
test data silently stops meaning what it says (found in a corpus test's paths).
Compiling in the test run catches it regardless of cached bytecode."""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCES = sorted(p for d in ("src", "tests", "scripts") for p in (REPO_ROOT / d).rglob("*.py"))


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_compiles_without_syntax_warnings(path: Path) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
