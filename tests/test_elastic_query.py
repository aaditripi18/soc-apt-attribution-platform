"""Elastic rule query parsing (ADR-0015 D2): each operator keeps its case semantics."""

from __future__ import annotations

import hashlib
from importlib.resources import files

import pytest

from attribution_platform.detection_content.elastic_query import (
    And,
    ElasticQueryError,
    Not,
    Or,
    Pred,
    Unsupported,
    is_single_event_eql,
    parse_eql,
    parse_kql,
)

BS = chr(92)  # one backslash, spelled out so no escape can be mistyped


def _eql(condition: str) -> object:
    return parse_eql(f"process where {condition}").expr


def test_vendored_kql_grammar_is_elastics_byte_for_byte() -> None:
    raw = files("attribution_platform.detection_content").joinpath("grammars/elastic_kql.g")
    digest = hashlib.sha256(raw.read_bytes()).hexdigest()
    assert digest == "e71d797a1a76b413a33bc2616104dd993f010f44b0be58ba6a83b6550cdea327"


# --- EQL operators and their case semantics -------------------------------------


def test_eql_double_equals_is_case_sensitive() -> None:
    assert _eql('process.name == "cmd.exe"') == Pred("process.name", "equals", "cmd.exe", False)


def test_eql_colon_is_case_insensitive() -> None:
    assert _eql('process.name : "cmd.exe"') == Pred("process.name", "equals", "cmd.exe", True)


def test_eql_like_is_sensitive_and_like_tilde_insensitive() -> None:
    assert _eql('process.name like "cmd*"') == Pred("process.name", "startswith", "cmd", False)
    assert _eql('process.name like~ "cmd*"') == Pred("process.name", "startswith", "cmd", True)


def test_eql_in_is_sensitive_and_in_tilde_insensitive() -> None:
    assert _eql('process.name in ("a", "b")') == Pred("process.name", "in", ("a", "b"), False)
    assert _eql('process.name in~ ("a", "b")') == Pred("process.name", "in", ("a", "b"), True)
    assert _eql('process.name not in ("a", "b")') == Not(
        Pred("process.name", "in", ("a", "b"), False)
    )


def test_eql_string_functions_and_their_tilde_forms() -> None:
    assert _eql('startsWith(process.name, "a")') == Pred("process.name", "startswith", "a", False)
    assert _eql('endswith~(process.name, "a")') == Pred("process.name", "endswith", "a", True)
    assert _eql('stringContains(process.name, "a")') == Pred("process.name", "contains", "a", False)


def test_eql_wildcard_shapes() -> None:
    node = _eql('process.command_line : ("*-enc*", "*.ps1", "iex*", "a*b")')
    assert node == Or(
        (
            Pred("process.command_line", "startswith", "iex", True),
            Pred("process.command_line", "endswith", ".ps1", True),
            Pred("process.command_line", "contains", "-enc", True),
            Pred("process.command_line", "wildcard", "a*b", True),
        )
    )


def test_eql_question_mark_is_a_single_character_wildcard() -> None:
    assert _eql('process.name : "a?.exe"') == Pred("process.name", "wildcard", "a?.exe", True)


def test_eql_backslashes_are_literal_in_patterns() -> None:
    # EQL source "C:\\Users\\*" is the string C:\Users\* ; in the engine's wildcard
    # syntax a literal backslash is escaped.
    query = 'process.executable : "C:' + BS * 2 + "Users" + BS * 2 + '*\\\\a.exe"'
    node = _eql(query)
    assert isinstance(node, Pred) and node.operator == "wildcard"
    assert node.value == "C:" + BS * 2 + "Users" + BS * 2 + "*" + BS * 2 + "a.exe"


def test_eql_null_comparisons_are_existence() -> None:
    assert _eql("process.name != null") == Pred("process.name", "exists", None, False)
    assert _eql("process.name == null") == Not(Pred("process.name", "exists", None, False))


def test_eql_boolean_literals_are_marked() -> None:
    assert _eql("?process.code_signature.trusted == false") == Pred(
        "process.code_signature.trusted", "equals", "false", False, boolean=True
    )


def test_eql_unsupported_constructs_are_named_not_approximated() -> None:
    assert _eql('process.name regex~ "a.*"') == Unsupported("eql:regex")
    # ordering against a whole number is the engine's integer operator (Amendment E) ...
    assert _eql("process.pid > 4") == Pred("process.pid", "gt", "4", False)
    # ... against anything else it is not reproduced
    assert _eql('process.name > "a"') == Unsupported("eql:ordering_comparison")
    assert _eql("process.pid > 4.5") == Unsupported("eql:ordering_comparison")
    assert _eql("length(process.name) > 4") == Unsupported("eql:compare_on_expression")
    assert _eql("startsWith(process.name, process.parent.name)") == Unsupported(
        "eql:function_args:startswith"
    )
    assert _eql('cidrMatch(source.ip, "10.0.0.0/8")') == Unsupported("eql:function:cidrmatch")


def test_eql_comments_and_structure() -> None:
    parsed = parse_eql(
        'process where /* block */ process.name == "a" and // line\n not process.pid != null'
    )
    assert parsed.category == "process"
    assert parsed.expr == And(
        (
            Pred("process.name", "equals", "a", False),
            Not(Pred("process.pid", "exists", None, False)),
        )
    )
    assert parse_eql('any where process.name == "a"').category is None


def test_eql_string_escapes() -> None:
    assert _eql('process.name == "a' + BS + 't"') == Pred("process.name", "equals", "a\t", False)
    assert _eql('process.name == """r' + BS + 'aw"""') == Pred(
        "process.name", "equals", "r" + BS + "aw", False
    )
    with pytest.raises(ElasticQueryError):
        _eql('process.name == "a' + BS + 'q"')


def test_multi_event_eql_is_refused() -> None:
    assert not is_single_event_eql("sequence by host.id [process where true]")
    assert not is_single_event_eql("// c\nsample by host.id [any where true]")
    with pytest.raises(ElasticQueryError):
        parse_eql("sequence [process where true]")


# --- KQL with Elastic's grammar ----------------------------------------------------


def test_kql_values_are_case_sensitive_and_exact() -> None:
    assert parse_kql("event.action:CreateUser").expr == Pred(
        "event.action", "equals", "CreateUser", False
    )
    assert parse_kql('event.action:"Create*User"').expr == Pred(
        "event.action",
        "equals",
        "Create*User",
        False,  # quoted: the * is literal
        quoted=True,
    )


def test_kql_wildcards_lists_and_negation() -> None:
    node = parse_kql("event.action:(Get* or *Bucket) and not event.outcome:failure").expr
    assert node == And(
        (
            Or(
                (
                    Pred("event.action", "startswith", "Get", False),
                    Pred("event.action", "endswith", "Bucket", False),
                )
            ),
            Not(Pred("event.outcome", "equals", "failure", False)),
        )
    )


def test_kql_only_star_is_a_wildcard_and_escapes_are_honoured() -> None:
    node = parse_kql("file.path:C" + BS + ":" + BS * 2 + "Users" + BS * 2 + "*" + BS * 2 + "a?")
    assert node.expr == Pred(
        "file.path",
        "wildcard",
        "C:" + BS * 2 + "Users" + BS * 2 + "*" + BS * 2 + "a" + BS + "?",
        False,
    )
    # An escaped asterisk is a literal asterisk, not a wildcard.
    assert parse_kql("process.name:a" + BS + "*b").expr == Pred(
        "process.name", "equals", "a*b", False
    )


def test_kql_existence_numbers_and_booleans() -> None:
    assert parse_kql("process.name:*").expr == Pred("process.name", "exists", None, False)
    assert parse_kql("event.code:4688").expr == Pred("event.code", "equals", "4688", False)
    assert parse_kql("x.trusted:true").expr == Pred(
        "x.trusted", "equals", "true", False, boolean=True
    )


def test_kql_unsupported_constructs() -> None:
    assert parse_kql("x.size >= 10").expr == Unsupported("kql:range")
    assert parse_kql('"free text"').expr == Unsupported("kql:free_text")
    assert parse_kql("x:{ y:1 }").expr == Unsupported("kql:nested")
    with pytest.raises(ElasticQueryError):
        parse_kql("event.action:(")
