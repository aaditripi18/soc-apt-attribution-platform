"""Build-time parsers for Elastic prebuilt-rule queries (ADR-0015 D2).

Two query languages are parsed into one small intermediate form
(:class:`Pred` / :class:`And` / :class:`Or` / :class:`Not` / :class:`Unsupported`)
that keeps **each operator's documented case semantics** — the property Elastic's
own Python ``eql`` package loses (ADR-0015, "Parser finding").

**KQL** is parsed with Elastic's own grammar (``grammars/elastic_kql.g``, vendored
byte-for-byte) and interpreted the way Elastic's ``lib/kql`` does: a quoted value is
literal; an unquoted value with an unescaped ``*`` is a wildcard; a value that is
only ``*`` means *exists*; escapes are undone with Elastic's own tables. On a
``keyword`` field every KQL comparison is case-sensitive (a ``match`` or
``query_string`` query on an un-normalised keyword); which fields are ``keyword``
is the field map's business, not the parser's.

**EQL** is a single-event subset written here from Elastic's documented syntax:
``<category> where <condition>`` with ``and`` / ``or`` / ``not``, ``==`` / ``!=``
(case-sensitive), ``:`` (case-insensitive equality or wildcard), ``like`` /
``like~``, ``in`` / ``in~`` / ``not in``, and the string functions ``startsWith``,
``endsWith``, ``stringContains`` (case-sensitive; ``~`` forms insensitive).
Sequences, samples, pipes, ``regex``, arithmetic, ordering comparisons and every
other function parse to :class:`Unsupported` or fail to parse — both are
translation gaps, never approximations.

Wildcards: ``*`` (and, in EQL, the single-character ``?``) at the ends of a pattern
become equals / startswith / endswith / contains; any other pattern becomes the
engine's exact ``wildcard`` operator, with literal backslash, ``*`` and ``?`` escaped.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from lark import Lark, Token, Tree
from lark.exceptions import LarkError


class ElasticQueryError(ValueError):
    """The query does not parse (a translation gap for the importer)."""


# ===========================================================================
# Intermediate form
# ===========================================================================


@dataclass(frozen=True)
class Pred:
    """One positive predicate on one ECS field.

    ``operator`` is ``equals`` / ``in`` / ``startswith`` / ``endswith`` /
    ``contains`` / ``wildcard`` / ``exists``. ``value`` is a ``str`` for ``equals``,
    a tuple for ``in``, a ``str`` or a tuple (*any of*) for the substring and
    wildcard operators, ``None`` for ``exists``. ``boolean`` marks a comparison
    with a boolean literal (``value`` ``"true"`` / ``"false"``), which only a
    boolean-typed field can satisfy. ``quoted`` marks a KQL value written in
    double quotes: on an analysed ``text`` field that is a phrase."""

    field: str
    operator: str
    value: str | tuple[str, ...] | None
    case_insensitive: bool
    boolean: bool = False
    quoted: bool = False


@dataclass(frozen=True)
class Unsupported:
    detail: str


@dataclass(frozen=True)
class And:
    args: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    args: tuple[Node, ...]


@dataclass(frozen=True)
class Not:
    arg: Node


Node = Pred | Unsupported | And | Or | Not


@dataclass(frozen=True)
class ParsedQuery:
    """``category`` is the EQL event category (``None`` for KQL and ``any``)."""

    category: str | None
    expr: Node


def _or(nodes: list[Node]) -> Node:
    return nodes[0] if len(nodes) == 1 else Or(tuple(nodes))


def _and(nodes: list[Node]) -> Node:
    return nodes[0] if len(nodes) == 1 else And(tuple(nodes))


def _escape_wildcard(text: str) -> str:
    """Escape the engine's ``wildcard`` specials so ``text`` matches literally."""
    return "".join("\\" + c if c in "\\*?" else c for c in text)


def _eql_pattern(text: str) -> str:
    """An EQL ``:`` / ``like`` pattern (after string unescaping) in engine syntax:
    every ``*`` and ``?`` is a wildcard; a backslash is a literal character."""
    return text.replace("\\", "\\\\")


def _tokens(pattern: str) -> list[str]:
    """Split an engine-syntax pattern into ``*`` / ``?`` wildcard tokens and
    single literal characters (escapes undone)."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\":
            out.append("\\" + pattern[i + 1])  # a literal, still marked
            i += 2
        else:
            out.append(pattern[i])
            i += 1
    return out


def _patterns(field: str, patterns: list[str], case_insensitive: bool) -> Node:
    """Patterns on one field in the engine's ``wildcard`` syntax (``*`` any run,
    ``?`` one character, backslash escapes), grouped by shape: edge-only ``*``
    becomes equals / startswith / endswith / contains, a pattern of only ``*``
    becomes *exists*, anything else the exact ``wildcard`` operator."""
    by_operator: dict[str, list[str]] = {}
    nodes: list[Node] = []
    for pattern in patterns:
        tokens = _tokens(pattern)
        if all(t == "*" for t in tokens):
            nodes.append(
                Pred(field, "exists", None, False) if tokens else Unsupported("empty_value")
            )
            continue
        lead, trail = tokens[0] == "*", tokens[-1] == "*"
        inner = tokens[1 if lead else 0 : len(tokens) - 1 if trail else len(tokens)]
        if any(t in ("*", "?") for t in inner):
            by_operator.setdefault("wildcard", []).append(pattern)
            continue
        core = "".join(t[-1] for t in inner)
        if not core.strip():
            nodes.append(Unsupported("blank_value"))
            continue
        operator = {
            (False, False): "equals",
            (False, True): "startswith",
            (True, False): "endswith",
            (True, True): "contains",
        }[(lead, trail)]
        by_operator.setdefault(operator, []).append(core)
    for operator in ("equals", "startswith", "endswith", "contains", "wildcard"):
        values = by_operator.get(operator)
        if not values:
            continue
        unique = tuple(dict.fromkeys(values))
        if operator == "equals":
            nodes.append(
                Pred(field, "equals", unique[0], case_insensitive)
                if len(unique) == 1
                else Pred(field, "in", unique, case_insensitive)
            )
        else:
            nodes.append(
                Pred(field, operator, unique[0] if len(unique) == 1 else unique, case_insensitive)
            )
    return _or(nodes)


def _literals(field: str, values: list[str], case_insensitive: bool) -> Node:
    """Exact values (no wildcard meaning) on one field."""
    if any(v == "" for v in values):
        return Unsupported("empty_value")
    unique = tuple(dict.fromkeys(values))
    if len(unique) == 1:
        return Pred(field, "equals", unique[0], case_insensitive)
    return Pred(field, "in", unique, case_insensitive)


# ===========================================================================
# KQL (Elastic's grammar)
# ===========================================================================

_KQL_GRAMMAR = files("attribution_platform.detection_content").joinpath("grammars/elastic_kql.g")
_kql_parser: Lark | None = None

# Elastic lib/kql/parser.py BaseKqlParser escape tables, reproduced exactly.
_KQL_UNQUOTED_ESCAPES = {"\\t": "\t", "\\r": "\r", "\\n": "\n"}
for _special in '\\():<>"*{}]':
    _KQL_UNQUOTED_ESCAPES["\\" + _special] = _special
_KQL_UNQUOTED_RE = re.compile(
    "(" + "|".join(re.escape(e) for e in sorted(_KQL_UNQUOTED_ESCAPES)) + ")"
)
_KQL_QUOTED_ESCAPES = {"\\t": "\t", "\\r": "\r", "\\n": "\n", "\\\\": "\\", '\\"': '"'}
_KQL_QUOTED_RE = re.compile("(" + "|".join(re.escape(e) for e in sorted(_KQL_QUOTED_ESCAPES)) + ")")


def _kql() -> Lark:
    global _kql_parser
    if _kql_parser is None:
        _kql_parser = Lark(_KQL_GRAMMAR.read_text(encoding="utf-8"), start="query", parser="lalr")
    return _kql_parser


def _has_unescaped_wildcard(text: str) -> bool:
    escaped = False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "*":
            return True
    return False


def _kql_scalar(token: Token) -> tuple[str, Any]:
    """``(kind, value)``: kind is ``string`` / ``wildcard`` / ``number`` / ``other``."""
    text = str(token)
    if token.type == "QUOTED_STRING":
        return "string", _KQL_QUOTED_RE.sub(lambda m: _KQL_QUOTED_ESCAPES[m.group()], text[1:-1])
    if token.type == "WILDCARD_LITERAL" or _has_unescaped_wildcard(text):
        # Engine wildcard syntax: an unescaped '*' is the wildcard; an escape pair
        # (Elastic's table, scanned left to right exactly as its re.sub does) is
        # its literal character, as Kibana treats an escaped '\*'; KQL has no
        # single-character wildcard, so '?' is literal.
        parts: list[str] = []
        for index, piece in enumerate(_KQL_UNQUOTED_RE.split(text)):
            if index % 2:  # a captured escape pair
                parts.append(_escape_wildcard(_KQL_UNQUOTED_ESCAPES[piece]))
            else:
                parts.append("".join(c if c == "*" else _escape_wildcard(c) for c in piece))
        return "wildcard", "".join(parts)
    if text in ("true", "false"):
        return "boolean", text
    if text == "null":
        return "other", "literal_null"
    for numeric in (int, float):
        try:
            return "number", str(numeric(text))
        except ValueError:
            pass
    return "string", _KQL_UNQUOTED_RE.sub(lambda m: _KQL_UNQUOTED_ESCAPES[m.group()], text)


def _kql_field(tree: Tree[Any]) -> str | None:
    literal = tree.children[0]
    token = literal.children[0] if isinstance(literal, Tree) else literal
    if not isinstance(token, Token):
        return None
    kind, value = _kql_scalar(token)
    if kind != "string" or "*" in str(value):
        return None
    return str(value)


def _kql_values(field: str, node: Any) -> Node:
    if isinstance(node, Token):
        kind, value = _kql_scalar(node)
        if kind == "wildcard":
            return _patterns(field, [value], False)
        if kind in ("string", "number"):
            literal = _literals(field, [value], False)
            if node.type == "QUOTED_STRING" and isinstance(literal, Pred):
                return dataclasses.replace(literal, quoted=True)
            return literal
        if kind == "boolean":
            return Pred(field, "equals", value, False, boolean=True)
        return Unsupported(value)
    if node.data == "value":
        return _kql_values(field, node.children[0])
    if node.data == "or_list_of_values":
        return _or([_kql_values(field, c) for c in node.children if isinstance(c, Tree)])
    if node.data == "and_list_of_values":
        return _and([_kql_values(field, c) for c in node.children if isinstance(c, Tree)])
    if node.data in ("not_list_of_values", "list_of_values"):
        trees = [c for c in node.children if isinstance(c, Tree)]
        nots = sum(1 for c in node.children if isinstance(c, Token) and c.type == "NOT") + sum(
            _kql_not_count(c) for c in trees if c.data == "optional_not"
        )
        inner = next(c for c in reversed(trees) if c.data != "optional_not")
        result = _kql_values(field, inner)
        for _ in range(nots):
            result = Not(result)
        return result
    return Unsupported(f"kql:{node.data}")


def _kql_not_count(node: Tree[Any]) -> int:
    return sum(
        1 if isinstance(c, Token) and c.type == "NOT" else _kql_not_count(c)
        for c in node.children
        if isinstance(c, Token) or c.data == "optional_not"
    )


def _kql_node(node: Any) -> Node:
    if isinstance(node, Token):
        return Unsupported("kql:free_text")
    data = node.data
    trees = [c for c in node.children if isinstance(c, Tree)]
    tokens = [c for c in node.children if isinstance(c, Token)]
    if any(t.type in ("OR", "AND", "NOT") and str(t) != str(t).lower() for t in tokens):
        return Unsupported("kql:uppercase_keyword")
    if data == "or_query":
        return _or([_kql_node(c) for c in trees])
    if data == "and_query":
        return _and([_kql_node(c) for c in trees])
    if data == "not_query":
        return Not(_kql_node(trees[-1]))
    if data == "field_value_expression":
        field = _kql_field(trees[0])
        if field is None:
            return Unsupported("kql:field_name")
        return _kql_values(field, trees[1])
    if data == "field_range_expression":
        return Unsupported("kql:range")
    if data == "nested_query":
        return Unsupported("kql:nested")
    if data == "value":
        return Unsupported("kql:free_text")
    return Unsupported(f"kql:{data}")


def parse_kql(text: str) -> ParsedQuery:
    """Parse a KQL query with Elastic's grammar into the intermediate form."""
    if not text.strip():
        raise ElasticQueryError("empty KQL query")
    try:
        tree = _kql().parse(text)
    except LarkError as exc:
        raise ElasticQueryError(f"KQL does not parse: {type(exc).__name__}") from exc
    return ParsedQuery(category=None, expr=_kql_node(tree))


# ===========================================================================
# EQL (single-event subset)
# ===========================================================================

_EQL_GRAMMAR = r'''
start: CATEGORY "where" expr

?expr: disj
?disj: conj | disj "or" conj -> or_
?conj: neg | conj "and" neg -> and_
?neg: "not" neg -> not_
    | pred
?pred: atom
     | atom COMPARE value -> compare
     | atom "in" TILDE? "(" literal_list ")" -> in_
     | atom "not" "in" TILDE? "(" literal_list ")" -> not_in
     | atom ":" match_rhs -> colon
     | atom "like" TILDE? match_rhs -> like
     | atom "regex" TILDE? match_rhs -> regex
?match_rhs: literal | "(" literal_list ")"
literal_list: literal ("," literal)*
?value: literal | field | call
?atom: field | call | literal | "(" expr ")"
call: NAME TILDE? "(" [arg_list] ")"
arg_list: value ("," value)*
field: OPTIONAL? NAME | ESCAPED_NAME
?literal: string | NUMBER -> number | "true" -> true | "false" -> false | "null" -> null
string: STRING | TRIPLE_STRING | RAW_STRING

CATEGORY: /[A-Za-z_][A-Za-z0-9_]*/ | /"[A-Za-z_][A-Za-z0-9_]*"/
COMPARE: "==" | "!=" | "<=" | ">=" | "<" | ">"
TILDE: "~"
OPTIONAL: "?"
NAME: /[A-Za-z_@][A-Za-z0-9_@]*(\.[A-Za-z0-9_@]+)*/
ESCAPED_NAME: /`[^`\r\n]+`/
NUMBER: /-?\d+(\.\d+)?/
TRIPLE_STRING.3: /"""(.|\n)*?"""/
RAW_STRING.2: /\?"[^"\r\n]*"/
STRING: /"(\\.|[^"\\\r\n])*"/

COMMENT: /\/\/[^\n]*/ | /\/\*(.|\n)*?\*\//
%ignore COMMENT
%ignore /\s+/
'''

_eql_parser: Lark | None = None
_EQL_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "'": "'", "\\": "\\"}
_STRING_FUNCTIONS = {
    "startswith": "startswith",
    "endswith": "endswith",
    "stringcontains": "contains",
}


def _eql() -> Lark:
    global _eql_parser
    if _eql_parser is None:
        _eql_parser = Lark(_EQL_GRAMMAR, start="start", parser="lalr")
    return _eql_parser


def _eql_string(token: Token) -> str:
    text = str(token)
    if token.type == "TRIPLE_STRING":
        return text[3:-3]
    if token.type == "RAW_STRING":
        return text[2:-1]
    body = text[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        char = body[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in _EQL_ESCAPES:
            out.append(_EQL_ESCAPES[nxt])
            i += 2
            continue
        match = re.match(r"u\{([0-9A-Fa-f]{2,8})\}", body[i + 1 :])
        if match:
            out.append(chr(int(match.group(1), 16)))
            i += 1 + match.end()
            continue
        raise ElasticQueryError(f"invalid EQL escape \\{nxt}")
    return "".join(out)


def _eql_literal(node: Any) -> tuple[str, str | None]:
    """``(kind, value)``: kind is ``string`` / ``number`` / ``null`` / ``other``."""
    if isinstance(node, Tree):
        if node.data == "string" and isinstance(node.children[0], Token):
            return "string", _eql_string(node.children[0])
        if node.data == "number":
            return "number", str(node.children[0])
        if node.data == "null":
            return "null", None
        if node.data in ("true", "false"):
            return "boolean", node.data
    return "other", None


def _eql_field(node: Any) -> str | None:
    if isinstance(node, Tree) and node.data == "field":
        name = str(node.children[-1])
        return name[1:-1] if name.startswith("`") else name
    return None


def _strings(nodes: list[Any]) -> list[str] | None:
    values: list[str] = []
    for node in nodes:
        kind, value = _eql_literal(node)
        if kind not in ("string", "number") or value is None:
            return None
        values.append(value)
    return values


def _eql_node(node: Any) -> Node:
    if not isinstance(node, Tree):
        return Unsupported("eql:token")
    data = node.data
    children = node.children
    if data == "or_":
        return Or((_eql_node(children[0]), _eql_node(children[1])))
    if data == "and_":
        return And((_eql_node(children[0]), _eql_node(children[1])))
    if data == "not_":
        return Not(_eql_node(children[0]))
    if data == "call":
        return _eql_call(node)
    if data in ("compare", "in_", "not_in", "colon", "like", "regex"):
        field = _eql_field(children[0])
        if field is None:
            return Unsupported(f"eql:{data}_on_expression")
        tilde = any(isinstance(c, Token) and c.type == "TILDE" for c in children)
        rest = [c for c in children[1:] if not (isinstance(c, Token) and c.type == "TILDE")]
        if data == "regex":
            return Unsupported("eql:regex")
        if data == "compare":
            operator, rhs = str(rest[0]), rest[1]
            if operator not in ("==", "!="):
                return Unsupported("eql:ordering_comparison")
            kind, value = _eql_literal(rhs)
            if kind == "null":
                exists = Pred(field, "exists", None, False)
                return exists if operator == "!=" else Not(exists)
            if kind == "boolean" and value is not None:
                boolean = Pred(field, "equals", value, False, boolean=True)
                return boolean if operator == "==" else Not(boolean)
            if kind not in ("string", "number") or value is None:
                return Unsupported("eql:compare_non_literal")
            if kind == "string" and value == "":
                return Unsupported("empty_value")
            pred = Pred(field, "equals", value, False)
            return pred if operator == "==" else Not(pred)
        rhs_nodes = (
            rest[0].children
            if isinstance(rest[0], Tree) and rest[0].data == ("literal_list")
            else [rest[0]]
        )
        values = _strings(rhs_nodes)
        if values is None:
            return Unsupported(f"eql:{data}_non_string")
        if data in ("in_", "not_in"):
            result = _literals(field, values, tilde)
            return Not(result) if data == "not_in" else result
        # ':' and 'like': '*' and '?' are wildcards; ':' and 'like~' are insensitive.
        return _patterns(
            field,
            [_eql_pattern(v) for v in values],
            case_insensitive=(data == "colon" or tilde),
        )
    return Unsupported(f"eql:{data}")


def _eql_call(node: Tree[Any]) -> Node:
    name = str(node.children[0])
    tilde = any(isinstance(c, Token) and c.type == "TILDE" for c in node.children)
    operator = _STRING_FUNCTIONS.get(name.lower())
    if operator is None:
        return Unsupported(f"eql:function:{name.lower()}")
    arg_list = next((c for c in node.children if isinstance(c, Tree)), None)
    args = list(arg_list.children) if arg_list is not None else []
    field = _eql_field(args[0]) if args else None
    values = _strings(args[1:]) if len(args) > 1 else None
    if field is None or not values:
        return Unsupported(f"eql:function_args:{name.lower()}")
    if any(v == "" for v in values):
        return Unsupported("empty_value")
    unique = tuple(dict.fromkeys(values))
    return Pred(field, operator, unique[0] if len(unique) == 1 else unique, tilde)


def is_single_event_eql(text: str) -> bool:
    """False for ``sequence`` / ``sample`` queries and pipes (multi-event)."""
    stripped = re.sub(r"//[^\n]*|/\*(.|\n)*?\*/", "", text).lstrip()
    return not re.match(r"(sequence|sample)\b", stripped)


def parse_eql(text: str) -> ParsedQuery:
    """Parse a single-event EQL query into the intermediate form."""
    if not is_single_event_eql(text):
        raise ElasticQueryError("multi-event EQL (sequence / sample)")
    try:
        tree = _eql().parse(text)
    except LarkError as exc:
        raise ElasticQueryError(f"EQL does not parse: {type(exc).__name__}") from exc
    category = str(tree.children[0]).strip('"')
    return ParsedQuery(
        category=None if category == "any" else category, expr=_eql_node(tree.children[1])
    )


__all__ = [
    "ElasticQueryError",
    "Pred",
    "Unsupported",
    "And",
    "Or",
    "Not",
    "Node",
    "ParsedQuery",
    "parse_kql",
    "parse_eql",
    "is_single_event_eql",
]
