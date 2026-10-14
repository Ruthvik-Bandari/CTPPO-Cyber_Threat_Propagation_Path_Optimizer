"""Parser for the bounded single-event Sigma subset (plan section 5, "Version one semantics").

Supported: one process_creation/windows rule, named map selections, exact / contains /
startswith / endswith string matching with value lists, and conditions built from
selection names with ``and``, ``or``, ``not`` and parentheses. Everything else is
rejected with a reason code before conversion.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

import yaml

from ..core.errors import Reason, Rejected
from ..core.safe_load import load_yaml

Modifier = Literal["equals", "contains", "startswith", "endswith"]
SUPPORTED_MODIFIERS: frozenset[str] = frozenset({"contains", "startswith", "endswith"})

# Sysmon EventID 1 field names accepted in version one.
PROCESS_CREATION_FIELDS: frozenset[str] = frozenset(
    {
        "Image",
        "OriginalFileName",
        "CommandLine",
        "CurrentDirectory",
        "User",
        "LogonId",
        "IntegrityLevel",
        "Hashes",
        "Product",
        "Company",
        "Description",
        "FileVersion",
        "ParentImage",
        "ParentCommandLine",
        "ParentUser",
        "ProcessId",
        "ParentProcessId",
    }
)

MAX_SELECTIONS = 32
MAX_VALUES = 64
MAX_VALUE_CHARS = 4096
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*|\S+)")
_RESERVED = frozenset({"and", "or", "not", "of", "them", "all"})


@dataclass(frozen=True)
class Predicate:
    field: str
    modifier: Modifier
    values: tuple[str, ...]

    @property
    def key(self) -> str:
        return self.field if self.modifier == "equals" else f"{self.field}|{self.modifier}"


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    operand: Cond


@dataclass(frozen=True)
class And:
    operands: tuple[Cond, ...]


@dataclass(frozen=True)
class Or:
    operands: tuple[Cond, ...]


Cond = Ref | Not | And | Or


@dataclass(frozen=True)
class Rule:
    """Validated rule. ``sha256`` is over the exact source bytes."""

    title: str
    rule_id: str | None
    selections: dict[str, tuple[Predicate, ...]]
    condition: Cond
    meta: dict[str, object]
    source: str
    sha256: str

    @property
    def fields(self) -> frozenset[str]:
        return frozenset(p.field for preds in self.selections.values() for p in preds)

    def to_yaml(self) -> str:
        """Serialize to canonical Sigma YAML (used for patched rules)."""
        doc: dict[str, object] = {"title": self.title}
        if self.rule_id:
            doc["id"] = self.rule_id
        doc.update(self.meta)
        doc["logsource"] = {"category": "process_creation", "product": "windows"}
        detection: dict[str, object] = {}
        for name, preds in self.selections.items():
            detection[name] = {p.key: list(p.values) if len(p.values) > 1 else p.values[0] for p in preds}
        detection["condition"] = render_condition(self.condition)
        doc["detection"] = detection
        return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def render_condition(cond: Cond, parent: type | None = None) -> str:
    match cond:
        case Ref(name):
            return name
        case Not(operand):
            return f"not {render_condition(operand, Not)}"
        case And(ops) | Or(ops):
            word = " and " if isinstance(cond, And) else " or "
            text = word.join(render_condition(o, type(cond)) for o in ops)
            return f"({text})" if parent is not None and parent is not type(cond) else text
    raise TypeError(cond)


def condition_refs(cond: Cond) -> set[str]:
    match cond:
        case Ref(name):
            return {name}
        case Not(operand):
            return condition_refs(operand)
        case And(ops) | Or(ops):
            return set().union(*(condition_refs(o) for o in ops))
    raise TypeError(cond)


def parse_condition(text: str) -> Cond:
    """Recursive descent: or -> and -> not -> atom. Precedence: not > and > or."""
    tokens = [m.group(1) for m in _TOKEN.finditer(text)]
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = peek()
        if tok is None:
            raise Rejected(Reason.UNSUPPORTED_CONDITION, "unexpected end of condition")
        pos += 1
        return tok

    def parse_or() -> Cond:
        ops = [parse_and()]
        while peek() == "or":
            take()
            ops.append(parse_and())
        return ops[0] if len(ops) == 1 else Or(tuple(ops))

    def parse_and() -> Cond:
        ops = [parse_not()]
        while peek() == "and":
            take()
            ops.append(parse_not())
        return ops[0] if len(ops) == 1 else And(tuple(ops))

    def parse_not() -> Cond:
        if peek() == "not":
            take()
            return Not(parse_not())
        return parse_atom()

    def parse_atom() -> Cond:
        tok = take()
        if tok == "(":
            inner = parse_or()
            if take() != ")":
                raise Rejected(Reason.UNSUPPORTED_CONDITION, "unbalanced parentheses")
            return inner
        if not _NAME.fullmatch(tok) or tok in _RESERVED:
            raise Rejected(Reason.UNSUPPORTED_CONDITION, f"unsupported token {tok!r}")
        return Ref(tok)

    if not tokens:
        raise Rejected(Reason.INVALID_RULE, "empty condition")
    result = parse_or()
    if pos != len(tokens):
        raise Rejected(Reason.UNSUPPORTED_CONDITION, f"unsupported token {tokens[pos]!r}")
    return result


def has_wildcard(value: str) -> bool:
    """True if a Sigma string contains an unescaped ``*`` or ``?``. Sigma escapes are ``\\*``,
    ``\\?`` and ``\\\\``; any other backslash is literal."""
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            i += 2
            continue
        if value[i] in "*?":
            return True
        i += 1
    return False


def sigma_escape(raw: str) -> str:
    """Encode a raw event value as a plain Sigma string that matches it literally."""
    out = []
    for i, ch in enumerate(raw):
        if ch in "*?":
            out.append("\\" + ch)
        elif ch == "\\" and (i + 1 == len(raw) or raw[i + 1] in "*?\\"):
            out.append("\\\\")
        else:
            out.append(ch)
    return "".join(out)


def _parse_value(field: str, value: object) -> str:
    if value is None:
        raise Rejected(Reason.UNSUPPORTED_VALUE, f"{field}: null matching is not supported in v1")
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Rejected(Reason.UNSUPPORTED_VALUE, f"{field}: {type(value).__name__} values are not supported")
    text = str(value)
    if not text or len(text) > MAX_VALUE_CHARS:
        raise Rejected(Reason.UNSUPPORTED_VALUE, f"{field}: empty or oversized value")
    if has_wildcard(text):
        raise Rejected(Reason.UNSUPPORTED_WILDCARD, f"{field}: wildcard values are not supported in v1")
    return text


def _parse_selection(name: str, body: object) -> tuple[Predicate, ...]:
    if not isinstance(body, dict) or not body:
        raise Rejected(Reason.UNSUPPORTED_SELECTION_FORM, f"{name}: only non-empty field maps are supported")
    preds = []
    for key, raw in body.items():
        if not isinstance(key, str):
            raise Rejected(Reason.INVALID_RULE, f"{name}: field keys must be strings")
        field, *mods = key.split("|")
        if field not in PROCESS_CREATION_FIELDS:
            raise Rejected(Reason.UNKNOWN_FIELD, f"{name}: field {field!r} is not a supported process_creation field")
        if len(mods) > 1 or (mods and mods[0] not in SUPPORTED_MODIFIERS):
            raise Rejected(Reason.UNSUPPORTED_MODIFIER, f"{name}: modifier {'|'.join(mods)!r} is not supported")
        items = raw if isinstance(raw, list) else [raw]
        if not items or len(items) > MAX_VALUES:
            raise Rejected(Reason.UNSUPPORTED_VALUE, f"{name}.{field}: 1..{MAX_VALUES} values required")
        preds.append(Predicate(field, mods[0] if mods else "equals", tuple(_parse_value(field, v) for v in items)))  # type: ignore[arg-type]
    return tuple(preds)


def parse_rule(source: str) -> Rule:
    doc = load_yaml(source)
    if not isinstance(doc, dict):
        raise Rejected(Reason.INVALID_RULE, "rule must be a mapping")
    for meta_key in ("correlation", "filter", "action"):
        if meta_key in doc:
            raise Rejected(Reason.UNSUPPORTED_RULE_TYPE, f"{meta_key} rules are not supported")
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        raise Rejected(Reason.INVALID_RULE, "title is required")
    logsource = doc.get("logsource")
    if (
        not isinstance(logsource, dict)
        or logsource.get("category") != "process_creation"
        or logsource.get("product") != "windows"
    ):
        raise Rejected(Reason.UNSUPPORTED_LOGSOURCE, "only logsource process_creation/windows is supported")
    if set(logsource) - {"category", "product", "service", "definition"} or logsource.get("service"):
        raise Rejected(Reason.UNSUPPORTED_LOGSOURCE, "logsource service and custom keys are not supported")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise Rejected(Reason.INVALID_RULE, "detection must be a mapping")
    if "timeframe" in detection:
        raise Rejected(Reason.UNSUPPORTED_RULE_TYPE, "timeframe/aggregation is not supported")
    condition_text = detection.get("condition")
    if not isinstance(condition_text, str):
        raise Rejected(Reason.UNSUPPORTED_CONDITION, "condition must be a single string")
    if "|" in condition_text:
        raise Rejected(Reason.UNSUPPORTED_CONDITION, "aggregation pipes are not supported")

    selections: dict[str, tuple[Predicate, ...]] = {}
    for name, body in detection.items():
        if name == "condition":
            continue
        # pySigma's grammar reads a leading and/or/not as an operator even inside a longer name.
        if (
            not isinstance(name, str)
            or not _NAME.fullmatch(name)
            or name.lower().startswith(("and", "or", "not"))
            or name in _RESERVED
        ):
            raise Rejected(Reason.INVALID_RULE, f"invalid selection name {name!r}")
        selections[name] = _parse_selection(name, body)
    if not selections or len(selections) > MAX_SELECTIONS:
        raise Rejected(Reason.INVALID_RULE, f"1..{MAX_SELECTIONS} selections required")

    condition = parse_condition(condition_text)
    undefined = condition_refs(condition) - selections.keys()
    if undefined:
        raise Rejected(Reason.UNDEFINED_SELECTION, f"condition references {sorted(undefined)}")

    meta = {
        k: v
        for k, v in doc.items()
        if k in ("status", "description", "author", "level", "tags", "references", "falsepositives")
    }
    rule_id = doc.get("id")
    return Rule(
        title=title,
        rule_id=str(rule_id) if rule_id is not None else None,
        selections=selections,
        condition=condition,
        meta=meta,
        source=source,
        sha256=sha256_text(source),
    )
