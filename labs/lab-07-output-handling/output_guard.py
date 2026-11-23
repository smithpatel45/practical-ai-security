"""Lab 07: treat model output as untrusted input to whatever consumes it next.

Three consumers, three controls:
  1. Browser   -> escape HTML, remove images, allowlist link hosts, block javascript: URLs.
  2. Tools     -> validate every proposed tool call against a strict schema before running it.
  3. Database  -> never execute model-written SQL; translate a structured filter into a
                  parameterized query over allowlisted columns.

Usage:
    python output_guard.py
"""
from __future__ import annotations

import html
import json
import re
import sqlite3
import sys
from pathlib import Path

# --------------------------------------------------------------------------- 1. rendering
ALLOWED_HOSTS = {"help.northwind.example"}
# URL part allows one level of balanced parentheses, e.g. javascript:alert(1)
_URL = r"((?:[^()\s]|\([^()\s]*\))+)"
_IMAGE = re.compile(r"!\[([^\]]*)\]\(" + _URL + r"\)")
_LINK = re.compile(r"\[([^\]]*)\]\(" + _URL + r"\)")
_PLACEHOLDERS = re.compile("[\u0000-\u0002]")


def _host(url: str) -> str | None:
    m = re.match(r"^https://([^/?#:]+)", url, re.I)
    return m.group(1).lower() if m else None


def render_safe(model_text: str) -> str:
    """Return HTML that is safe to insert into a page."""
    def image(m):
        return f"[image removed: {m.group(1)}]"

    def link(m):
        text, url = m.group(1), m.group(2)
        if _host(url) in ALLOWED_HOSTS:
            return f"\u0000A{html.escape(url, quote=True)}\u0001{html.escape(text)}\u0002"
        return f"{text} (link removed)"

    # Strip the internal placeholder characters first, so model output can't forge a vetted link.
    text = _IMAGE.sub(image, _PLACEHOLDERS.sub("", model_text))
    text = _LINK.sub(link, text)
    text = html.escape(text)                     # everything else becomes inert text
    # Re-insert the vetted links as real anchors (only https, allowlisted hosts).
    return re.sub("\u0000A([^\u0001]*)\u0001([^\u0002]*)\u0002",
                  r'<a href="\1" rel="noopener noreferrer">\2</a>', text)


def render_unsafe(model_text: str) -> str:
    """What many apps do: convert Markdown links/images to HTML and trust the rest."""
    text = _IMAGE.sub(r'<img src="\2" alt="\1">', model_text)
    return _LINK.sub(r'<a href="\2">\1</a>', text)


# --------------------------------------------------------------------------- 2. tool calls
TOOLS = {
    "lookup_order": {"order_id": {"type": str, "pattern": r"^ORD-\d{6}$", "required": True}},
    "issue_refund": {"order_id": {"type": str, "pattern": r"^ORD-\d{6}$", "required": True},
                     "amount": {"type": (int, float), "min": 0.01, "max": 100.0, "required": True}},
    "set_ticket_status": {"ticket_id": {"type": int, "min": 1, "required": True},
                          "status": {"type": str, "enum": {"open", "pending", "resolved"}, "required": True}},
}


class ToolCallRejected(ValueError):
    pass


def validate_tool_call(raw: str) -> dict:
    """Parse and validate a model-proposed tool call. Raises ToolCallRejected."""
    try:
        call = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ToolCallRejected(f"not valid JSON: {exc.msg}") from None
    if not isinstance(call, dict) or set(call) != {"tool", "arguments"}:
        raise ToolCallRejected("expected exactly {'tool', 'arguments'}")
    schema = TOOLS.get(call["tool"])
    if schema is None:
        raise ToolCallRejected(f"unknown tool {call['tool']!r}")
    args = call["arguments"]
    if not isinstance(args, dict):
        raise ToolCallRejected("arguments must be an object")
    extra = set(args) - set(schema)
    if extra:
        raise ToolCallRejected(f"unexpected arguments {sorted(extra)}")
    for name, rule in schema.items():
        if name not in args:
            if rule.get("required"):
                raise ToolCallRejected(f"missing argument {name!r}")
            continue
        value = args[name]
        if isinstance(value, bool) or not isinstance(value, rule["type"]):
            raise ToolCallRejected(f"{name} has the wrong type")
        if "pattern" in rule and not re.fullmatch(rule["pattern"], value):
            raise ToolCallRejected(f"{name} has an invalid format")
        if "enum" in rule and value not in rule["enum"]:
            raise ToolCallRejected(f"{name} must be one of {sorted(rule['enum'])}")
        if "min" in rule and value < rule["min"] or "max" in rule and value > rule["max"]:
            raise ToolCallRejected(f"{name} out of allowed range")
    return call


# --------------------------------------------------------------------------- 3. database
def make_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE orders (id TEXT, customer TEXT, status TEXT, total REAL)")
    db.executemany("INSERT INTO orders VALUES (?,?,?,?)", [
        ("ORD-100001", "sam@example.org", "shipped", 42.0),
        ("ORD-100002", "lee@example.org", "pending", 310.5),
        ("ORD-100003", "kim@example.org", "shipped", 18.9),
    ])
    return db


def query_unsafe(db: sqlite3.Connection, model_where_clause: str) -> list[tuple]:
    """Executes SQL text produced by a model. Don't do this."""
    return db.execute(f"SELECT id, customer FROM orders WHERE {model_where_clause}").fetchall()


ALLOWED_FILTERS = {"status": {"=", "!="}, "total": {"<", ">", "="}}


def query_safe(db: sqlite3.Connection, user_email: str, model_filter_json: str) -> list[tuple]:
    """The model proposes a structured filter; code builds a parameterized query that is
    always scoped to the signed-in user's own orders."""
    spec = json.loads(model_filter_json)
    clauses, params = ["customer = ?"], [user_email]          # scope fixed by code, not model
    for cond in spec.get("filters", []):
        col, op, val = cond.get("column"), cond.get("op"), cond.get("value")
        if col not in ALLOWED_FILTERS or op not in ALLOWED_FILTERS[col]:
            raise ValueError(f"filter on {col!r} with {op!r} is not allowed")
        clauses.append(f"{col} {op} ?")                       # col/op come from the allowlist
        params.append(val)
    sql = "SELECT id, customer FROM orders WHERE " + " AND ".join(clauses)
    return db.execute(sql, params).fetchall()


# --------------------------------------------------------------------------- demo
def demo() -> None:
    samples = json.loads((Path(__file__).parent / "data" / "model_outputs.json").read_text(encoding="utf-8"))
    print("== 1. Rendering untrusted model output")
    for sample in samples["render"]:
        print("   model :", sample)
        print("   unsafe:", render_unsafe(sample))
        print("   safe  :", render_safe(sample))
    print()
    print("== 2. Validating proposed tool calls")
    for raw in samples["tool_calls"]:
        try:
            validate_tool_call(raw)
            print("   ACCEPT:", raw)
        except ToolCallRejected as exc:
            print("   REJECT:", raw[:70], "->", exc)
    print()
    print("== 3. Database queries from model output")
    db = make_db()
    print("   unsafe (model wrote SQL):", query_unsafe(db, samples["sql_injected_where"]))
    print("   safe (structured filter):", query_safe(db, "sam@example.org", samples["safe_filter"]))
    try:
        query_safe(db, "sam@example.org", samples["forbidden_filter"])
    except ValueError as exc:
        print("   safe rejects:", exc)


if __name__ == "__main__":
    demo()
    sys.exit(0)
