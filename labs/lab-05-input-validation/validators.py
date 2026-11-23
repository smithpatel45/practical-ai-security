"""Lab 05: input validation for LLM applications, and its limits.

Validation is worth doing: it bounds cost, removes invisible characters that hide
instructions from human reviewers, and enforces structure on fields that should be
structured. But it cannot decide whether free text "contains an instruction"; natural
language has no grammar for that. This module implements the useful parts and includes
a deliberately naive injection heuristic so you can watch it fail.

Usage:
    python validators.py
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

MAX_CHARS = 2000
# Zero-width, bidirectional-override and other format characters often used to hide text.
INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
CONTROL = re.compile(r"[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]")
ORDER_ID = re.compile(r"^ORD-\d{6}$")
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
CATEGORIES = {"billing", "shipping", "returns", "technical"}
NAIVE_INJECTION = re.compile(r"ignore (all )?(previous|prior) instructions|system prompt|you are now", re.I)


@dataclass
class Validation:
    ok: bool
    cleaned: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def normalize_text(text: str) -> tuple[str, list[str]]:
    """NFKC-normalize, remove invisible and control characters. Returns (text, warnings)."""
    warnings = []
    norm = unicodedata.normalize("NFKC", text)
    if norm != text:
        warnings.append("text changed by Unicode normalization (look-alike or full-width characters)")
    hidden = INVISIBLE.findall(norm)
    if hidden:
        warnings.append(f"removed {len(hidden)} invisible formatting character(s)")
    norm = INVISIBLE.sub("", norm)
    norm = CONTROL.sub("", norm)
    return norm.strip(), warnings


def validate_ticket(raw: dict) -> Validation:
    """Validate a support-ticket submission before any of it reaches a model."""
    v = Validation(ok=True)
    if not isinstance(raw, dict):
        return Validation(False, errors=["payload must be an object"])
    unknown = set(raw) - {"email", "order_id", "category", "message"}
    if unknown:
        v.errors.append(f"unexpected fields: {sorted(unknown)}")

    email = str(raw.get("email", "")).strip()
    if not EMAIL.match(email):
        v.errors.append("email is not a valid address")
    order = str(raw.get("order_id", "")).strip().upper()
    if not ORDER_ID.match(order):
        v.errors.append("order_id must look like ORD-123456")
    category = str(raw.get("category", "")).strip().lower()
    if category not in CATEGORIES:
        v.errors.append(f"category must be one of {sorted(CATEGORIES)}")

    message = raw.get("message", "")
    if not isinstance(message, str):
        v.errors.append("message must be text")
        message = ""
    message, warns = normalize_text(message)
    v.warnings += warns
    if not message:
        v.errors.append("message is empty")
    if len(message) > MAX_CHARS:
        v.errors.append(f"message exceeds {MAX_CHARS} characters")
    if NAIVE_INJECTION.search(message):
        # A signal for monitoring, not a reason to trust everything that doesn't match.
        v.warnings.append("message matches a known injection phrase (logged for review)")

    v.ok = not v.errors
    v.cleaned = {"email": email, "order_id": order, "category": category, "message": message}
    return v


def main() -> int:
    cases = json.loads((Path(__file__).parent / "data" / "inputs.json").read_text(encoding="utf-8"))
    for case in cases:
        if "repeat" in case:  # build long test strings instead of storing them in the JSON
            text, times = case["repeat"]
            case["payload"]["message"] = text * times
        v = validate_ticket(case["payload"])
        print(f"== {case['name']}")
        print(f"   accepted: {v.ok}")
        for e in v.errors:
            print(f"   error  : {e}")
        for w in v.warnings:
            print(f"   warning: {w}")
        if v.ok:
            print(f"   message passed to model: {v.cleaned['message'][:90]!r}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
