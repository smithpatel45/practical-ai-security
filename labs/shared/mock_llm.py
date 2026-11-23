"""A deterministic mock language model for the Practical AI Security labs.

This is NOT a real language model and makes no claim to behave like one in general.
It reproduces, on purpose and predictably, two behaviors that matter for security
teaching:

1. It works from the text it is given: it can summarize a document, answer a question
   from supplied context, or propose a tool call when tools are offered.
2. Like real LLMs, it has no reliable way to tell the application's instructions apart
   from instructions hidden inside data. If any text it processes contains an
   instruction-like directive (see ``DIRECTIVE_MARKERS``), it obeys the most recent
   one. That is the failure mode behind prompt injection.

Because the second behavior is deterministic here, the labs can show exactly which
defenses work *outside* the model (access control, output handling, tool policy,
data minimization). Defenses that rely on the model "deciding" to resist are not
simulated, by design: real models don't reliably provide that guarantee either.

Standard library only. Python 3.11+.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Phrases that the mock treats as an instruction to obey, wherever they appear.
DIRECTIVE_MARKERS = [
    r"ignore (?:all |any )?(?:previous|prior|above) instructions[.:,]?",
    r"system override:",
    r"new instructions:",
    r"<!--\s*ai:",
    r"note to (?:the )?(?:ai|assistant):",
]
_MARKER_RE = re.compile("|".join(DIRECTIVE_MARKERS), re.IGNORECASE)
_SECRET_RE = re.compile(r"(?:SECRET|API_KEY|PASSWORD|TOKEN)\s*[:=]\s*(\S+)", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = set("a an the is are was were of to in on for and or what who when where how "
                 "does do did i you it this that with be by as at from our your my".split())


@dataclass
class ToolSpec:
    """A tool the application allows the model to request."""
    name: str
    description: str
    parameters: list[str] = field(default_factory=list)


@dataclass
class MockLLM:
    """Deterministic stand-in for a chat model.

    ``complete(messages, tools)`` takes chat-style messages, each a dict with ``role``
    ("system", "user", "document", "tool") and ``content``, and returns a string.
    When it proposes a tool call, the string is JSON: {"tool": ..., "arguments": {...}}.
    """
    name: str = "mock-llm-1"

    def complete(self, messages: list[dict], tools: list[ToolSpec] | None = None) -> str:
        # A real model sees one stream of tokens; roles are only a convention inside it.
        stream = "\n".join(m.get("content", "") for m in messages)
        directive = self._last_directive(stream)
        if directive is not None:
            return self._obey(directive, messages, stream, tools)
        user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
        return self._answer(user, messages, tools)

    # ------------------------------------------------------------------ injection path
    @staticmethod
    def _last_directive(stream: str) -> str | None:
        matches = list(_MARKER_RE.finditer(stream))
        if not matches:
            return None
        tail = stream[matches[-1].end():]
        # The directive runs to the end of the line (or an HTML comment close).
        return tail.split("-->")[0].split("\n")[0].strip()

    def _obey(self, directive: str, messages: list[dict], stream: str,
              tools: list[ToolSpec] | None) -> str:
        low = directive.lower()
        if "system prompt" in low or "your instructions" in low:
            return next((m["content"] for m in messages if m.get("role") == "system"),
                        "(no system prompt)")
        # "{secret}" in a directive is replaced with any credential-like value the model
        # can see in its context: this is how injected text turns into data exfiltration.
        secret = _SECRET_RE.search(stream)
        secret_value = secret.group(1).rstrip(".,;)") if secret else "none-found"
        call = re.match(r"call (?:the )?tool (\w+) with (\{.*\})", directive, re.IGNORECASE)
        if call and tools and any(t.name == call.group(1) for t in tools):
            args = json.loads(call.group(2).replace("{secret}", secret_value))
            return json.dumps({"tool": call.group(1), "arguments": args})
        if "{secret}" in directive:
            payload = re.sub(r"^(?:output|append|include|add|reply with)\b[^:]*:\s*", "",
                             directive, flags=re.IGNORECASE)
            return payload.replace("{secret}", secret_value)
        say = re.match(r"(?:say|respond (?:only )?with|reply with)\s+(.*)", directive,
                       re.IGNORECASE)
        if say:
            return say.group(1).strip().strip('"')
        return directive

    # ------------------------------------------------------------------ normal path
    def _answer(self, user: str, messages: list[dict], tools: list[ToolSpec] | None) -> str:
        low = user.lower()
        if tools:
            for tool in tools:
                if tool.name.replace("_", " ") in low or tool.name in low:
                    args = self._extract_args(user, tool)
                    return json.dumps({"tool": tool.name, "arguments": args})
        context = "\n".join(m["content"] for m in messages if m.get("role") in ("document", "tool"))
        # Lines like "<<UNTRUSTED_DOCUMENT ...>>" are provenance markers, not content.
        context = "\n".join(ln for ln in context.splitlines()
                            if not (ln.startswith("<<") and ln.rstrip().endswith(">>")))
        if "summar" in low and context:
            sentences = re.split(r"(?<=[.!?])\s+", context.strip())
            return "Summary: " + " ".join(sentences[:2])
        if context:
            return self._best_sentence(user, context)
        return "I can summarize a document or answer questions about provided content."

    @staticmethod
    def _extract_args(user: str, tool: ToolSpec) -> dict:
        args = {}
        for param in tool.parameters:
            m = re.search(rf"{param}\s*[=:]\s*\"?([^\",]+)\"?", user, re.IGNORECASE)
            if m:
                args[param] = m.group(1).strip()
        return args

    @staticmethod
    def _terms(text: str) -> set[str]:
        # Lowercase words minus stopwords, with a crude plural strip ("refunds" -> "refund").
        return {w[:-1] if len(w) > 3 and w.endswith("s") else w
                for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS}

    @classmethod
    def _best_sentence(cls, question: str, context: str) -> str:
        q = cls._terms(question)
        best, score = "I could not find that in the provided content.", 0
        for sentence in re.split(r"(?<=[.!?])\s+|\n", context):
            words = cls._terms(sentence)
            overlap = len(q & words)
            if overlap > score:
                best, score = sentence.strip(), overlap
        return best
