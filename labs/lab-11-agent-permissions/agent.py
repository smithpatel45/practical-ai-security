"""Lab 11: an AI agent with tools, made safe by a policy layer the model cannot override.

A support agent processes tickets. It can search the knowledge base, read tickets, send
email, issue refunds and delete tickets. A customer's ticket contains injected
instructions. In "unrestricted" mode every proposed tool call runs. In "guarded" mode a
PolicyEngine sits between the model and the tools and enforces:

  * an allowlist of tools for the agent's role (deny by default)
  * argument constraints (refund ceiling, internal-only email recipients)
  * taint tracking: once untrusted content enters the session, tools that move money or
    send data outside require explicit human approval
  * human approval for high-risk actions, decided outside the model's context
  * an audit trail of every proposal and decision

Usage:
    python agent.py
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
from mock_llm import MockLLM, ToolSpec  # noqa: E402

DATA = Path(__file__).parent / "data"
TICKETS = json.loads((DATA / "tickets.json").read_text(encoding="utf-8"))

TOOLS = [
    ToolSpec("search_kb", "Search the help-center knowledge base", ["query"]),
    ToolSpec("read_ticket", "Read a customer ticket", ["ticket_id"]),
    ToolSpec("send_email", "Send an email", ["to", "body"]),
    ToolSpec("issue_refund", "Refund an order", ["order_id", "amount"]),
    ToolSpec("delete_ticket", "Delete a ticket", ["ticket_id"]),
]


# --------------------------------------------------------------------------- tools (simulated)
class ToolBox:
    def __init__(self):
        self.effects: list[str] = []   # what actually happened in the "real world"

    def run(self, name: str, args: dict) -> tuple[str, bool]:
        """Returns (result_text, result_is_untrusted)."""
        if name == "search_kb":
            return "Refunds are allowed within 30 days for damaged items, up to the item price.", False
        if name == "read_ticket":
            t = TICKETS.get(str(args.get("ticket_id")), {"text": "no such ticket"})
            return f"Ticket {args.get('ticket_id')} from {t.get('customer')}: {t['text']}", True
        if name == "send_email":
            self.effects.append(f"EMAIL to {args.get('to')}: {args.get('body')}")
            return "sent", False
        if name == "issue_refund":
            self.effects.append(f"REFUND {args.get('amount')} on {args.get('order_id')}")
            return "refunded", False
        if name == "delete_ticket":
            self.effects.append(f"DELETED ticket {args.get('ticket_id')}")
            return "deleted", False
        return "unknown tool", False


# --------------------------------------------------------------------------- policy
@dataclass
class Decision:
    allowed: bool
    reason: str


@dataclass
class PolicyEngine:
    approver: Callable[[str, dict, str], bool] = lambda tool, args, why: False   # default: deny
    allowed_tools: set = field(default_factory=lambda: {"search_kb", "read_ticket", "send_email", "issue_refund"})
    internal_domain: str = "northwind.example"
    refund_limit: float = 50.0
    tainted: bool = False
    audit: list[dict] = field(default_factory=list)

    def check(self, tool: str, args: dict) -> Decision:
        d = self._decide(tool, args)
        self.audit.append({"tool": tool, "args": args, "allowed": d.allowed, "reason": d.reason,
                           "session_tainted": self.tainted})
        return d

    def _decide(self, tool: str, args: dict) -> Decision:
        if tool not in self.allowed_tools:
            return Decision(False, f"{tool} is not permitted for this agent role")
        if tool == "send_email":
            to = str(args.get("to", ""))
            if not to.lower().endswith("@" + self.internal_domain):
                return Decision(False, f"external recipient {to} not allowed")
        if tool == "issue_refund":
            try:
                amount = float(args.get("amount", 0))
            except ValueError:
                return Decision(False, "refund amount is not a number")
            if amount <= 0 or amount > self.refund_limit:
                return Decision(False, f"refund {amount} outside limit 0-{self.refund_limit}")
        high_risk = tool in {"send_email", "issue_refund"}
        if high_risk and self.tainted:
            why = "session contains untrusted content; high-risk action needs a human"
            if not self.approver(tool, args, why):
                return Decision(False, why + " (approval denied)")
            return Decision(True, "approved by human reviewer")
        return Decision(True, "within policy")


# --------------------------------------------------------------------------- agent loop
@dataclass
class Agent:
    guarded: bool
    policy: PolicyEngine = field(default_factory=PolicyEngine)
    tools: ToolBox = field(default_factory=ToolBox)
    model: MockLLM = field(default_factory=MockLLM)
    transcript: list[str] = field(default_factory=list)

    def run(self, task: str, max_steps: int = 4) -> list[str]:
        messages = [{"role": "system", "content": "You are a support agent. Resolve tickets using the tools."},
                    {"role": "user", "content": task}]
        seen = set()
        for _ in range(max_steps):
            raw = self.model.complete(messages, tools=TOOLS)
            try:
                call = json.loads(raw)
            except json.JSONDecodeError:
                self.transcript.append(f"final answer: {raw}")
                break
            key = json.dumps(call, sort_keys=True)
            if key in seen:                       # loop guard: don't repeat an identical call
                self.transcript.append("stopped: repeated tool call")
                break
            seen.add(key)
            name, args = call["tool"], call.get("arguments", {})
            if self.guarded:
                d = self.policy.check(name, args)
                if not d.allowed:
                    self.transcript.append(f"BLOCKED {name} {args}: {d.reason}")
                    messages.append({"role": "tool", "content": f"{name} was blocked: {d.reason}"})
                    continue
            result, untrusted = self.tools.run(name, args)
            if untrusted:
                self.policy.tainted = True
            self.transcript.append(f"ran {name} {args} -> {result[:60]}")
            messages.append({"role": "tool", "content": result})
        return self.tools.effects


def show(title: str, agent: Agent, tasks: list[str], audit: bool = False) -> None:
    print(f"== {title}")
    for t in tasks:          # several tasks = one session: taint persists across them
        agent.run(t)
    for line in agent.transcript:
        print("  ", line)
    print("   real-world effects:", agent.tools.effects or "none")
    if audit:
        for entry in agent.policy.audit:
            print("   audit:", json.dumps(entry))
    print()


def demo() -> None:
    print("######## UNRESTRICTED AGENT")
    show("ticket 42 (injected $900 refund)", Agent(guarded=False), ["read ticket ticket_id=42"])
    show("ticket 43 (injected data exfiltration email)", Agent(guarded=False), ["read ticket ticket_id=43"])
    print("######## GUARDED AGENT (approver denies by default)")
    show("ticket 42 (injected $900 refund)", Agent(guarded=True), ["read ticket ticket_id=42"], audit=True)
    show("ticket 43 (injected data exfiltration email)", Agent(guarded=True), ["read ticket ticket_id=43"])
    show("ticket 44, then a legitimate $35 refund in the same (tainted) session", Agent(guarded=True),
         ["read ticket ticket_id=44", "issue refund order_id=ORD-555200, amount=35"])
    approver = lambda tool, args, why: print(f"   [human reviewer asked: {tool} {args} because {why}] -> approve") or True
    show("same, with a human reviewer who approves", Agent(guarded=True, policy=PolicyEngine(approver=approver)),
         ["read ticket ticket_id=44", "issue refund order_id=ORD-555200, amount=35"])


if __name__ == "__main__":
    demo()
