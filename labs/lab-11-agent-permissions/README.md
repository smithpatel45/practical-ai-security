# Lab 11: Secure an AI Agent's Tool Permissions

**Chapter:** 15 (AI Agents, Tool Permissions and Excessive Agency) · **Time:** 60 minutes · **Level:** Intermediate–Advanced

## Objective

Give an AI agent useful tools without giving an attacker those tools. You will watch injected ticket text make an unrestricted agent issue a $900 refund and email customer data outside the company, then enforce a policy layer that the model cannot override.

## Prerequisites

- Python 3.11+
- Chapter 15 (agent architecture, excessive agency, the "lethal trifecta"); Lab 04 helps

## Run

```bash
python agent.py
```

## Components

| Component | Role |
|---|---|
| `Agent` | Loop: ask the model for the next step, run the proposed tool, feed the result back (max 4 steps, with a repeated-call guard) |
| `ToolBox` | Simulated tools. Real-world "effects" are recorded, not performed |
| `PolicyEngine` | Role allowlist, argument limits, taint tracking, human approval, audit log |
| `data/tickets.json` | Ticket 42 (injected refund), 43 (injected exfiltration email), 44 (legitimate request) |

## Steps

1. Read `data/tickets.json` and find the injected instructions in tickets 42 and 43.
2. Run the demo. In the unrestricted block, confirm both injected actions became real-world effects.
3. In the guarded block, identify which policy rule stopped each action:
   - $900 refund: argument limit (refund ceiling of $50);
   - external email: internal-only recipients;
   - legitimate $35 refund after reading a ticket: **taint tracking**. The session processed untrusted content, so a human must approve.
4. **Hard limits beat approval.** Read `test_approval_cannot_override_hard_limits`. Why should some limits hold even when a human approves?
5. **Map to the lethal trifecta.** Which of the three legs (private data, untrusted content, external communication) does each control break?
6. **Extend.** Add a per-session refund budget (total ≤ $100 across all refunds) and an approval message that shows the reviewer the *original ticket text*, not only the model's proposal. Add tests.

## Expected outcome

`expected_output.txt`: the unrestricted agent produces two harmful effects; the guarded agent produces none until a human approves the legitimate $35 refund.

## Security implications

- The model proposes; deterministic code disposes. Authorization for tool calls must be enforced outside the model's context, and must fail closed.
- Taint tracking is a practical way to apply the lethal-trifecta idea: once untrusted content is in play, tighten what the agent may do.
- Approval prompts must give reviewers enough context to say no. A wall of approvals breeds rubber-stamping (OWASP ASI09 Human-Agent Trust Exploitation).
- Every proposal, including blocked ones, belongs in the audit trail.

## Troubleshooting

| Problem | Fix |
|---|---|
| The agent repeats a call and stops | Intended: the loop guard stops identical repeated calls |
| A tool call isn't parsed | Arguments must appear as `name=value` in the task text, or as valid JSON in an injected instruction |

## Tests

```bash
python -m pytest test_lab11_agent.py
```
