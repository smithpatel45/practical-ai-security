# Lab 07: Implement Safe Output Handling

**Chapters:** 9 (Insecure AI APIs) and 13 (Securing AI APIs and Data Pipelines) · **Time:** 45 minutes · **Level:** Intermediate

## Objective

Model output is attacker-influenced data. Learn to make it safe for the three places it most often goes next: a web page, a tool or function call, and a database query (OWASP LLM10:2026 Improper Output Handling).

## Prerequisites

- Python 3.11+, `pytest` for the tests (optional)
- Chapter 9 sections on output validation; basic SQL

## Run

```bash
python output_guard.py
```

## What the demo shows

The sample model outputs, tool calls and filters are in `data/model_outputs.json`.

| Consumer | Unsafe pattern | Safe pattern in `output_guard.py` |
|---|---|---|
| Browser | Convert model Markdown to HTML and insert it | `render_safe`: escape everything, remove images, keep only `https` links to allowlisted hosts |
| Tools | Execute whatever JSON the model proposes | `validate_tool_call`: known tool, exact argument set, types, formats, enums, ranges |
| Database | Run SQL the model wrote | `query_safe`: model proposes a structured filter; code builds a parameterized query scoped to the user |

## Steps

1. Run the demo and compare the unsafe and safe rendering of each sample. Which unsafe output would execute code, and which would silently send data to another host?
2. Read `validate_tool_call`. List every check, then explain why rejecting **unexpected arguments** (the `notify` field) matters.
3. In section 3, the unsafe query returns every customer's orders. Write down the exact SQL that ran. Why can't the safe version be tricked the same way, even when the attacker controls the filter **value**?
4. **Scope by identity.** In `query_safe`, the `customer = ?` clause is added by code using the signed-in user's email. Explain why this must never be a filter the model chooses.
5. **Extend.** Add an `escalate_ticket` tool whose `reason` argument is free text limited to 200 characters. Add tests for a valid call and an over-long one.

## Expected outcome

Output matches `expected_output.txt`. All `pytest` tests pass.

## Security implications

- Escaping must happen **after** the model and **before** rendering, every time. Content-Security-Policy headers add a second layer in real web apps.
- Images in model output are an exfiltration channel: a browser fetches them automatically.
- Schema validation turns a model's free-form suggestion into a narrow, checked request. Authorization and business limits (refund ceilings, human approval) still apply afterwards (Chapters 12 and 15).
- Never let the model choose the data scope (tenant, user, account). Code sets it from the authenticated session.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: pytest` | `python -m pip install pytest`, or just run `python output_guard.py` |
| SQLite errors after editing | The demo uses an in-memory database rebuilt on every run |

## Tests

```bash
python -m pytest test_lab07_output.py
```
