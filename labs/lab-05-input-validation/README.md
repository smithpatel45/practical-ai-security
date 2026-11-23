# Lab 05: Implement Input Validation, and Learn Its Limits

**Chapter:** 11 (Securing LLM-Based Applications) · **Time:** 30–45 minutes · **Level:** Beginner–Intermediate

## Objective

Write the input validation every LLM application should have (strict structured fields, Unicode normalization, invisible-character removal, size limits), then demonstrate with your own eyes that no validator can reliably detect prompt injection in free text.

## Prerequisites

- Python 3.11+
- Chapter 11, section "Input validation: necessary, not sufficient"

## Run

```bash
python validators.py
```

On Windows, if the console shows encoding errors, run `$env:PYTHONIOENCODING="utf-8"` (PowerShell) first.

## Files

| File | Description |
|---|---|
| `validators.py` | `normalize_text()` and `validate_ticket()` for a support-ticket form |
| `data/inputs.json` | Seven test submissions, from valid to adversarial |

## Steps

1. Run the demo. For each case, note whether it was accepted and why.
2. **Structured fields.** The "malformed" case is fully rejected. Why is strict validation of `order_id`, `email` and `category` so effective compared with validating `message`?
3. **Invisible characters.** In the third case the instruction was hidden from a human reader with zero-width and bidirectional formatting characters. After cleaning, it is visible. Did cleaning remove the *instruction*? What did it achieve?
4. **The heuristic.** Case 4 is flagged; case 5, a paraphrase with the same intent, is not. Try three more paraphrases of your own and see how many pass.
5. **Add a control that does work.** The order ID is validated, so the application, not the model, can look up the order and decide refund eligibility. Sketch, in pseudocode, a flow where the model drafts the reply but a business rule decides whether a refund is allowed.

## Expected outcome

Output matches `expected_output.txt`: three cases rejected or warned for structural reasons; the paraphrased injection is **accepted with no warning**.

## Security implications

- Validate structured inputs strictly (allowlists, formats, enums, unknown-field rejection). This genuinely shrinks the attack surface.
- Normalize and strip invisible characters so humans reviewing logs and tickets see what the model sees.
- Treat injection-phrase matching as **telemetry** for monitoring, never as a gate you rely on. OWASP's prompt injection guidance states that input validation is not a security boundary.
- Real protection comes from limiting what a successfully injected model can do (Chapters 11 and 15).

## Troubleshooting

| Problem | Fix |
|---|---|
| `UnicodeEncodeError` printing to the console | Set `PYTHONIOENCODING=utf-8` |
| Your new JSON test case isn't loaded | Check for trailing commas; JSON doesn't allow them |

## Tests

```bash
python -m pytest test_lab05_validation.py
```
