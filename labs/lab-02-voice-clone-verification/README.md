# Lab 02: Voice-Clone and Deepfake Verification Scenarios

**Chapter:** 6 (Deepfakes, Voice Cloning and Identity Fraud) · **Time:** 30 minutes · **Level:** Beginner

## Objective

Design and test a verification policy that stops impersonation fraud **without** asking anyone to judge whether a voice or face is real. You will evaluate six hypothetical scenarios, inspired by publicly reported patterns (Chapter 6), against a machine-readable policy.

## Prerequisites

- Python 3.11+
- Chapter 6, sections on verification procedures

## Setup and run

```bash
python verify_request.py
```

Optional: `--policy` and `--scenarios` point to alternative JSON files.

## Files

| File | Description |
|---|---|
| `verify_request.py` | Evaluates each scenario against the policy |
| `data/policy.json` | Trusted channels, sensitive request types, never-share rules, dual-approval threshold |
| `data/scenarios.json` | Six hypothetical impersonation scenarios |

## Steps

1. **Predict.** For each scenario in `data/scenarios.json`, decide what an employee should do. Write it down before running anything.
2. **Run** the tool and compare. Where your answer differed, decide whether the policy or your instinct was right.
3. **Notice what the policy ignores.** No field asks whether the voice or video *seemed genuine*. Open `test_lab02_verification.py` and read `test_convincing_voice_does_not_change_outcome`. Why is that the right design?
4. **Tighten the policy.** Add `"information"` requests from executives on unofficial channels to a new rule that also requires reporting to security. (S2 already triggers verification; make the step text mention the security team's reporting address.)
5. **Write a scenario that beats the policy.** Create S7, an impersonation the current rules would wrongly ALLOW. Then fix the policy and add a test.

## Expected outcome

Output matches `expected_output.txt`: S1, S2, S3 and S5 → **VERIFY_FIRST**; S4 → **ALLOW** (verification completed); S6 → **REFUSE**.

## Security implications

- Detection of synthetic media is an arms race; procedures are not. A call-back to a number **you already hold** defeats a cloned voice regardless of quality.
- A call-back to a number supplied by the requester (S3) verifies nothing.
- Dual approval inside the payment system prevents a single deceived person from moving money.
- Some requests (passwords, MFA codes) should be refused on every channel, by everyone.

## Troubleshooting

| Problem | Fix |
|---|---|
| `KeyError: 'impersonation_prone_roles'` | Your policy file is missing the field; copy it from `data/policy.json` |
| JSON decode error | Validate your edited JSON (trailing commas are not allowed) |

## Tests

```bash
python -m pytest test_lab02_verification.py
```
