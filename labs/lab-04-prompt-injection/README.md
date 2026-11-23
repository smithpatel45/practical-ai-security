# Lab 04: Demonstrate Prompt Injection Safely, Then Verify Mitigations

**Chapters:** 7 (Prompt Injection and Jailbreaking) and 17 (Testing) · **Time:** 60–90 minutes · **Level:** Intermediate

## Objective

Watch prompt injection succeed against a deliberately vulnerable local assistant, both **direct** (typed by the user) and **indirect** (hidden in a document the assistant reads). Then confirm which controls stop the damage and which don't.

> This lab attacks only the local `ResearchMate` application in this folder. The "attacker" domains (`*.attacker.example`, `conference-updates.example`) are reserved documentation names. Nothing leaves your machine: "fetched URLs" and "sent emails" are recorded in memory, not performed.

## Prerequisites

- Python 3.11+
- Chapter 7 (concepts); Chapter 17 (test method) for the reporting steps

## Run

```bash
python injection_lab.py --mode vulnerable
python injection_lab.py --mode secure
python injection_lab.py --mode both        # both, plus a summary table
```

## The scenario

ResearchMate summarizes documents for a user. It can see the user's private notes, which contain a fictional session token, and it can send email.

| File | Role |
|---|---|
| `data/private_notes.txt` | The user's private data, including `TOKEN: rm-session-7f3a9c` (fictional) |
| `data/article_benign.txt` | A normal article |
| `data/article_poisoned.txt` | An article with an HTML comment telling the AI to output an image whose URL carries the token |
| `data/email_poisoned.txt` | An email instructing the AI to call `send_email` and send the token to an outside address |

## Steps

1. **Read the poisoned files.** Find the hidden instruction in each. Notice that a human reading the rendered article would never see the HTML comment.
2. **Run vulnerable mode.** Confirm three exploits: system prompt and notes revealed (direct); token in an auto-loaded image URL (indirect exfiltration); token emailed out (indirect tool misuse).
3. **Run secure mode.** For each scenario, identify *which* control stopped it:
   - image exfiltration: output handling removed the non-allowlisted image;
   - tool exfiltration: tool policy disabled external communication after untrusted content was processed (and the recipient wasn't allowlisted anyway);
   - direct injection: still "exposed", but the hidden context now holds nothing sensitive.
4. **Prove spotlighting isn't enough.** Read `test_spotlighting_alone_does_not_stop_the_model_following_injection`. The untrusted document was clearly labeled, yet the model still produced the attacker's image. Labels reduce risk with real models; they are not a boundary.
5. **Defense in depth.** Run `test_output_handling_still_blocks_if_data_minimization_fails`. Even when private data *is* in context, the output layer still blocks the leak.
6. **Write a test report.** Use the worksheet in Appendix C of the book and the summary table from `--mode both` to record objective, steps, expected result, actual result and evidence for each scenario.
7. **Stretch.** Write a new poisoned document that leaks the token through a *link* rather than an image. Does secure mode catch it? Why?

## Expected outcome

`expected_output.txt` shows the full run. The summary table should read:

| Scenario | Vulnerable | Secure |
|---|---|---|
| benign summary | OK | OK |
| direct injection | EXPLOITED | EXPOSED (no sensitive data) |
| indirect: image exfiltration | EXPLOITED | BLOCKED |
| indirect: tool exfiltration | EXPLOITED | BLOCKED |

## Security implications

- Indirect prompt injection needs no access to the victim's chat: the attacker only has to get text in front of the model (a web page, email, document, ticket).
- Auto-loading images in model output turns any injection into a zero-click exfiltration channel. This pattern appeared in real disclosures (Chapter 7).
- The "lethal trifecta" (private data + untrusted content + external communication) is what makes exfiltration possible. Breaking any one leg breaks the attack.

## Troubleshooting

| Problem | Fix |
|---|---|
| Output differs from `expected_output.txt` | Make sure you haven't edited files in `data/` or `../shared/mock_llm.py`; re-copy them from the repository |
| `json.decoder.JSONDecodeError` after editing `email_poisoned.txt` | The tool arguments must be valid JSON with double quotes |
| `ModuleNotFoundError: mock_llm` | Run from this folder |

## Tests

```bash
python -m pytest test_lab04_injection.py
```
