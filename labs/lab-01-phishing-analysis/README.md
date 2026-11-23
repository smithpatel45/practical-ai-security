# Lab 01: Analyze Simulated AI-Generated Phishing

**Chapter:** 5 (AI-Generated Phishing and Social Engineering) · **Time:** 30–45 minutes · **Level:** Beginner

## Objective

Learn to judge a suspicious email by the signals an attacker *cannot* polish away with generative AI (sender identity, authentication results, reply routing, link targets, and the action requested) instead of spelling and grammar, which AI-written messages no longer get wrong.

## Prerequisites

- Python 3.11+ (`python --version`)
- Basic familiarity with email headers (Chapter 5 explains each one used here)

## Setup

No installation. From this folder:

```bash
python analyze_email.py data/*.eml
```

## What's in the lab

| File | Description |
|---|---|
| `analyze_email.py` | Rule-based analyzer that scores red flags and prints a verdict |
| `data/sample_1_ceo_wire.eml` | Polished, personalized "CEO" wire request |
| `data/sample_2_vendor_bank_change.eml` | Supplier asks to change bank details |
| `data/sample_3_payroll_mfa.eml` | Payroll lure with a deceptive link and MFA request |
| `data/sample_4_legitimate_newsletter.eml` | A genuine internal email (control sample) |
| `data/trusted_domains.json` | Your organization's own and trusted partner domains, plus executive names |

All names, companies and domains are fictional; `.example` and `example.net` are reserved for documentation.

## Steps

1. **Read before you run.** Open each `.eml` file in a text editor. For each one, write down your own verdict (phishing, suspicious, legitimate) and *why*. Notice that none of the fraudulent emails contain spelling mistakes.
2. **Run the analyzer** with the command above and compare its findings with yours.
3. **Study sample 2.** SPF *passes*. Explain why that does not make the email trustworthy. (Hint: who owns `contoso-suppiles.example`?)
4. **Study sample 3.** Find the line in the HTML where the visible link text and the real destination differ.
5. **Extend the analyzer.** Add a rule that flags requests to buy gift cards. Write a test for it in `test_lab01_phishing.py`.
6. **Make it fail.** Edit `sample_1_ceo_wire.eml` so it still reads as a fraud to a human but scores below 6. What does that tell you about relying on automated scoring alone?

## Expected outcome

Your output should match `expected_output.txt`: the three fraudulent samples score **LIKELY PHISHING / FRAUD** and the newsletter scores **0**.

## Security implications

- AI removes the "bad grammar" tell and makes personalization cheap (the CEO email references a real report). Training that still says "look for typos" is out of date.
- Authentication results (SPF, DKIM, DMARC) prove only that a domain authorized the sender; a lookalike domain can pass them all.
- The most reliable control is procedural: any request to move money or change payment details is verified **out of band** using contact details you already hold.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python: command not found` | Try `python3`, or install Python 3.11+ |
| `No such file or directory: data/*.eml` on Windows PowerShell | Run `python analyze_email.py (Get-ChildItem data\*.eml)` or list the files explicitly |
| Unicode errors on Windows console | Run `set PYTHONIOENCODING=utf-8` (cmd) or `$env:PYTHONIOENCODING="utf-8"` (PowerShell) |

## Tests

```bash
python -m pytest test_lab01_phishing.py
```
