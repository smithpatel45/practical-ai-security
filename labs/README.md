# Practical AI Security: Labs

Eleven hands-on labs accompany the book. Every lab runs **offline** on your own computer:

- Python 3.11 or newer, **standard library only**: nothing to install, no API keys, no accounts.
- A shared, deterministic **mock model** (`shared/mock_llm.py`) stands in for a real LLM. It reproduces, predictably, the failure mode that matters for security teaching: it cannot tell your instructions apart from instructions hidden in data, so it obeys injected directives. That lets each lab show which defenses work *outside* the model.
- All data is fictional. Domains use `example.com`, `example.net`, `example.org` or the `.example` top-level domain, which are reserved for documentation.

> **Safety and scope.** These labs attack only the deliberately vulnerable applications in this folder, on your own machine. Do not point any technique from this book at systems you do not own or are not explicitly authorized to test.

## Quick start

```bash
cd labs
python --version
python -m pytest
```

Then open any lab folder and follow its `README.md`. Each lab contains:

| File | Purpose |
|---|---|
| `README.md` | Objective, prerequisites, setup, steps, expected outcome, security implications, troubleshooting |
| `*.py` | Lab source code |
| `requirements.txt` | Dependencies (standard library only) |
| `data/` | Sample input data |
| `expected_output.txt` | Output you should see from the main command |
| `test_*.py` | Automated tests that confirm the lab behaves as documented |

Worked solutions to every lab are printed in the book (*Practical AI Security*, Appendix H).

## Lab index

| Lab | Topic | Book chapter |
|---|---|---|
| [lab-01-phishing-analysis](lab-01-phishing-analysis/) | Analyze simulated AI-written phishing and BEC emails | 5 |
| [lab-02-voice-clone-verification](lab-02-voice-clone-verification/) | Apply a verification policy to impersonation scenarios | 6 |
| [lab-03-secure-llm-app](lab-03-secure-llm-app/) | Compare a vulnerable and a hardened minimal LLM web app | 11 |
| [lab-04-prompt-injection](lab-04-prompt-injection/) | Direct and indirect prompt injection, then verify mitigations | 7, 17 |
| [lab-05-input-validation](lab-05-input-validation/) | Normalize and validate input, and see why validation is not a boundary | 11 |
| [lab-06-api-auth](lab-06-api-auth/) | API keys, roles, object-level authorization, rate limiting | 12 |
| [lab-07-output-handling](lab-07-output-handling/) | Escape, allowlist and schema-validate model output | 9, 13 |
| [lab-08-rag-security](lab-08-rag-security/) | Permission-aware retrieval, poisoning detection, tenant isolation | 14 |
| [lab-09-threat-model](lab-09-threat-model/) | Build a STRIDE + OWASP + MITRE ATLAS threat model | 18 |
| [lab-10-incident-response](lab-10-incident-response/) | Triage AI application logs for injection and exfiltration | 19 |
| [lab-11-agent-permissions](lab-11-agent-permissions/) | Policy-enforced tools, taint tracking and human approval for an agent | 15 |

## Tested environment

See `TESTED_WITH.md`, which records the exact Python version and test results from the last verification run.
