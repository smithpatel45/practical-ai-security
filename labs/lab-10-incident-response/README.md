# Lab 10: Develop an AI Incident Response Checklist and Triage Logs

**Chapter:** 19 (AI Security Policies, Governance and Incident Response) · **Time:** 60 minutes · **Level:** Intermediate

## Objective

Investigate a simulated incident in an AI support assistant's logs: find the poisoned content, the affected users, the data that left, and the action the model took. Then refine an AI-specific incident response checklist.

## Prerequisites

- Python 3.11+
- Chapter 19; Labs 03 and 04 help (canaries, exfiltration patterns)

## Run

```bash
python triage.py
```

## Files

| File | Description |
|---|---|
| `triage.py` | Detection rules R1–R5, a timeline of findings, and a draft incident summary |
| `data/app_logs.jsonl` | Ten log events from a fictional assistant (one JSON object per line) |
| `checklist.md` | Working copy of the AI incident response checklist |

## Detection rules

| Rule | Looks for | Typical meaning |
|---|---|---|
| R1 | Injection phrases in user input or retrieved content | Attempted direct or indirect prompt injection |
| R2 | External URLs with parameters in model output | Possible exfiltration (data in the URL) |
| R3 | `send_email` to a non-company address | Model-initiated external communication |
| R4 | The system-prompt canary in output | Hidden context leaked |
| R5 | Token use far above normal | Abuse, runaway automation or compromised key |

## Steps

1. Run the triage and read the timeline. Build the attack story in your own words: who planted what, when, and which users were affected.
2. **Find the gap.** The poisoning happened in event `r-1003`, yet no rule fires on it. What should the application have logged at upload time to make it detectable? (`test_upload_event_itself_is_not_detected` documents this gap.)
3. **Scope the data loss.** From the R2 URLs, list exactly what data left for each affected user.
4. **False positives.** Is the R5 finding necessarily malicious? What would you check before suspending the key?
5. **Improve the checklist.** Open `checklist.md` and add at least three items you discovered were missing while doing steps 1–4.
6. **Extend the rules.** Add R6: flag any event where a document uploaded by a non-employee account (name not in an employee list) is retrieved. Add a test.

## Expected outcome

`expected_output.txt`: 9 findings (1 critical) across five users, and a draft summary whose suspected chain is built only from rules that fired.

## Security implications

- You can only investigate what you log. AI applications need logs of retrieved sources, tool calls and approvals, not just chat text, with sensitive data redacted.
- Prompt injection incidents are often multi-user: one poisoned document affects everyone who retrieves it.
- Contain by capability (disable the tool, quarantine the source), not just by blocking a single malicious string.

## Troubleshooting

| Problem | Fix |
|---|---|
| `json.decoder.JSONDecodeError` | Each line of the `.jsonl` file must be one complete JSON object |
| No findings after editing rules | Check your regex against the raw log text; JSON escapes quotes as `\"` |

## Tests

```bash
python -m pytest test_lab10_triage.py
```
