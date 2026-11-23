# Lab 09: Create an AI Security Threat Model

**Chapter:** 18 (AI Security Risk Assessment and Threat Modeling) · **Time:** 60–90 minutes · **Level:** Intermediate

## Objective

Produce a prioritized threat model for an AI support assistant, mapping each threat to STRIDE, the OWASP Top 10 for LLM Applications 2026 (plus the Agentic Top 10 where relevant) and MITRE ATLAS. A generator gives you a first draft; your job is to challenge it.

## Prerequisites

- Python 3.11+
- Chapter 18; Chapter 4 for trust boundaries

## Run

```bash
python threat_model.py
python threat_model.py --markdown my_threat_model.md     # also save the table
```

## Files

| File | Description |
|---|---|
| `threat_model.py` | Rules that turn components and flows into threats with scores and mappings |
| `data/system.json` | The system description: components (with security-relevant properties) and data flows |
| `data/scores.json` | Your team's score overrides by threat ID |

## Steps

1. **Draw it first.** Sketch the system in `data/system.json` on paper: components, flows, and where trust boundaries sit. Mark every place untrusted content enters.
2. **Generate.** Run the tool. Read each row and ask: is the threat real here? Is the likelihood and impact right *for this system*?
3. **Score.** The draft gives the refund tool's excessive agency an impact of 5. `scores.json` lowers it to 3 because refunds are capped by a business rule. Make at least two more justified overrides of your own and record the justification in your notes.
4. **Find what's missing.** The rules don't know everything. Add at least three threats by hand. Suggestions: human reviewers trusting AI-drafted refund decisions (automation bias); the assistant giving wrong policy information to customers (LLM07:2026 Misinformation, as in the Air Canada case in Chapter 3); model provider outage.
5. **Change the design.** Set `"hidden_context_has_secrets": true` for `assistant_llm` and rerun. What changes, and what single design decision removes that threat?
6. **Plan remediation.** For every High risk, write one owner, one control, and a date. Chapter 18 shows a remediation plan format.

## Expected outcome

`expected_output.txt`: 11 threats, 5 High and 6 Medium, with indirect prompt injection and output-based exfiltration at the top.

## Security implications

- Threat modeling AI systems is ordinary threat modeling plus a few new rules: the model is a confusable component that will follow untrusted text, and every flow carrying untrusted content into the model is a potential control path.
- Mapping to OWASP and ATLAS gives shared vocabulary for reports and lets you look up known attack procedures and mitigations.
- Scores are judgments. Record *why* you chose them so others can challenge them.

## Troubleshooting

| Problem | Fix |
|---|---|
| `KeyError` on a component ID | Every `from`/`to` in `flows` must match a component `id` |
| Your override has no effect | Threat IDs change if you change the system file; re-run and check the IDs |

## Tests

```bash
python -m pytest test_lab09_threat_model.py
```
