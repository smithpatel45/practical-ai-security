# AI Incident Response Checklist (Lab 10 working copy)

Organized by the NIST CSF 2.0 functions used in NIST SP 800-61 Rev. 3. Adapt it to your organization; Appendix F of the book contains the full template.

## Before an incident (Govern / Identify / Protect)

- [ ] Inventory of AI applications, models, providers, data sources and tools, with owners
- [ ] Logging of inputs, retrieved sources, outputs, tool calls and approvals (redacted where required), retained for at least the investigation window
- [ ] Canary marker in system prompts; detections for canary leaks, external URLs in output, and model-initiated external communication
- [ ] Kill switches: disable a tool, disable retrieval from a source, switch a feature to "human-only" mode, revoke provider keys
- [ ] Contacts: AI product owner, security, privacy/legal, model provider support, communications

## Detect and analyze (Detect)

- [ ] Identify the first malicious input (user prompt, document, email, ticket) and its origin
- [ ] Determine which sessions retrieved or processed it (search logs by document ID)
- [ ] Determine impact: data exposed (which fields, which users), actions executed (tool calls), cost incurred
- [ ] Classify: prompt injection, data leakage, poisoning, abuse/cost, model or supply-chain issue, harmful output
- [ ] Preserve evidence: logs, the malicious content, model/version and prompt configuration at the time

## Contain, eradicate, recover (Respond / Recover)

- [ ] Disable affected tools or features; quarantine malicious content; block exfiltration hosts
- [ ] Rotate exposed credentials and tokens; revoke compromised API keys
- [ ] Remove poisoned content from indexes **and** caches; re-embed if needed
- [ ] Fix the root cause (a missing control), not only the specific payload
- [ ] Re-enable features gradually with added monitoring

## After the incident

- [ ] Notify affected users and regulators as required (privacy/legal decide)
- [ ] Add a regression test reproducing the attack (see Lab 04)
- [ ] Update the threat model (Lab 09) and the acceptable-use policy if needed
- [ ] Record lessons learned and owners for follow-up actions
