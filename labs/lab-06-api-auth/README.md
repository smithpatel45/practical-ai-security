# Lab 06: Add Authentication and Authorization to an AI API

**Chapter:** 12 (Authentication, Authorization and Access Control) · **Time:** 45–60 minutes · **Level:** Intermediate

## Objective

Secure a small AI chat API: authenticate callers with API keys stored safely, authorize every action by role, check object ownership on every read (preventing Broken Object Level Authorization, OWASP API1:2023), revoke keys, and rate-limit to control cost.

## Prerequisites

- Python 3.11+
- Chapter 12; Chapter 9 for API vulnerability background

## Run

```bash
python ai_api.py
```

The demo starts each API on a random free port on `127.0.0.1`, makes real HTTP requests as different users (defined in `data/users.json`), then shuts it down.

## Endpoints

| Method and path | Purpose | Permission (secure mode) |
|---|---|---|
| `POST /v1/chat` | Send a message; the conversation is saved | `chat` |
| `GET /v1/conversations/{id}` | Read a saved conversation | `conversations:read_own` for your own; `conversations:read_any` (admin) for others' |
| `POST /v1/admin/revoke` | Revoke an API key by key ID | `keys:revoke` |

Roles: `viewer` (chat only), `analyst` (chat and own history), `admin` (everything).

## Steps

1. Run the demo and compare the two blocks of output line by line.
2. **BOLA.** In vulnerable mode Bob reads Alice's conversation. Find the missing check in `get_conversation`. Why does the secure version return **404** rather than 403 for someone else's conversation?
3. **Unguessable IDs aren't authorization.** Conversation IDs are random, yet the vulnerable API still leaks. How might Bob obtain Alice's ID in a real system? (Think logs, shared links, browser history, referrer headers.)
4. **Key storage.** The secure store keeps only a SHA-256 hash of each key. Why is a fast hash acceptable for random API keys but not for user passwords?
5. **Rate limiting as cost control.** Change `rate_capacity` to 2 and rerun. How does a per-key limit relate to OWASP LLM06:2026 Unbounded Consumption?
6. **Extend.** Add a `conversations:delete_own` permission and a `DELETE /v1/conversations/{id}` route that only the owner or an admin may use. Add tests for both outcomes.

## Expected outcome

`expected_output.txt`. In the secure block: Bob gets **404** for Alice's conversation and **403** for revoke, rapid requests start returning **429**, and keys are stored as hashes.

## Security implications

- Authorization must be checked for **every object** on **every request**, in the API, never left to the client or to the model.
- Treat the model as having no authority of its own. If an AI feature retrieves records, the API call it makes must carry the end user's identity and be authorized as that user (Chapter 12).
- Keys should be scoped to roles, revocable and rate-limited; the full key is shown once at creation.

## Troubleshooting

| Problem | Fix |
|---|---|
| Demo hangs | A firewall prompt may be blocking localhost connections; allow Python on private networks or run the tests instead |
| Counts of 200/429 differ slightly | Token refill depends on timing; differences of one are expected on slow machines |

## Tests

```bash
python -m pytest test_lab06_api_auth.py
```
