# Lab 08: Build a Basic RAG Security Assessment

**Chapter:** 14 (Protecting RAG Systems and Vector Databases) · **Time:** 45–60 minutes · **Level:** Intermediate

## Objective

Assess a small retrieval-augmented generation (RAG) system for the three most common failures: retrieving data across **tenants**, retrieving data across **permission groups**, and letting a **poisoned document** steer answers. Then verify the fixes.

## Prerequisites

- Python 3.11+
- Chapter 2 (how RAG works) and Chapter 14

## Run

```bash
python rag_lab.py
```

## The system

| Component | Implementation |
|---|---|
| Embeddings | Bag-of-words vectors (a simple stand-in for real embedding models; the security logic is identical) |
| Vector store | In-memory list of chunks with `tenant`, `groups` and `source` metadata |
| Generator | The shared mock model |
| Data | `data/documents.json` (six chunks, two tenants), `data/users.json` (three users) |

## Steps

1. Read `data/documents.json`. Identify the confidential chunk, the other tenant's chunk, and the poisoned chunk. Who uploaded the poisoned one (`source`)?
2. Run the lab. In the vulnerable block, user **jo** (tenant `acme`, group `all-staff`) receives another company's merger code name, HR salary bands, and a phishing instruction.
3. Explain each fix in the secure block:
   - `retrieve()` filters by tenant and group **before** ranking;
   - `ingest()` quarantines chunks with instruction-like text, external links or untrusted sources;
   - `answer()` removes non-intranet links from output.
4. Read `test_permission_filter_happens_before_ranking`. Why is "rank first, filter later" (fetch top-k, then drop forbidden results) still risky?
5. **Assess a change.** Set `"source": "it_wiki"` on `poison-vpn` and rerun. Is it still quarantined? Which control caught it, and what does this tell you about relying on source labels alone?
6. **Extend.** Add a `classification` field (`public`, `internal`, `confidential`) and require an extra group (`confidential-readers`) for confidential chunks. Add a test.

## Expected outcome

`expected_output.txt` ends with:

| Check | Vulnerable | Secure |
|---|---|---|
| cross-tenant leakage | FAIL | PASS |
| cross-group leakage | FAIL | PASS |
| poisoned document influence | FAIL | PASS |
| normal question still answered | PASS | PASS |

## Security implications

- A vector database returns whatever is *similar*, not what the user is *allowed* to see. Authorization has to be enforced in the retrieval query itself, using the end user's identity.
- Anyone who can write to the knowledge base can influence answers. Research such as PoisonedRAG (Chapter 14) shows a handful of crafted chunks can dominate retrieval for a target question.
- Ingestion screening is a useful filter but imperfect. Combine it with write-access control, provenance tracking and output handling.

## Troubleshooting

| Problem | Fix |
|---|---|
| A question returns no chunks | The toy embedding needs shared words; rephrase using words from the document |
| Assessment table differs | Restore `data/*.json` from the repository |

## Tests

```bash
python -m pytest test_lab08_rag.py
```
