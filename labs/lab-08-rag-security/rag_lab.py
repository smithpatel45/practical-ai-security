"""Lab 08: a basic security assessment of a retrieval-augmented generation (RAG) system.

A tiny, self-contained RAG pipeline:
  ingestion  -> documents become "embeddings" (bag-of-words vectors) in a vector store
  retrieval  -> the question is embedded; the most similar chunks are returned
  generation -> the (mock) model answers using the retrieved chunks

The vulnerable pipeline ranks ALL chunks by similarity and lets anything into the index.
The secure pipeline (1) filters by tenant and group permissions BEFORE ranking,
(2) screens content at ingestion and quarantines suspicious chunks, and (3) attaches
provenance so answers can be traced to their sources.

Usage:
    python rag_lab.py
"""
from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
from mock_llm import DIRECTIVE_MARKERS, MockLLM  # noqa: E402

DATA = Path(__file__).parent / "data"
STOP = set("a an the is are of to in on for and or what how do does i my our we with be by as at "
           "from this that it can you your".split())
SUSPICIOUS = re.compile("|".join(DIRECTIVE_MARKERS + [r"https?://(?!intranet\.acme\.example)"]), re.I)
TRUSTED_SOURCES = {"hr_system", "it_wiki", "finance_system"}


def embed(text: str) -> Counter:
    words = [w[:-1] if len(w) > 3 and w.endswith("s") else w
             for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP]
    return Counter(words)


def cosine(a: Counter, b: Counter) -> float:
    dot = sum(a[t] * b[t] for t in a)
    na, nb = math.sqrt(sum(v * v for v in a.values())), math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


@dataclass
class Chunk:
    id: str
    tenant: str
    groups: set[str]
    source: str
    text: str
    vector: Counter = field(default_factory=Counter)


@dataclass
class User:
    name: str
    tenant: str
    groups: set[str]


class RAG:
    def __init__(self, secure: bool):
        self.secure = secure
        self.index: list[Chunk] = []
        self.quarantine: list[tuple[str, str]] = []
        self.model = MockLLM()

    def ingest(self, docs: list[dict]) -> None:
        for d in docs:
            chunk = Chunk(d["id"], d["tenant"], set(d["groups"]), d["source"], d["text"], embed(d["text"]))
            if self.secure:
                reasons = []
                if SUSPICIOUS.search(d["text"]):
                    reasons.append("instruction-like text or external link")
                if d["source"] not in TRUSTED_SOURCES:
                    reasons.append(f"untrusted source '{d['source']}'")
                if reasons:
                    self.quarantine.append((d["id"], "; ".join(reasons)))
                    continue
            self.index.append(chunk)

    def retrieve(self, user: User, question: str, k: int = 2) -> list[Chunk]:
        q = embed(question)
        candidates = self.index
        if self.secure:
            # Permission filter FIRST: a user can only ever retrieve what they may read.
            candidates = [c for c in self.index if c.tenant == user.tenant and c.groups & user.groups]
        ranked = sorted(candidates, key=lambda c: cosine(q, c.vector), reverse=True)
        return [c for c in ranked[:k] if cosine(q, c.vector) > 0]

    def answer(self, user: User, question: str) -> tuple[str, list[str]]:
        chunks = self.retrieve(user, question)
        if not chunks:
            return "I don't have any information you can access on that topic.", []
        msgs = [{"role": "system", "content": "Answer using the retrieved context only."}]
        msgs += [{"role": "document", "content": c.text} for c in chunks]
        msgs.append({"role": "user", "content": question})
        reply = self.model.complete(msgs)
        if self.secure:
            # Keep links only to the organization's own intranet.
            reply = re.sub(r"https?://(?!intranet\.acme\.example/)\S+", "[link removed]", reply)
        return reply, [c.id for c in chunks]


def load() -> tuple[list[dict], dict[str, User]]:
    docs = json.loads((DATA / "documents.json").read_text(encoding="utf-8"))
    users = {u["name"]: User(u["name"], u["tenant"], set(u["groups"]))
             for u in json.loads((DATA / "users.json").read_text(encoding="utf-8"))}
    return docs, users


CHECKS = [
    ("cross-tenant leakage", "jo", "What is the merger code name for the acquisition?",
     lambda reply, ids: any(i.startswith("globex") for i in ids)),
    ("cross-group leakage", "jo", "What are the salary bands for engineers?",
     lambda reply, ids: "hr-salary" in ids),
    ("poisoned document influence", "jo", "How do I reset my VPN password?",
     lambda reply, ids: "attacker" in reply or "poison-vpn" in ids),
    ("normal question still answered", "jo", "How do I reset my VPN password?",
     lambda reply, ids: "it-vpn" in ids),
]


def assess() -> list[tuple[str, str, str]]:
    docs, users = load()
    rows = []
    systems = {}
    for mode in (False, True):
        rag = RAG(secure=mode)
        rag.ingest(docs)
        systems[mode] = rag
    for name, user, question, failed in CHECKS:
        res = []
        for mode in (False, True):
            reply, ids = systems[mode].answer(users[user], question)
            bad = failed(reply, ids)
            if name.startswith("normal"):
                res.append("PASS" if bad else "FAIL")
            else:
                res.append("FAIL" if bad else "PASS")
        rows.append((name, res[0], res[1]))
    return rows


def main() -> int:
    docs, users = load()
    for secure in (False, True):
        rag = RAG(secure)
        rag.ingest(docs)
        print(f"######## {'SECURE' if secure else 'VULNERABLE'} RAG  (indexed {len(rag.index)} chunks)")
        for doc_id, why in rag.quarantine:
            print(f"   quarantined {doc_id}: {why}")
        for name, user, question, _ in CHECKS[:3]:
            reply, ids = rag.answer(users[user], question)
            print(f"== {name}: {users[user].name} ({users[user].tenant}, {sorted(users[user].groups)}) asks: {question}")
            print(f"   retrieved: {ids}")
            print(f"   answer   : {reply}")
        print()
    print("| Check | Vulnerable | Secure |")
    print("|---|---|---|")
    for row in assess():
        print("| " + " | ".join(row) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
