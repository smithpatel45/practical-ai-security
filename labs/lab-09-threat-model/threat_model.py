"""Lab 09: generate a first-draft AI threat model from a system description.

Reads a JSON description of components and data flows, applies rules that encode common
AI-application threats, and prints a prioritized table mapped to STRIDE, the OWASP Top 10
for LLM Applications 2026 (and the Agentic Top 10 where agents are involved), and MITRE
ATLAS technique IDs (as listed on atlas.mitre.org in November 2026).

A generator gives you a starting point, not a finished model. The exercise is to review
every row, adjust the scores with `data/scores.json`, and add the threats the rules miss.

Usage:
    python threat_model.py
    python threat_model.py --system data/system.json --scores data/scores.json --markdown out.md
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).parent


@dataclass
class Threat:
    tid: str
    title: str
    target: str
    stride: str
    owasp: str
    atlas: str
    likelihood: int
    impact: int
    mitigation: str

    @property
    def risk(self) -> int:
        return self.likelihood * self.impact

    @property
    def level(self) -> str:
        return "High" if self.risk >= 15 else "Medium" if self.risk >= 8 else "Low"


def generate(system: dict) -> list[Threat]:
    comps = {c["id"]: c for c in system["components"]}
    threats: list[Threat] = []

    def add(*args):
        threats.append(Threat(f"T{len(threats) + 1:02d}", *args))

    for f in system["flows"]:
        src, dst = comps[f["from"]], comps[f["to"]]
        if dst["type"] == "llm" and src["type"] == "user":
            add("Direct prompt injection / jailbreak", dst["id"], "Tampering", "LLM01:2026",
                "AML.T0051, AML.T0054", 5, 3, "Limit model authority; output handling; monitoring")
        if dst["type"] == "llm" and src.get("untrusted_content"):
            add(f"Indirect prompt injection via {src['id']}", dst["id"], "Elevation of privilege", "LLM01:2026",
                "AML.T0051", 4, 4, "Treat retrieved content as data; least privilege; tool policy outside the model")
        if src["type"] == "llm" and dst["type"] == "tool" and dst.get("side_effects"):
            add(f"Excessive agency: model can trigger {dst['id']}", dst["id"], "Elevation of privilege",
                "LLM03:2026 / ASI02", "AML.T0053", 3, 5, "Allowlisted actions, argument validation, human approval")
        if src["type"] == "llm" and dst["type"] == "ui" and dst.get("renders_markdown"):
            add("Exfiltration through rendered output (images/links)", dst["id"], "Information disclosure",
                "LLM10:2026", "AML.T0077", 4, 4, "Escape output; strip images; allowlist link hosts; CSP")

    for c in comps.values():
        p = c
        if c["type"] == "llm" and p.get("hidden_context_has_secrets"):
            add("Secrets exposed from hidden context", c["id"], "Information disclosure", "LLM08:2026",
                "AML.T0069", 4, 5, "Remove secrets from prompts; never rely on prompt secrecy")
        elif c["type"] == "llm":
            add("System prompt / hidden context discovered", c["id"], "Information disclosure", "LLM08:2026",
                "AML.T0069", 4, 2, "Assume discoverable; keep sensitive logic in code")
        if c["type"] == "llm" and p.get("hosted_api"):
            add("Cost exhaustion / denial of wallet", c["id"], "Denial of service", "LLM06:2026",
                "AML.T0034, AML.T0029", 3, 3, "Per-user quotas, max tokens, budget alerts")
        if c["type"] == "vector_store" and p.get("multi_tenant"):
            add("Cross-tenant retrieval", c["id"], "Information disclosure", "LLM09:2026 / LLM02:2026",
                "n/a", 3, 5, "Tenant and permission filters inside the retrieval query")
        if c["type"] == "vector_store" and p.get("user_writable"):
            add("RAG poisoning by users who can add content", c["id"], "Tampering", "LLM09:2026",
                "AML.T0070", 3, 4, "Restrict writes; provenance; ingestion screening; review")
        if c["type"] == "model_artifact" and p.get("from_public_hub"):
            add("Malicious or tampered model artifact", c["id"], "Tampering", "LLM04:2026",
                "AML.T0010", 2, 5, "Pin versions and hashes; safe formats (no pickle); scan")
        if c["type"] == "logs" and p.get("stores_prompts"):
            add("Sensitive data retained in logs", c["id"], "Information disclosure", "LLM02:2026",
                "n/a", 3, 3, "Redact; minimize; restrict access; retention limits")
        if c["type"] == "tool" and p.get("side_effects") and not p.get("audit_logged"):
            add(f"Actions by {c['id']} cannot be attributed", c["id"], "Repudiation", "n/a (control gap)",
                "n/a", 3, 3, "Audit log every tool call with user, inputs, approval")
        if c["type"] == "api" and not p.get("authenticated"):
            add(f"Unauthenticated access to {c['id']}", c["id"], "Spoofing", "API2:2023 (OWASP API)",
                "AML.T0040", 4, 4, "Authenticate every request; scoped, revocable keys")
    return threats


def apply_scores(threats: list[Threat], scores: dict) -> None:
    for t in threats:
        if t.tid in scores:
            t.likelihood = scores[t.tid].get("likelihood", t.likelihood)
            t.impact = scores[t.tid].get("impact", t.impact)


def to_markdown(system: dict, threats: list[Threat]) -> str:
    lines = [f"# Threat model: {system['name']}", "",
             "| ID | Threat | Target | STRIDE | OWASP | ATLAS | L | I | Risk | Mitigation |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for t in sorted(threats, key=lambda t: -t.risk):
        lines.append(f"| {t.tid} | {t.title} | {t.target} | {t.stride} | {t.owasp} | {t.atlas} | "
                     f"{t.likelihood} | {t.impact} | {t.risk} {t.level} | {t.mitigation} |")
    counts = {lvl: sum(t.level == lvl for t in threats) for lvl in ("High", "Medium", "Low")}
    lines += ["", f"Totals: {counts['High']} High, {counts['Medium']} Medium, {counts['Low']} Low "
                  f"({len(threats)} threats). L = likelihood 1-5, I = impact 1-5, Risk = L x I."]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", type=Path, default=HERE / "data" / "system.json")
    ap.add_argument("--scores", type=Path, default=HERE / "data" / "scores.json")
    ap.add_argument("--markdown", type=Path, help="also write the table to this file")
    args = ap.parse_args(argv)
    system = json.loads(args.system.read_text(encoding="utf-8"))
    threats = generate(system)
    if args.scores.exists():
        apply_scores(threats, json.loads(args.scores.read_text(encoding="utf-8")))
    md = to_markdown(system, threats)
    print(md)
    if args.markdown:
        args.markdown.write_text(md + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
