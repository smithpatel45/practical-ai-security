"""Lab 10: triage AI application logs for prompt injection, data exfiltration and abuse.

Reads JSON Lines logs from an LLM application (one event per line), applies simple
detection rules, and prints a timeline of findings plus a draft incident summary.
The rules are deliberately transparent so you can see what each one looks for and
where it would miss.

Usage:
    python triage.py
    python triage.py --logs data/app_logs.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
from mock_llm import DIRECTIVE_MARKERS  # noqa: E402

HERE = Path(__file__).parent
INJECTION = re.compile("|".join(DIRECTIVE_MARKERS), re.I)
URL = re.compile(r"https?://([^/\s)\"']+)[^\s)\"']*")
INTERNAL_HOSTS = {"help.northwind.example", "intranet.northwind.example"}
INTERNAL_EMAIL_DOMAIN = "northwind.example"
CANARY = "cnry-5e1f0a"   # random marker placed in the system prompt (see Lab 03)


@dataclass
class Finding:
    ts: str
    severity: str
    rule: str
    user: str
    request_id: str
    detail: str


def detect(events: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for e in events:
        rid, user, ts = e["request_id"], e["user"], e["ts"]
        if INJECTION.search(e.get("input", "")):
            out.append(Finding(ts, "Medium", "R1 injection phrase in user input", user, rid, e["input"][:70]))
        for doc in e.get("retrieved", []):
            if INJECTION.search(doc.get("text", "")):
                out.append(Finding(ts, "High", "R1 injection phrase in retrieved content", user, rid,
                                   f"document {doc['id']} (uploaded by {doc.get('uploaded_by', 'unknown source')})"))
        for m in URL.finditer(e.get("output", "")):
            host = m.group(1).lower()
            if host not in INTERNAL_HOSTS and "?" in m.group(0):
                out.append(Finding(ts, "High", "R2 external URL with parameters in output", user, rid, m.group(0)[:80]))
        for call in e.get("tool_calls", []):
            to = str(call.get("arguments", {}).get("to", ""))
            if call.get("tool") == "send_email" and not to.endswith("@" + INTERNAL_EMAIL_DOMAIN):
                out.append(Finding(ts, "Critical", "R3 email sent to external address by the model", user, rid,
                                   f"to={to} executed={call.get('executed')}"))
        if CANARY in e.get("output", ""):
            out.append(Finding(ts, "High", "R4 system-prompt canary in output", user, rid, "hidden context leaked"))
    # R5: token usage far above the per-user median.
    by_user = defaultdict(list)
    for e in events:
        by_user[e["user"]].append(e.get("tokens", 0))
    median = statistics.median([t for e in events for t in [e.get("tokens", 0)]])
    for user, toks in by_user.items():
        if sum(toks) > 20 * median:
            out.append(Finding(events[-1]["ts"], "Medium", "R5 abnormal token consumption", user, "-",
                               f"{sum(toks)} tokens vs median request {median}"))
    return sorted(out, key=lambda f: (f.ts, f.rule))


def summarize(findings: list[Finding]) -> str:
    users = sorted({f.user for f in findings})
    critical = [f for f in findings if f.severity == "Critical"]
    first = findings[0].ts if findings else "-"
    rules = {f.rule.split()[0] for f in findings}
    # Only claim links in the chain that the evidence actually shows.
    chain, steps = [], ["preserve logs and model inputs/outputs"]
    if "R1" in rules and any("retrieved" in f.rule for f in findings):
        chain.append("untrusted content (document/email) carrying injected instructions")
        steps.append("quarantine the documents named in R1 findings")
    if "R2" in rules:
        chain.append("data exfiltration via URLs in model output")
        steps.append("block the external hosts in R2 findings; review what data the URLs carried")
    if "R3" in rules:
        chain.append("model-initiated email to an external address")
        steps.append("disable the send_email tool until a tool policy is in place")
    if "R4" in rules:
        steps.append("assume the system prompt is public; rotate anything sensitive it contained")
    if "R5" in rules:
        steps.append("suspend or rate-limit the keys in R5 findings; check billing")
    lines = ["DRAFT INCIDENT SUMMARY (verify every point before reporting)",
             f"  first indicator : {first}",
             f"  findings        : {len(findings)} ({len(critical)} critical)",
             f"  users involved  : {', '.join(users)}",
             f"  suspected chain : {' -> '.join(chain) if chain else 'no linked chain identified'}",
             "  immediate steps :"]
    lines += [f"    {i}) {s}" for i, s in enumerate(steps, 1)]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", type=Path, default=HERE / "data" / "app_logs.jsonl")
    args = ap.parse_args(argv)
    events = [json.loads(line) for line in args.logs.read_text(encoding="utf-8").splitlines() if line.strip()]
    findings = detect(events)
    print(f"Analyzed {len(events)} events; {len(findings)} findings\n")
    for f in findings:
        print(f"{f.ts}  {f.severity:<8} {f.rule}")
        print(f"   user={f.user} request={f.request_id}: {f.detail}")
    print()
    print(summarize(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
