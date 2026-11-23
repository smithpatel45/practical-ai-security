"""Lab 01: score red flags in (simulated) AI-written phishing and BEC emails.

Polished grammar is no longer a useful warning sign: generative AI writes fluent, well-
targeted text. This analyzer therefore ignores writing quality and focuses on signals an
attacker cannot easily polish away: who really sent the message, where replies go, where
links lead, and what the message asks you to do.

Usage:
    python analyze_email.py data/*.eml
    python analyze_email.py --json data/sample_2_vendor_bank_change.eml
"""
from __future__ import annotations

import argparse
import email
import json
import re
import sys
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).parent
CONFIG = json.loads((HERE / "data" / "trusted_domains.json").read_text(encoding="utf-8"))

PRESSURE = [r"\burgent(ly)?\b", r"\bimmediately\b", r"\btoday\b", r"\bwithin (an|one|1|two|2) hours?\b",
            r"\bconfidential\b", r"\bdo not (discuss|share|tell)\b", r"\bbefore end of day\b"]
PAYMENT = [r"\bbank (details|account)\b", r"\bwire\b", r"\bpayment (details|instructions)\b",
           r"\bgift cards?\b", r"\binvoice\b", r"\bIBAN\b", r"\brouting number\b"]
CREDENTIALS = [r"\b(verify|confirm|re-?enter) your (password|credentials|account)\b",
               r"\bsign in\b", r"\bMFA code\b", r"\bone-time code\b"]


@dataclass
class Finding:
    rule: str
    weight: int
    detail: str


@dataclass
class Report:
    file: str
    subject: str
    score: int = 0
    findings: list[Finding] = field(default_factory=list)

    def add(self, rule: str, weight: int, detail: str) -> None:
        self.findings.append(Finding(rule, weight, detail))
        self.score += weight

    @property
    def verdict(self) -> str:
        if self.score >= 6:
            return "LIKELY PHISHING / FRAUD"
        if self.score >= 3:
            return "SUSPICIOUS - verify out of band"
        return "NO STRONG INDICATORS"


class _LinkParser(HTMLParser):
    """Collect (visible text, href) pairs from HTML bodies."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(("".join(self._text).strip(), self._href))
            self._href = None


def domain_of(address: str) -> str:
    return parseaddr(address)[1].rpartition("@")[2].lower()


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str) -> str | None:
    """Return the trusted domain this one imitates, if it is close but not equal."""
    for trusted in CONFIG["trusted_domains"]:
        if domain != trusted and (levenshtein(domain, trusted) <= 2
                                  or domain.replace("-", "") == trusted.replace("-", "")):
            return trusted
    return None


def body_text(msg: email.message.EmailMessage) -> tuple[str, str]:
    plain, html = "", ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            plain += part.get_content()
        elif part.get_content_type() == "text/html":
            html += part.get_content()
    return plain, html


def analyze(path: Path) -> Report:
    msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    report = Report(file=path.name, subject=str(msg.get("Subject", "")))
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = domain_of(from_addr)

    # 1. Sender authentication results recorded by the receiving server.
    auth = str(msg.get("Authentication-Results", "")).lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}=(fail|softfail|none)", auth):
            report.add(f"{mech.upper()} not passing", 2, f"Authentication-Results shows {mech} did not pass")

    # 2. Lookalike sender domain.
    imitated = lookalike_of(from_dom)
    if imitated:
        report.add("Lookalike sender domain", 3, f"{from_dom} resembles trusted {imitated}")

    # 3. Display name claims an internal person but the address is external.
    if from_name and from_dom not in CONFIG["internal_domains"]:
        for person in CONFIG["executives"]:
            if person.lower() in from_name.lower():
                report.add("Executive name from external address", 3,
                           f'"{from_name}" sent from {from_dom}')

    # 4. Replies diverted elsewhere.
    reply_to = msg.get("Reply-To")
    if reply_to and domain_of(str(reply_to)) != from_dom:
        report.add("Reply-To differs from sender", 2, f"replies go to {domain_of(str(reply_to))}")

    plain, html = body_text(msg)
    text = f"{report.subject}\n{plain}\n{re.sub('<[^>]+>', ' ', html)}"

    # 5. Links whose visible text names one domain but whose target is another.
    parser = _LinkParser()
    parser.feed(html)
    for visible, href in parser.links:
        target = (urlparse(href).hostname or "").lower()
        shown = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", visible.lower())
        shown_dom = shown.group(0) if shown else ""
        # A target matches only if it IS the shown domain or a true subdomain of it.
        if shown and target and not (target == shown_dom or target.endswith("." + shown_dom)):
            report.add("Link text/target mismatch", 3, f'shows "{shown_dom}" but goes to {target}')
        elif target and lookalike_of(target):
            report.add("Link to lookalike domain", 3, target)

    # 6. What the message asks for, and how hard it pushes.
    pressure = sorted({m.group(0).lower() for p in PRESSURE for m in re.finditer(p, text, re.I)})
    if pressure:
        report.add("Pressure or secrecy language", min(2, len(pressure)), ", ".join(pressure))
    if any(re.search(p, text, re.I) for p in PAYMENT) and re.search(r"\b(new|updated|change[ds]?)\b", text, re.I):
        report.add("Payment-detail change request", 3, "asks to change where money is sent")
    if any(re.search(p, text, re.I) for p in CREDENTIALS):
        report.add("Credential request", 2, "asks you to sign in or provide a code")
    return report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--json", action="store_true", help="print machine-readable output")
    args = ap.parse_args(argv)
    reports = [analyze(p) for p in sorted(args.files)]
    if args.json:
        print(json.dumps([{**r.__dict__, "verdict": r.verdict,
                           "findings": [f.__dict__ for f in r.findings]} for r in reports], indent=2))
        return 0
    for r in reports:
        print(f"== {r.file}  |  {r.subject}")
        print(f"   score {r.score}: {r.verdict}")
        for f in r.findings:
            print(f"   +{f.weight} {f.rule}: {f.detail}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
