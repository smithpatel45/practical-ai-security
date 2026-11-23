"""Lab 02: apply an identity-verification policy to impersonation scenarios.

A convincing cloned voice or deepfake video defeats "does this sound like the boss?"
The defense is a policy that decides what must be verified *regardless of how genuine
the request seems*. This tool evaluates scenarios against such a policy and prints the
decision, the red flags it saw, and the verification steps that are required.

Usage:
    python verify_request.py
    python verify_request.py --policy data/policy.json --scenarios data/scenarios.json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).parent


@dataclass
class Decision:
    scenario_id: str
    action: str                      # ALLOW, VERIFY_FIRST, or REFUSE
    red_flags: list[str] = field(default_factory=list)
    required_steps: list[str] = field(default_factory=list)


def evaluate(s: dict, policy: dict) -> Decision:
    d = Decision(s["id"], "ALLOW")
    req = s["request_type"]
    sensitive = req in policy["sensitive_request_types"]
    channel_trusted = s["channel"] in policy["trusted_channels"]

    # Red flags are things a person should notice; the policy does not depend on them.
    if s.get("urgency"):
        d.red_flags.append("pressure to act quickly")
    if s.get("secrecy"):
        d.red_flags.append("asked to keep it secret or bypass normal process")
    if not channel_trusted:
        d.red_flags.append(f"request arrived on an unofficial channel ({s['channel']})")
    if s.get("new_payee_or_details"):
        d.red_flags.append("new payee or changed payment details")
    if s.get("caller_refused_callback"):
        d.red_flags.append("requester discouraged a call back")

    # Executives contacting staff on unofficial channels is the opening move of many
    # impersonation attempts, whatever the first request looks like.
    if not channel_trusted and s.get("claimed_role") in policy["impersonation_prone_roles"]:
        d.action = "VERIFY_FIRST"
        d.required_steps.append("Do not continue on this channel: contact the person through an official "
                                "channel and report the contact to security.")

    if req in policy["never_over_voice_or_video"]:
        d.action = "REFUSE"
        d.required_steps.append(policy["never_rule_text"])
        return d

    if sensitive:
        d.action = "VERIFY_FIRST"
        d.required_steps.append("Call back using the number in the company directory, not one given in the request.")
        if s.get("amount", 0) >= policy["dual_approval_threshold"] or s.get("new_payee_or_details"):
            d.required_steps.append("Obtain a second approver through the payment system's normal workflow.")
        if s.get("callback_done") and s.get("callback_used_directory_number") and \
                (s.get("second_approval") or not (s.get("amount", 0) >= policy["dual_approval_threshold"]
                                                  or s.get("new_payee_or_details"))):
            d.action = "ALLOW"
            d.required_steps.append("Verification completed: proceed and record the evidence.")
        elif s.get("callback_done") and not s.get("callback_used_directory_number"):
            d.red_flags.append("call-back went to a number supplied by the requester")
    if s.get("is_family_emergency"):
        d.action = "VERIFY_FIRST"
        d.required_steps.append("Ask for the pre-agreed family code word, then hang up and call the person directly.")
    return d


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--policy", type=Path, default=HERE / "data" / "policy.json")
    ap.add_argument("--scenarios", type=Path, default=HERE / "data" / "scenarios.json")
    args = ap.parse_args(argv)
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    scenarios = json.loads(args.scenarios.read_text(encoding="utf-8"))
    for s in scenarios:
        d = evaluate(s, policy)
        print(f"== {s['id']}: {s['summary']}")
        print(f"   decision: {d.action}")
        for f in d.red_flags:
            print(f"   red flag: {f}")
        for step in d.required_steps:
            print(f"   step: {step}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
