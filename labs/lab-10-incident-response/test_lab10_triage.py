import json
from pathlib import Path

import triage

EVENTS = [json.loads(l) for l in (Path(__file__).parent / "data" / "app_logs.jsonl").read_text().splitlines() if l.strip()]


def rules_for(request_id, findings):
    return {f.rule.split()[0] for f in findings if f.request_id == request_id}


def test_expected_detections():
    f = triage.detect(EVENTS)
    assert rules_for("r-1004", f) == {"R1", "R2"}
    assert rules_for("r-1006", f) == {"R1", "R4"}
    assert rules_for("r-1007", f) == {"R1", "R3"}
    assert any(x.rule.startswith("R5") and x.user == "svc-batch-key-3" for x in f)


def test_benign_events_produce_no_findings():
    f = triage.detect(EVENTS)
    for rid in ("r-1001", "r-1002", "r-1008"):
        assert not rules_for(rid, f)


def test_internal_link_not_flagged_even_with_query():
    e = dict(EVENTS[1], output="See https://help.northwind.example/refunds?lang=en")
    assert not triage.detect([e, EVENTS[0]])


def test_summary_only_claims_observed_chain():
    only_r5 = [f for f in triage.detect(EVENTS) if f.rule.startswith("R5")]
    s = triage.summarize(only_r5)
    assert "no linked chain identified" in s and "send_email" not in s


def test_upload_event_itself_is_not_detected():
    # Teaching point: the poisoning happened at r-1003, but nothing in that log line shows it.
    assert not rules_for("r-1003", triage.detect(EVENTS))
