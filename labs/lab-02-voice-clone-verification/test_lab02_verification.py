import json
from pathlib import Path

import verify_request as vr

DATA = Path(__file__).parent / "data"
POLICY = json.loads((DATA / "policy.json").read_text())
SCEN = {s["id"]: s for s in json.loads((DATA / "scenarios.json").read_text())}


def test_deepfake_video_payment_requires_callback_and_second_approver():
    d = vr.evaluate(SCEN["S1"], POLICY)
    assert d.action == "VERIFY_FIRST"
    assert any("directory" in s for s in d.required_steps)
    assert any("second approver" in s for s in d.required_steps)


def test_unofficial_executive_contact_is_not_allowed_silently():
    assert vr.evaluate(SCEN["S2"], POLICY).action == "VERIFY_FIRST"


def test_callback_to_supplied_number_does_not_count():
    d = vr.evaluate(SCEN["S3"], POLICY)
    assert d.action == "VERIFY_FIRST"
    assert "call-back went to a number supplied by the requester" in d.red_flags


def test_verified_small_routine_payment_allowed():
    assert vr.evaluate(SCEN["S4"], POLICY).action == "ALLOW"


def test_mfa_code_request_always_refused_even_on_company_phone():
    assert vr.evaluate(SCEN["S6"], POLICY).action == "REFUSE"


def test_convincing_voice_does_not_change_outcome():
    # Policy decisions must not depend on how authentic the voice sounds.
    s = dict(SCEN["S1"], voice_sounds_authentic=True)
    assert vr.evaluate(s, POLICY).action == "VERIFY_FIRST"
