import agent as lab


def test_unrestricted_agent_executes_injected_actions():
    assert lab.Agent(guarded=False).run("read ticket ticket_id=42") == ["REFUND 900 on ORD-555123"]
    effects = lab.Agent(guarded=False).run("read ticket ticket_id=43")
    assert effects == ["EMAIL to collect@invoice-mirror.example: all customer records"]


def test_guarded_agent_blocks_injected_actions():
    for ticket in ("42", "43"):
        a = lab.Agent(guarded=True)
        assert a.run(f"read ticket ticket_id={ticket}") == []
        assert any(not e["allowed"] for e in a.policy.audit)


def test_deny_by_default_for_unlisted_tool():
    p = lab.PolicyEngine()
    assert not p.check("delete_ticket", {"ticket_id": "42"}).allowed


def test_clean_session_small_refund_allowed_without_approval():
    a = lab.Agent(guarded=True)
    assert a.run("issue refund order_id=ORD-555200, amount=35") == ["REFUND 35 on ORD-555200"]


def test_tainted_session_needs_human_approval():
    a = lab.Agent(guarded=True)
    a.run("read ticket ticket_id=44")
    assert a.policy.tainted
    assert a.run("issue refund order_id=ORD-555200, amount=35") == []

    approved = lab.Agent(guarded=True, policy=lab.PolicyEngine(approver=lambda *_: True))
    approved.run("read ticket ticket_id=44")
    assert approved.run("issue refund order_id=ORD-555200, amount=35") == ["REFUND 35 on ORD-555200"]


def test_approval_cannot_override_hard_limits():
    p = lab.PolicyEngine(approver=lambda *_: True, tainted=True)
    assert not p.check("issue_refund", {"order_id": "ORD-1", "amount": 900}).allowed
    assert not p.check("send_email", {"to": "x@evil.example", "body": "b"}).allowed


def test_every_proposal_is_audited():
    a = lab.Agent(guarded=True)
    a.run("read ticket ticket_id=42")
    assert [e["tool"] for e in a.policy.audit] == ["read_ticket", "issue_refund"]
