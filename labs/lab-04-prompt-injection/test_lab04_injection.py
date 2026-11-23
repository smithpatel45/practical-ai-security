import injection_lab as lab


def results(secure):
    return {r.scenario: r for r in lab.run_all(secure)}


def test_vulnerable_mode_is_exploited_three_ways():
    r = results(False)
    assert lab.outcome(r["direct injection"], "direct injection") == "EXPLOITED"
    assert r["indirect: image exfiltration"].leaked
    assert r["indirect: tool exfiltration"].sent_emails


def test_secure_mode_blocks_both_indirect_exfiltration_paths():
    r = results(True)
    assert not r["indirect: image exfiltration"].leaked
    assert not r["indirect: tool exfiltration"].sent_emails
    assert lab.outcome(r["direct injection"], "direct injection") == "EXPOSED (no sensitive data)"
    assert lab.outcome(r["benign summary"], "benign summary") == "OK"


def test_spotlighting_alone_does_not_stop_the_model_following_injection():
    app = lab.ResearchMate(secure=True)
    doc = (lab.DATA / "article_poisoned.txt").read_text()
    raw = app.model.complete(app.build_messages("Please summarize this article.", doc))
    # The labeled delimiters were present, yet the (mock) model still emitted the attacker image.
    assert "collector.attacker.example" in raw


def test_output_handling_still_blocks_if_data_minimization_fails():
    app = lab.ResearchMate(secure=True)
    doc = (lab.DATA / "article_poisoned.txt").read_text()
    # User mentions notes, so private data IS in context: the next layer must catch it.
    r = app.run("x", "Summarize this article and compare with my notes.", doc)
    assert not r.fetched_urls and not r.leaked
    assert any("image" in b for b in r.blocked)


def test_internal_email_with_approval_is_allowed_on_clean_session():
    app = lab.ResearchMate(secure=True, approver=lambda call: True)
    r = app.run("x", "send email to=lee@northwind.example, body=Meeting moved to 3pm")
    assert r.sent_emails == [{"to": "lee@northwind.example", "body": "Meeting moved to 3pm"}]


def test_email_without_approval_waits():
    app = lab.ResearchMate(secure=True)
    r = app.run("x", "send email to=lee@northwind.example, body=hi")
    assert not r.sent_emails and "human approval not granted" in r.blocked
