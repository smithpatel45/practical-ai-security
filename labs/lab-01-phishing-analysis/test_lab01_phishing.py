from pathlib import Path

import analyze_email as ae

DATA = Path(__file__).parent / "data"


def verdict(name):
    return ae.analyze(DATA / name)


def rules(report):
    return {f.rule for f in report.findings}


def test_ceo_wire_is_flagged_with_bec_signals():
    r = verdict("sample_1_ceo_wire.eml")
    assert r.verdict == "LIKELY PHISHING / FRAUD"
    assert {"Lookalike sender domain", "Executive name from external address",
            "Reply-To differs from sender", "Payment-detail change request"} <= rules(r)


def test_vendor_bank_change_flagged_even_with_spf_pass():
    r = verdict("sample_2_vendor_bank_change.eml")
    assert "SPF not passing" not in rules(r)  # attacker controls their own lookalike domain
    assert "Lookalike sender domain" in rules(r)
    assert r.verdict == "LIKELY PHISHING / FRAUD"


def test_payroll_link_mismatch_detected():
    r = verdict("sample_3_payroll_mfa.eml")
    assert "Link text/target mismatch" in rules(r)
    assert "Credential request" in rules(r)


def test_legitimate_newsletter_is_clean():
    r = verdict("sample_4_legitimate_newsletter.eml")
    assert r.score == 0


def test_subdomain_trick_is_not_treated_as_match():
    assert ae.lookalike_of("contoso-suppiles.example") == "contoso-supplies.example"
    assert ae.lookalike_of("northwind.example") is None
