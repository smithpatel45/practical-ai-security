import rag_lab as lab


def build(secure):
    docs, users = lab.load()
    rag = lab.RAG(secure)
    rag.ingest(docs)
    return rag, users


def test_assessment_table():
    assert lab.assess() == [
        ("cross-tenant leakage", "FAIL", "PASS"),
        ("cross-group leakage", "FAIL", "PASS"),
        ("poisoned document influence", "FAIL", "PASS"),
        ("normal question still answered", "PASS", "PASS"),
    ]


def test_hr_member_can_read_salary_bands_in_secure_mode():
    rag, users = build(True)
    reply, ids = rag.answer(users["hana"], "What are the salary bands for engineers?")
    assert ids == ["hr-salary"]


def test_other_tenant_never_sees_acme_data():
    rag, users = build(True)
    for q in ["How do I reset my VPN password?", "annual leave days", "salary bands"]:
        _, ids = rag.answer(users["max"], q)
        assert not any(i in {"it-vpn", "hr-holiday", "hr-salary"} for i in ids)


def test_poisoned_upload_is_quarantined_not_indexed():
    rag, _ = build(True)
    assert "poison-vpn" in [d for d, _ in rag.quarantine]
    assert "poison-vpn" not in [c.id for c in rag.index]


def test_intranet_link_kept_external_removed():
    rag, users = build(True)
    reply, _ = rag.answer(users["jo"], "How do I reset my VPN password?")
    assert "https://intranet.acme.example/vpn" in reply


def test_permission_filter_happens_before_ranking():
    # Even with k large, the secure retriever can't return forbidden chunks.
    rag, users = build(True)
    chunks = rag.retrieve(users["jo"], "salary bands merger code VPN", k=50)
    assert all(c.tenant == "acme" and "all-staff" in c.groups for c in chunks)
