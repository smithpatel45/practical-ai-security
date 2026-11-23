import json
from pathlib import Path

import threat_model as tm

SYSTEM = json.loads((Path(__file__).parent / "data" / "system.json").read_text())


def titles(threats):
    return {t.title for t in threats}


def test_core_threats_generated():
    t = titles(tm.generate(SYSTEM))
    assert "Direct prompt injection / jailbreak" in t
    assert "Indirect prompt injection via inbound_email" in t
    assert "Exfiltration through rendered output (images/links)" in t
    assert "Actions by refund_tool cannot be attributed" in t


def test_secret_in_prompt_raises_impact():
    sys2 = json.loads(json.dumps(SYSTEM))
    for c in sys2["components"]:
        if c["id"] == "assistant_llm":
            c["hidden_context_has_secrets"] = True
    hc = [t for t in tm.generate(sys2) if t.owasp == "LLM08:2026"][0]
    assert hc.impact == 5 and hc.title == "Secrets exposed from hidden context"


def test_score_override_and_sorting():
    threats = tm.generate(SYSTEM)
    tm.apply_scores(threats, {"T05": {"impact": 1}})
    assert next(t for t in threats if t.tid == "T05").risk == 3
    md = tm.to_markdown(SYSTEM, threats)
    risks = [int(line.split("|")[9].split()[0]) for line in md.splitlines() if line.startswith("| T")]
    assert risks == sorted(risks, reverse=True)


def test_public_hub_model_adds_supply_chain_threat():
    sys2 = json.loads(json.dumps(SYSTEM))
    for c in sys2["components"]:
        if c["id"] == "base_model":
            c["from_public_hub"] = True
    assert any(t.owasp == "LLM04:2026" for t in tm.generate(sys2))


def test_atlas_ids_are_from_verified_list():
    verified = {"AML.T0051", "AML.T0054", "AML.T0053", "AML.T0077", "AML.T0069", "AML.T0034",
                "AML.T0029", "AML.T0070", "AML.T0010", "AML.T0040", "n/a"}
    for t in tm.generate(SYSTEM):
        for atlas_id in [x.strip() for x in t.atlas.split(",")]:
            assert atlas_id in verified
