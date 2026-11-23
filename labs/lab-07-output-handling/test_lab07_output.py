import pytest

import output_guard as og


def test_script_is_escaped():
    assert "<script>" not in og.render_safe("<script>x()</script>")


def test_images_always_removed():
    out = og.render_safe("![a](https://help.northwind.example/x.png) ![b](https://evil.example/p?d=1)")
    assert "<img" not in out and "evil.example" not in out


def test_only_https_allowlisted_links_survive():
    assert '<a href="https://help.northwind.example/r"' in og.render_safe("[ok](https://help.northwind.example/r)")
    assert "<a " not in og.render_safe("[x](http://help.northwind.example/r)")   # http not allowed
    assert "<a " not in og.render_safe("[x](javascript:alert(1))")
    assert "<a " not in og.render_safe("[x](https://help.northwind.example.evil.example/)")


def test_placeholder_characters_cannot_forge_links():
    forged = "\u0000Ajavascript:alert(1)\u0001click\u0002"
    assert "<a " not in og.render_safe(forged)


@pytest.mark.parametrize("raw,ok", [
    ('{"tool": "lookup_order", "arguments": {"order_id": "ORD-123456"}}', True),
    ('{"tool": "lookup_order", "arguments": {"order_id": "ORD-1; DROP"}}', False),
    ('{"tool": "issue_refund", "arguments": {"order_id": "ORD-123456", "amount": 101}}', False),
    ('{"tool": "issue_refund", "arguments": {"order_id": "ORD-123456", "amount": true}}', False),
    ('{"tool": "set_ticket_status", "arguments": {"ticket_id": 3, "status": "deleted"}}', False),
    ('{"tool": "lookup_order"}', False),
    ('not json', False),
])
def test_tool_call_validation(raw, ok):
    if ok:
        assert og.validate_tool_call(raw)
    else:
        with pytest.raises(og.ToolCallRejected):
            og.validate_tool_call(raw)


def test_unsafe_query_leaks_all_rows_safe_query_scoped():
    db = og.make_db()
    assert len(og.query_unsafe(db, "customer = 'sam@example.org' OR '1'='1'")) == 3
    assert og.query_safe(db, "sam@example.org", '{"filters": []}') == [("ORD-100001", "sam@example.org")]


def test_safe_query_rejects_non_allowlisted_column_and_injection_in_value():
    db = og.make_db()
    with pytest.raises(ValueError):
        og.query_safe(db, "sam@example.org", '{"filters": [{"column": "customer", "op": "=", "value": "x"}]}')
    # Malicious value is bound as a parameter, so it is just a string that matches nothing.
    assert og.query_safe(db, "sam@example.org",
                         '{"filters": [{"column": "status", "op": "=", "value": "x\' OR \'1\'=\'1"}]}') == []
