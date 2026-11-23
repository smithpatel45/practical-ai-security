import json

import ai_api as lab


def setup(secure, **kw):
    api = lab.AIApi(secure=secure, **kw)
    keys = {u: api.keys.issue(u, r) for u, r in [("alice", "analyst"), ("bob", "analyst"),
                                                 ("viv", "viewer"), ("root", "admin")]}
    return api, keys


def req(api, method, path, key, body=None):
    return api.dispatch(method, path, f"Bearer {key}" if key else None, body or {})


def test_missing_and_tampered_keys_rejected():
    api, k = setup(True)
    assert req(api, "POST", "/v1/chat", None)[0] == 401
    assert req(api, "POST", "/v1/chat", k["alice"][:-2] + "zz")[0] == 401


def test_bola_vulnerable_vs_secure():
    for secure, expected in [(False, 200), (True, 404)]:
        api, k = setup(secure)
        conv = req(api, "POST", "/v1/chat", k["alice"], {"message": "private"})[1]["conversation_id"]
        assert req(api, "GET", f"/v1/conversations/{conv}", k["bob"])[0] == expected


def test_roles_enforced():
    api, k = setup(True)
    conv = req(api, "POST", "/v1/chat", k["alice"], {"message": "m"})[1]["conversation_id"]
    assert req(api, "GET", f"/v1/conversations/{conv}", k["root"])[0] == 200      # admin may read any
    assert req(api, "POST", "/v1/admin/revoke", k["bob"], {"key_id": "x"})[0] == 403
    viv_conv = req(api, "POST", "/v1/chat", k["viv"], {"message": "m"})[1]["conversation_id"]
    assert req(api, "GET", f"/v1/conversations/{viv_conv}", k["viv"])[0] == 403    # viewer can't read history


def test_revocation_takes_effect():
    api, k = setup(True)
    key_id = k["alice"].split("_")[1]
    assert req(api, "POST", "/v1/admin/revoke", k["root"], {"key_id": key_id})[0] == 200
    assert req(api, "POST", "/v1/chat", k["alice"], {"message": "hi"}) == (401, {"error": "API key revoked"})


def test_rate_limit():
    api, k = setup(True, rate_capacity=3, rate_refill=0.0)
    codes = [req(api, "POST", "/v1/chat", k["bob"], {"message": "x"})[0] for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_keys_stored_hashed_only_in_secure_mode():
    api, k = setup(True)
    assert k["alice"] not in json.dumps(api.keys._records)
    api_v, k_v = setup(False)
    assert k_v["alice"] in json.dumps(api_v.keys._records)


def test_http_round_trip():
    api, k = setup(True)
    server = lab.make_server(api)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    status, body = lab.call(base, "POST", "/v1/chat", k["alice"], {"message": "hello"})
    server.shutdown()
    assert status == 200 and "conversation_id" in body
