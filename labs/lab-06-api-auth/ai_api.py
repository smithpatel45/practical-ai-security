"""Lab 06: authentication, authorization and rate limiting for a small AI API.

The API lets users chat with the (mock) model and read back their saved conversations.
Run it in two modes:

  vulnerable: API keys stored in plain text and compared with ==; any authenticated user
              can read any conversation by ID (Broken Object Level Authorization, OWASP
              API1:2023); no rate limit.
  secure:     keys stored as SHA-256 hashes and compared in constant time; role-based
              permissions; object ownership checked on every read; per-key rate limit;
              key revocation.

Usage:
    python ai_api.py              # runs the HTTP demo against both modes on localhost
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "shared"))
from mock_llm import MockLLM  # noqa: E402

ROLE_PERMISSIONS = {
    "viewer": {"chat"},
    "analyst": {"chat", "conversations:read_own"},
    "admin": {"chat", "conversations:read_own", "conversations:read_any", "keys:revoke"},
}


@dataclass
class Principal:
    user_id: str
    role: str
    key_id: str


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass
class KeyStore:
    secure: bool
    _records: dict = field(default_factory=dict)   # key_id -> record

    def issue(self, user_id: str, role: str) -> str:
        key_id = secrets.token_hex(4)
        secret = secrets.token_urlsafe(24)
        api_key = f"lab_{key_id}_{secret}"          # the only time the full key is visible
        stored = hashlib.sha256(api_key.encode()).hexdigest() if self.secure else api_key
        self._records[key_id] = {"stored": stored, "user_id": user_id, "role": role, "revoked": False}
        return api_key

    def authenticate(self, header: str | None) -> Principal:
        if not header or not header.startswith("Bearer "):
            raise AuthError(401, "missing bearer token")
        api_key = header[len("Bearer "):].strip()
        m = re.fullmatch(r"lab_([0-9a-f]{8})_[A-Za-z0-9_-]+", api_key)
        rec = self._records.get(m.group(1)) if m else None
        if rec is None:
            raise AuthError(401, "invalid API key")
        if self.secure:
            candidate = hashlib.sha256(api_key.encode()).hexdigest()
            valid = hmac.compare_digest(candidate, rec["stored"])   # constant-time comparison
        else:
            valid = api_key == rec["stored"]
        if not valid:
            raise AuthError(401, "invalid API key")
        if rec["revoked"]:
            raise AuthError(401, "API key revoked")
        return Principal(rec["user_id"], rec["role"], m.group(1))

    def revoke(self, key_id: str) -> bool:
        if key_id in self._records:
            self._records[key_id]["revoked"] = True
            return True
        return False


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity, self.rate, self._state, self._lock = capacity, refill_per_sec, {}, threading.Lock()

    def take(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self._state[key] = (tokens - 1 if ok else tokens, now)
            return ok


class AIApi:
    def __init__(self, secure: bool, rate_capacity: int = 5, rate_refill: float = 0.2):
        self.secure = secure
        self.keys = KeyStore(secure)
        self.model = MockLLM()
        self.conversations: dict[str, dict] = {}
        self.limiter = TokenBucket(rate_capacity, rate_refill)

    def authorize(self, p: Principal, permission: str) -> None:
        if self.secure and permission not in ROLE_PERMISSIONS.get(p.role, set()):
            raise AuthError(403, f"role '{p.role}' lacks permission '{permission}'")

    # Each method returns (status, body).
    def chat(self, p: Principal, body: dict) -> tuple[int, dict]:
        self.authorize(p, "chat")
        reply = self.model.complete([{"role": "user", "content": str(body.get("message", ""))[:2000]}])
        conv_id = secrets.token_hex(6)  # unguessable IDs help, but are NOT authorization
        self.conversations[conv_id] = {"owner": p.user_id, "messages": [body.get("message"), reply]}
        return 200, {"conversation_id": conv_id, "reply": reply}

    def get_conversation(self, p: Principal, conv_id: str) -> tuple[int, dict]:
        conv = self.conversations.get(conv_id)
        if not self.secure:
            return (200, conv) if conv else (404, {"error": "not found"})   # BOLA: no owner check
        if conv is None:
            return 404, {"error": "not found"}
        if conv["owner"] == p.user_id:
            self.authorize(p, "conversations:read_own")
        else:
            try:
                self.authorize(p, "conversations:read_any")
            except AuthError:
                return 404, {"error": "not found"}   # don't reveal that the ID exists
        return 200, conv

    def revoke(self, p: Principal, body: dict) -> tuple[int, dict]:
        self.authorize(p, "keys:revoke")
        return (200, {"revoked": True}) if self.keys.revoke(str(body.get("key_id"))) else (404, {"error": "no such key"})

    def dispatch(self, method: str, path: str, auth: str | None, body: dict) -> tuple[int, dict]:
        try:
            p = self.keys.authenticate(auth)
            if self.secure and not self.limiter.take(p.key_id):
                return 429, {"error": "rate limit exceeded"}
            if method == "POST" and path == "/v1/chat":
                return self.chat(p, body)
            m = re.fullmatch(r"/v1/conversations/([0-9a-f]+)", path)
            if method == "GET" and m:
                return self.get_conversation(p, m.group(1))
            if method == "POST" and path == "/v1/admin/revoke":
                return self.revoke(p, body)
            return 404, {"error": "unknown route"}
        except AuthError as e:
            return e.status, {"error": str(e)}


def make_server(api: AIApi) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _handle(self, method):
            length = min(int(self.headers.get("Content-Length", 0) or 0), 16_384)
            try:
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except json.JSONDecodeError:
                body = {}
            status, out = api.dispatch(method, self.path, self.headers.get("Authorization"), body)
            data = json.dumps(out).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)   # localhost, random free port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def call(base: str, method: str, path: str, key: str | None = None, body: dict | None = None):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {key}"} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def demo(secure: bool) -> None:
    api = AIApi(secure=secure)
    server = make_server(api)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    users = json.loads((Path(__file__).parent / "data" / "users.json").read_text(encoding="utf-8"))
    keys = {u["user_id"]: api.keys.issue(u["user_id"], u["role"]) for u in users}
    alice, bob, admin = keys["alice"], keys["bob"], keys["ops-admin"]
    print(f"######## {'SECURE' if secure else 'VULNERABLE'} API")
    print("no key            ->", call(base, "POST", "/v1/chat", None, {"message": "hi"})[0])
    s, out = call(base, "POST", "/v1/chat", alice, {"message": "Draft my salary negotiation email"})
    conv = out["conversation_id"]
    print("alice chats       ->", s)
    print("alice reads own   ->", call(base, "GET", f"/v1/conversations/{conv}", alice)[0])
    s, out = call(base, "GET", f"/v1/conversations/{conv}", bob)
    print("bob reads alice's ->", s, "(LEAKED: " + str(out.get("messages", [""])[0]) + ")" if s == 200 else "")
    print("admin reads it    ->", call(base, "GET", f"/v1/conversations/{conv}", admin)[0])
    print("bob tries revoke  ->", call(base, "POST", "/v1/admin/revoke", bob, {"key_id": alice.split("_")[1]})[0])
    codes = [call(base, "POST", "/v1/chat", bob, {"message": "x"})[0] for _ in range(8)]
    print("bob sends 8 fast  ->", codes)
    print("stored key form   ->", "plaintext" if alice in json.dumps(api.keys._records) else "sha256 hash")
    server.shutdown()
    print()


if __name__ == "__main__":
    demo(secure=False)
    demo(secure=True)
