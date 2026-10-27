"""The MCP server and pages, end to end over real HTTP."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shutil
import socket
import statistics
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "2025-11-25"
PASSPHRASE = "correct horse battery staple"
SIM_SECRET = "sim-secret-for-tests"
ALEXA_SECRET = "alexa-secret-for-tests"
ALEXA_REDIRECT = "https://alexa.test/cb"
EXPECTED_TOOLS = {"order_usual", "request_purchase", "request_transfer", "freeze_spending", "unlock_spending", "change_limit", "cancel_waiting", "safety_status", "explain_last_decision"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import uvicorn

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    (tmp_path / "clients.json").write_text(json.dumps([
        {"client_id": "simulator", "secret_sha256": hashlib.sha256(SIM_SECRET.encode()).hexdigest(), "redirect_uris": [], "grants": ["client_credentials"]},
        {"client_id": "alexa", "secret_sha256": hashlib.sha256(ALEXA_SECRET.encode()).hexdigest(), "redirect_uris": [ALEXA_REDIRECT], "grants": ["authorization_code", "refresh_token"]},
    ]))
    shutil.copy(ROOT / "data" / "policy.example.json", tmp_path / "policy.json")
    env = {
        "KINLOCK_PUBLIC_URL": base,
        "KINLOCK_DATA": str(tmp_path),
        "KINLOCK_OWNER_PASSPHRASE_SHA256": hashlib.sha256(PASSPHRASE.encode()).hexdigest(),
        "KINLOCK_PORT": str(port),
        "KINLOCK_SIM_CLIENT_ID": "simulator",
        "KINLOCK_SIM_CLIENT_SECRET": SIM_SECRET,
        "KINLOCK_SIMULATOR": "1",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("KINLOCK_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("KINLOCK_NTFY_URL", raising=False)
    from kinlock.server import create_app

    app = create_app()
    # Tests run at any hour; switch off the late-night rule so results don't depend on the clock.
    pol = json.loads((tmp_path / "policy.json").read_text())
    pol["night_hours"] = None
    (tmp_path / "policy.json").write_text(json.dumps(pol))
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield {"base": base, "app": app, "dir": tmp_path}
    srv.should_exit = True
    t.join(timeout=5)


def bearer(base: str) -> str:
    r = httpx2.post(f"{base}/token", data={"grant_type": "client_credentials", "scope": "mcp:service", "resource": f"{base}/mcp"}, auth=("simulator", SIM_SECRET))
    r.raise_for_status()
    return r.json()["access_token"]


def owner_bearer(base: str) -> str:
    """An access token the owner linked herself: authorization code + PKCE, as Alexa+ does."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"client_id": "alexa", "redirect_uri": ALEXA_REDIRECT, "response_type": "code", "code_challenge": challenge, "code_challenge_method": "S256", "resource": f"{base}/mcp", "state": "s"}
    r = httpx2.post(f"{base}/authorize", data={**params, "passphrase": PASSPHRASE})
    assert r.status_code == 302, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    t = httpx2.post(f"{base}/token", data={"grant_type": "authorization_code", "code": code, "code_verifier": verifier, "redirect_uri": ALEXA_REDIRECT, "resource": f"{base}/mcp"}, auth=("alexa", ALEXA_SECRET))
    t.raise_for_status()
    return t.json()["access_token"]


def rpc(base: str, tok: str, method: str, params: dict | None = None) -> httpx2.Response:
    msg = {"jsonrpc": "2.0", "id": secrets.randbelow(10**6), "method": method, **({"params": params} if params is not None else {})}
    return httpx2.post(f"{base}/mcp", json=msg, headers={"Authorization": f"Bearer {tok}", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL})


def call(base: str, tok: str, name: str, args: dict | None = None) -> str:
    r = rpc(base, tok, "tools/call", {"name": name, "arguments": args or {}})
    r.raise_for_status()
    return " ".join(c["text"] for c in r.json()["result"]["content"] if c["type"] == "text")


def test_auth_documents_and_401_without_www_authenticate(server):
    base = server["base"]
    assert httpx2.get(f"{base}/.well-known/oauth-authorization-server").json()["code_challenge_methods_supported"] == ["S256"]
    assert httpx2.get(f"{base}/.well-known/oauth-protected-resource").json()["resource"] == f"{base}/mcp"
    r = httpx2.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401 and "www-authenticate" not in {k.lower() for k in r.headers}


def test_initialize_and_tools(server):
    base = server["base"]
    tok = bearer(base)
    init = rpc(base, tok, "initialize", {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}).json()
    assert init["result"]["protocolVersion"] == PROTOCOL
    names = {t["name"] for t in rpc(base, tok, "tools/list", {}).json()["result"]["tools"]}
    assert names == EXPECTED_TOOLS
    assert not ({"approve", "approve_request", "unfreeze", "raise_limit"} & names)


def test_voice_flow_end_to_end_with_contact_approval(server):
    base = server["base"]
    tok = owner_bearer(base)
    assert call(base, tok, "order_usual").startswith("Done.")
    held = call(base, tok, "request_purchase", {"merchant": "TechZone", "amount_dollars": 849.99, "category": "electronics", "item": "a laptop"})
    assert "held" in held and "Anna" in held
    link = json.loads((server["dir"] / "outbox.jsonl").read_text().splitlines()[-1])["link"]
    page = httpx2.get(link)
    assert page.status_code == 200 and "$849.99" in page.text and "Approve this exact purchase" in page.text
    digest = re.search(r"name=digest value='([0-9a-f]{64})'", page.text).group(1)
    done = httpx2.post(link, data={"digest": digest, "decision": "approve"})
    assert done.status_code == 200 and "Approved" in done.text
    again = httpx2.post(link, data={"digest": digest, "decision": "approve"})
    assert again.status_code == 409
    assert httpx2.get(f"{base}/healthz").json()["receipt_chain_ok"]


def test_voice_cannot_unlock_or_raise(server):
    base = server["base"]
    tok = owner_bearer(base)
    assert "frozen" in call(base, tok, "freeze_spending")
    assert "never" in call(base, tok, "unlock_spending")
    assert "safety lock is on" in call(base, tok, "order_usual").lower()
    assert "never" in call(base, tok, "change_limit", {"category": "groceries", "limit": "daily_total", "new_value": 5000})
    assert "Done" in call(base, tok, "change_limit", {"category": "groceries", "limit": "daily_total", "new_value": 100})


def test_owner_page_unlocks(server):
    base = server["base"]
    tok = owner_bearer(base)
    call(base, tok, "freeze_spending")
    with httpx2.Client(base_url=base, follow_redirects=True) as c:
        assert c.post("/owner", data={"passphrase": "wrong"}).status_code == 401
        page = c.post("/owner", data={"passphrase": PASSPHRASE})
        assert "Safety lock is ON" in page.text
        csrf = re.search(r"name=csrf value='([^']+)'", page.text).group(1)
        assert c.post("/owner/act", data={"op": "unfreeze"}).status_code == 403  # no CSRF token
        after = c.post("/owner/act", data={"csrf": csrf, "op": "unfreeze"})
        assert "Safety lock is off" in after.text
    assert call(base, tok, "order_usual").startswith("Done.")


def test_simulator_drives_mcp_and_attacks_are_blocked(server):
    base = server["base"]
    say = lambda u: httpx2.post(f"{base}/sim/assist", json={"utterance": u, "session": "t"}, timeout=10).json()  # noqa: E731
    r = say("Order the laptop from TechZone")
    assert r["protocol"] == PROTOCOL and any(t.get("tool") == "request_purchase" for t in r["trace"])
    tamper = httpx2.post(f"{base}/sim/attack", json={"kind": "tamper"}).json()
    assert tamper["ok"]
    link = httpx2.get(f"{base}/sim/state").json()["last_notification"]["link"]
    page = httpx2.get(link)
    # Anna's page now shows the tampered amount, but the approval must still fail: the digest she
    # approves no longer matches the one recorded when the order was held.
    digest = re.search(r"name=digest value='([0-9a-f]{64})'", page.text).group(1)
    res = httpx2.post(link, data={"digest": digest, "decision": "approve"})
    assert res.status_code == 409 and "changed" in res.text
    assert "never" in say("Unfreeze everything")["reply"] or "nothing" in say("Unfreeze everything")["reply"].lower()
    assert "always blocked" in say("Buy $500 of gift cards")["reply"]


def test_voice_round_trip_is_well_under_500_ms(server):
    base = server["base"]
    tok = bearer(base)
    times = []
    for _ in range(15):
        t0 = time.perf_counter()
        call(base, tok, "safety_status")
        times.append((time.perf_counter() - t0) * 1000)
    assert statistics.median(times) < 250


# -- scopes: a service token can't spend --------------------------------------------------------


def test_service_token_cannot_spend_or_change_rules(server):
    base = server["base"]
    svc = bearer(base)
    for name, args in [
        ("order_usual", {}),
        ("request_purchase", {"merchant": "Fresh Market", "amount_dollars": 10, "category": "groceries", "item": "milk"}),
        ("request_transfer", {"payee": "Anna", "amount_dollars": 10}),
        ("change_limit", {"category": "groceries", "limit": "daily_total", "new_value": 1}),
    ]:
        assert "can't do that from this connection" in call(base, svc, name, args), name
    app = server["app"]
    assert not any(r.kind == "decided" for r in app.engine.chain.receipts())
    # It can still read and lower authority.
    assert "safety lock is off" in call(base, svc, "safety_status").lower()
    assert "frozen" in call(base, svc, "freeze_spending")


def test_owner_linked_token_can_spend(server):
    assert call(server["base"], owner_bearer(server["base"]), "order_usual").startswith("Done.")


def test_check_bearer_enforces_required_scope(server):
    from kinlock.auth import ACT_SCOPE, SERVICE_SCOPE

    base, auth = server["base"], server["app"].auth
    svc, own = bearer(base), owner_bearer(base)
    assert auth.check_bearer(f"Bearer {svc}") is not None
    assert auth.check_bearer(f"Bearer {svc}", SERVICE_SCOPE) is not None
    assert auth.check_bearer(f"Bearer {svc}", ACT_SCOPE) is None
    assert auth.check_bearer(f"Bearer {own}", ACT_SCOPE).subject == "owner"
    assert auth.check_bearer(f"Bearer {own}", SERVICE_SCOPE) is None


def test_service_client_cannot_ask_for_owner_scopes(server):
    base = server["base"]
    r = httpx2.post(f"{base}/token", data={"grant_type": "client_credentials", "scope": "kinlock:act", "resource": f"{base}/mcp"}, auth=("simulator", SIM_SECRET))
    assert r.status_code == 400 and r.json()["error"] == "invalid_scope"
