"""The simulator acts as the owner, so it is off by default and gated off loopback."""

from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
from pathlib import Path

import httpx2
import pytest
from test_server import PASSPHRASE, ROOT, SIM_SECRET, _free_port

from kinlock.settings import Settings, is_loopback


def _start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **env: str):
    import uvicorn

    port = _free_port()
    (tmp_path / "clients.json").write_text(json.dumps([{"client_id": "simulator", "secret_sha256": hashlib.sha256(SIM_SECRET.encode()).hexdigest(), "redirect_uris": [], "grants": ["client_credentials"]}]))
    shutil.copy(ROOT / "data" / "policy.example.json", tmp_path / "policy.json")
    base_env = {
        "KINLOCK_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "KINLOCK_DATA": str(tmp_path),
        "KINLOCK_OWNER_PASSPHRASE_SHA256": hashlib.sha256(PASSPHRASE.encode()).hexdigest(),
        "KINLOCK_PORT": str(port),
        "KINLOCK_SIM_CLIENT_ID": "simulator",
        "KINLOCK_SIM_CLIENT_SECRET": SIM_SECRET,
    }
    monkeypatch.delenv("KINLOCK_SIMULATOR", raising=False)
    monkeypatch.delenv("KINLOCK_HOST", raising=False)
    monkeypatch.delenv("KINLOCK_LLM_BASE_URL", raising=False)
    for k, v in {**base_env, **env}.items():
        monkeypatch.setenv(k, v)
    from kinlock.server import create_app

    app = create_app()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    return f"http://127.0.0.1:{port}", app, srv, t


@pytest.fixture
def start(tmp_path, monkeypatch):
    running = []

    def go(**env):
        base, app, srv, t = _start(tmp_path, monkeypatch, **env)
        running.append((srv, t))
        return base, app

    yield go
    for srv, t in running:
        srv.should_exit = True
        t.join(timeout=5)


def test_simulator_is_off_by_default(start):
    base, app = start()
    assert app.settings.simulator is False
    assert httpx2.get(f"{base}/sim").status_code == 404
    assert httpx2.post(f"{base}/sim/reset").status_code in (404, 405)
    r = httpx2.get(f"{base}/receipts")
    assert r.status_code == 303 and r.headers["location"] == "/owner"
    assert httpx2.get(f"{base}/").headers["location"] == "/owner"


def test_simulator_on_loopback_is_open(start):
    base, app = start(KINLOCK_SIMULATOR="1")
    assert app.settings.simulator_open
    assert httpx2.get(f"{base}/sim/state").status_code == 200
    assert httpx2.get(f"{base}/receipts").status_code == 200


@pytest.mark.parametrize("env", [
    {"KINLOCK_SIMULATOR": "1", "KINLOCK_HOST": "0.0.0.0"},
    {"KINLOCK_SIMULATOR": "1", "KINLOCK_PUBLIC_URL": "https://kinlock.example.com"},
])
def test_simulator_off_loopback_needs_the_owner(start, env):
    base, app = start(**env)
    assert app.settings.simulator and not app.settings.simulator_open
    assert httpx2.get(f"{base}/sim/state").status_code == 401
    assert httpx2.post(f"{base}/sim/reset").status_code == 401
    assert httpx2.post(f"{base}/sim/attack", json={"kind": "replay"}).status_code == 401
    assert httpx2.post(f"{base}/sim/assist", json={"utterance": "order my usual groceries"}).status_code == 401
    r = httpx2.get(f"{base}/sim")
    assert r.status_code == 303 and r.headers["location"] == "/owner"
    assert httpx2.get(f"{base}/receipts").status_code == 303
    assert not list(app.engine.chain.receipts())  # nothing ran
    signin = httpx2.post(f"{base}/owner", data={"passphrase": PASSPHRASE})
    assert signin.status_code == 303
    # Sent by hand: with an https public URL the cookie is Secure, and this test speaks plain http.
    cookie = signin.headers["set-cookie"].split(";", 1)[0]
    assert httpx2.get(f"{base}/sim/state", headers={"Cookie": cookie}).status_code == 200
    assert httpx2.get(f"{base}/receipts", headers={"Cookie": cookie}).status_code == 200
    assert httpx2.get(f"{base}/sim/state", headers={"Cookie": "kinlock_owner=forged"}).status_code == 401


def test_loopback_detection():
    assert all(is_loopback(h) for h in ["127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2"])
    assert not any(is_loopback(h) for h in ["0.0.0.0", "192.168.1.5", "kinlock.example.com", ""])


def test_settings_default_simulator_is_off(tmp_path, monkeypatch):
    monkeypatch.setenv("KINLOCK_DATA", str(tmp_path))
    monkeypatch.setenv("KINLOCK_OWNER_PASSPHRASE_SHA256", "0" * 64)
    monkeypatch.delenv("KINLOCK_SIMULATOR", raising=False)
    monkeypatch.delenv("KINLOCK_PUBLIC_URL", raising=False)
    monkeypatch.delenv("KINLOCK_HOST", raising=False)
    s = Settings.from_env()
    assert s.simulator is False and s.simulator_open is False and s.host == "127.0.0.1"
    monkeypatch.setenv("KINLOCK_SIMULATOR", "1")
    assert Settings.from_env().simulator_open is True
