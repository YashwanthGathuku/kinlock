"""Owner passphrase: salted PBKDF2, constant-time checks, and a lockout after wrong guesses."""

from __future__ import annotations

import hashlib

import httpx2
import pytest
import test_server
from test_server import ALEXA_REDIRECT, PASSPHRASE

from kinlock import auth as auth_mod
from kinlock.auth import LOCKOUT_SECONDS, MAX_PASSPHRASE_FAILURES, AuthServer, hash_passphrase, verify_passphrase

live_server = test_server.server  # re-export the `server` fixture from test_server


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


def make(stored: str, clock: Clock) -> AuthServer:
    return AuthServer("http://k.test", "http://k.test/mcp", stored, {}, clock=clock)


def test_pbkdf2_hash_round_trip_and_salt():
    h = hash_passphrase("open sesame", iterations=1000)
    assert h.startswith("pbkdf2_sha256$1000$") and len(h.split("$")) == 4
    assert verify_passphrase(h, "open sesame")
    assert not verify_passphrase(h, "open sesame ")
    assert hash_passphrase("open sesame", iterations=1000) != h  # fresh salt every time


def test_legacy_sha256_hex_still_works():
    legacy = hashlib.sha256(b"open sesame").hexdigest()
    assert verify_passphrase(legacy, "open sesame") and verify_passphrase(legacy.upper(), "open sesame")
    assert not verify_passphrase(legacy, "nope")


def test_malformed_stored_hash_never_matches():
    assert not verify_passphrase("pbkdf2_sha256$x$zz$00", "")
    assert not verify_passphrase("pbkdf2_sha256$1000", "")


def test_comparisons_are_constant_time(monkeypatch):
    seen = []
    real = auth_mod.hmac.compare_digest
    monkeypatch.setattr(auth_mod.hmac, "compare_digest", lambda a, b: seen.append(1) or real(a, b))
    verify_passphrase(hash_passphrase("x", iterations=1000), "y")
    verify_passphrase(hashlib.sha256(b"x").hexdigest(), "y")
    assert len(seen) == 2


def test_lockout_after_repeated_failures_then_recovers():
    clock = Clock()
    a = make(hash_passphrase("right", iterations=1000), clock)
    for _ in range(MAX_PASSPHRASE_FAILURES - 1):
        assert a.attempt_owner_passphrase("wrong") == "wrong"
    assert a.attempt_owner_passphrase("right") == "ok"  # a success resets the count
    for _ in range(MAX_PASSPHRASE_FAILURES):
        assert a.attempt_owner_passphrase("wrong") == "wrong"
    assert a.attempt_owner_passphrase("right") == "locked"  # even the right one, while locked
    assert a.lockout_remaining() == LOCKOUT_SECONDS
    clock.t += LOCKOUT_SECONDS + 1
    assert a.attempt_owner_passphrase("right") == "ok"


def test_failures_outside_the_window_are_forgotten():
    clock = Clock()
    a = make(hash_passphrase("right", iterations=1000), clock)
    for _ in range(MAX_PASSPHRASE_FAILURES - 1):
        a.attempt_owner_passphrase("wrong")
    clock.t += auth_mod.FAILURE_WINDOW + 1
    assert a.attempt_owner_passphrase("wrong") == "wrong"
    assert a.attempt_owner_passphrase("right") == "ok"


def test_owner_page_locks_after_wrong_guesses(live_server):
    base = live_server["base"]
    for _ in range(MAX_PASSPHRASE_FAILURES):
        assert httpx2.post(f"{base}/owner", data={"passphrase": "guess"}).status_code == 401
    r = httpx2.post(f"{base}/owner", data={"passphrase": PASSPHRASE})
    assert r.status_code == 429 and "Too many wrong passphrases" in r.text and int(r.headers["retry-after"]) > 0


def test_account_linking_shares_the_lockout(live_server):
    base = live_server["base"]
    for _ in range(MAX_PASSPHRASE_FAILURES):
        httpx2.post(f"{base}/owner", data={"passphrase": "guess"})
    params = {"client_id": "alexa", "redirect_uri": ALEXA_REDIRECT, "response_type": "code", "code_challenge": "c" * 43, "code_challenge_method": "S256", "resource": f"{base}/mcp"}
    r = httpx2.post(f"{base}/authorize", data={**params, "passphrase": PASSPHRASE})
    assert r.status_code == 429


@pytest.mark.parametrize("env_name", ["KINLOCK_OWNER_PASSPHRASE_HASH", "KINLOCK_OWNER_PASSPHRASE_SHA256"])
def test_settings_accept_both_hash_forms(tmp_path, monkeypatch, env_name):
    from kinlock.settings import Settings

    monkeypatch.delenv("KINLOCK_OWNER_PASSPHRASE_HASH", raising=False)
    monkeypatch.delenv("KINLOCK_OWNER_PASSPHRASE_SHA256", raising=False)
    monkeypatch.setenv("KINLOCK_DATA", str(tmp_path))
    stored = hash_passphrase("pw", iterations=1000) if env_name.endswith("HASH") else hashlib.sha256(b"pw").hexdigest()
    monkeypatch.setenv(env_name, stored)
    assert verify_passphrase(Settings.from_env().owner_passphrase_sha256, "pw")
