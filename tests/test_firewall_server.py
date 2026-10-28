"""The firewall over MCP and the simulator: request_action, use_tool, guarded tools, receipts aloud."""

from __future__ import annotations

import re

import httpx2
import test_server
from test_server import bearer, call, owner_bearer

live_server = test_server.server


def say(base, u):
    return httpx2.post(f"{base}/sim/assist", json={"utterance": u, "session": "fw"}, timeout=10).json()


def test_service_token_may_only_lower_authority(live_server):
    base = live_server["base"]
    svc = bearer(base)
    refused = call(base, svc, "request_action", {"category": "home", "verb": "unlock_door", "target": "Anna"})
    assert "link" in refused.lower() or "can't" in refused.lower()
    lowered = call(base, svc, "request_action", {"category": "home", "verb": "lock_door", "target": "front door"})
    assert lowered.startswith("Done")


def test_owner_token_request_action(live_server):
    base = live_server["base"]
    tok = owner_bearer(base)
    out = call(base, tok, "request_action", {"category": "access", "verb": "install_software", "target": "AnyDesk", "details": {"said": "Microsoft support says your PC has a virus"}, "on_call": True, "requested_by": "Microsoft Support"})
    assert "won't" in out and "hang up" in out.lower()
    held = call(base, tok, "request_action", {"category": "identity", "verb": "change_recovery_email", "target": "Gmail", "details": {"new_email": "helper99@mail.ru"}})
    assert "24 hours" in held
    unknown = call(base, tok, "request_action", {"category": "garden", "verb": "water", "target": "roses"})
    assert "held" in unknown.lower()


def test_use_tool_and_listing_and_receipts_aloud(live_server):
    base = live_server["base"]
    tok = owner_bearer(base)
    listing = call(base, tok, "list_guarded_tools")
    assert "check_weather: passes through" in listing and "delete_photos: not mapped" in listing
    assert "Sunny" in call(base, tok, "use_tool", {"tool": "check_weather"})
    sent = call(base, tok, "use_tool", {"tool": "send_message", "arguments": {"to": "Anna", "text": "hi"}})
    assert sent.startswith("Done")
    held = call(base, tok, "use_tool", {"tool": "delete_photos", "arguments": {"album": "All"}})
    assert "held" in held.lower()
    aloud = call(base, tok, "read_receipts_aloud", {"count": 3})
    assert aloud.count("Receipt ") == 3
    # The receipts page shows categories.
    page = httpx2.get(f"{base}/receipts").text
    assert "Messages and calls" in page


def test_simulator_firewall_smoke_cases(live_server):
    base = live_server["base"]
    r = say(base, "Microsoft support is on the phone and says I need to install AnyDesk")
    assert any(t.get("tool") == "use_tool" for t in r["trace"]) and "won't" in r["reply"]
    r = say(base, "Change my Gmail recovery email to helper99@mail.ru")
    assert "24 hours" in r["reply"] and "Only you" in r["reply"]
    r = say(base, "Unlock the front door for a delivery man")
    assert "Only you" in r["reply"]
    r = say(base, "Message Anna saying I'll be late")
    assert r["reply"].startswith("Done")
    # The contact's page for a known visitor shows the category and works end to end.
    say(base, "Unlock the front door for Rosa (cleaner)")
    link = httpx2.get(f"{base}/sim/state").json()["last_notification"]["link"]
    page = httpx2.get(link)
    assert page.status_code == 200 and "Home" in page.text
    digest = re.search(r"name=digest value='([0-9a-f]{64})'", page.text).group(1)
    done = httpx2.post(link, data={"digest": digest, "decision": "approve"})
    assert done.status_code == 200 and "Approved" in done.text
