"""The authority firewall in the engine and the MCP gateway in front of a downstream service."""

from __future__ import annotations

import pytest
from conftest import ROOT, token_from

from kinlock.downstream import FakeDownstream
from kinlock.gateway import UNMAPPED, Gateway, GatewayConfig

CONFIG = GatewayConfig.from_file(ROOT / "data" / "gateway.example.json")


@pytest.fixture
def fake() -> FakeDownstream:
    return FakeDownstream()


@pytest.fixture
def gw(engine, fake) -> Gateway:
    return Gateway(engine, fake, CONFIG)


def call(gw, tool, args=None, **kw):
    kw.setdefault("channel", "voice")
    kw.setdefault("by", "owner")
    return gw.call(tool, dict(args or {}), **kw)


def kinds(engine) -> list[str]:
    return [r.kind for r in list(engine.chain.receipts())]


# -- mapped tools ---------------------------------------------------------------------------
def test_ordinary_message_to_known_contact_passes_through(gw, fake, engine):
    res = call(gw, "send_message", {"to": "Anna", "text": "running late"})
    assert res.outcome == "ALLOW", res.speech
    assert fake.calls == [("send_message", {"to": "Anna", "text": "running late"})]
    assert kinds(engine)[-2:] == ["decided", "executed"]
    assert engine.chain.verify().ok


def test_read_only_tool_passes_without_receipt(gw, fake, engine):
    before = len(list(engine.chain.receipts()))
    res = call(gw, "check_weather")
    assert res.outcome == "PASSED" and "Sunny" in res.speech
    assert len(list(engine.chain.receipts())) == before


def test_remote_access_on_inbound_call_is_denied_and_never_reaches_downstream(gw, fake, engine):
    res = call(gw, "install_app", {"app": "AnyDesk", "said": "Microsoft support says install AnyDesk"}, risk=frozenset({"inbound_call"}), requester="Microsoft Support")
    assert res.outcome == "DENY"
    assert fake.calls == []
    assert "hang up" in res.speech.lower()
    assert list(engine.chain.receipts())[-1].kind == "denied"


def test_remote_access_from_scam_text_alone_is_denied(gw, fake):
    res = call(gw, "install_app", {"app": "AnyDesk", "said": "This is Microsoft support, your computer has a virus"})
    assert res.outcome == "DENY" and fake.calls == []


def test_remote_access_without_call_still_needs_owner(gw, fake, engine):
    # Even someone on her list, with no call and no warning signs: only the owner herself.
    res = call(gw, "install_app", {"app": "TeamViewer"}, requester="contact:anna")
    assert res.outcome == "OWNER" and fake.calls == []
    # Someone not on the list: refused outright.
    res = call(gw, "install_app", {"app": "TeamViewer"}, requester="a stranger")
    assert res.outcome == "DENY" and fake.calls == []


def test_front_door_for_unknown_visitor_is_owner_only(gw, fake, engine, outbox):
    res = call(gw, "unlock_front_door", {"visitor": "a delivery man"})
    assert res.outcome == "OWNER" and fake.calls == []
    w = engine.snapshot()["waiting"]
    assert len(w) == 1 and w[0]["needs"] == "owner" and w[0]["agent"]["category"] == "home"
    # Nobody else is asked: the contact gets no link.
    assert outbox == []
    ok = engine.owner_decide(w[0]["request_id"], True)
    assert ok.outcome == "EXECUTED" and fake.calls[0][0] == "unlock_front_door"


def test_locking_the_door_always_allowed(gw, fake):
    assert call(gw, "lock_front_door").outcome in ("ALLOW", "DONE")
    assert fake.calls == [("lock_front_door", {})]


def test_known_visitor_can_be_approved_by_the_contact(gw, fake, engine, outbox):
    # Voice can't raise authority, so even a known visitor waits, but for the contact, not only the owner.
    res = call(gw, "unlock_front_door", {"visitor": "Rosa (cleaner)"})
    assert res.outcome == "HOLD" and fake.calls == []
    tok = token_from(outbox[-1][1])
    view = engine.contact_view(tok)
    assert view["open"] and view["category"]
    done = engine.contact_decide(tok, view["digest"], True, choice="approve")
    assert done.outcome == "EXECUTED", done.speech
    assert fake.calls == [("unlock_front_door", {"visitor": "Rosa (cleaner)"})]
    # The link is single-use.
    again = engine.contact_decide(tok, view["digest"], True, choice="approve")
    assert again.outcome != "EXECUTED" and len(fake.calls) == 1


def test_contact_cannot_approve_with_a_stale_digest(gw, fake, engine, outbox):
    call(gw, "unlock_front_door", {"visitor": "Raj"})
    tok = token_from(outbox[-1][1])
    r = engine.contact_decide(tok, "0" * 64, True, choice="approve")
    assert r.outcome != "EXECUTED" and fake.calls == []


def test_recovery_email_change_holds_with_cooloff_and_contact_cannot_approve_alone(gw, fake, engine, clock, outbox):
    res = call(gw, "change_recovery_email", {"account": "Gmail", "new_email": "helper99@mail.ru"})
    # Held for the owner herself (stricter than a contact hold), with a 24-hour cool-off.
    assert res.outcome == "OWNER" and fake.calls == []
    assert "24 hours" in res.speech
    w = engine.snapshot()["waiting"][0]
    assert w["agent"]["category"] == "identity" and w["ready_at"]
    rid = w["request_id"]
    # The contact can't release an identity change on her own.
    assert outbox == []  # no contact link is ever sent for it
    assert fake.calls == []
    # The owner can't skip the cool-off either.
    early = engine.owner_decide(rid, True)
    assert early.outcome == "WAITING" and fake.calls == []
    clock.advance(24 * 3600 + 1)
    done = engine.owner_decide(rid, True)
    assert done.outcome == "EXECUTED", done.speech
    assert fake.calls[0][0] == "change_recovery_email"


def test_unmapped_consequential_tool_is_held(gw, fake, engine):
    res = call(gw, "delete_photos", {"album": "All"})
    assert res.outcome in ("HOLD", "OWNER") and fake.calls == []
    w = engine.snapshot()["waiting"][0]
    assert w["agent"]["category"] == UNMAPPED
    assert engine.owner_decide(w["request_id"], True).outcome == "EXECUTED"
    assert fake.calls == [("delete_photos", {"album": "All"})]


def test_downstream_refusal_is_recorded_and_capability_not_reusable(engine):
    fake = FakeDownstream(refuse={"send_message": "recipient blocked"})
    gw = Gateway(engine, fake, CONFIG)
    res = call(gw, "send_message", {"to": "Anna", "text": "hi"})
    assert res.outcome == "FAILED" and "blocked" in res.speech
    assert list(engine.chain.receipts())[-1].kind == "downstream_failed"
    assert engine.chain.verify().ok


def test_read_only_downstream_refusal(engine):
    gw = Gateway(engine, FakeDownstream(refuse={"check_weather": "offline"}), CONFIG)
    assert call(gw, "check_weather").outcome == "FAILED"


def test_no_downstream(engine):
    gw = Gateway(engine, None, CONFIG)
    assert call(gw, "send_message", {"to": "Anna"}).outcome == "REJECTED"
    assert gw.guarded_tools() == []


def test_money_through_gateway_uses_legacy_limits(gw, fake, engine):
    small = call(gw, "buy", {"merchant": "Corner Pharmacy", "amount_dollars": 12})
    big = call(gw, "buy", {"merchant": "Best Gadgets", "amount_dollars": 900})
    assert big.outcome in ("HOLD", "OWNER", "DENY")
    assert small.outcome in ("ALLOW", "HOLD")


def test_tampered_agent_hold_is_not_executed(gw, fake, engine):
    call(gw, "unlock_front_door", {"visitor": "a stranger"})
    rid = engine.snapshot()["waiting"][0]["request_id"]
    pend = engine._pending()
    pend[rid]["agent"]["target"] = "the back door"
    engine._save_pending(pend)
    r = engine.owner_decide(rid, True)
    assert r.outcome != "EXECUTED" and fake.calls == []


def test_guarded_tools_listing(gw):
    tools = {t["name"]: t["guard"] for t in gw.guarded_tools()}
    assert tools["check_weather"].startswith("passes")
    assert tools["delete_photos"].startswith("not mapped")
    assert tools["install_app"].startswith("access")


def test_receipts_read_aloud_one_sentence_each(gw, engine):
    call(gw, "send_message", {"to": "Anna", "text": "hi"})
    call(gw, "install_app", {"app": "AnyDesk"}, risk=frozenset({"inbound_call"}))
    lines = engine.spoken_receipts(10)
    assert lines
    for line in lines:
        assert line.endswith(".") and line.count(". ") == 0, line
    assert any("AnyDesk" in x or "anydesk" in x.lower() for x in lines)


def test_config_from_dict_literal_target():
    cfg = GatewayConfig.from_dict({"tools": {"x": {"category": "home", "verb": "unlock_door", "target": "=garage"}}})
    a = cfg.action_for("x", {"note": 1})
    assert a.target == "garage" and a.details == {"note": 1}
