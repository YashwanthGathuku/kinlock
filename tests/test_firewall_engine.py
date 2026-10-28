"""Firewall flows in the engine: quorum, pause, conflict of interest, voice only lowers, receipts, pages."""

from __future__ import annotations

import itertools

import pytest
from conftest import token_from
from test_accessibility import check_page, name, text

from kinlock import pages
from kinlock.downstream import FakeDownstream
from kinlock_authority import CATEGORIES, VERBS, AgentAction, Outcome, evaluate_action
from kinlock_authority.firewall import REDUCE

LEASE = AgentAction("q1", "legal", "sign_document", "Lease renewal", {"from": "Oak Property"})


@pytest.fixture
def fake(engine) -> FakeDownstream:
    engine.downstream = FakeDownstream()
    return engine.downstream


def links(outbox) -> dict[str, str]:
    return {t.split(":", 1)[0]: token_from(link) for t, link in outbox}


def vote(engine, tok, choice, comment=""):
    return engine.contact_decide(tok, engine.contact_view(tok)["digest"], choice == "approve", choice=choice, comment=comment)


def test_quorum_asks_each_member_and_owner_is_final(engine, fake, outbox):
    r = engine.request_agent(LEASE, "voice", "owner", call={"tool": "send_message", "arguments": {"to": "Oak Property"}})
    assert r.outcome == "OWNER" and "2 of your people" in r.speech
    tok = links(outbox)
    assert set(tok) == {"Anna", "Raj (neighbour)"}
    # Two supporters agreeing is not enough: the owner is final.
    assert vote(engine, tok["Anna"], "approve").outcome == "RECORDED"
    assert vote(engine, tok["Raj (neighbour)"], "approve").outcome == "RECORDED"
    assert fake.calls == []
    assert engine.owner_decide("q1", True).outcome == "EXECUTED"
    assert len(fake.calls) == 1


def test_supporter_can_pause_and_comment_and_owner_sees_it(engine, fake, outbox):
    engine.request_agent(LEASE, "voice", "owner", call={"tool": "send_message", "arguments": {}})
    tok = links(outbox)
    assert vote(engine, tok["Raj (neighbour)"], "pause", "Who is Oak Property?").outcome == "RECORDED"
    assert vote(engine, tok["Anna"], "approve").outcome == "RECORDED"
    w = engine.snapshot()["waiting"][0]
    assert w["state"] == "paused" and ("Raj (neighbour)", "Who is Oak Property?") in [tuple(c) for c in w["comments"]]
    # Paused: even the owner's approval waits until it is resumed.
    assert engine.owner_decide("q1", True).outcome == "RECORDED" and fake.calls == []
    done = vote(engine, tok["Raj (neighbour)"], "resume")
    assert done.outcome == "EXECUTED" and len(fake.calls) == 1


def test_owner_decline_is_final(engine, fake, outbox):
    engine.request_agent(LEASE, "voice", "owner")
    tok = links(outbox)
    assert engine.owner_decide("q1", False).outcome == "DECLINED"
    assert vote(engine, tok["Anna"], "approve").outcome != "EXECUTED"
    assert fake.calls == []


def test_conflict_of_interest_member_gets_no_vote(engine, fake, outbox):
    r = engine.request_agent(AgentAction("q2", "legal", "change_beneficiary", "Anna", {}), "voice", "owner")
    assert r.outcome == "OWNER"
    assert "Anna" not in links(outbox)  # it names her, so she isn't asked


def test_contact_cannot_point_recovery_at_her_own_email(engine, fake, outbox):
    a = AgentAction("q3", "identity", "change_recovery_email", "Gmail", {"new_email": "anna@example.com"})
    assert engine.request_agent(a, "voice", "owner").outcome == "OWNER"
    assert outbox == []


def test_spoken_receipts_cover_every_kind(engine, fake, outbox):
    engine.request_agent(LEASE, "voice", "owner", call={"tool": "send_message", "arguments": {}})
    tok = links(outbox)
    vote(engine, tok["Raj (neighbour)"], "pause", "why?")
    engine.request_agent(AgentAction("q4", "access", "install_software", "AnyDesk", {}, frozenset({"inbound_call"})), "voice", "owner")
    lines = engine.spoken_receipts(20)
    assert any("paused" in x for x in lines) and any("refused" in x.lower() or "denied" in x.lower() or "blocked" in x.lower() for x in lines)
    assert all(x.endswith(".") for x in lines)


# -- voice only lowers (property, over the whole taxonomy) -----------------------------------
RISKS = [frozenset(), frozenset({"inbound_call"})]


@pytest.mark.parametrize("category", CATEGORIES)
def test_voice_never_allows_an_increase(engine, category):
    policy = engine.policy()
    fw = engine.firewall()
    for (verb, (direction, _)), risk, target in itertools.product(VERBS[category].items(), RISKS, ["Anna", "Stranger Co", ""]):
        a = AgentAction("p", category, verb, target, {"amount": 1}, risk, True, "", (), 500 if category == "money" else 0)
        d = evaluate_action(a, policy, channel="voice", frozen=False, firewall=fw)
        if direction == REDUCE:
            assert d.outcome == Outcome.ALLOW, (category, verb)
        elif direction not in ("use", "spend"):
            assert d.outcome != Outcome.ALLOW, (category, verb, target, risk)


def test_reduce_always_allowed_even_when_frozen(engine):
    policy, fw = engine.policy(), engine.firewall()
    for category in CATEGORIES:
        for verb, (direction, _) in VERBS[category].items():
            if direction == REDUCE:
                d = evaluate_action(AgentAction("p", category, verb, "x", {}, frozenset({"inbound_call"})), policy, channel="voice", frozen=True, firewall=fw)
                assert d.outcome == Outcome.ALLOW, (category, verb)


# -- pages ------------------------------------------------------------------------------------
def test_agent_contact_and_owner_pages_are_accessible(engine, fake, outbox):
    engine.request_agent(LEASE, "voice", "owner")
    engine.request_agent(AgentAction("q5", "home", "unlock_door", "Rosa (cleaner)", {}), "voice", "owner")
    engine.request_agent(AgentAction("q6", "identity", "change_recovery_email", "Gmail", {"new_email": "x@y.z"}), "voice", "owner")
    tok = links(outbox)
    vote(engine, tok["Raj (neighbour)"], "pause", "Who is Oak Property?")
    # A supporter's quorum page: category, plain description, approve/deny/pause, a labelled comment box.
    t = check_page(pages.contact_page(tok["Raj (neighbour)"], engine.contact_view(tok["Raj (neighbour)"])))
    body = text(t.root)
    assert "Legal" in body and "sign Lease renewal" in body and "Paused" in body
    buttons = [name(t, n) for n in t.all() if n["tag"] == "button"]
    assert "Approve this exact action" in buttons and "Deny" in buttons and "Resume" in buttons
    assert name(t, t.ids["comment"]).startswith("A note")
    # The trusted contact's single-approver page.
    anna_home = [token_from(link) for title, link in outbox if "Rosa" in title or "unlock" in title]
    t = check_page(pages.contact_page(anna_home[-1], engine.contact_view(anna_home[-1])))
    assert "Home" in text(t.root)
    # The owner page: a card per waiting action with category, cool-off and named buttons.
    t = check_page(pages.owner_page(engine.snapshot(), "csrf", ""))
    body = text(t.root)
    assert "Accounts and identity" in body and "Cool-off" in body and "Paused by a supporter" in body
    buttons = [name(t, n) for n in t.all() if n["tag"] == "button"]
    assert "Approve: sign Lease renewal" in buttons and "Deny: sign Lease renewal" in buttons
    # Receipts page, with the plain-words list.
    t = check_page(pages.receipts_page(engine))
    assert name(t, next(n for n in t.all() if n["tag"] == "section" and n["attrs"].get("aria-labelledby") == "spoken-h")) == "In plain words"
    assert "Legal" in text(t.root)


def test_protocol_digest_matches_the_spec():
    """docs/PROTOCOL.md: SHA-256 of sorted, compact JSON of the fields plus the schema."""
    import hashlib
    import json

    a = AgentAction("req_1", "identity", "change_recovery_email", "Gmail", {"new_email": "helper99@mail.ru"}, frozenset({"inbound_call"}))
    doc = {"schema": "kinlock.action/1", **a.to_dict()}
    assert set(doc) == {"schema", "request_id", "category", "verb", "target", "details", "risk", "reversible", "requester", "beneficiaries", "amount_cents"}
    assert a.digest() == hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert AgentAction.from_dict(a.to_dict()).digest() == a.digest()
