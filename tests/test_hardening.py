"""Hardening: claims the engine must keep even when the caller lies or waits."""

from __future__ import annotations

import json

from conftest import KEY, Clock, token_from

from kinlock.engine import HOLD_TTL, Engine, receipt_key
from kinlock_authority import Action, ReceiptChain


def buy(rid: str, amount: int, merchant: str, category: str, item: str = "item") -> Action:
    return Action(rid, "purchase", amount, merchant, category, (item,))


# -- 1. the category comes from the owner's merchant list, not the caller ---------------------


def test_gift_card_merchant_claimed_as_other_is_denied(engine: Engine):
    r = engine.request(buy("r-gc", 5000, "Gift Card Outlet", "other", "a present"))
    assert r.outcome == "DENY"
    decided = next(x for x in engine.chain.receipts() if x.kind == "decided")
    assert decided.data["action"]["category"] == "gift cards"


def test_gift_card_merchant_claimed_as_groceries_is_denied(engine: Engine):
    assert engine.request(buy("r-gc2", 2000, "Gift Card Outlet", "groceries")).outcome == "DENY"


def test_crypto_in_the_item_text_is_denied(engine: Engine):
    r = engine.request(buy("r-btc", 3000, "Some Shop", "other", "Bitcoin voucher"))
    assert r.outcome == "DENY"
    assert any(c["code"] == "keywords" and not c["ok"] for c in r.decision["checks"])


def test_gift_card_words_at_a_known_shop_are_denied(engine: Engine):
    r = engine.request(buy("r-gc3", 2500, "Fresh Market", "groceries", "Apple gift card"))
    assert r.outcome == "DENY"


def test_unknown_shop_cannot_claim_a_generous_category(engine: Engine):
    # Groceries allow $120 per order; an unknown shop's claim of "groceries" is ignored.
    engine.request(buy("r-x", 4000, "Unknown Shop", "groceries"))
    decided = next(x for x in engine.chain.receipts() if x.kind == "decided")
    assert decided.data["action"]["category"] == "other"


def test_honest_routine_order_still_runs(engine: Engine):
    assert engine.request(buy("r-ok", 4620, "Fresh Market", "other", "your usual groceries")).outcome == "ALLOW"
    assert engine.state().history.spent_cents["groceries"] == 4620


# -- 2. the owner cannot release an expired hold ----------------------------------------------


def test_owner_decide_rejects_an_expired_hold(engine: Engine, clock: Clock):
    engine.request(Action("r-wire", "transfer", 90000, "Account 4471", "transfer"))
    clock.advance(HOLD_TTL + 1)
    res = engine.owner_decide("r-wire", approve=True)
    assert res.outcome == "REJECTED" and "This request expired" in res.problems
    assert "r-wire" not in engine.state().held
    assert not any(r.kind == "executed" for r in engine.chain.receipts())
    assert engine.owner_decide("r-wire", approve=True).outcome == "REJECTED"


def test_owner_decide_inside_the_window_still_works(engine: Engine, clock: Clock):
    engine.request(Action("r-wire", "transfer", 90000, "Account 4471", "transfer"))
    clock.advance(HOLD_TTL - 5)
    assert engine.owner_decide("r-wire", approve=True).outcome == "EXECUTED"


# -- 4. the receipt chain is signed -----------------------------------------------------------


def test_receipts_are_signed_and_a_recomputed_chain_is_caught(engine: Engine, data_dir):
    engine.request(buy("r-1", 4620, "Fresh Market", "groceries"))
    assert engine.chain.verify().ok
    lines = (data_dir / "receipts.jsonl").read_text().splitlines()
    assert all(json.loads(line).get("sig") for line in lines)
    # Rebuild the whole chain without the key, as an attacker with file access would.
    forged = ReceiptChain(data_dir / "forged.jsonl")
    for line in lines:
        r = json.loads(line)
        if r["kind"] == "executed":
            r["data"]["amount_cents"] = 1
        forged.append(r["kind"], r["data"], ts=r["ts"])
    (data_dir / "receipts.jsonl").write_text((data_dir / "forged.jsonl").read_text())
    report = Engine(data_dir, KEY, "http://kinlock.test").chain.verify()
    assert not report.ok and report.broken_at == 0


def test_receipt_key_is_a_separate_subkey():
    assert receipt_key(KEY) != KEY and len(receipt_key(KEY)) == 32


# -- 7. the owner sees every trusted-contact decision -----------------------------------------


def laptop(rid: str) -> Action:
    return buy(rid, 84999, "TechZone", "electronics", "a laptop")


def test_owner_is_told_when_the_contact_approves_or_declines(data_dir, clock: Clock):
    told: list[tuple[str, str]] = []
    eng = Engine(data_dir, KEY, "http://kinlock.test", clock=clock, notify_owner=lambda t, l: told.append((t, l)))
    r1 = eng.request(laptop("r-a"))
    v1 = eng.contact_view(token_from(r1.link))
    assert eng.contact_decide(token_from(r1.link), v1["digest"], True).outcome == "EXECUTED"
    r2 = eng.request(laptop("r-b"))
    v2 = eng.contact_view(token_from(r2.link))
    assert eng.contact_decide(token_from(r2.link), v2["digest"], False).outcome == "DECLINED"

    assert [t for t, _ in told] == ["Anna approved a laptop from TechZone for $849.99", "Anna declined a laptop from TechZone for $849.99"]
    assert all(link == "http://kinlock.test/owner" for _, link in told)
    snap = eng.snapshot()
    assert [(d["request_id"], d["decision"], d["by"]) for d in snap["contact_decisions"]] == [("r-b", "declined", "contact:anna"), ("r-a", "approved", "contact:anna")]
    kinds = [r.kind for r in eng.chain.receipts()]
    assert kinds.count("owner_notified") == 2
    assert eng.chain.verify().ok


def test_rejected_contact_attempts_do_not_claim_a_decision(engine: Engine):
    assert engine.contact_decide("not-a-real-token", "x", True).outcome == "REJECTED"
    assert engine.snapshot()["contact_decisions"] == []
