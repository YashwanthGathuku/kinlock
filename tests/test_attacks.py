"""Kinlock's behaviour, written as the attacks and mistakes it must stop.

Each test is one claim we make in the demo. If a test here fails, the claim
comes out of the video and the write-up.
"""

from __future__ import annotations

import json
import threading

from conftest import KEY, Clock, token_from

from kinlock.engine import Engine
from kinlock_authority import Action, Signer
from kinlock_authority.approvals import Capability


def buy(rid: str, amount: int, merchant: str, category: str, item: str = "item") -> Action:
    return Action(rid, "purchase", amount, merchant, category, (item,))


def usual(rid: str = "r-usual") -> Action:
    return buy(rid, 4620, "Fresh Market", "groceries", "your usual groceries")


def laptop(rid: str = "r-laptop") -> Action:
    return buy(rid, 84999, "TechZone", "electronics", "a laptop")


# -- routine and held actions ----------------------------------------------------------------


def test_routine_groceries_run_at_once(engine: Engine):
    r = engine.request(usual())
    assert r.outcome == "ALLOW"
    assert all(c["ok"] for c in r.decision["checks"])
    assert engine.chain.verify().ok


def test_new_shop_and_large_amount_are_held_for_the_trusted_contact(engine: Engine, outbox):
    r = engine.request(laptop())
    assert r.outcome == "HOLD"
    failed = {c["code"] for c in r.decision["checks"] if not c["ok"]}
    assert {"merchant", "per_action"} <= failed
    assert r.link and "/approve/" in r.link
    assert outbox and "/approve/" in outbox[0][1]


def test_contact_approves_the_exact_action_and_it_runs(engine: Engine):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    assert view["open"] and view["action"]["amount_cents"] == 84999
    done = engine.contact_decide(token_from(r.link), view["digest"], approve=True)
    assert done.outcome == "EXECUTED"
    assert engine.state().held == {}


def test_contact_can_decline(engine: Engine):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    assert engine.contact_decide(token_from(r.link), view["digest"], approve=False).outcome == "DECLINED"
    assert engine.state().history.spent_cents.get("electronics") is None


# -- hard rules -------------------------------------------------------------------------------


def test_gift_cards_are_always_denied(engine: Engine):
    r = engine.request(buy("r-gc", 50000, "Gift Card Outlet", "gift cards"))
    assert r.outcome == "DENY"
    assert "always blocked" in r.speech


def test_transfer_to_a_new_payee_needs_the_owner(engine: Engine):
    r = engine.request(Action("r-wire", "transfer", 90000, "Account 4471", "transfer"))
    assert r.outcome == "OWNER"
    assert r.link.endswith("/owner")


def test_contact_cannot_approve_an_owner_only_action(engine: Engine, clock: Clock):
    # Over the owner-only threshold: even the contact's page must refuse it.
    r = engine.request(buy("r-big", 160000, "Fresh Market", "groceries"))
    assert r.outcome == "OWNER"
    held = engine.state().held["r-big"]
    assert held["needs"] == "owner" and held["contact_id"] is None


def test_owner_can_release_an_owner_only_action(engine: Engine):
    engine.request(Action("r-wire", "transfer", 90000, "Account 4471", "transfer"))
    assert engine.owner_decide("r-wire", approve=True).outcome == "EXECUTED"


def test_amount_over_the_contacts_ceiling_goes_to_the_owner(engine: Engine):
    # Anna may approve up to $1,000; $1,200 is under the owner-only line but over her ceiling.
    r = engine.request(buy("r-tv", 120000, "TechZone", "electronics", "a TV"))
    assert r.outcome == "HOLD"
    assert engine.state().held["r-tv"]["needs"] == "owner"


# -- authority only goes down by voice --------------------------------------------------------


def test_voice_can_freeze_but_cannot_unfreeze(engine: Engine):
    assert engine.request(Action("r-f", "freeze"), "voice").outcome == "DONE"
    assert engine.state().frozen
    r = engine.request(Action("r-u", "unfreeze"), "voice")
    assert r.outcome == "DENY" and engine.state().frozen
    assert "never" in r.speech


def test_trusted_contact_cannot_unfreeze_either(engine: Engine):
    engine.request(Action("r-f", "freeze"), "voice")
    assert engine.request(Action("r-u", "unfreeze"), "contact").outcome == "DENY"
    assert engine.state().frozen


def test_owner_can_unfreeze(engine: Engine):
    engine.request(Action("r-f", "freeze"), "voice")
    assert engine.request(Action("r-u", "unfreeze"), "owner").outcome == "DONE"
    assert not engine.state().frozen


def test_freeze_blocks_all_spending(engine: Engine):
    engine.request(Action("r-f", "freeze"), "voice")
    assert engine.request(usual()).outcome == "DENY"
    assert engine.request(Action("r-t", "transfer", 1000, "Anna", "transfer")).outcome == "DENY"


def test_voice_can_lower_a_limit_but_not_raise_it(engine: Engine):
    low = engine.request(Action("r-l", "set_limit", setting="groceries.daily_cents", value=10000), "voice")
    assert low.outcome == "DONE" and engine.policy().limits_for("groceries").daily_cents == 10000
    high = engine.request(Action("r-h", "set_limit", setting="groceries.daily_cents", value=500000), "voice")
    assert high.outcome == "DENY" and engine.policy().limits_for("groceries").daily_cents == 10000


def test_voice_cannot_raise_the_owner_only_line_or_the_contacts_ceiling(engine: Engine):
    assert engine.request(Action("r-1", "set_limit", setting="owner_only_above_cents", value=10**8), "voice").outcome == "DENY"
    assert engine.request(Action("r-2", "set_limit", setting="contact:anna.ceiling_cents", value=10**8), "voice").outcome == "DENY"
    assert engine.request(Action("r-3", "add_merchant", counterparty="TechZone"), "voice").outcome == "DENY"
    assert engine.request(Action("r-4", "unblock_category", category="gift cards"), "voice").outcome == "DENY"


def test_unknown_setting_or_action_is_denied(engine: Engine):
    assert engine.request(Action("r-1", "set_limit", setting="nonsense", value=1), "voice").outcome == "DENY"
    assert engine.request(Action("r-2", "delete_everything"), "voice").outcome == "DENY"


# -- approvals are bound to one exact action ---------------------------------------------------


def test_replayed_approval_is_rejected(engine: Engine):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    assert engine.contact_decide(token_from(r.link), view["digest"], True).outcome == "EXECUTED"
    again = engine.attack_replay()
    assert again.outcome == "REJECTED"
    assert "This approval was already used" in again.problems
    assert engine.state().history.count["electronics"] == 1


def test_amount_changed_after_hold_is_rejected(engine: Engine):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))  # Anna sees $849.99 at TechZone
    engine.attack_tamper("r-laptop", 850000, "TechZone")
    res = engine.contact_decide(token_from(r.link), view["digest"], True)
    assert res.outcome == "REJECTED" and "changed" in res.speech
    assert engine.state().history.spent_cents.get("electronics") is None
    assert "r-laptop" not in engine.state().held  # a tampered request is cancelled, not left approvable


def test_merchant_changed_after_hold_is_rejected(engine: Engine):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    engine.attack_tamper("r-laptop", 84999, "CryptoCash")
    assert engine.contact_decide(token_from(r.link), view["digest"], True).outcome == "REJECTED"


def test_approval_for_one_request_cannot_release_another(engine: Engine):
    r1 = engine.request(laptop("r-a"))
    v1 = engine.contact_view(token_from(r1.link))
    engine.request(buy("r-b", 84999, "TechZone", "electronics", "a laptop"))
    assert engine.contact_decide(token_from(r1.link), v1["digest"], True).outcome == "EXECUTED"
    cap = engine.last_capability
    moved = Capability(**{**cap.payload(), "request_id": "r-b", "cap_id": "cap_new", "sig": cap.sig})
    res = engine.execute_with(moved)
    assert res.outcome == "REJECTED"
    assert "The approval's signature is not valid" in res.problems


def test_forged_approval_is_rejected(engine: Engine):
    engine.request(laptop())
    st = engine.state()
    forged_signer = Signer(b"x" * 32)
    from kinlock_authority import issue_capability

    cap = issue_capability(forged_signer, request_id="r-laptop", action_digest=st.held["r-laptop"]["digest"], approver="contact:anna", role="contact", ceiling_cents=100000, now=engine.clock())
    res = engine.execute_with(cap)
    assert res.outcome == "REJECTED" and "The approval's signature is not valid" in res.problems


def test_expired_hold_cannot_be_approved(engine: Engine, clock: Clock):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    clock.advance(16 * 60)
    res = engine.contact_decide(token_from(r.link), view["digest"], True)
    assert res.outcome == "REJECTED" and "expired" in res.speech


def test_expired_capability_is_rejected(engine: Engine, clock: Clock):
    engine.request(laptop())
    from kinlock_authority import issue_capability

    st = engine.state()
    cap = issue_capability(Signer(KEY), request_id="r-laptop", action_digest=st.held["r-laptop"]["digest"], approver="contact:anna", role="contact", ceiling_cents=100000, now=engine.clock(), ttl=60)
    clock.advance(61)
    assert "This approval has expired" in engine.execute_with(cap).problems


def test_wrong_link_is_rejected(engine: Engine):
    engine.request(laptop())
    assert engine.contact_view("not-a-real-token") is None
    assert engine.contact_decide("not-a-real-token", "x", True).outcome == "REJECTED"


def test_freeze_cancels_waiting_requests_and_their_approval_fails(engine: Engine, outbox):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    f = engine.request(Action("r-f", "freeze"), "voice")
    assert "cancelled 1 waiting request" in f.speech
    res = engine.contact_decide(token_from(r.link), view["digest"], True)
    assert res.outcome == "REJECTED"
    assert engine.state().history.spent_cents.get("electronics") is None


def test_double_tap_approves_once(engine: Engine):
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    results = []
    ts = [threading.Thread(target=lambda: results.append(engine.contact_decide(token_from(r.link), view["digest"], True))) for _ in range(5)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(x.outcome for x in results).count("EXECUTED") == 1
    assert engine.state().history.count["electronics"] == 1


# -- splitting and context ---------------------------------------------------------------------


def test_splitting_into_small_orders_hits_the_daily_total(engine: Engine):
    outcomes = [engine.request(buy(f"r-s{i}", 9900, "Fresh Market", "groceries")).outcome for i in range(4)]
    assert outcomes[:2] == ["ALLOW", "ALLOW"]
    assert outcomes[2] == "HOLD"  # $297 would pass the $200 daily total


def test_daily_count_limit(engine: Engine):
    outcomes = [engine.request(buy(f"r-c{i}", 1000, "Fresh Market", "groceries")).outcome for i in range(4)]
    assert outcomes == ["ALLOW", "ALLOW", "ALLOW", "HOLD"]


def test_late_night_purchase_is_held(engine: Engine, clock: Clock):
    clock.set_local_hour(2)
    r = engine.request(usual())
    assert r.outcome == "HOLD"
    assert any(c["code"] == "hours" and not c["ok"] for c in r.decision["checks"])


def test_rules_run_again_at_release(engine: Engine):
    # Held for Anna at $849.99. Before she taps approve, Mary tightens her rules by voice
    # (lowering is always allowed): anything over $500 now needs Mary herself.
    r = engine.request(laptop())
    view = engine.contact_view(token_from(r.link))
    assert engine.request(Action("r-tighten", "set_limit", setting="owner_only_above_cents", value=50000), "voice").outcome == "DONE"
    res = engine.contact_decide(token_from(r.link), view["digest"], True)
    assert res.outcome == "REJECTED"
    assert any("owner herself" in p for p in res.problems)
    assert engine.state().history.spent_cents.get("electronics") is None


# -- receipts and restarts ---------------------------------------------------------------------


def test_editing_a_past_receipt_breaks_the_chain(engine: Engine, data_dir):
    engine.request(usual())
    engine.request(laptop())
    path = data_dir / "receipts.jsonl"
    lines = path.read_text().splitlines()
    first = json.loads(lines[1])
    first["data"]["amount_cents"] = 1
    lines[1] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n")
    report = engine.chain.verify()
    assert not report.ok and report.broken_at == 1


def test_state_survives_a_restart(data_dir, clock: Clock):
    e1 = Engine(data_dir, KEY, "http://kinlock.test", clock=clock)
    e1.request(laptop())
    e1.request(Action("r-f", "freeze"), "voice")
    e2 = Engine(data_dir, KEY, "http://kinlock.test", clock=clock)
    assert e2.state().frozen
    assert e2.request(usual()).outcome == "DENY"
    assert e2.chain.verify().ok
