"""Verified Causal Commit v2: runtime tests, including the six attacks from the Oct 28 audit.

A1-A6 are written the way a compromised certificate builder would actually attack:
with a consistent certificate, not one that announces its own escalation.
"""

from __future__ import annotations

import copy
import json

import pytest
from conftest import ROOT

from kinlock.certificate_builder import CertificateBuilder, extend
from kinlock.downstream import FAKE_TOOLS, DownstreamError, FakeDownstream, ToolSpec
from kinlock.gateway import Gateway, GatewayConfig
from kinlock.theustad_verifier import evidence_unsigned, mac
from kinlock.verified_engine import VerifiedEngine
from kinlock.verified_runtime import AuthorityScope, TemporalContract
from kinlock_authority import AgentAction

KEY = b"k" * 32
CAL = ToolSpec("calendar_lookup", "Read the calendar.", read_only=True)
MSG = {"to": "Anna", "text": "Your appointment is at 3 PM."}
TAKEOVER = {"account": "Gmail", "new_email": "attacker@protonmail.com"}


def msg_scope(depth=2, targets=("Anna",)):
    return AuthorityScope(("send_message",), ("comms",), ("send_message",), targets, 0, depth)


@pytest.fixture
def world(data_dir, clock):
    cfg = json.loads((ROOT / "data" / "gateway.example.json").read_text())
    cfg["read_only"] = cfg["read_only"] + ["calendar_lookup"]
    engine = VerifiedEngine(data_dir, KEY, "http://kinlock.test", clock=clock)
    ds = FakeDownstream(tools=FAKE_TOOLS + (CAL,))
    gw = Gateway(engine, ds, GatewayConfig.from_dict(cfg))
    return engine, gw, ds


def effects(ds):
    return [c for c in ds.calls if c[0] not in ("calendar_lookup", "check_weather")]


def planner(engine, gw, clock, *, scope=None, required=("calendar_lookup",), channel="voice", **kw):
    token = engine.mint_intent(purpose="Tell Anna my appointment time", scope=scope or msg_scope(), channel=channel, required_evidence=required, **kw)
    b = CertificateBuilder(token, clock=clock).delegate("planner")
    if required:
        res = gw.call("calendar_lookup", {"day": "today"}, channel="voice", by="calendar-agent", intent_id=b.intent_id)
        b.add_evidence(res.evidence)
    return b.delegate("messenger")


def cert(gw, b, tool, args):
    return b.build(tool=tool, arguments=args, **gw.config.describe(tool, args))


# -- the happy path ------------------------------------------------------------------------
def test_valid_certificate_commits_once_through_the_gate(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock)
    res = gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG))
    assert res.outcome == "ALLOW"
    assert res.proof["ok"] and res.proof["stage"] == "commit"
    assert "kinlock_signed_intent_chain" in res.proof["checks"]
    assert effects(ds) == [("send_message", MSG)]
    kinds = [r.kind for r in engine.chain.receipts()]
    assert kinds.index("intent_minted") < kinds.index("verification_witness") < kinds.index("executed") < kinds.index("verified_commit_result")
    assert engine.downstream.consumed[-1]["tool"] == "send_message"
    assert engine.chain.verify().ok


# -- the audit attacks ---------------------------------------------------------------------
def test_A1_builder_cannot_write_authority_into_the_root(world, clock):
    """v1: the compromised builder wrote identity authority into an unsigned root and THEUSTAD passed."""
    engine, gw, ds = world
    b = planner(engine, gw, clock)
    wide = {"tools": ["change_recovery_email"], "categories": ["identity"], "verbs": ["change_recovery_email"], "targets": ["Gmail"]}
    b.token["root"]["scope"].update(wide)
    for e in b.token["edges"]:
        e["scope"].update(wide)
    res = gw.call("change_recovery_email", TAKEOVER, channel="voice", by="worker", certificate=cert(gw, b, "change_recovery_email", TAKEOVER))
    assert not res.proof["ok"]
    assert any("chain signature does not verify" in p for p in res.proof["problems"])
    assert effects(ds) == []


def test_A2_declared_amount_cannot_bypass_the_intent_ceiling(world, clock):
    """v1: an honest $20 intent, a certificate claiming $15, a $110 purchase executed."""
    engine, gw, ds = world
    scope = AuthorityScope(("buy",), ("money",), ("purchase",), ("Fresh Market",), 2000, 1)
    b = CertificateBuilder(engine.mint_intent(purpose="groceries, at most $20", scope=scope, channel="owner"), clock=clock).delegate("shopper")
    args = {"merchant": "Fresh Market", "item": "groceries", "amount_dollars": 110}
    lie = b.build(tool="buy", arguments=args, category="money", verb="purchase", target="Fresh Market", amount_cents=1500)
    res = gw.call("buy", args, channel="voice", by="shopper", certificate=lie)
    assert res.outcome == "FAILED"
    assert "amount exceeds the owner's intent ceiling" in res.proof["problems"]
    assert effects(ds) == []


def test_A2b_honest_money_actions_commit_on_the_verified_path(world, clock):
    """v1: every money action failed, because the digest changed when Kinlock added the spend category."""
    engine, gw, ds = world
    scope = AuthorityScope(("buy",), ("money",), ("purchase",), ("Fresh Market",), 2000, 1)
    b = CertificateBuilder(engine.mint_intent(purpose="groceries, at most $20", scope=scope, channel="owner"), clock=clock).delegate("shopper")
    args = {"merchant": "Fresh Market", "item": "groceries", "amount_dollars": 15}
    res = gw.call("buy", args, channel="voice", by="shopper", certificate=cert(gw, b, "buy", args))
    assert res.outcome == "ALLOW" and res.proof["ok"]
    assert effects(ds) == [("buy", args)]


def test_A3_declared_target_cannot_redirect_the_message(world, clock):
    """v1: the certificate said Anna, the message went to Raj (a standing-permission target)."""
    engine, gw, ds = world
    b = planner(engine, gw, clock)
    args = {"to": "Raj", "text": "Leave the spare key under the mat."}
    lie = b.build(tool="send_message", arguments=args, category="comms", verb="send_message", target="Anna")
    res = gw.call("send_message", args, channel="voice", by="messenger", certificate=lie)
    assert res.outcome == "FAILED"
    assert any("target 'Raj' is outside the owner's intent" in p for p in res.proof["problems"])
    assert effects(ds) == []


def test_A4_revocation_comes_from_kinlock_state_not_the_certificate(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock)
    engine.revoke_intent(b.intent_id, by="voice")
    res = gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG))
    assert res.outcome == "FAILED"
    assert any("intent_revoked" in p for p in res.proof["problems"])
    assert effects(ds) == []


def test_A5_required_evidence_comes_from_the_signed_root(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock)
    b.evidence = []
    res = gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG))
    assert "required evidence missing: calendar_lookup" in res.proof["problems"]
    assert effects(ds) == []


def test_A5b_builder_cannot_sign_its_own_evidence(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock)
    rec = dict(b.evidence[0], evidence_id="ev-forged")
    rec["signature"] = mac(b"x" * 32, evidence_unsigned(rec))
    b.evidence = [rec]
    res = gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG))
    assert any("not signed by Kinlock's gateway" in p for p in res.proof["problems"])
    assert effects(ds) == []


def test_A6_replay_after_restart_is_refused(world, data_dir, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock, max_effects=5)
    c = cert(gw, b, "send_message", MSG)
    assert gw.call("send_message", MSG, channel="voice", by="messenger", certificate=c).outcome == "ALLOW"

    engine2 = VerifiedEngine(data_dir, KEY, "http://kinlock.test", clock=clock)  # a restart: fresh process state
    ds2 = FakeDownstream(tools=FAKE_TOOLS + (CAL,))
    gw2 = Gateway(engine2, ds2, gw.config)
    res = gw2.call("send_message", MSG, channel="voice", by="messenger", certificate=copy.deepcopy(c))
    assert res.outcome == "FAILED"
    assert res.proof["problems"][0].startswith("certificate replay")
    assert effects(ds2) == []


# -- the chain -------------------------------------------------------------------------------
def test_correctly_chained_amplifying_edge_is_refused(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock, scope=msg_scope(depth=3))
    wide = b.scope | {"targets": ["Anna", "Raj"]}
    b.token = extend(b.token, {"edge_id": "esc", "parent": b.subject, "child": "worker", "scope": wide, "issued_at": clock(), "expires_at": b._expiry(), "nonce": "n"})
    args = {"to": "Raj", "text": "hi"}
    res = gw.call("send_message", args, channel="voice", by="worker", certificate=cert(gw, b, "send_message", args))
    assert any("amplifies authority (targets widened)" in p for p in res.proof["problems"])
    assert effects(ds) == []


def test_stripping_or_reordering_edges_breaks_the_chain(world, clock):
    engine, gw, ds = world
    for mutate in (lambda e: e[1:], lambda e: list(reversed(e))):
        b = planner(engine, gw, clock, max_effects=3)
        b.token["edges"] = mutate(b.token["edges"])
        res = gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG))
        assert any("chain signature does not verify" in p for p in res.proof["problems"])
    assert effects(ds) == []


def test_builder_refuses_to_widen_locally_but_that_is_only_a_convenience(world, clock):
    engine, gw, _ = world
    b = planner(engine, gw, clock, scope=msg_scope(depth=3))
    with pytest.raises(ValueError):
        b.delegate("worker", b.scope | {"tools": ["send_message", "install_app"]})


def test_effect_budget_is_enforced_across_certificates(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock, max_effects=1)
    assert gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG)).outcome == "ALLOW"
    msg2 = {"to": "Anna", "text": "and one more thing"}
    res = gw.call("send_message", msg2, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", msg2))
    assert any("budget used up" in p for p in res.proof["problems"])
    assert len(effects(ds)) == 1


def test_evidence_from_another_intent_does_not_count(world, clock):
    engine, gw, ds = world
    other = planner(engine, gw, clock)
    b = CertificateBuilder(engine.mint_intent(purpose="x", scope=msg_scope(), channel="voice", required_evidence=("calendar_lookup",)), clock=clock).delegate("p").delegate("m")
    b.evidence = copy.deepcopy(other.evidence)
    res = gw.call("send_message", MSG, channel="voice", by="m", certificate=cert(gw, b, "send_message", MSG))
    assert any("belongs to a different intent" in p for p in res.proof["problems"])
    assert effects(ds) == []


def test_not_before_and_expiry_come_from_the_signed_root(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock, temporal=TemporalContract(not_before=clock() + 3600))
    res = gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG))
    assert "temporal contract is not yet satisfied" in res.proof["problems"]
    b2 = planner(engine, gw, clock, ttl=60)
    c2 = cert(gw, b2, "send_message", MSG)
    clock.advance(120)
    res2 = gw.call("send_message", MSG, channel="voice", by="messenger", certificate=c2)
    assert "root intent expired" in res2.proof["problems"]
    assert effects(ds) == []


# -- binding and the gate --------------------------------------------------------------------
def test_action_and_call_must_describe_the_same_effect(world, clock):
    engine, gw, ds = world
    b = planner(engine, gw, clock)
    c = cert(gw, b, "send_message", MSG)
    action = AgentAction("mismatch", "comms", "send_message", "Anna", {"text": MSG["text"]})
    res = engine.request_agent(action, "voice", "messenger", call={"tool": "send_message", "arguments": {"to": "Raj", "text": MSG["text"]}}, certificate=c)
    assert res.outcome == "FAILED"
    assert any("does not match the action Kinlock decided" in p for p in res.problems)
    assert effects(ds) == []


def test_no_certificate_fails_closed_on_the_allow_path(world, clock):
    engine, gw, ds = world
    res = gw.call("send_message", MSG, channel="voice", by="messenger")
    assert res.outcome == "FAILED"
    assert effects(ds) == []


def test_downstream_refuses_calls_without_a_commit_token(world):
    engine, _, ds = world
    with pytest.raises(DownstreamError, match="no commit token"):
        engine.downstream.call("send_message", {"to": "Raj", "text": "direct"})
    assert effects(ds) == []


def test_a_consumed_commit_token_cannot_be_rearmed(world, clock):
    engine, gw, ds = world
    gate = engine.downstream
    captured = []
    arm = gate.arm
    gate.arm = lambda t: (captured.append(t), arm(t))[1]
    b = planner(engine, gw, clock)
    gw.call("send_message", MSG, channel="voice", by="messenger", certificate=cert(gw, b, "send_message", MSG))
    gate.arm = arm
    gate.arm(captured[0])
    with pytest.raises(DownstreamError, match="replay"):
        gate.call("send_message", MSG)
    assert len(effects(ds)) == 1


def test_a_token_for_one_call_cannot_run_another(world, clock):
    engine, gw, ds = world
    token = engine.issuer.issue("not-this-call", "certificate:x", clock())
    engine.downstream.arm(token)
    with pytest.raises(DownstreamError, match="different call"):
        engine.downstream.call("send_message", MSG)


# -- minting --------------------------------------------------------------------------------
def test_voice_channel_cannot_grant_identity_authority(world, clock):
    engine, gw, ds = world
    scope = AuthorityScope(("change_recovery_email",), ("identity",), ("change_recovery_email",), ("Gmail",), 0, 1)
    token = engine.mint_intent(purpose="change my recovery email", scope=scope, channel="voice")
    assert token["root"]["scope"]["tools"] == [] and token["root"]["scope"]["categories"] == []
    minted = [r.data for r in engine.chain.receipts() if r.kind == "intent_minted"][-1]
    assert "category:identity" in minted["clamped"]
    b = CertificateBuilder(token, clock=clock).delegate("worker")
    res = gw.call("change_recovery_email", TAKEOVER, channel="voice", by="worker", certificate=cert(gw, b, "change_recovery_email", TAKEOVER))
    assert not res.proof["ok"]
    assert effects(ds) == []


def test_valid_owner_intent_still_gets_owner_and_cooloff(world, clock):
    engine, gw, ds = world
    scope = AuthorityScope(("change_recovery_email",), ("identity",), ("change_recovery_email",), ("Gmail",), 0, 1)
    b = CertificateBuilder(engine.mint_intent(purpose="change my recovery email", scope=scope, channel="owner", ttl=3 * 86400), clock=clock).delegate("worker")
    args = {"account": "Gmail", "new_email": "mary.backup@example.com"}
    res = gw.call("change_recovery_email", args, channel="voice", by="worker", certificate=cert(gw, b, "change_recovery_email", args))
    assert res.proof["ok"] is True
    assert res.outcome == "OWNER"
    assert effects(ds) == []


def test_held_action_releases_only_on_an_exact_action_approval(world, clock):
    engine, gw, ds = world
    b = CertificateBuilder(engine.mint_intent(purpose="x", scope=msg_scope(depth=1), channel="voice"), clock=clock).delegate("m")
    args = {"to": "Dr Smith", "text": "Please call Mary back."}
    res = gw.call("send_message", args, channel="voice", by="m", certificate=cert(gw, b, "send_message", args))
    assert res.outcome == "HOLD" and effects(ds) == []
    out = engine.agent_vote(res.request_id, "contact:anna", "approve")
    assert out.outcome == "EXECUTED"
    assert effects(ds) == [("send_message", args)]
    witness = [r.data for r in engine.chain.receipts() if r.kind == "verification_witness"][-1]
    assert witness["basis"] == "approval_capability" and witness["cap_id"]


def test_malformed_certificates_fail_closed(world, clock):
    engine, gw, ds = world
    for junk in ({}, {"schema": "kinlock.verified-action/2", "intent": "nope"}, {"intent": {"root": {"scope": {"tools": "send_message"}}, "edges": [], "sig": "00"}}):
        res = gw.call("send_message", MSG, channel="voice", by="m", certificate=junk)
        assert res.outcome == "FAILED"
    assert effects(ds) == []


def test_invalid_amounts_are_refused_before_any_decision(world):
    _, gw, ds = world
    for bad in ("nan", "inf", -5):
        res = gw.call("buy", {"merchant": "Fresh Market", "amount_dollars": bad}, channel="voice", by="m")
        assert res.outcome == "REJECTED"
    assert effects(ds) == []


def test_keys_are_derived_per_purpose_and_never_leave_the_engine(world):
    engine, _, _ = world
    assert len({engine.keys.intent, engine.keys.evidence, engine.keys.commit, KEY}) == 4
    token = engine.mint_intent(purpose="x", scope=msg_scope(), channel="voice")
    blob = json.dumps(token)
    for k in (engine.keys.intent, engine.keys.evidence, engine.keys.commit):
        assert k.hex() not in blob

