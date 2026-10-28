from __future__ import annotations

from kinlock.downstream import FakeDownstream
from kinlock.verified_engine import VerifiedEngine
from kinlock.verified_runtime import (
    ActionCertificate,
    AuthorityScope,
    CommitTokenIssuer,
    Delegation,
    EvidenceRecord,
    ProposedEffect,
    RootIntent,
    TemporalContract,
    TheUstadVerifier,
    VerificationError,
    VerifiedExecutionGuard,
    sign_evidence,
)
from kinlock_authority import AgentAction

EVIDENCE_KEY = b"e" * 32
COMMIT_KEY = b"c" * 32
ENGINE_KEY = b"k" * 32


def guard() -> VerifiedExecutionGuard:
    return VerifiedExecutionGuard(
        TheUstadVerifier(EVIDENCE_KEY),
        CommitTokenIssuer(COMMIT_KEY, ttl_seconds=30),
    )


def certificate(action: AgentAction, call: dict, now: float, *, not_before: float | None = None) -> ActionCertificate:
    root_scope = AuthorityScope(
        tools=("send_message",),
        categories=("comms",),
        verbs=("send_message",),
        targets=("Anna",),
        max_amount_cents=0,
        max_delegation_depth=2,
        expires_at=now + 120,
    )
    planner_scope = AuthorityScope(
        tools=("send_message",),
        categories=("comms",),
        verbs=("send_message",),
        targets=("Anna",),
        max_amount_cents=0,
        max_delegation_depth=1,
        expires_at=now + 90,
    )
    worker_scope = AuthorityScope(
        tools=("send_message",),
        categories=("comms",),
        verbs=("send_message",),
        targets=("Anna",),
        max_amount_cents=0,
        max_delegation_depth=0,
        expires_at=now + 60,
    )
    ev = sign_evidence(
        EvidenceRecord(
            "ev1",
            "calendar-agent",
            "calendar_lookup",
            "request-hash",
            "response-hash",
            now - 2,
        ),
        EVIDENCE_KEY,
    )
    effect = ProposedEffect(
        request_id=action.request_id,
        actor="messenger",
        action_digest=action.digest(),
        tool=call["tool"],
        arguments=dict(call["arguments"]),
        category=action.category,
        verb=action.verb,
        target=action.target,
        amount_cents=action.amount_cents,
        required_evidence=("ev1",),
        proposed_at=now - 1,
    )
    return ActionCertificate(
        root=RootIntent(
            "intent1",
            "owner",
            "Tell Anna the verified appointment time",
            now - 10,
            now + 120,
            root_scope,
            "root-nonce",
        ),
        delegations=(
            Delegation("d1", "owner", "planner", planner_scope, now - 9, now + 90, "d1-nonce"),
            Delegation("d2", "planner", "messenger", worker_scope, now - 8, now + 60, "d2-nonce"),
        ),
        evidence=(ev,),
        effect=effect,
        temporal=TemporalContract(
            not_before=not_before if not_before is not None else now - 1,
            expires_at=now + 30,
            required_facts=("appointment_verified",),
            forbidden_facts=("owner_revoked",),
        ),
        facts=("appointment_verified",),
        created_at=now - 1,
        nonce="cert-nonce-" + action.request_id,
    )


def make_engine(data_dir, clock):
    downstream = FakeDownstream()
    execution_guard = guard()
    engine = VerifiedEngine(
        data_dir,
        ENGINE_KEY,
        "http://kinlock.test",
        clock=clock,
        downstream=downstream,
        execution_guard=execution_guard,
    )
    return engine, downstream, execution_guard


def test_valid_agentfleet_proof_reaches_existing_kinlock_downstream(data_dir, clock):
    engine, downstream, execution_guard = make_engine(data_dir, clock)
    action = AgentAction("verified1", "comms", "send_message", "Anna", {})
    call = {"tool": "send_message", "arguments": {"to": "Anna", "text": "Appointment is 3 PM"}}
    execution_guard.stage(certificate(action, call, clock()))

    result = engine.request_agent(action, "voice", "owner", call=call)

    assert result.outcome == "ALLOW"
    assert downstream.calls == [("send_message", {"to": "Anna", "text": "Appointment is 3 PM"})]
    kinds = [r.kind for r in engine.chain.receipts()]
    assert "verification_witness" in kinds
    assert "executed" in kinds
    assert kinds.index("verification_witness") < kinds.index("executed")
    assert "verified_commit_result" in kinds


def test_allowed_kinlock_action_still_fails_closed_without_external_proof(data_dir, clock):
    engine, downstream, _ = make_engine(data_dir, clock)
    action = AgentAction("verified2", "comms", "send_message", "Anna", {})
    call = {"tool": "send_message", "arguments": {"to": "Anna", "text": "Hello"}}

    result = engine.request_agent(action, "voice", "owner", call=call)

    assert result.outcome == "FAILED"
    assert downstream.calls == []
    assert any("no proof-carrying certificate" in p for p in result.problems)
    assert any(r.kind == "verification_failed" for r in engine.chain.receipts())


def test_tool_argument_swap_after_verification_is_blocked(data_dir, clock):
    engine, downstream, execution_guard = make_engine(data_dir, clock)
    action = AgentAction("verified3", "comms", "send_message", "Anna", {})
    original = {"tool": "send_message", "arguments": {"to": "Anna", "text": "Safe"}}
    execution_guard.stage(certificate(action, original, clock()))
    tampered = {"tool": "send_message", "arguments": {"to": "Mallory", "text": "Safe"}}

    result = engine.request_agent(action, "voice", "owner", call=tampered)

    assert result.outcome == "FAILED"
    assert downstream.calls == []
    assert any("different downstream arguments" in p for p in result.problems)


def test_temporal_contract_blocks_commit_even_when_kinlock_would_allow(data_dir, clock):
    engine, downstream, execution_guard = make_engine(data_dir, clock)
    action = AgentAction("verified4", "comms", "send_message", "Anna", {})
    call = {"tool": "send_message", "arguments": {"to": "Anna", "text": "Too early"}}
    execution_guard.stage(certificate(action, call, clock(), not_before=clock() + 60))

    result = engine.request_agent(action, "voice", "owner", call=call)

    assert result.outcome == "FAILED"
    assert downstream.calls == []
    assert any("not yet satisfied" in p for p in result.problems)


def test_authority_amplification_in_certificate_is_rejected():
    execution_guard = guard()
    action = AgentAction("verified5", "comms", "send_message", "Anna", {})
    call = {"tool": "send_message", "arguments": {"to": "Anna", "text": "Hi"}}
    cert = certificate(action, call, 1000.0)
    widened = AuthorityScope(
        tools=("send_message", "change_recovery_email"),
        categories=("comms", "identity"),
        verbs=("send_message", "change_recovery_email"),
        targets=("Anna", "Gmail"),
        max_amount_cents=0,
        max_delegation_depth=0,
        expires_at=1060.0,
    )
    bad = ActionCertificate(
        root=cert.root,
        delegations=(cert.delegations[0], Delegation("d2", "planner", "messenger", widened, 992.0, 1060.0, "x")),
        evidence=cert.evidence,
        effect=cert.effect,
        temporal=cert.temporal,
        facts=cert.facts,
        created_at=cert.created_at,
        nonce="bad-cert",
    )
    execution_guard.stage(bad)

    try:
        execution_guard.authorize(action, call, now=1000.0)
    except VerificationError as exc:
        assert "amplifies authority" in str(exc)
    else:
        raise AssertionError("authority amplification unexpectedly passed")


def test_commit_tokens_are_single_use():
    verifier = TheUstadVerifier(EVIDENCE_KEY)
    issuer = CommitTokenIssuer(COMMIT_KEY, ttl_seconds=30)
    action = AgentAction("verified6", "comms", "send_message", "Anna", {})
    call = {"tool": "send_message", "arguments": {"to": "Anna"}}
    report = verifier.verify(certificate(action, call, 1000.0), now=1000.0)
    assert report.ok
    token = issuer.issue(report, 1000.0)
    issuer.consume(token, report.effect_digest, 1000.0)
    try:
        issuer.consume(token, report.effect_digest, 1000.1)
    except VerificationError as exc:
        assert "replay" in str(exc)
    else:
        raise AssertionError("commit token replay unexpectedly passed")
