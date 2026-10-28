from __future__ import annotations

import json

import pytest

from kinlock._vendor.agentfleet_causal_authority import (
    AuthorityAmplification,
    AuthorityScope,
    CausalCertificateBuilder,
)
from kinlock._vendor.agentfleet_effect_outbox import EffectOutbox, OutboxError
from kinlock._vendor.theustad_causal_commit import verify_causal_certificate

KEY = b"agentfleet-public-lock-key-32!!"
NOW = 1000.0


def scopes():
    root = AuthorityScope(
        tools=("send_message",),
        categories=("comms",),
        verbs=("send_message",),
        targets=("Anna",),
        max_amount_cents=0,
        max_delegation_depth=2,
        expires_at=1120.0,
    )
    planner = AuthorityScope(
        tools=("send_message",),
        categories=("comms",),
        verbs=("send_message",),
        targets=("Anna",),
        max_amount_cents=0,
        max_delegation_depth=1,
        expires_at=1090.0,
    )
    worker = AuthorityScope(
        tools=("send_message",),
        categories=("comms",),
        verbs=("send_message",),
        targets=("Anna",),
        max_amount_cents=0,
        max_delegation_depth=0,
        expires_at=1060.0,
    )
    return root, planner, worker


def certificate():
    root, planner, worker = scopes()
    builder = CausalCertificateBuilder(
        principal="owner",
        purpose="Tell Anna my verified appointment time",
        scope=root,
        evidence_key=KEY,
        now=NOW,
        ttl_seconds=120,
        intent_id="intent-public-agentfleet",
    )
    builder.delegate("planner", planner, edge_id="d1")
    builder.delegate("messenger", worker, edge_id="d2")
    evidence_id = builder.add_evidence(
        producer="calendar-agent",
        source_tool="calendar_lookup",
        request={"event": "appointment"},
        response={"time": "3 PM"},
        evidence_id="ev-calendar",
    )
    return builder.build(
        request_id="r-public-agentfleet",
        action_digest="action-public-agentfleet",
        tool="send_message",
        arguments={"to": "Anna", "text": "Appointment is 3 PM"},
        category="comms",
        verb="send_message",
        target="Anna",
        required_evidence=(evidence_id,),
        not_before=999.0,
        expires_at=1030.0,
        required_facts=("appointment_verified",),
        forbidden_facts=("owner_revoked",),
        facts=("appointment_verified",),
        nonce="cert-public-agentfleet",
    )


def test_agentfleet_emitted_certificate_passes_independent_theustad_checker():
    cert = certificate()
    verdict = verify_causal_certificate(
        cert,
        evidence_key=KEY,
        now=NOW,
        expected_action_digest="action-public-agentfleet",
        expected_tool="send_message",
        expected_arguments={"to": "Anna", "text": "Appointment is 3 PM"},
    )
    assert verdict.ok, verdict.problems
    assert set(verdict.checks) == {
        "root_intent_time",
        "authority_conservation",
        "effect_within_scope",
        "bound_evidence_provenance",
        "temporal_contract",
    }


def test_agentfleet_builder_refuses_to_mint_identity_authority():
    root, planner, _ = scopes()
    builder = CausalCertificateBuilder(
        principal="owner",
        purpose="Tell Anna my appointment time",
        scope=root,
        evidence_key=KEY,
        now=NOW,
    )
    builder.delegate("planner", planner)
    illegal = AuthorityScope(
        tools=("change_recovery_email",),
        categories=("identity",),
        verbs=("change_recovery_email",),
        targets=("Gmail",),
        max_amount_cents=0,
        max_delegation_depth=0,
        expires_at=1060.0,
    )
    with pytest.raises(AuthorityAmplification):
        builder.delegate("identity-worker", illegal)


def test_agentfleet_outbox_stages_without_any_execution_primitive(tmp_path):
    outbox = EffectOutbox(tmp_path / "effects.jsonl")
    envelope = outbox.stage(certificate(), now=NOW)
    assert outbox.state(envelope.effect_id) == "STAGED"
    assert list(outbox.staged()) == [envelope]
    assert outbox.verify_chain()
    assert not hasattr(outbox, "execute")
    assert not hasattr(outbox, "run_tool")


def test_outbox_requires_both_proof_and_result_receipts_to_record_commit(tmp_path):
    outbox = EffectOutbox(tmp_path / "effects.jsonl")
    envelope = outbox.stage(certificate(), now=NOW)
    with pytest.raises(OutboxError):
        outbox.commit(envelope.effect_id, verification_receipt="", result_receipt="result")
    outbox.commit(
        envelope.effect_id,
        verification_receipt="verification-receipt-hash",
        result_receipt="execution-receipt-hash",
        now=NOW + 1,
    )
    assert outbox.state(envelope.effect_id) == "COMMITTED"
    assert outbox.verify_chain()


def test_outbox_hash_chain_detects_after_the_fact_argument_tampering(tmp_path):
    path = tmp_path / "effects.jsonl"
    outbox = EffectOutbox(path)
    outbox.stage(certificate(), now=NOW)
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    rows[0]["data"]["arguments"]["to"] = "Mallory"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")
    assert not outbox.verify_chain()
