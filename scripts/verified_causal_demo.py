"""Reproducible demo for Kinlock's Verified Causal Commit architecture.

This demo is deterministic and does not call a model or the network.  Its job is
to prove the systems property shown in the hackathon video:

    agents may propose a bad effect -> no valid causal proof -> no commit

It also shows the complementary layer:

    valid proof for a consequential identity action -> Kinlock still requires
    owner authority + cool-off -> no commit yet

Use ``--json`` for the judge UI / benchmark pipeline.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kinlock.downstream import FakeDownstream
from kinlock.theustad_bridge import VendoredTheUstadVerifier
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
    VerifiedExecutionGuard,
    sign_evidence,
)
from kinlock_authority import AgentAction

EVIDENCE_KEY = b"demo-evidence-key-32-bytes-long!!"
COMMIT_KEY = b"demo-commit-key---32-bytes-long!!"
ENGINE_KEY = b"demo-engine-key---32-bytes-long!!"
NOW = 1_798_000_000.0


def _scope(*, tools, categories, verbs, targets, depth, expires, max_amount=0):
    return AuthorityScope(
        tools=tuple(tools),
        categories=tuple(categories),
        verbs=tuple(verbs),
        targets=tuple(targets),
        max_amount_cents=max_amount,
        max_delegation_depth=depth,
        expires_at=expires,
    )


def _signed_evidence(eid: str, producer: str, tool: str, request_hash: str, response_hash: str, parents=()):
    return sign_evidence(
        EvidenceRecord(
            evidence_id=eid,
            producer=producer,
            source_tool=tool,
            request_hash=request_hash,
            response_hash=response_hash,
            observed_at=NOW - 3,
            parent_evidence=tuple(parents),
        ),
        EVIDENCE_KEY,
    )


def distributed_authority_attack() -> dict:
    """Several benign-looking steps compose into an authority escalation."""

    # Human intent permits checking Gmail recovery state and messaging Anna.
    root_scope = _scope(
        tools=("check_account", "send_message"),
        categories=("data", "comms"),
        verbs=("read_account", "send_message"),
        targets=("Gmail", "Anna"),
        depth=3,
        expires=NOW + 300,
    )
    planner_scope = _scope(
        tools=("check_account", "send_message"),
        categories=("data", "comms"),
        verbs=("read_account", "send_message"),
        targets=("Gmail", "Anna"),
        depth=2,
        expires=NOW + 240,
    )
    reader_scope = _scope(
        tools=("check_account",),
        categories=("data",),
        verbs=("read_account",),
        targets=("Gmail",),
        depth=1,
        expires=NOW + 180,
    )

    ev_message = _signed_evidence("ev-msg", "message-reader", "read_message", "rq1", "rs1")
    ev_account = _signed_evidence("ev-account", "account-reader", "check_account", "rq2", "rs2")

    # A compromised planner splices those individually harmless observations into a
    # recovery-email mutation.  It also fabricates a final delegation that grants the
    # worker authority its parent never had.  This is the multi-agent fragmentation case.
    escalated_scope = _scope(
        tools=("change_recovery_email",),
        categories=("identity",),
        verbs=("change_recovery_email",),
        targets=("Gmail",),
        depth=0,
        expires=NOW + 120,
    )
    effect = ProposedEffect(
        request_id="attack-recovery-1",
        actor="identity-worker",
        action_digest="not-issued-because-proof-is-invalid",
        tool="change_recovery_email",
        arguments={"account": "Gmail", "new_email": "attacker@protonmail.com"},
        category="identity",
        verb="change_recovery_email",
        target="Gmail",
        required_evidence=("ev-msg", "ev-account"),
        proposed_at=NOW - 1,
    )
    cert = ActionCertificate(
        root=RootIntent(
            "intent-check-recovery",
            "owner",
            "Check my Gmail recovery settings and tell Anna if anything looks wrong",
            NOW - 10,
            NOW + 300,
            root_scope,
            "root-attack-nonce",
        ),
        delegations=(
            Delegation("edge-plan", "owner", "planner", planner_scope, NOW - 9, NOW + 240, "n1"),
            Delegation("edge-read", "planner", "account-reader", reader_scope, NOW - 8, NOW + 180, "n2"),
            # Broken ancestry + authority amplification: account-reader never had identity write authority.
            Delegation("edge-escalate", "account-reader", "identity-worker", escalated_scope, NOW - 2, NOW + 120, "n3"),
        ),
        evidence=(ev_message, ev_account),
        effect=effect,
        temporal=TemporalContract(expires_at=NOW + 60),
        facts=("message_read", "recovery_state_read"),
        created_at=NOW - 1,
        nonce="attack-cert",
    )

    verdict = VendoredTheUstadVerifier(EVIDENCE_KEY).verify(cert, now=NOW)
    return {
        "name": "distributed_authority_amplification",
        "root_intent": cert.root.purpose,
        "agents": [
            {"agent": "message-reader", "step": "read suspicious message", "locally_dangerous": False},
            {"agent": "account-reader", "step": "read Gmail recovery state", "locally_dangerous": False},
            {"agent": "planner", "step": "compose next step from both observations", "locally_dangerous": False},
            {"agent": "identity-worker", "step": "propose recovery-email mutation", "locally_dangerous": True},
        ],
        "proposed_effect": cert.effect.to_dict(),
        "theustad": verdict.to_dict(),
        "kinlock_commit_token_issued": False,
        "downstream_executed": False,
        "headline": "The swarm assembled the attack, but the authority path could not prove the write was granted.",
    }


def _verified_engine(tmp: Path):
    shutil.copy(ROOT / "data" / "policy.example.json", tmp / "policy.json")
    downstream = FakeDownstream()
    verifier = VendoredTheUstadVerifier(EVIDENCE_KEY)
    guard = VerifiedExecutionGuard(verifier, CommitTokenIssuer(COMMIT_KEY))
    engine = VerifiedEngine(
        tmp,
        ENGINE_KEY,
        "http://kinlock.demo",
        clock=lambda: NOW,
        downstream=downstream,
        execution_guard=guard,
    )
    return engine, downstream, guard


def valid_safe_transaction() -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="kinlock-verified-safe-"))
    engine, downstream, guard = _verified_engine(tmp)
    action = AgentAction("safe-message-1", "comms", "send_message", "Anna", {})
    call = {"tool": "send_message", "arguments": {"to": "Anna", "text": "Your appointment is at 3 PM."}}
    ev = _signed_evidence("ev-calendar", "calendar-agent", "calendar_lookup", "calendar-request", "calendar-response")
    root_scope = _scope(
        tools=("send_message",), categories=("comms",), verbs=("send_message",), targets=("Anna",), depth=1, expires=NOW + 120,
    )
    worker_scope = replace(root_scope, max_delegation_depth=0, expires_at=NOW + 60)
    cert = ActionCertificate(
        RootIntent("intent-safe", "owner", "Tell Anna my verified appointment time", NOW - 10, NOW + 120, root_scope, "safe-root"),
        (Delegation("safe-edge", "owner", "messenger", worker_scope, NOW - 8, NOW + 60, "safe-edge-nonce"),),
        (ev,),
        ProposedEffect(
            action.request_id, "messenger", action.digest(), call["tool"], call["arguments"],
            action.category, action.verb, action.target, required_evidence=(ev.evidence_id,), proposed_at=NOW - 1,
        ),
        TemporalContract(NOW - 1, NOW + 30, ("appointment_verified",), ("owner_revoked",)),
        ("appointment_verified",), NOW - 1, "safe-cert",
    )
    guard.stage(cert)
    result = engine.request_agent(action, "voice", "owner", call=call)
    witness = next((r for r in engine.chain.receipts() if r.kind == "verification_witness"), None)
    return {
        "name": "verified_safe_transaction",
        "theustad_passed": witness is not None,
        "kinlock_outcome": result.outcome,
        "downstream_executed": bool(downstream.calls),
        "downstream_calls": downstream.calls,
        "receipt_chain_ok": engine.chain.verify().ok,
    }


def valid_proof_but_kinlock_holds_identity_change() -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="kinlock-verified-identity-"))
    engine, downstream, guard = _verified_engine(tmp)
    action = AgentAction(
        "identity-owner-1",
        "identity",
        "change_recovery_email",
        "Gmail",
        {"new_email": "mary.backup@example.com"},
    )
    call = {"tool": "change_recovery_email", "arguments": {"account": "Gmail", "new_email": "mary.backup@example.com"}}
    root_scope = _scope(
        tools=("change_recovery_email",), categories=("identity",), verbs=("change_recovery_email",), targets=("Gmail",), depth=1, expires=NOW + 172800,
    )
    worker_scope = replace(root_scope, max_delegation_depth=0, expires_at=NOW + 86400)
    ev = _signed_evidence("ev-owner", "owner-surface", "owner_request", "owner-rq", "owner-rs")
    cert = ActionCertificate(
        RootIntent("intent-identity", "owner", "Change my Gmail recovery email", NOW - 10, NOW + 172800, root_scope, "identity-root"),
        (Delegation("identity-edge", "owner", "identity-worker", worker_scope, NOW - 8, NOW + 86400, "identity-edge-nonce"),),
        (ev,),
        ProposedEffect(
            action.request_id, "identity-worker", action.digest(), call["tool"], call["arguments"],
            action.category, action.verb, action.target, required_evidence=(ev.evidence_id,), proposed_at=NOW - 1,
        ),
        TemporalContract(NOW - 1, NOW + 86400, ("owner_requested",), ("owner_revoked",)),
        ("owner_requested",), NOW - 1, "identity-cert",
    )
    # The proof is valid and staged. Kinlock still applies its own owner-only + cool-off policy.
    proof_preview = VendoredTheUstadVerifier(EVIDENCE_KEY).verify(cert, now=NOW)
    guard.stage(cert)
    result = engine.request_agent(action, "voice", "owner", call=call)
    return {
        "name": "valid_proof_consequential_identity_change",
        "theustad": proof_preview.to_dict(),
        "kinlock_outcome": result.outcome,
        "kinlock_reason": (result.decision or {}).get("reasons", []),
        "downstream_executed": bool(downstream.calls),
        "headline": "A valid proof does not grant authority; Kinlock still requires owner confirmation and cool-off.",
    }


def run_all() -> dict:
    return {
        "schema": "kinlock.verified-causal-demo/1",
        "mode": "deterministic-local-no-model-calls",
        "scenarios": [
            distributed_authority_attack(),
            valid_safe_transaction(),
            valid_proof_but_kinlock_holds_identity_change(),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_all()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    for scenario in result["scenarios"]:
        print("\n===", scenario["name"], "===")
        if "headline" in scenario:
            print(scenario["headline"])
        if "theustad" in scenario:
            print("THEUSTAD:", "PASS" if scenario["theustad"]["ok"] else "FAIL")
            for problem in scenario["theustad"].get("problems", []):
                print("  -", problem)
        if "kinlock_outcome" in scenario:
            print("KINLOCK:", scenario["kinlock_outcome"])
        print("DOWNSTREAM EXECUTED:", scenario["downstream_executed"])


if __name__ == "__main__":
    main()
