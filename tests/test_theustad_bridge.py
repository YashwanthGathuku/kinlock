from __future__ import annotations

from kinlock.theustad_bridge import VendoredTheUstadVerifier
from kinlock.verified_runtime import (
    ActionCertificate,
    AuthorityScope,
    Delegation,
    EvidenceRecord,
    ProposedEffect,
    RootIntent,
    TemporalContract,
    sign_evidence,
)

KEY = b"e" * 32
NOW = 1000.0


def make_cert(*, amplify: bool = False):
    root_scope = AuthorityScope(
        tools=("send_message",), categories=("comms",), verbs=("send_message",), targets=("Anna",),
        max_amount_cents=0, max_delegation_depth=1, expires_at=1080.0,
    )
    child_scope = AuthorityScope(
        tools=("send_message", "change_recovery_email") if amplify else ("send_message",),
        categories=("comms", "identity") if amplify else ("comms",),
        verbs=("send_message", "change_recovery_email") if amplify else ("send_message",),
        targets=("Anna", "Gmail") if amplify else ("Anna",),
        max_amount_cents=0, max_delegation_depth=0, expires_at=1060.0,
    )
    ev = sign_evidence(EvidenceRecord("ev", "calendar", "lookup", "rq", "rs", 998.0), KEY)
    effect = ProposedEffect(
        "r", "messenger", "action-digest", "send_message", {"to": "Anna"},
        "comms", "send_message", "Anna", required_evidence=("ev",), proposed_at=999.0,
    )
    return ActionCertificate(
        RootIntent("i", "owner", "message Anna", 990.0, 1100.0, root_scope, "rn"),
        (Delegation("d", "owner", "messenger", child_scope, 991.0, 1060.0, "dn"),),
        (ev,), effect,
        TemporalContract(999.0, 1030.0, ("verified",), ("revoked",)),
        ("verified",), 999.0, "cn",
    )


def test_public_vendored_theustad_accepts_valid_certificate():
    verdict = VendoredTheUstadVerifier(KEY).verify(make_cert(), now=NOW)
    assert verdict.ok
    assert "authority_conservation" in verdict.checks
    assert "bound_evidence_provenance" in verdict.checks


def test_public_vendored_theustad_rejects_authority_amplification():
    verdict = VendoredTheUstadVerifier(KEY).verify(make_cert(amplify=True), now=NOW)
    assert not verdict.ok
    assert any("amplifies authority" in p for p in verdict.problems)
