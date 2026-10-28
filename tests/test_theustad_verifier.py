"""The THEUSTAD verifier stands alone: stdlib only, no Kinlock planner or policy imports."""

from __future__ import annotations

import ast
from pathlib import Path

from kinlock.theustad_verifier import DerivedEffect, chain_mac, mac, scope_attenuates, verify_certificate

SRC = Path(__file__).resolve().parents[1] / "src" / "kinlock" / "theustad_verifier.py"
KI, KE = b"i" * 32, b"e" * 32
NOW = 1000.0


def test_verifier_imports_only_the_standard_library():
    tree = ast.parse(SRC.read_text())
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert mods <= {"__future__", "hashlib", "hmac", "json", "dataclasses", "typing"}, mods


def _cert(root, edges, sig):
    return {
        "schema": "kinlock.verified-action/2",
        "intent": {"root": root, "edges": edges, "sig": sig},
        "evidence": [],
        "effect": {"actor": edges[-1]["child"] if edges else root["principal"], "tool": "send_message", "arguments": {"to": "Anna"}, "category": "comms", "verb": "send_message", "target": "Anna", "amount_cents": 0},
        "created_at": NOW,
        "nonce": "n",
    }


ROOT = {
    "schema": "kinlock.intent/2", "intent_id": "i1", "principal": "owner", "issued_at": NOW - 1, "expires_at": NOW + 60, "max_effects": 1,
    "scope": {"tools": ["send_message"], "categories": ["comms"], "verbs": ["send_message"], "targets": ["Anna"], "max_amount_cents": 0, "max_delegation_depth": 1, "expires_at": NOW + 60},
    "required_evidence": [], "temporal": {},
}
DERIVED = DerivedEffect("send_message", {"to": "Anna"}, "comms", "send_message", "Anna", 0)


def test_chain_recomputes_from_the_root_key():
    edge = {"edge_id": "e", "parent": "owner", "child": "m", "scope": ROOT["scope"] | {"max_delegation_depth": 0}, "issued_at": NOW, "expires_at": NOW + 30, "nonce": "x"}
    sig = chain_mac(mac(KI, ROOT), edge)
    assert verify_certificate(_cert(ROOT, [edge], sig), intent_key=KI, evidence_key=KE, now=NOW, derived=DERIVED).ok
    assert not verify_certificate(_cert(ROOT, [edge], sig), intent_key=b"x" * 32, evidence_key=KE, now=NOW, derived=DERIVED).ok


def test_no_derived_effect_means_no_pass():
    v = verify_certificate(_cert(ROOT, [], mac(KI, ROOT)), intent_key=KI, evidence_key=KE, now=NOW, derived=None)
    assert not v.ok and any("no derived effect" in p for p in v.problems)


def test_string_scope_sets_are_malformed_not_character_sets():
    bad = ROOT | {"scope": ROOT["scope"] | {"tools": "send_message"}}
    v = verify_certificate(_cert(bad, [], mac(KI, bad)), intent_key=KI, evidence_key=KE, now=NOW, derived=DERIVED)
    assert not v.ok and v.problems[0].startswith("malformed")


def test_attenuation_is_checked_on_every_axis():
    parent = ROOT["scope"]
    assert scope_attenuates(parent | {"max_delegation_depth": 0}, parent) == []
    assert "tools widened" in scope_attenuates(parent | {"tools": ["*"]}, parent)
    assert "amount ceiling widened" in scope_attenuates(parent | {"max_amount_cents": 1}, parent)
    assert "lifetime widened" in scope_attenuates(parent | {"expires_at": NOW + 999}, parent)
