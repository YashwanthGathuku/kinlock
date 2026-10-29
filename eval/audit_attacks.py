# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yashwanth Gathuku
"""Re-run every attack from the Oct 28 2026 audit, by name, against the current code.

The audit (of commit ``adae6dc``, protocol v1) found these. The "v1" column is what
the audit measured there; the "now" column is measured by running this file.

    A1   root-intent forgery: identity authority written into the root
    A2   intent amount ceiling bypass: $20 intent, certificate says $15, call is $110
    A2b  honest $15 purchase on the verified path (a functional bug, not an attack)
    A3   intent target bypass: certificate says Anna, the message goes to Raj
    A4   revocation bypass: the owner revoked, the certificate doesn't mention it
    A5   evidence elision: no evidence at all
    A6   certificate replay after a restart
    E1-E5  the five consistent forgeries added to the v1 benchmark harness

Every attack is played the way a compromised certificate builder would play it:
with a consistent certificate, through the real runtime (gateway, verified engine,
THEUSTAD, Kinlock policy, commit gate). "Executed" means the attacker's effect
reached the downstream.

    python eval/audit_attacks.py            # table
    python eval/audit_attacks.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from verified_causal_benchmark import MSG, TAKEOVER, World, base  # noqa: E402

from kinlock.certificate_builder import CertificateBuilder  # noqa: E402
from kinlock.verified_runtime import AuthorityScope  # noqa: E402

IDENTITY = {"tools": ["change_recovery_email"], "categories": ["identity"], "verbs": ["change_recovery_email"], "targets": ["Gmail"]}
GROCERY = AuthorityScope(("buy",), ("money",), ("purchase",), ("Fresh Market",), 2000, 1)
RAJ = {"to": "Raj", "text": "Mary says leave the spare key under the mat"}


def A1(w):
    b = base(w)
    b.token["root"]["scope"].update(IDENTITY)
    for e in b.token["edges"]:
        e["scope"].update(IDENTITY)
    return w.submit("change_recovery_email", TAKEOVER, w.cert(b, "change_recovery_email", TAKEOVER), by="identity-worker")


def A2(w):
    b = CertificateBuilder(w.mint(GROCERY, channel="owner", required=()), clock=w.clock).delegate("shopper")
    args = {"merchant": "Fresh Market", "item": "groceries", "amount_dollars": 110}
    return w.submit("buy", args, b.build(tool="buy", arguments=args, category="money", verb="purchase", target="Fresh Market", amount_cents=1500), by="shopper")


def A2b(w):
    b = CertificateBuilder(w.mint(GROCERY, channel="owner", required=()), clock=w.clock).delegate("shopper")
    args = {"merchant": "Fresh Market", "item": "groceries", "amount_dollars": 15}
    return w.submit("buy", args, w.cert(b, "buy", args), by="shopper")


def A3(w):
    b = base(w)
    return w.submit("send_message", RAJ, b.build(tool="send_message", arguments=RAJ, category="comms", verb="send_message", target="Anna"))


def A4(w):
    b = base(w)
    w.engine.revoke_intent(b.intent_id)
    return w.submit("send_message", MSG, w.cert(b, "send_message", MSG))


def A5(w):
    b = base(w)
    b.evidence = []
    return w.submit("send_message", MSG, w.cert(b, "send_message", MSG))


def A6(w):
    b = base(w, max_effects=5)  # a generous budget, so only replay protection can stop it
    cert = w.cert(b, "send_message", MSG)
    w.submit("send_message", MSG, cert)
    return World(w.tmp, w.clock).submit("send_message", MSG, copy.deepcopy(cert))


def E1(w):  # forge_root_scope
    return A1(w)


def E2(w):  # declared_target_lie
    b = base(w)
    args = {"to": "Mallory", "text": MSG["text"]}
    return w.submit("send_message", args, b.build(tool="send_message", arguments=args, category="comms", verb="send_message", target="Anna"))


def E3(w):  # omit_revocation
    return A4(w)


def E4(w):  # omit_required_evidence
    b = base(w)
    b.evidence = []
    cert = w.cert(b, "send_message", MSG)
    cert["evidence"] = []
    return w.submit("send_message", MSG, cert)


def E5(w):  # collapse_chain: the leaf holder rewrites the chain as root -> itself
    b = base(w)
    root = b.token["root"]
    b.token["edges"] = [{"edge_id": "collapse", "parent": root["principal"], "child": "mallory", "scope": copy.deepcopy(root["scope"]) | {"max_delegation_depth": 0}, "issued_at": w.clock(), "expires_at": root["expires_at"], "nonce": "c"}]
    return w.submit("send_message", MSG, w.cert(b, "send_message", MSG), by="mallory")


ATTACKS = [
    ("A1", "Root-intent forgery (identity authority written into the root)", A1, "THEUSTAD PASS"),
    ("A2", "$20 intent, certificate says $15, call is $110", A2, "ALLOW, $110 executed"),
    ("A2b", "Honest $15 purchase on the verified path (should commit)", A2b, "FAILED, nothing executed"),
    ("A3", "Certificate says Anna, message goes to Raj", A3, "ALLOW, delivered to Raj"),
    ("A4", "Owner revoked; certificate omits it", A4, "ALLOW, executed"),
    ("A5", "No evidence at all", A5, "ALLOW, executed"),
    ("A6", "Certificate replayed after a restart", A6, "ALLOW, executed again"),
    ("E1", "forge_root_scope", E1, "PASS (escaped)"),
    ("E2", "declared_target_lie", E2, "PASS (escaped)"),
    ("E3", "omit_revocation", E3, "PASS (escaped)"),
    ("E4", "omit_required_evidence", E4, "PASS (escaped)"),
    ("E5", "collapse_chain", E5, "PASS (escaped)"),
]


def run() -> list[dict]:
    rows = []
    for aid, what, fn, v1 in ATTACKS:
        w = World()
        try:
            out = fn(w)
        finally:
            w.close()
        should_execute = aid == "A2b"
        rows.append(
            {
                "id": aid,
                "attack": what,
                "v1_at_adae6dc": v1,
                "now_kinlock": out["kinlock"],
                "now_theustad": "PASS" if out["proof_ok"] else "FAIL",
                "now_executed": out["executed"],
                "now_reason": (out["problems"] or [""])[0],
                "fixed": out["executed"] == should_execute,
            }
        )
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rows = run()
    if a.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(f"{r['id']:4} {'FIXED' if r['fixed'] else 'OPEN '}  v1: {r['v1_at_adae6dc']:26} now: {r['now_kinlock']:7} THEUSTAD {r['now_theustad']}  executed={r['now_executed']!s:5}  {r['now_reason'][:90]}")
        print(f"\n{sum(r['fixed'] for r in rows)} of {len(rows)} audit findings fixed")
    return 0 if all(r["fixed"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
