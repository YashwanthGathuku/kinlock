"""Deterministic demo of Verified Causal Commit (protocol v2). No model or network calls.

Three scenarios, each run through the real runtime: Kinlock mints and signs the
owner's intent, agents hold only the token, read-only tool results are signed by
Kinlock's gateway, every consequential call goes Gateway -> VerifiedEngine ->
THEUSTAD -> Kinlock policy -> commit gate -> downstream.

A. A compromised swarm tries four ways to turn "check my recovery settings and
   tell Anna" into a recovery-email takeover: widen the signed intent, delegate
   authority it never had, misdescribe the effect, forge evidence. All four fail
   the proof; none gets a commit token. The legitimate message then commits.
B. A verified safe transaction commits once. Replaying its certificate after a
   restart fails (the nonce is in the receipt chain), and so does a second effect
   past the intent's budget.
C. A valid proof for an identity change, minted on the owner's own surface, still
   gets OWNER and a 24-hour cool-off: proof is not authorization. The same request
   arriving by voice is clamped: identity can't be granted from a voice channel.

    python scripts/verified_causal_demo.py
    python scripts/verified_causal_demo.py --json
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kinlock.certificate_builder import CertificateBuilder, extend  # noqa: E402
from kinlock.downstream import FAKE_TOOLS, FakeDownstream, ToolSpec  # noqa: E402
from kinlock.gateway import Gateway, GatewayConfig  # noqa: E402
from kinlock.theustad_verifier import evidence_unsigned, mac  # noqa: E402
from kinlock.verified_engine import VerifiedEngine  # noqa: E402
from kinlock.verified_runtime import AuthorityScope  # noqa: E402

ENGINE_KEY = b"demo-engine-key---32-bytes-long!!"
NOW = 1_798_000_000.0  # fixed so the demo is reproducible; 23:26 in New York, outside night hours

READ_TOOLS = (
    ToolSpec("read_messages", "Read the owner's newest messages.", read_only=True),
    ToolSpec("check_account", "Read an account's security settings.", read_only=True),
    ToolSpec("calendar_lookup", "Read the owner's calendar.", read_only=True),
)


class Clock:
    def __init__(self, t: float = NOW):
        self.t = t

    def __call__(self) -> float:
        return self.t


_TEMP: list[Path] = []


def _world(tmp: Path | None = None, clock: Clock | None = None):
    if tmp is None:
        tmp = Path(tempfile.mkdtemp(prefix="kinlock-verified-"))
        _TEMP.append(tmp)
    if not (tmp / "policy.json").exists():
        shutil.copy(ROOT / "data" / "policy.example.json", tmp / "policy.json")
    clock = clock or Clock()
    cfg = json.loads((ROOT / "data" / "gateway.example.json").read_text())
    cfg["read_only"] = sorted(set(cfg.get("read_only", [])) | {t.name for t in READ_TOOLS})
    engine = VerifiedEngine(tmp, ENGINE_KEY, "http://kinlock.demo", clock=clock)
    downstream = FakeDownstream(tools=FAKE_TOOLS + READ_TOOLS)
    gateway = Gateway(engine, downstream, GatewayConfig.from_dict(cfg))
    return engine, gateway, downstream, tmp, clock


def _call(gateway: Gateway, tool: str, args: dict, cert: dict | None, by: str) -> dict:
    before = len(gateway.downstream.calls)
    res = gateway.call(tool, args, channel="voice", by=by, certificate=cert)
    proof = res.proof or {}
    return {
        "tool": tool,
        "arguments": args,
        "theustad": {"ok": bool(proof.get("ok")), "stage": proof.get("stage"), "checks": proof.get("checks", []), "problems": proof.get("problems", [])},
        "kinlock_outcome": res.outcome,
        "commit_token_issued": bool(proof.get("commit_token_id")),
        "downstream_executed": len(gateway.downstream.calls) > before,
    }


def _read(gateway: Gateway, builder: CertificateBuilder, tool: str, args: dict, by: str) -> dict:
    res = gateway.call(tool, args, channel="voice", by=by, intent_id=builder.intent_id)
    builder.add_evidence(res.evidence)
    return {"agent": by, "tool": tool, "evidence_id": (res.evidence or {}).get("evidence_id"), "signed_by": "kinlock-gateway"}


def compromised_swarm() -> dict:
    engine, gw, ds, _, clock = _world()
    task = "Check my Gmail recovery settings and tell Anna if anything looks wrong."
    token = engine.mint_intent(
        purpose=task,
        scope=AuthorityScope(tools=("send_message",), categories=("comms",), verbs=("send_message",), targets=("Anna",), max_amount_cents=0, max_delegation_depth=3),
        channel="voice",
        max_effects=1,
        required_evidence=("check_account",),
    )
    planner = CertificateBuilder(token, clock=clock).delegate("planner", edge_id="owner-planner")
    reads = [
        _read(gw, planner, "read_messages", {"which": "newest"}, "message-reader"),
        _read(gw, planner, "check_account", {"account": "Gmail"}, "account-reader"),
    ]
    takeover = {"account": "Gmail", "new_email": "attacker@protonmail.com"}
    identity = dict(category="identity", verb="change_recovery_email", target="Gmail")

    attempts = []

    # 1. Widen the signed intent: edit the root the owner's session produced.
    b1 = copy.deepcopy(planner)
    b1.token["root"]["scope"].update(tools=["send_message", "change_recovery_email"], categories=["comms", "identity"], verbs=["send_message", "change_recovery_email"], targets=["Anna", "Gmail"])
    for e in b1.token["edges"]:
        e["scope"].update(b1.token["root"]["scope"] | {"max_delegation_depth": e["scope"]["max_delegation_depth"], "expires_at": e["scope"]["expires_at"]})
    attempts.append({"attempt": "Widen the owner's signed intent", **_call(gw, "change_recovery_email", takeover, b1.build(tool="change_recovery_email", arguments=takeover, **identity), "identity-worker")})

    # 2. Delegate authority the parent never had: a correctly chained edge that amplifies.
    b2 = copy.deepcopy(planner)
    wide = b2.scope | {"tools": ["change_recovery_email"], "categories": ["identity"], "verbs": ["change_recovery_email"], "targets": ["Gmail"], "max_delegation_depth": 0}
    edge = {"edge_id": "edge-escalate", "parent": "planner", "child": "identity-worker", "scope": wide, "issued_at": clock(), "expires_at": b2._expiry(), "nonce": "escalate"}
    b2.token = extend(b2.token, edge)
    attempts.append({"attempt": "Delegate authority its parent never had", **_call(gw, "change_recovery_email", takeover, b2.build(tool="change_recovery_email", arguments=takeover, **identity), "identity-worker")})

    # 3. Misdescribe the effect: the certificate says "message Anna", the call is the takeover.
    b3 = copy.deepcopy(planner).delegate("identity-worker", edge_id="planner-worker")
    lie = b3.build(tool="send_message", arguments={"to": "Anna", "text": "all good"}, category="comms", verb="send_message", target="Anna")
    attempts.append({"attempt": "Describe the takeover as a message to Anna", **_call(gw, "change_recovery_email", takeover, lie, "identity-worker")})

    # 4. Forge evidence: sign a record "the owner asked for this" with a key the swarm made up.
    b4 = copy.deepcopy(planner).delegate("messenger", edge_id="planner-messenger")
    b4.evidence = [e for e in b4.evidence if e["source_tool"] != "check_account"]
    fake = {"schema": "kinlock.evidence/2", "evidence_id": "ev-forged", "intent_id": b4.intent_id, "producer": "account-reader", "source_tool": "check_account", "request_hash": "x", "response_hash": "y", "observed_at": clock(), "parent_evidence": []}
    fake["signature"] = mac(b"swarm-made-up-key-32-bytes-long!!", evidence_unsigned(fake))
    b4.evidence.append(fake)
    msg = {"to": "Anna", "text": "Your Gmail recovery settings look fine."}
    attempts.append({"attempt": "Forge the account-check evidence", **_call(gw, "send_message", msg, b4.build(tool="send_message", arguments=msg, category="comms", verb="send_message", target="Anna"), "messenger")})

    # The legitimate step: the messenger, holding a narrowed token and real gateway-signed evidence.
    b5 = copy.deepcopy(planner).delegate("messenger", edge_id="planner-messenger")
    legit = _call(gw, "send_message", msg, b5.build(tool="send_message", arguments=msg, category="comms", verb="send_message", target="Anna"), "messenger")

    return {
        "name": "compromised_swarm",
        "headline": "Four forgery attempts, zero commit tokens. The legitimate message still commits.",
        "root_intent": task,
        "intent": {"intent_id": token["root"]["intent_id"], "channel": "voice", "scope": token["root"]["scope"], "required_evidence": token["root"]["required_evidence"], "max_effects": token["root"]["max_effects"]},
        "reads": reads,
        "attempts": attempts,
        "legitimate": legit,
        "forgeries_committed": sum(a["downstream_executed"] for a in attempts),
        "downstream_calls": [c for c in ds.calls if c[0] not in {t.name for t in READ_TOOLS}],
        "receipt_chain_ok": engine.chain.verify().ok,
    }


def verified_safe_transaction() -> dict:
    engine, gw, ds, tmp, clock = _world()
    token = engine.mint_intent(
        purpose="Tell Anna my verified appointment time.",
        scope=AuthorityScope(tools=("send_message",), categories=("comms",), verbs=("send_message",), targets=("Anna",), max_amount_cents=0, max_delegation_depth=1),
        channel="voice",
        max_effects=1,
        required_evidence=("calendar_lookup",),
    )
    b = CertificateBuilder(token, clock=clock)
    _read(gw, b, "calendar_lookup", {"day": "today"}, "calendar-agent")
    b.delegate("messenger", edge_id="owner-messenger")
    msg = {"to": "Anna", "text": "Your appointment is at 3 PM."}
    cert = b.build(tool="send_message", arguments=msg, category="comms", verb="send_message", target="Anna", nonce="safe-cert")
    first = _call(gw, "send_message", msg, cert, "messenger")

    # Restart: same data directory, fresh process state. The nonce is in the receipt chain.
    engine2, gw2, _, _, _ = _world(tmp, clock)
    replay = _call(gw2, "send_message", msg, cert, "messenger")
    # A fresh certificate from the same token: the intent allowed one effect, and it's spent.
    again = _call(gw2, "send_message", msg, b.build(tool="send_message", arguments=msg, category="comms", verb="send_message", target="Anna"), "messenger")
    return {
        "name": "verified_safe_transaction",
        "first": first,
        "replay_after_restart": replay,
        "second_effect_past_budget": again,
        "downstream_calls": ds.calls[-1:] if first["downstream_executed"] else [],
        "commit_gate": engine.downstream.consumed,
        "receipt_chain_ok": engine2.chain.verify().ok,
    }


def valid_proof_identity_change() -> dict:
    engine, gw, ds, _, clock = _world()
    scope = AuthorityScope(tools=("change_recovery_email",), categories=("identity",), verbs=("change_recovery_email",), targets=("Gmail",), max_amount_cents=0, max_delegation_depth=1)
    owner_token = engine.mint_intent(purpose="Change my Gmail recovery email to mary.backup@example.com.", scope=scope, channel="owner", ttl=3 * 86400)
    b = CertificateBuilder(owner_token, clock=clock).delegate("identity-worker", edge_id="owner-identity")
    args = {"account": "Gmail", "new_email": "mary.backup@example.com"}
    owner_path = _call(gw, "change_recovery_email", args, b.build(tool="change_recovery_email", arguments=args, category="identity", verb="change_recovery_email", target="Gmail"), "identity-worker")
    voice_token = engine.mint_intent(purpose="(by voice) Change my Gmail recovery email.", scope=scope, channel="voice")
    clamped = next(r.data["clamped"] for r in reversed(list(engine.chain.receipts())) if r.kind == "intent_minted")
    held = next((r.data for r in engine.chain.receipts() if r.kind == "held"), {})
    return {
        "name": "valid_proof_identity_change",
        "headline": "A valid proof is not authorization: Kinlock still requires the owner and a 24-hour cool-off.",
        "owner_surface": {**owner_path, "kinlock_reasons": held.get("reasons", []), "ready_after_hours": round((held.get("ready_at", clock()) - clock()) / 3600, 1)},
        "voice_request": {"granted_scope": voice_token["root"]["scope"], "clamped": clamped},
        "downstream_executed": owner_path["downstream_executed"],
    }


def run_all() -> dict:
    try:
        return {
            "schema": "kinlock.verified-causal-demo/2",
            "mode": "deterministic-local-no-model-calls",
            "scenarios": [compromised_swarm(), verified_safe_transaction(), valid_proof_identity_change()],
        }
    finally:
        while _TEMP:
            shutil.rmtree(_TEMP.pop(), ignore_errors=True)


def _line(c: dict) -> str:
    t = c["theustad"]
    s = f"THEUSTAD {'PASS' if t['ok'] else 'FAIL'} | Kinlock {c['kinlock_outcome']} | token {'issued' if c['commit_token_issued'] else 'none'} | executed {c['downstream_executed']}"
    return s + ("" if t["ok"] else f"\n      - {t['problems'][0]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    out = run_all()
    if a.json:
        print(json.dumps(out, indent=2, sort_keys=True))
        return
    swarm, safe, ident = out["scenarios"]
    print("\n=== A. compromised swarm ===\n" + swarm["headline"])
    for x in swarm["attempts"]:
        print(f"  {x['attempt']}: {_line(x)}")
    print(f"  Legitimate message: {_line(swarm['legitimate'])}")
    print("\n=== B. verified safe transaction ===")
    for k in ("first", "replay_after_restart", "second_effect_past_budget"):
        print(f"  {k}: {_line(safe[k])}")
    print("\n=== C. valid proof, identity change ===\n" + ident["headline"])
    print(f"  owner surface: {_line(ident['owner_surface'])}")
    print(f"  by voice, clamped: {ident['voice_request']['clamped']}")


if __name__ == "__main__":
    main()
