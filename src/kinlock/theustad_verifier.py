# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yashwanth Gathuku
"""THEUSTAD causal-commit verifier, protocol ``kinlock.verified-action/2``.

This module is the planner-independent checker. It imports nothing from Kinlock's
planner, agent loop or policy engine: it takes a serialized certificate, the two
verification keys, the clock, the effect Kinlock *derived* from the call it is
about to execute, and a few facts read from Kinlock's own state.

What changed from v1, and why
-----------------------------
v1 verified a document the untrusted side wrote: an unsigned root intent,
unsigned delegation edges, self-declared effect metadata, builder-chosen temporal
facts and required evidence, and evidence signed with a key the builder held.
Every check was about internal consistency, so a consistent forgery passed.

v2 moves every trust anchor to the trusted side:

* **Root.** The root intent is minted by Kinlock and MACed with ``K_intent``:
  ``sig_0 = HMAC(K_intent, root)``. A root the builder edits, or signs with its
  own key, fails.
* **Delegation is a caveat chain** (the Macaroons construction, Birgisson et al.,
  NDSS 2014): ``sig_i = HMAC(sig_{i-1}, edge_i)``. Holding a token lets you
  append a narrower edge; without ``K_intent`` you can't widen the root, drop
  an edge, or reorder the chain, because the verifier recomputes ``sig_n``.
  Each edge must still attenuate its parent.
* **Derived, not declared.** Scope is checked against the tool, arguments,
  category, verb, target and amount Kinlock derived from the call it will
  execute. The certificate's copies must match, or it is refused.
* **Rules ride in the signed root.** Required evidence kinds, ``not_before``,
  required and forbidden facts, and the effect budget are covered by ``sig_0``.
* **Evidence** is signed by Kinlock's gateway with ``K_evidence`` and bound to
  the intent id. The builder never holds that key.
* **State facts** (revocation, safety lock) and the effect budget come from
  Kinlock's receipt chain, passed in by the caller.

The function never raises on malformed input: anything it can't parse is a
problem, and a problem means no commit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Iterable

SCHEMA = "kinlock.verified-action/2"
INTENT_SCHEMA = "kinlock.intent/2"
EVIDENCE_SCHEMA = "kinlock.evidence/2"
VERIFIER = "theustad.causal-commit/2"
REVOKED_FACT = "intent_revoked"

SCOPE_SETS = ("tools", "categories", "verbs", "targets")


# -- canonical encoding --------------------------------------------------------------------
def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def mac(key: bytes, value: Any) -> str:
    return hmac.new(key, canonical_json(value), hashlib.sha256).hexdigest()


def chain_mac(sig_hex: str, edge: dict[str, Any]) -> str:
    """One caveat step: the previous signature is the key for the next."""
    return hmac.new(bytes.fromhex(sig_hex), canonical_json(edge), hashlib.sha256).hexdigest()


def norm(value: Any) -> str:
    return " ".join(str(value).casefold().split())


# -- scopes --------------------------------------------------------------------------------
def _set(value: Any) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or value is None:
        # A bare string would otherwise iterate into characters; treat it as malformed.
        raise ValueError("scope sets must be lists")
    return frozenset(norm(v) for v in value)


def scope_attenuates(child: dict[str, Any], parent: dict[str, Any]) -> list[str]:
    """Problems if ``child`` is not a subset of ``parent`` on every axis."""
    problems: list[str] = []
    for f in SCOPE_SETS:
        c, p = _set(child.get(f, [])), _set(parent.get(f, []))
        if "*" in p:
            continue
        if "*" in c or not c <= p:
            problems.append(f"{f} widened")
    p_amt, c_amt = parent.get("max_amount_cents"), child.get("max_amount_cents")
    if p_amt is not None and (c_amt is None or int(c_amt) > int(p_amt)):
        problems.append("amount ceiling widened")
    if int(child.get("max_delegation_depth", 0)) > int(parent.get("max_delegation_depth", 0)):
        problems.append("delegation depth widened")
    p_exp, c_exp = parent.get("expires_at"), child.get("expires_at")
    if p_exp is not None and (c_exp is None or float(c_exp) > float(p_exp)):
        problems.append("lifetime widened")
    return problems


def _allows(values: Any, value: str) -> bool:
    allowed = _set(values)
    return "*" in allowed or norm(value) in allowed


# -- the effect Kinlock derived from the call it is about to run -----------------------------
@dataclass(frozen=True)
class DerivedEffect:
    tool: str
    arguments: dict[str, Any]
    category: str
    verb: str
    target: str
    amount_cents: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "category": self.category,
            "verb": self.verb,
            "target": self.target,
            "amount_cents": int(self.amount_cents),
        }

    @property
    def call_digest(self) -> str:
        """What the commit token binds to: exactly the downstream call that will run."""
        return call_digest(self.tool, self.arguments)


def call_digest(tool: str, arguments: dict[str, Any]) -> str:
    return digest({"tool": tool, "arguments": dict(arguments)})


# -- evidence ------------------------------------------------------------------------------
EVIDENCE_FIELDS = (
    "schema",
    "evidence_id",
    "intent_id",
    "producer",
    "source_tool",
    "request_hash",
    "response_hash",
    "observed_at",
    "parent_evidence",
)


def evidence_unsigned(record: dict[str, Any]) -> dict[str, Any]:
    out = {f: record.get(f) for f in EVIDENCE_FIELDS}
    out["parent_evidence"] = list(record.get("parent_evidence") or [])
    return out


def evidence_signature_ok(record: dict[str, Any], key: bytes) -> bool:
    sig = str(record.get("signature") or "")
    return bool(sig) and hmac.compare_digest(sig, mac(key, evidence_unsigned(record)))


# -- verdict -------------------------------------------------------------------------------
@dataclass(frozen=True)
class Verdict:
    ok: bool
    checks: tuple[str, ...]
    problems: tuple[str, ...]
    certificate_digest: str = ""
    call_digest: str = ""
    intent_id: str = ""
    nonce: str = ""
    verifier: str = VERIFIER

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": list(self.checks),
            "problems": list(self.problems),
            "certificate_digest": self.certificate_digest,
            "call_digest": self.call_digest,
            "intent_id": self.intent_id,
            "nonce": self.nonce,
            "verifier": self.verifier,
        }


def verify_certificate(
    certificate: Any,
    *,
    intent_key: bytes,
    evidence_key: bytes,
    now: float,
    derived: DerivedEffect | None,
    state_facts: Iterable[str] = (),
    effects_used: int = 0,
    max_clock_skew: float = 5.0,
) -> Verdict:
    if not intent_key or not evidence_key:
        raise ValueError("verification keys are required")
    try:
        return _verify(certificate, intent_key, evidence_key, now, derived, frozenset(state_facts), int(effects_used), max_clock_skew)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:  # malformed input fails closed
        return Verdict(False, (), (f"malformed certificate: {type(exc).__name__}",))


def _verify(cert: Any, k_intent: bytes, k_evidence: bytes, now: float, derived: DerivedEffect | None, state: frozenset[str], used: int, skew: float) -> Verdict:
    if not isinstance(cert, dict):
        raise TypeError("certificate must be an object")
    problems: list[str] = []
    checks: list[str] = []
    start = len(problems)

    def passed(name: str, since: int) -> None:
        if len(problems) == since:
            checks.append(name)

    # 0. envelope ------------------------------------------------------------------------
    if cert.get("schema") != SCHEMA:
        problems.append("unknown certificate schema")
    nonce = str(cert.get("nonce") or "")
    if not nonce:
        problems.append("certificate nonce is required")
    if float(cert.get("created_at") or 0.0) > now + skew:
        problems.append("certificate was created in the future")
    intent = cert.get("intent")
    if not isinstance(intent, dict):
        raise TypeError("intent token missing")
    root = intent.get("root")
    edges = intent.get("edges") or []
    if not isinstance(root, dict) or not isinstance(edges, list):
        raise TypeError("intent token malformed")
    intent_id = str(root.get("intent_id") or "")
    passed("envelope", start)

    # 1. root: minted by Kinlock --------------------------------------------------------------
    s = len(problems)
    sig0 = mac(k_intent, root)
    if root.get("schema") != INTENT_SCHEMA:
        problems.append("unknown intent schema")
    if not intent_id or not root.get("principal"):
        problems.append("root intent identity is incomplete")
    scope = root.get("scope")
    if not isinstance(scope, dict):
        raise TypeError("root scope missing")
    root_exp = float(root.get("expires_at") or 0.0)
    if float(root.get("issued_at") or 0.0) > now + skew:
        problems.append("root intent was issued in the future")
    if now > root_exp:
        problems.append("root intent expired")
    if scope.get("expires_at") is not None and float(scope["expires_at"]) > root_exp:
        problems.append("root scope outlives root intent")
    passed("root_intent_time", s)

    # 2. caveat chain: recompute sig_n from K_intent -------------------------------------------
    s = len(problems)
    sig = sig0
    for e in edges:
        if not isinstance(e, dict):
            raise TypeError("edge must be an object")
        sig = chain_mac(sig, e)
    if not hmac.compare_digest(str(intent.get("sig") or ""), sig):
        problems.append("intent chain signature does not verify: the root or a delegation edge was forged, edited, removed or reordered")
    passed("kinlock_signed_intent_chain", s)

    # 3. authority conservation along the (now authenticated) edges ------------------------------
    s = len(problems)
    subject, current, parent_exp = str(root["principal"]), scope, root_exp
    if len(edges) > int(scope.get("max_delegation_depth", 0)):
        problems.append("delegation depth exceeds root authority")
    seen_edges: set[str] = set()
    seen_subjects = {subject}
    for e in edges:
        eid, child = str(e.get("edge_id") or ""), str(e.get("child") or "")
        if not eid or eid in seen_edges:
            problems.append("duplicate or missing delegation edge id")
        seen_edges.add(eid)
        if str(e.get("parent") or "") != subject:
            problems.append(f"delegation {eid or '?'} does not continue the authority path")
        if not child or child in seen_subjects:
            problems.append("delegation cycle or missing child")
        seen_subjects.add(child)
        cscope = e.get("scope")
        if not isinstance(cscope, dict):
            raise TypeError("edge scope missing")
        for p in scope_attenuates(cscope, current):
            problems.append(f"delegation {eid or '?'} amplifies authority ({p})")
        e_exp = float(e.get("expires_at") or 0.0)
        if float(e.get("issued_at") or 0.0) > now + skew:
            problems.append(f"delegation {eid or '?'} was issued in the future")
        if e_exp > parent_exp:
            problems.append(f"delegation {eid or '?'} outlives its parent")
        if now > e_exp:
            problems.append(f"delegation {eid or '?'} expired")
        subject, current, parent_exp = child, cscope, e_exp
    passed("authority_conservation", s)

    # 4. the effect: derived by Kinlock, checked against the final scope -------------------------
    s = len(problems)
    effect = cert.get("effect")
    if not isinstance(effect, dict):
        raise TypeError("effect missing")
    if str(effect.get("actor") or "") != subject:
        problems.append("effect actor is not the end of the authenticated delegation path")
    if derived is None:
        problems.append("no derived effect: Kinlock did not bind this certificate to a concrete call")
        call_dg = ""
    else:
        call_dg = derived.call_digest
        declared = {k: effect.get(k) for k in ("tool", "arguments", "category", "verb", "target", "amount_cents")}
        want = derived.to_dict()
        for k in ("tool", "category", "verb", "target"):
            if norm(declared.get(k) or "") != norm(want[k]):
                problems.append(f"certificate {k} {declared.get(k)!r} does not match the call Kinlock will execute ({want[k]!r})")
        if dict(declared.get("arguments") or {}) != want["arguments"]:
            problems.append("certificate arguments do not match the call Kinlock will execute")
        if int(declared.get("amount_cents") or 0) != want["amount_cents"]:
            problems.append("certificate amount does not match the call Kinlock will execute")
        # Scope is judged on what Kinlock derived, never on what the certificate declares.
        for f, val in (("tools", want["tool"]), ("categories", want["category"]), ("verbs", want["verb"]), ("targets", want["target"])):
            if not _allows(current.get(f, []), val):
                problems.append(f"{f[:-1] if f != 'categories' else 'category'} {val!r} is outside the owner's intent")
        ceiling = current.get("max_amount_cents")
        if ceiling is not None and want["amount_cents"] > int(ceiling):
            problems.append("amount exceeds the owner's intent ceiling")
        if current.get("expires_at") is not None and now > float(current["expires_at"]):
            problems.append("authority scope expired")
    passed("effect_derived_and_within_intent", s)

    # 5. evidence: gateway-signed, bound to this intent, kinds required by the signed root ---------
    s = len(problems)
    valid_kinds: set[str] = set()
    seen: set[str] = set()
    for raw in cert.get("evidence") or []:
        if not isinstance(raw, dict):
            raise TypeError("evidence must be an object")
        eid = str(raw.get("evidence_id") or "")
        if not eid or eid in seen:
            problems.append("duplicate or missing evidence id")
            continue
        ok = True
        if raw.get("schema") != EVIDENCE_SCHEMA:
            problems.append(f"evidence {eid} has an unknown schema")
            ok = False
        if not evidence_signature_ok(raw, k_evidence):
            problems.append(f"evidence {eid} was not signed by Kinlock's gateway")
            ok = False
        if str(raw.get("intent_id") or "") != intent_id:
            problems.append(f"evidence {eid} belongs to a different intent")
            ok = False
        observed = float(raw.get("observed_at") or 0.0)
        if observed > now + skew:
            problems.append(f"evidence {eid} was observed in the future")
            ok = False
        for parent in raw.get("parent_evidence") or []:
            if parent not in seen:
                problems.append(f"evidence {eid} references unavailable parent evidence {parent}")
                ok = False
        seen.add(eid)
        if ok:
            valid_kinds.add(norm(raw.get("source_tool") or ""))
    missing = sorted(norm(k) for k in root.get("required_evidence") or [] if norm(k) not in valid_kinds)
    if missing:
        problems.append("required evidence missing: " + ", ".join(missing))
    passed("gateway_signed_evidence", s)

    # 6. temporal contract from the signed root + facts from Kinlock state ------------------------
    s = len(problems)
    temporal = root.get("temporal") or {}
    facts = {norm(f) for f in state} | valid_kinds
    if temporal.get("not_before") is not None and now < float(temporal["not_before"]):
        problems.append("temporal contract is not yet satisfied")
    req = sorted(norm(f) for f in temporal.get("required_facts") or [] if norm(f) not in facts)
    if req:
        problems.append("required facts missing: " + ", ".join(req))
    forbidden = sorted({norm(f) for f in temporal.get("forbidden_facts") or []} & facts)
    if norm(REVOKED_FACT) in facts:
        forbidden = sorted(set(forbidden) | {REVOKED_FACT})
    if forbidden:
        problems.append("forbidden facts present: " + ", ".join(forbidden))
    passed("temporal_contract_from_state", s)

    # 7. effect budget from the receipt chain ---------------------------------------------------
    s = len(problems)
    budget = int(root.get("max_effects", 1))
    if used >= budget:
        problems.append(f"intent effect budget used up ({used} of {budget})")
    passed("effect_budget", s)

    return Verdict(
        ok=not problems,
        checks=tuple(checks),
        problems=tuple(problems),
        certificate_digest=digest(cert),
        call_digest=call_dg,
        intent_id=intent_id,
        nonce=nonce,
    )
