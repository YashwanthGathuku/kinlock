# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yashwanth Gathuku
"""The trusted side of Verified Causal Commit (protocol ``kinlock.verified-action/2``).

Everything here runs inside the Kinlock host and is the only code that touches a key:

* ``IntentMinter`` signs the root of an owner's intent with ``K_intent``.
* ``EvidenceSigner`` signs what a read-only tool returned, at the gateway, with
  ``K_evidence``, bound to the intent it was read for.
* ``VerifiedExecutionGuard`` derives the effect from the call Kinlock is about to
  run, asks the THEUSTAD verifier (``theustad_verifier``) to check the certificate
  against it, and issues a commit token bound to that exact call.
* ``CommitGate`` wraps the downstream. It refuses any call that doesn't come with
  an unused, unexpired token bound to exactly that tool and those arguments, so
  the token is the boundary, not a receipt.

Three keys are derived from Kinlock's signing key, one per purpose; the agent
side never receives any of them.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from .theustad_verifier import (
    EVIDENCE_SCHEMA,
    INTENT_SCHEMA,
    DerivedEffect,
    Verdict,
    call_digest,
    digest,
    evidence_unsigned,
    mac,
    norm,
    verify_certificate,
)

__all__ = [
    "AuthorityScope",
    "CommitGate",
    "CommitToken",
    "CommitTokenIssuer",
    "DerivedEffect",
    "EvidenceSigner",
    "IntentMinter",
    "Keys",
    "TemporalContract",
    "VerificationError",
    "VerifiedExecutionGuard",
    "derive_keys",
]


class VerificationError(RuntimeError):
    def __init__(self, message: str, problems: tuple[str, ...] = ()):
        super().__init__(message)
        self.problems = tuple(problems) or (message,)


@dataclass(frozen=True)
class Keys:
    intent: bytes
    evidence: bytes
    commit: bytes


def derive_keys(signing_key: bytes) -> Keys:
    if not signing_key:
        raise ValueError("signing key is required")

    def sub(label: str) -> bytes:
        return hmac.new(signing_key, b"kinlock/verified-commit/v2/" + label.encode(), hashlib.sha256).digest()

    return Keys(sub("intent"), sub("evidence"), sub("commit"))


# -- scopes and contracts (plain data; the verifier reads them as dicts) ---------------------------
@dataclass(frozen=True)
class AuthorityScope:
    tools: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    verbs: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    max_amount_cents: int | None = 0
    max_delegation_depth: int = 1
    expires_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": list(self.tools),
            "categories": list(self.categories),
            "verbs": list(self.verbs),
            "targets": list(self.targets),
            "max_amount_cents": self.max_amount_cents,
            "max_delegation_depth": int(self.max_delegation_depth),
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class TemporalContract:
    not_before: float | None = None
    required_facts: tuple[str, ...] = ()
    forbidden_facts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"not_before": self.not_before, "required_facts": list(self.required_facts), "forbidden_facts": list(self.forbidden_facts)}


# -- minting -------------------------------------------------------------------------------------
class IntentMinter:
    """Signs the root of an intent token. Only Kinlock holds this."""

    def __init__(self, key: bytes, kid: str = "kinlock-intent-1"):
        if not key:
            raise ValueError("intent key is required")
        self._key = key
        self.kid = kid

    def mint(
        self,
        *,
        principal: str,
        purpose: str,
        scope: AuthorityScope,
        channel: str,
        now: float,
        ttl: float = 600.0,
        max_effects: int = 1,
        required_evidence: tuple[str, ...] = (),
        temporal: TemporalContract = TemporalContract(),
        intent_id: str | None = None,
    ) -> dict[str, Any]:
        expires = now + ttl
        sc = scope.to_dict()
        if sc["expires_at"] is None or float(sc["expires_at"]) > expires:
            sc["expires_at"] = expires
        root = {
            "schema": INTENT_SCHEMA,
            "kid": self.kid,
            "intent_id": intent_id or "intent_" + secrets.token_hex(8),
            "principal": principal,
            "purpose": purpose[:500],
            "channel": channel,
            "issued_at": now,
            "expires_at": expires,
            "scope": sc,
            "max_effects": max(1, int(max_effects)),
            "required_evidence": list(required_evidence),
            "temporal": temporal.to_dict(),
            "nonce": secrets.token_hex(12),
        }
        return {"root": root, "edges": [], "sig": mac(self._key, root)}


class EvidenceSigner:
    """Signs read-only tool results at the gateway. The agent side gets records, not the key."""

    def __init__(self, key: bytes):
        if not key:
            raise ValueError("evidence key is required")
        self._key = key

    def sign(
        self,
        *,
        intent_id: str,
        producer: str,
        source_tool: str,
        request: Any,
        response: Any,
        observed_at: float,
        parent_evidence: tuple[str, ...] = (),
        evidence_id: str | None = None,
    ) -> dict[str, Any]:
        record = {
            "schema": EVIDENCE_SCHEMA,
            "evidence_id": evidence_id or "ev_" + secrets.token_hex(6),
            "intent_id": intent_id,
            "producer": producer,
            "source_tool": source_tool,
            "request_hash": digest(request),
            "response_hash": digest(response),
            "observed_at": observed_at,
            "parent_evidence": list(parent_evidence),
        }
        record["signature"] = mac(self._key, evidence_unsigned(record))
        return record


# -- commit tokens and the gate ----------------------------------------------------------------------
@dataclass(frozen=True)
class CommitToken:
    token_id: str
    call_digest: str
    basis: str  # "certificate:<nonce>" or "approval:<cap_id>"
    issued_at: float
    expires_at: float
    signature: str = ""

    def unsigned(self) -> dict[str, Any]:
        return {"token_id": self.token_id, "call_digest": self.call_digest, "basis": self.basis, "issued_at": self.issued_at, "expires_at": self.expires_at}

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "signature": self.signature}


class CommitTokenIssuer:
    def __init__(self, key: bytes, ttl_seconds: float = 30.0):
        if not key:
            raise ValueError("commit key is required")
        self._key = key
        self.ttl_seconds = ttl_seconds

    def issue(self, call_dg: str, basis: str, now: float) -> CommitToken:
        t = CommitToken("commit_" + secrets.token_hex(8), call_dg, basis, now, now + self.ttl_seconds)
        return replace(t, signature=mac(self._key, t.unsigned()))

    def check(self, token: CommitToken, call_dg: str, now: float) -> None:
        if not hmac.compare_digest(token.signature, mac(self._key, token.unsigned())):
            raise VerificationError("invalid commit token signature")
        if token.call_digest != call_dg:
            raise VerificationError("commit token is bound to a different call")
        if now > token.expires_at:
            raise VerificationError("commit token expired")


class CommitGate:
    """Wraps the real downstream: no valid single-use token for exactly this call, no call."""

    def __init__(self, inner: Any, issuer: CommitTokenIssuer, clock: Callable[[], float]):
        self.inner = inner
        self.issuer = issuer
        self.clock = clock
        self._armed: CommitToken | None = None
        self._used: set[str] = set()
        self._lock = threading.RLock()
        self.consumed: list[dict[str, Any]] = []  # for the demo trace

    def list_tools(self):
        return self.inner.list_tools()

    def arm(self, token: CommitToken) -> None:
        with self._lock:
            self._armed = token

    def disarm(self) -> None:
        with self._lock:
            self._armed = None

    def call(self, name: str, arguments: dict[str, Any]) -> str:
        from .downstream import DownstreamError

        with self._lock:
            token, self._armed = self._armed, None
            if token is None:
                raise DownstreamError("commit gate: no commit token for this call")
            try:
                if token.token_id in self._used:
                    raise VerificationError("commit token replay")
                self.issuer.check(token, call_digest(name, arguments), self.clock())
            except VerificationError as e:
                raise DownstreamError(f"commit gate: {e}") from e
            self._used.add(token.token_id)
            self.consumed.append({"token_id": token.token_id, "basis": token.basis, "tool": name})
        return self.inner.call(name, arguments)


# -- the guard ---------------------------------------------------------------------------------------
def _intent_id(cert: Any) -> str:
    """Best-effort read for looking up state; the verifier itself rejects anything malformed."""
    intent = cert.get("intent") if isinstance(cert, dict) else None
    root = intent.get("root") if isinstance(intent, dict) else None
    return str(root.get("intent_id") or "") if isinstance(root, dict) else ""

@dataclass
class VerifiedExecutionGuard:
    keys: Keys
    issuer: CommitTokenIssuer
    state_facts: Callable[[str], frozenset[str]] = lambda intent_id: frozenset()
    consumed: Callable[[str], bool] = lambda nonce: False
    effects_used: Callable[[str], int] = lambda intent_id: 0
    max_clock_skew: float = 5.0
    _staged: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    # staging
    def stage(self, request_id: str, certificate: dict[str, Any]) -> None:
        with self._lock:
            if request_id in self._staged:
                raise VerificationError("a certificate is already staged for this request")
            self._staged[request_id] = copy.deepcopy(certificate)

    def staged(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._staged.get(request_id)

    def discard(self, request_id: str) -> None:
        with self._lock:
            self._staged.pop(request_id, None)

    # binding
    @staticmethod
    def derive(action: Any, call: dict[str, Any], tool_map: Any) -> DerivedEffect:
        """The effect, computed by Kinlock from the call it will run, never taken from the certificate.

        The decided action and the call must describe the same thing: the call is mapped
        through the gateway's tool map and compared with the action Kinlock evaluated.
        """
        if tool_map is None:
            raise VerificationError("no tool map: Kinlock can't derive what this call does")
        tool = str(call.get("tool") or "")
        arguments = dict(call.get("arguments") or {})
        mapped = tool_map.action_for(tool, arguments)
        for f in ("category", "verb", "target"):
            if norm(getattr(mapped, f)) != norm(getattr(action, f)):
                raise VerificationError(f"the call's {f} ({getattr(mapped, f)!r}) does not match the action Kinlock decided ({getattr(action, f)!r})")
        if int(mapped.amount_cents) != int(action.amount_cents):
            raise VerificationError("the call's amount does not match the action Kinlock decided")
        return DerivedEffect(tool, arguments, action.category, action.verb, action.target, int(action.amount_cents))

    def _verify(self, cert: dict[str, Any], derived: DerivedEffect, now: float) -> Verdict:
        intent_id = _intent_id(cert)
        v = verify_certificate(
            cert,
            intent_key=self.keys.intent,
            evidence_key=self.keys.evidence,
            now=now,
            derived=derived,
            state_facts=self.state_facts(intent_id) if intent_id else frozenset(),
            effects_used=self.effects_used(intent_id) if intent_id else 0,
            max_clock_skew=self.max_clock_skew,
        )
        if v.nonce and self.consumed(v.nonce):
            # Read from Kinlock's receipt chain, so a restart doesn't forget it.
            return replace(v, ok=False, problems=("certificate replay: this certificate already committed",) + v.problems)
        return v

    def preview(self, request_id: str, action: Any, call: dict[str, Any] | None, tool_map: Any, now: float) -> Verdict:
        """Dry run for display: nothing is consumed and no token is issued."""
        cert = self.staged(request_id)
        if cert is None:
            return Verdict(False, (), ("no certificate was staged for this request",))
        if call is None:
            return Verdict(False, (), ("no concrete downstream call",))
        try:
            derived = self.derive(action, call, tool_map)
        except VerificationError as e:
            return Verdict(False, (), (str(e),))
        return self._verify(cert, derived, now)

    def authorize(self, request_id: str, action: Any, call: dict[str, Any], tool_map: Any, now: float) -> tuple[Verdict, CommitToken]:
        with self._lock:
            cert = self._staged.get(request_id)
            if cert is None:
                raise VerificationError("no proof-carrying certificate was staged for this request")
            derived = self.derive(action, call, tool_map)
            v = self._verify(cert, derived, now)
            if not v.ok:
                raise VerificationError("; ".join(v.problems), v.problems)
            self._staged.pop(request_id, None)
            return v, self.issuer.issue(derived.call_digest, f"certificate:{v.nonce}", now)

    def authorize_approval(self, cap_id: str, action: Any, call: dict[str, Any], tool_map: Any, now: float) -> CommitToken:
        """A held action released by an exact-action approval capability (already verified by the engine)."""
        derived = self.derive(action, call, tool_map)
        return self.issuer.issue(derived.call_digest, f"approval:{cap_id}", now)
