# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yashwanth Gathuku
"""The untrusted side of Verified Causal Commit: building a certificate from an intent token.

An agent or orchestrator holds an *intent token* that Kinlock minted for the
owner's task: ``{"root", "edges", "sig"}``. It holds no key. With the token it can

* delegate: append an edge that narrows the scope (``sig' = HMAC(sig, edge)``);
* collect evidence records that Kinlock's gateway signed for this intent; and
* build a ``kinlock.verified-action/2`` certificate for one proposed call.

It cannot widen the root, drop or reorder an edge, or sign evidence: the verifier
recomputes the chain from ``K_intent`` and checks evidence with ``K_evidence``,
both of which stay inside Kinlock. Nothing here is trusted; the local checks only
save a round trip.
"""

from __future__ import annotations

import copy
import secrets
import time
from typing import Any

from .theustad_verifier import SCHEMA, chain_mac, scope_attenuates


def extend(token: dict[str, Any], edge: dict[str, Any]) -> dict[str, Any]:
    """Append one caveat edge. Anyone holding ``token`` can do this; nobody can undo it."""
    out = copy.deepcopy(token)
    out["edges"] = list(out.get("edges") or []) + [copy.deepcopy(edge)]
    out["sig"] = chain_mac(str(token["sig"]), edge)
    return out


class CertificateBuilder:
    def __init__(self, token: dict[str, Any], *, clock=time.time):
        self.token = copy.deepcopy(token)
        self.clock = clock
        self.evidence: list[dict[str, Any]] = []

    @property
    def intent_id(self) -> str:
        return str(self.token["root"]["intent_id"])

    @property
    def subject(self) -> str:
        edges = self.token.get("edges") or []
        return str(edges[-1]["child"]) if edges else str(self.token["root"]["principal"])

    @property
    def scope(self) -> dict[str, Any]:
        edges = self.token.get("edges") or []
        return copy.deepcopy(edges[-1]["scope"] if edges else self.token["root"]["scope"])

    def _expiry(self) -> float:
        edges = self.token.get("edges") or []
        return float(edges[-1]["expires_at"] if edges else self.token["root"]["expires_at"])

    def delegate(self, child: str, scope: dict[str, Any] | None = None, *, ttl: float | None = None, edge_id: str | None = None) -> "CertificateBuilder":
        now = self.clock()
        parent_scope = self.scope
        new_scope = copy.deepcopy(parent_scope if scope is None else scope)
        depth = int(parent_scope.get("max_delegation_depth", 0))
        new_scope.setdefault("max_delegation_depth", max(0, depth - 1))
        if scope is None:
            new_scope["max_delegation_depth"] = max(0, depth - 1)
        expires = self._expiry() if ttl is None else min(self._expiry(), now + ttl)
        if new_scope.get("expires_at") is None or float(new_scope["expires_at"]) > expires:
            new_scope["expires_at"] = expires
        problems = scope_attenuates(new_scope, parent_scope)
        if problems:
            raise ValueError("a delegation can only narrow authority: " + ", ".join(problems))
        edge = {
            "edge_id": edge_id or "edge_" + secrets.token_hex(6),
            "parent": self.subject,
            "child": child,
            "scope": new_scope,
            "issued_at": now,
            "expires_at": expires,
            "nonce": secrets.token_hex(12),
        }
        self.token = extend(self.token, edge)
        return self

    def add_evidence(self, record: dict[str, Any] | None) -> None:
        """Keep a gateway-signed evidence record. The builder can't make one itself."""
        if record and record.get("intent_id") == self.intent_id:
            self.evidence.append(copy.deepcopy(record))

    def build(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        category: str,
        verb: str,
        target: str,
        amount_cents: int = 0,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "intent": copy.deepcopy(self.token),
            "evidence": copy.deepcopy(self.evidence),
            "effect": {
                "actor": self.subject,
                "tool": tool,
                "arguments": dict(arguments),
                "category": category,
                "verb": verb,
                "target": target,
                "amount_cents": int(amount_cents),
            },
            "created_at": self.clock(),
            "nonce": nonce or "cert_" + secrets.token_hex(12),
        }
