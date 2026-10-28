"""Public source-locked copy of AgentFleet's Kinlock authority adapter.

Canonical upstream during the hackathon:
  YashwanthGathuku/agent-orchestration-os@df242cacc055686e9214f371962b6a9a866dfff9
  python/fleet/causal_authority.py blob 9359a4932ca10c01e5e196d8aab8a6e39f62af01

AgentFleet owns orchestration, not final authorization. This adapter exports the
causal ancestry behind a proposed external effect as `kinlock.verified-action/1`.
Its output remains untrusted and must be independently checked by THEUSTAD before
Kinlock may commit the effect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

SCHEMA = "kinlock.verified-action/1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _subset(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    c, p = set(child), set(parent)
    if "*" in p:
        return True
    if "*" in c:
        return False
    return c.issubset(p)


@dataclass(frozen=True)
class AuthorityScope:
    tools: tuple[str, ...]
    categories: tuple[str, ...]
    verbs: tuple[str, ...]
    targets: tuple[str, ...]
    max_amount_cents: int | None = None
    max_delegation_depth: int = 0
    expires_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": list(self.tools),
            "categories": list(self.categories),
            "verbs": list(self.verbs),
            "targets": list(self.targets),
            "max_amount_cents": self.max_amount_cents,
            "max_delegation_depth": self.max_delegation_depth,
            "expires_at": self.expires_at,
        }

    def attenuates(self, parent: "AuthorityScope") -> bool:
        if not all(
            _subset(getattr(self, field), getattr(parent, field))
            for field in ("tools", "categories", "verbs", "targets")
        ):
            return False
        if parent.max_amount_cents is not None:
            if self.max_amount_cents is None or self.max_amount_cents > parent.max_amount_cents:
                return False
        if self.max_delegation_depth > parent.max_delegation_depth:
            return False
        if parent.expires_at is not None:
            if self.expires_at is None or self.expires_at > parent.expires_at:
                return False
        return True


class AuthorityAmplification(ValueError):
    pass


class CausalCertificateBuilder:
    """Build a compact authority path for one consequential AgentFleet effect."""

    def __init__(
        self,
        *,
        principal: str,
        purpose: str,
        scope: AuthorityScope,
        evidence_key: bytes,
        now: float | None = None,
        ttl_seconds: float = 300.0,
        intent_id: str | None = None,
    ) -> None:
        if not evidence_key:
            raise ValueError("evidence_key is required")
        self.now = time.time() if now is None else now
        self.evidence_key = evidence_key
        self.root_scope = scope
        self.current_scope = scope
        self.current_subject = principal
        self.root_expiry = min(
            self.now + ttl_seconds,
            scope.expires_at if scope.expires_at is not None else self.now + ttl_seconds,
        )
        self.root = {
            "intent_id": intent_id or "intent_" + secrets.token_hex(6),
            "principal": principal,
            "purpose": purpose,
            "issued_at": self.now,
            "expires_at": self.root_expiry,
            "scope": scope.to_dict(),
            "nonce": secrets.token_hex(12),
        }
        self.delegations: list[dict[str, Any]] = []
        self.evidence: list[dict[str, Any]] = []

    def delegate(
        self,
        child: str,
        scope: AuthorityScope,
        *,
        ttl_seconds: float | None = None,
        edge_id: str | None = None,
    ) -> "CausalCertificateBuilder":
        if len(self.delegations) >= self.root_scope.max_delegation_depth:
            raise AuthorityAmplification("delegation depth exceeds root authority")
        if not scope.attenuates(self.current_scope):
            raise AuthorityAmplification("child scope must be a subset of parent authority")
        expiry = min(
            self.root_expiry,
            self.now + (ttl_seconds if ttl_seconds is not None else self.root_expiry - self.now),
            scope.expires_at if scope.expires_at is not None else self.root_expiry,
        )
        edge = {
            "edge_id": edge_id or "edge_" + secrets.token_hex(6),
            "parent": self.current_subject,
            "child": child,
            "scope": scope.to_dict(),
            "issued_at": self.now,
            "expires_at": expiry,
            "nonce": secrets.token_hex(12),
        }
        self.delegations.append(edge)
        self.current_subject = child
        self.current_scope = scope
        return self

    def add_evidence(
        self,
        *,
        producer: str,
        source_tool: str,
        request: Any,
        response: Any,
        parent_evidence: tuple[str, ...] = (),
        evidence_id: str | None = None,
        integrity: str = "trusted",
        confidentiality: str = "private",
    ) -> str:
        known = {e["evidence_id"] for e in self.evidence}
        if any(parent not in known for parent in parent_evidence):
            raise ValueError("parent evidence must already exist in the causal trace")
        eid = evidence_id or "ev_" + secrets.token_hex(6)
        unsigned = {
            "evidence_id": eid,
            "producer": producer,
            "source_tool": source_tool,
            "request_hash": sha256(request),
            "response_hash": sha256(response),
            "observed_at": self.now,
            "parent_evidence": list(parent_evidence),
            "integrity": integrity,
            "confidentiality": confidentiality,
        }
        unsigned["signature"] = hmac.new(
            self.evidence_key, canonical_json(unsigned), hashlib.sha256
        ).hexdigest()
        self.evidence.append(unsigned)
        return eid

    def build(
        self,
        *,
        request_id: str,
        action_digest: str,
        tool: str,
        arguments: dict[str, Any],
        category: str,
        verb: str,
        target: str,
        amount_cents: int = 0,
        required_evidence: tuple[str, ...] = (),
        not_before: float | None = None,
        expires_at: float | None = None,
        required_facts: tuple[str, ...] = (),
        forbidden_facts: tuple[str, ...] = (),
        facts: tuple[str, ...] = (),
        nonce: str | None = None,
    ) -> dict[str, Any]:
        if any(eid not in {e["evidence_id"] for e in self.evidence} for eid in required_evidence):
            raise ValueError("required evidence was not produced by this causal trace")
        return {
            "schema": SCHEMA,
            "root": self.root,
            "delegations": list(self.delegations),
            "evidence": list(self.evidence),
            "effect": {
                "request_id": request_id,
                "actor": self.current_subject,
                "action_digest": action_digest,
                "tool": tool,
                "arguments": dict(arguments),
                "category": category,
                "verb": verb,
                "target": target,
                "amount_cents": amount_cents,
                "required_evidence": list(required_evidence),
                "proposed_at": self.now,
            },
            "temporal": {
                "not_before": not_before,
                "expires_at": expires_at,
                "required_facts": list(required_facts),
                "forbidden_facts": list(forbidden_facts),
            },
            "facts": list(facts),
            "created_at": self.now,
            "nonce": nonce or secrets.token_hex(12),
        }
