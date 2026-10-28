"""Proof-carrying execution guard for consequential agent actions.

This module deliberately sits outside the LLM/agent control path.  An agent may
plan, delegate, retrieve evidence, and propose a tool call, but an external
checker must be able to derive a valid authority path before the downstream
call can run.

The first version is intentionally small and auditable.  It implements a linear
causal delegation chain (sufficient for the hackathon vertical slice) with:

* authority attenuation: a child scope must be a subset of its parent;
* cryptographically bound evidence provenance;
* temporal preconditions;
* proof binding to the exact Kinlock action digest and tool arguments; and
* a signed, single-use commit token consumed immediately before execution.

A later version can generalise the linear chain into a DAG without changing the
fail-closed boundary used by ``AgentActions._run_agent``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any

SCHEMA = "kinlock.verified-action/1"
VERIFIER = "theustad.causal-commit/1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _subset(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    """Return whether one explicit allow-set attenuates another.

    ``*`` is the only wildcard.  An empty tuple grants nothing.
    """

    c, p = set(child), set(parent)
    if "*" in p:
        return True
    if "*" in c:
        return False
    return c.issubset(p)


def _allows(allowed: tuple[str, ...], value: str) -> bool:
    return "*" in allowed or value in allowed


@dataclass(frozen=True)
class AuthorityScope:
    tools: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    verbs: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
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
        if not _subset(self.tools, parent.tools):
            return False
        if not _subset(self.categories, parent.categories):
            return False
        if not _subset(self.verbs, parent.verbs):
            return False
        if not _subset(self.targets, parent.targets):
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

    def permits(self, effect: "ProposedEffect", now: float) -> list[str]:
        problems: list[str] = []
        if self.expires_at is not None and now > self.expires_at:
            problems.append("authority scope expired")
        if not _allows(self.tools, effect.tool):
            problems.append(f"tool {effect.tool!r} is outside delegated authority")
        if not _allows(self.categories, effect.category):
            problems.append(f"category {effect.category!r} is outside delegated authority")
        if not _allows(self.verbs, effect.verb):
            problems.append(f"verb {effect.verb!r} is outside delegated authority")
        if not _allows(self.targets, effect.target):
            problems.append(f"target {effect.target!r} is outside delegated authority")
        if self.max_amount_cents is not None and effect.amount_cents > self.max_amount_cents:
            problems.append("effect exceeds delegated amount ceiling")
        return problems


@dataclass(frozen=True)
class RootIntent:
    intent_id: str
    principal: str
    purpose: str
    issued_at: float
    expires_at: float
    scope: AuthorityScope
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "principal": self.principal,
            "purpose": self.purpose,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope": self.scope.to_dict(),
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class Delegation:
    edge_id: str
    parent: str
    child: str
    scope: AuthorityScope
    issued_at: float
    expires_at: float
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "parent": self.parent,
            "child": self.child,
            "scope": self.scope.to_dict(),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    producer: str
    source_tool: str
    request_hash: str
    response_hash: str
    observed_at: float
    parent_evidence: tuple[str, ...] = ()
    integrity: str = "trusted"
    confidentiality: str = "private"
    signature: str = ""

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "producer": self.producer,
            "source_tool": self.source_tool,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "observed_at": self.observed_at,
            "parent_evidence": list(self.parent_evidence),
            "integrity": self.integrity,
            "confidentiality": self.confidentiality,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}


def sign_evidence(record: EvidenceRecord, key: bytes) -> EvidenceRecord:
    signature = hmac.new(key, canonical_json(record.unsigned_dict()), hashlib.sha256).hexdigest()
    return replace(record, signature=signature)


def verify_evidence(record: EvidenceRecord, key: bytes) -> bool:
    expected = hmac.new(key, canonical_json(record.unsigned_dict()), hashlib.sha256).hexdigest()
    return bool(record.signature) and hmac.compare_digest(record.signature, expected)


@dataclass(frozen=True)
class ProposedEffect:
    request_id: str
    actor: str
    action_digest: str
    tool: str
    arguments: dict[str, Any]
    category: str
    verb: str
    target: str
    amount_cents: int = 0
    required_evidence: tuple[str, ...] = ()
    proposed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "actor": self.actor,
            "action_digest": self.action_digest,
            "tool": self.tool,
            "arguments": self.arguments,
            "category": self.category,
            "verb": self.verb,
            "target": self.target,
            "amount_cents": self.amount_cents,
            "required_evidence": list(self.required_evidence),
            "proposed_at": self.proposed_at,
        }

    @property
    def effect_digest(self) -> str:
        return digest(self.to_dict())


@dataclass(frozen=True)
class TemporalContract:
    not_before: float | None = None
    expires_at: float | None = None
    required_facts: tuple[str, ...] = ()
    forbidden_facts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "required_facts": list(self.required_facts),
            "forbidden_facts": list(self.forbidden_facts),
        }


@dataclass(frozen=True)
class ActionCertificate:
    root: RootIntent
    delegations: tuple[Delegation, ...]
    evidence: tuple[EvidenceRecord, ...]
    effect: ProposedEffect
    temporal: TemporalContract = field(default_factory=TemporalContract)
    facts: tuple[str, ...] = ()
    created_at: float = 0.0
    nonce: str = ""
    schema: str = SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "root": self.root.to_dict(),
            "delegations": [d.to_dict() for d in self.delegations],
            "evidence": [e.to_dict() for e in self.evidence],
            "effect": self.effect.to_dict(),
            "temporal": self.temporal.to_dict(),
            "facts": list(self.facts),
            "created_at": self.created_at,
            "nonce": self.nonce,
        }

    @property
    def certificate_digest(self) -> str:
        return digest(self.to_dict())


@dataclass(frozen=True)
class VerificationReport:
    ok: bool
    certificate_digest: str
    effect_digest: str
    checks: tuple[str, ...]
    problems: tuple[str, ...]
    verifier: str = VERIFIER

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "certificate_digest": self.certificate_digest,
            "effect_digest": self.effect_digest,
            "checks": list(self.checks),
            "problems": list(self.problems),
            "verifier": self.verifier,
        }


class TheUstadVerifier:
    """Planner-independent verifier for one proof-carrying action certificate."""

    def __init__(self, evidence_key: bytes, max_clock_skew: float = 5.0):
        if not evidence_key:
            raise ValueError("evidence_key is required")
        self.evidence_key = evidence_key
        self.max_clock_skew = max_clock_skew

    def verify(self, cert: ActionCertificate, now: float | None = None) -> VerificationReport:
        now = time.time() if now is None else now
        problems: list[str] = []
        checks: list[str] = []

        if cert.schema != SCHEMA:
            problems.append("unknown certificate schema")
        if not cert.nonce:
            problems.append("certificate nonce is required")
        if cert.created_at > now + self.max_clock_skew:
            problems.append("certificate was created in the future")

        root = cert.root
        if root.issued_at > now + self.max_clock_skew:
            problems.append("root intent was issued in the future")
        if now > root.expires_at:
            problems.append("root intent expired")
        if root.scope.expires_at is not None and root.scope.expires_at > root.expires_at:
            problems.append("root scope outlives root intent")
        else:
            checks.append("root_intent_time")

        subject = root.principal
        scope = root.scope
        parent_expiry = root.expires_at
        if len(cert.delegations) > root.scope.max_delegation_depth:
            problems.append("delegation depth exceeds root authority")

        seen_edges: set[str] = set()
        seen_subjects: set[str] = {subject}
        for edge in cert.delegations:
            if edge.edge_id in seen_edges:
                problems.append("duplicate delegation edge")
            seen_edges.add(edge.edge_id)
            if edge.parent != subject:
                problems.append(f"delegation {edge.edge_id} does not continue the causal authority path")
            if edge.child in seen_subjects:
                problems.append("delegation cycle detected")
            seen_subjects.add(edge.child)
            if not edge.scope.attenuates(scope):
                problems.append(f"delegation {edge.edge_id} amplifies authority")
            if edge.issued_at > now + self.max_clock_skew:
                problems.append(f"delegation {edge.edge_id} was issued in the future")
            if edge.expires_at > parent_expiry:
                problems.append(f"delegation {edge.edge_id} outlives its parent")
            if now > edge.expires_at:
                problems.append(f"delegation {edge.edge_id} expired")
            subject = edge.child
            scope = edge.scope
            parent_expiry = edge.expires_at
        if not any("delegation" in p for p in problems):
            checks.append("authority_conservation")

        effect = cert.effect
        if effect.actor != subject:
            problems.append("effect actor has no complete delegation path to the root intent")
        problems.extend(scope.permits(effect, now))
        if not any("delegated authority" in p or "amount ceiling" in p or "scope expired" in p for p in problems):
            checks.append("effect_within_scope")

        evidence_by_id: dict[str, EvidenceRecord] = {}
        for record in cert.evidence:
            if record.evidence_id in evidence_by_id:
                problems.append("duplicate evidence id")
                continue
            evidence_by_id[record.evidence_id] = record
            if record.observed_at > now + self.max_clock_skew:
                problems.append(f"evidence {record.evidence_id} was observed in the future")
            if not verify_evidence(record, self.evidence_key):
                problems.append(f"evidence {record.evidence_id} has invalid provenance signature")
            for parent in record.parent_evidence:
                if parent not in evidence_by_id:
                    problems.append(f"evidence {record.evidence_id} references unavailable parent evidence {parent}")
        missing = sorted(set(effect.required_evidence) - set(evidence_by_id))
        if missing:
            problems.append("required evidence missing: " + ", ".join(missing))
        if not any("evidence" in p for p in problems):
            checks.append("bound_evidence_provenance")

        temporal = cert.temporal
        facts = set(cert.facts)
        if temporal.not_before is not None and now < temporal.not_before:
            problems.append("temporal contract is not yet satisfied")
        if temporal.expires_at is not None and now > temporal.expires_at:
            problems.append("temporal contract expired")
        missing_facts = sorted(set(temporal.required_facts) - facts)
        if missing_facts:
            problems.append("required temporal facts missing: " + ", ".join(missing_facts))
        forbidden = sorted(set(temporal.forbidden_facts) & facts)
        if forbidden:
            problems.append("forbidden temporal facts present: " + ", ".join(forbidden))
        if not any("temporal" in p for p in problems):
            checks.append("temporal_contract")

        return VerificationReport(
            ok=not problems,
            certificate_digest=cert.certificate_digest,
            effect_digest=effect.effect_digest,
            checks=tuple(checks),
            problems=tuple(problems),
        )


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommitToken:
    token_id: str
    certificate_digest: str
    effect_digest: str
    issued_at: float
    expires_at: float
    nonce: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "certificate_digest": self.certificate_digest,
            "effect_digest": self.effect_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}


class CommitTokenIssuer:
    """Issues and consumes commit tokens; every token is valid exactly once."""

    def __init__(self, key: bytes, ttl_seconds: float = 30.0):
        if not key:
            raise ValueError("commit key is required")
        self.key = key
        self.ttl_seconds = ttl_seconds
        self._used: set[str] = set()
        self._lock = threading.RLock()

    def issue(self, report: VerificationReport, now: float) -> CommitToken:
        if not report.ok:
            raise VerificationError("cannot issue a commit token for a failed proof")
        token = CommitToken(
            token_id="commit_" + secrets.token_hex(8),
            certificate_digest=report.certificate_digest,
            effect_digest=report.effect_digest,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            nonce=secrets.token_hex(12),
            signature="",
        )
        signature = hmac.new(self.key, canonical_json(token.unsigned_dict()), hashlib.sha256).hexdigest()
        return replace(token, signature=signature)

    def consume(self, token: CommitToken, effect_digest: str, now: float) -> None:
        with self._lock:
            expected = hmac.new(self.key, canonical_json(token.unsigned_dict()), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(token.signature, expected):
                raise VerificationError("invalid commit token signature")
            if token.effect_digest != effect_digest:
                raise VerificationError("commit token is bound to a different effect")
            if now > token.expires_at:
                raise VerificationError("commit token expired")
            if token.token_id in self._used:
                raise VerificationError("commit token replay")
            self._used.add(token.token_id)


@dataclass(frozen=True)
class VerificationWitness:
    report: VerificationReport
    commit_token_id: str
    commit_token_signature: str
    committed_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "report": self.report.to_dict(),
            "commit_token_id": self.commit_token_id,
            "commit_token_signature": self.commit_token_signature,
            "committed_at": self.committed_at,
        }


class VerifiedExecutionGuard:
    """Fail-closed bridge between staged AgentFleet work and Kinlock execution.

    ``stage`` may be called by orchestration code.  ``authorize`` is called only
    by Kinlock immediately before the downstream tool invocation.
    """

    def __init__(self, verifier: TheUstadVerifier, token_issuer: CommitTokenIssuer):
        self.verifier = verifier
        self.token_issuer = token_issuer
        self._staged: dict[str, ActionCertificate] = {}
        self._consumed_certificate_nonces: set[str] = set()
        self._lock = threading.RLock()

    def stage(self, certificate: ActionCertificate) -> None:
        if certificate.effect.request_id in self._staged:
            raise VerificationError("a certificate is already staged for this request")
        self._staged[certificate.effect.request_id] = certificate

    def discard(self, request_id: str) -> None:
        self._staged.pop(request_id, None)

    def authorize(self, action: Any, call: dict[str, Any], now: float | None = None) -> VerificationWitness:
        now = time.time() if now is None else now
        with self._lock:
            cert = self._staged.get(action.request_id)
            if cert is None:
                raise VerificationError("no proof-carrying certificate was staged for this request")
            if cert.nonce in self._consumed_certificate_nonces:
                raise VerificationError("certificate replay")
            effect = cert.effect
            if action.digest() != effect.action_digest:
                raise VerificationError("certificate is bound to a different Kinlock action")
            if call.get("tool") != effect.tool:
                raise VerificationError("certificate is bound to a different downstream tool")
            if dict(call.get("arguments") or {}) != effect.arguments:
                raise VerificationError("certificate is bound to different downstream arguments")

            report = self.verifier.verify(cert, now=now)
            if not report.ok:
                raise VerificationError("; ".join(report.problems))

            token = self.token_issuer.issue(report, now)
            # Consume before the external side effect.  A failed downstream call must not
            # leave a reusable authority token behind.
            self.token_issuer.consume(token, effect.effect_digest, now)
            self._consumed_certificate_nonces.add(cert.nonce)
            self._staged.pop(action.request_id, None)
            return VerificationWitness(report, token.token_id, token.signature, now)
