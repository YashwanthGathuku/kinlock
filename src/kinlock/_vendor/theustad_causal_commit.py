"""Public, source-locked copy of TheUstad's causal commit verifier.

Canonical upstream during the hackathon:
  YashwanthGathuku/theustad@6aca7311c8c4850bd7fb8772a066a569a611b90b
  theustadlib/causal_commit.py blob 17b232f3d3dfd306cb0bfe51b644c7701d686702

The public Kinlock repository includes this checker so judges can inspect the
trusted decision boundary without access to the private upstream repository.
It intentionally imports no Kinlock planner/orchestrator code.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

SCHEMA = "kinlock.verified-action/1"
VERIFIER = "theustad.causal-commit/1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _items(value: Any) -> tuple[str, ...]:
    return tuple(str(x) for x in (value or ()))


def _subset(child: Any, parent: Any) -> bool:
    c, p = set(_items(child)), set(_items(parent))
    if "*" in p:
        return True
    if "*" in c:
        return False
    return c.issubset(p)


def _allows(values: Any, value: str) -> bool:
    allowed = set(_items(values))
    return "*" in allowed or value in allowed


def _scope_attenuates(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    for field in ("tools", "categories", "verbs", "targets"):
        if not _subset(child.get(field), parent.get(field)):
            return False
    p_amount = parent.get("max_amount_cents")
    c_amount = child.get("max_amount_cents")
    if p_amount is not None and (c_amount is None or int(c_amount) > int(p_amount)):
        return False
    if int(child.get("max_delegation_depth", 0)) > int(parent.get("max_delegation_depth", 0)):
        return False
    p_exp = parent.get("expires_at")
    c_exp = child.get("expires_at")
    if p_exp is not None and (c_exp is None or float(c_exp) > float(p_exp)):
        return False
    return True


def _evidence_unsigned(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": record.get("evidence_id"),
        "producer": record.get("producer"),
        "source_tool": record.get("source_tool"),
        "request_hash": record.get("request_hash"),
        "response_hash": record.get("response_hash"),
        "observed_at": record.get("observed_at"),
        "parent_evidence": list(record.get("parent_evidence") or []),
        "integrity": record.get("integrity", "trusted"),
        "confidentiality": record.get("confidentiality", "private"),
    }


def verify_evidence_dict(record: dict[str, Any], key: bytes) -> bool:
    signature = str(record.get("signature") or "")
    expected = hmac.new(key, canonical_json(_evidence_unsigned(record)), hashlib.sha256).hexdigest()
    return bool(signature) and hmac.compare_digest(signature, expected)


@dataclass(frozen=True)
class CausalVerdict:
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


def verify_causal_certificate(
    certificate: dict[str, Any],
    *,
    evidence_key: bytes,
    now: float,
    expected_action_digest: str | None = None,
    expected_tool: str | None = None,
    expected_arguments: dict[str, Any] | None = None,
    max_clock_skew: float = 5.0,
) -> CausalVerdict:
    problems: list[str] = []
    checks: list[str] = []
    if not evidence_key:
        raise ValueError("evidence_key is required")

    if certificate.get("schema") != SCHEMA:
        problems.append("unknown certificate schema")
    if not certificate.get("nonce"):
        problems.append("certificate nonce is required")
    if float(certificate.get("created_at") or 0.0) > now + max_clock_skew:
        problems.append("certificate was created in the future")

    root = dict(certificate.get("root") or {})
    scope = dict(root.get("scope") or {})
    root_expiry = float(root.get("expires_at") or 0.0)
    if not root.get("intent_id") or not root.get("principal"):
        problems.append("root intent identity is incomplete")
    if float(root.get("issued_at") or 0.0) > now + max_clock_skew:
        problems.append("root intent was issued in the future")
    if now > root_expiry:
        problems.append("root intent expired")
    if scope.get("expires_at") is not None and float(scope["expires_at"]) > root_expiry:
        problems.append("root scope outlives root intent")
    if not any("root" in p for p in problems):
        checks.append("root_intent_time")

    subject = str(root.get("principal") or "")
    parent_expiry = root_expiry
    delegations = list(certificate.get("delegations") or [])
    if len(delegations) > int(scope.get("max_delegation_depth", 0)):
        problems.append("delegation depth exceeds root authority")
    seen_edges: set[str] = set()
    seen_subjects: set[str] = {subject}
    for raw in delegations:
        edge = dict(raw or {})
        edge_id = str(edge.get("edge_id") or "")
        child = str(edge.get("child") or "")
        child_scope = dict(edge.get("scope") or {})
        if not edge_id or edge_id in seen_edges:
            problems.append("duplicate or missing delegation edge")
        seen_edges.add(edge_id)
        if str(edge.get("parent") or "") != subject:
            problems.append(f"delegation {edge_id or '?'} does not continue the causal authority path")
        if not child or child in seen_subjects:
            problems.append("delegation cycle or missing child detected")
        seen_subjects.add(child)
        if not _scope_attenuates(child_scope, scope):
            problems.append(f"delegation {edge_id or '?'} amplifies authority")
        edge_issued = float(edge.get("issued_at") or 0.0)
        edge_expiry = float(edge.get("expires_at") or 0.0)
        if edge_issued > now + max_clock_skew:
            problems.append(f"delegation {edge_id or '?'} was issued in the future")
        if edge_expiry > parent_expiry:
            problems.append(f"delegation {edge_id or '?'} outlives its parent")
        if now > edge_expiry:
            problems.append(f"delegation {edge_id or '?'} expired")
        subject, scope, parent_expiry = child, child_scope, edge_expiry
    if not any("delegation" in p for p in problems):
        checks.append("authority_conservation")

    effect = dict(certificate.get("effect") or {})
    if str(effect.get("actor") or "") != subject:
        problems.append("effect actor has no complete delegation path to the root intent")
    tool = str(effect.get("tool") or "")
    category = str(effect.get("category") or "")
    verb = str(effect.get("verb") or "")
    target = str(effect.get("target") or "")
    if not _allows(scope.get("tools"), tool):
        problems.append(f"tool {tool!r} is outside delegated authority")
    if not _allows(scope.get("categories"), category):
        problems.append(f"category {category!r} is outside delegated authority")
    if not _allows(scope.get("verbs"), verb):
        problems.append(f"verb {verb!r} is outside delegated authority")
    if not _allows(scope.get("targets"), target):
        problems.append(f"target {target!r} is outside delegated authority")
    max_amount = scope.get("max_amount_cents")
    if max_amount is not None and int(effect.get("amount_cents") or 0) > int(max_amount):
        problems.append("effect exceeds delegated amount ceiling")
    if scope.get("expires_at") is not None and now > float(scope["expires_at"]):
        problems.append("authority scope expired")
    if expected_action_digest is not None and effect.get("action_digest") != expected_action_digest:
        problems.append("certificate is bound to a different Kinlock action")
    if expected_tool is not None and tool != expected_tool:
        problems.append("certificate is bound to a different downstream tool")
    if expected_arguments is not None and dict(effect.get("arguments") or {}) != dict(expected_arguments):
        problems.append("certificate is bound to different downstream arguments")
    if not any("delegated authority" in p or "amount ceiling" in p or "different" in p or "scope expired" in p for p in problems):
        checks.append("effect_within_scope")

    evidence_by_id: dict[str, dict[str, Any]] = {}
    for raw in list(certificate.get("evidence") or []):
        record = dict(raw or {})
        eid = str(record.get("evidence_id") or "")
        if not eid or eid in evidence_by_id:
            problems.append("duplicate or missing evidence id")
            continue
        if float(record.get("observed_at") or 0.0) > now + max_clock_skew:
            problems.append(f"evidence {eid} was observed in the future")
        if not verify_evidence_dict(record, evidence_key):
            problems.append(f"evidence {eid} has invalid provenance signature")
        for parent in list(record.get("parent_evidence") or []):
            if parent not in evidence_by_id:
                problems.append(f"evidence {eid} references unavailable parent evidence {parent}")
        evidence_by_id[eid] = record
    missing = sorted(set(effect.get("required_evidence") or []) - set(evidence_by_id))
    if missing:
        problems.append("required evidence missing: " + ", ".join(missing))
    if not any("evidence" in p for p in problems):
        checks.append("bound_evidence_provenance")

    temporal = dict(certificate.get("temporal") or {})
    facts = set(certificate.get("facts") or [])
    if temporal.get("not_before") is not None and now < float(temporal["not_before"]):
        problems.append("temporal contract is not yet satisfied")
    if temporal.get("expires_at") is not None and now > float(temporal["expires_at"]):
        problems.append("temporal contract expired")
    missing_facts = sorted(set(temporal.get("required_facts") or []) - facts)
    if missing_facts:
        problems.append("required temporal facts missing: " + ", ".join(missing_facts))
    forbidden = sorted(set(temporal.get("forbidden_facts") or []) & facts)
    if forbidden:
        problems.append("forbidden temporal facts present: " + ", ".join(forbidden))
    if not any("temporal" in p for p in problems):
        checks.append("temporal_contract")

    return CausalVerdict(
        ok=not problems,
        certificate_digest=sha256(certificate),
        effect_digest=sha256(effect),
        checks=tuple(checks),
        problems=tuple(problems),
    )
