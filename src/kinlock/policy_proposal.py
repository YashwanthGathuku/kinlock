"""Natural-language policy proposals without model-owned authority.

Nemotron may translate an owner's sentence into one *proposed* Kinlock policy
operation.  The model never receives a write handle to policy.json.  Its JSON is
strictly parsed into an existing ``kinlock_authority.Action`` and the existing
pure authority-direction function classifies the change.

This module deliberately stops at a validated proposal + deterministic preview.
Applying a loosening proposal remains an owner-surface responsibility; callers
cannot use this module to silently persist a model suggestion.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any, Protocol

from kinlock_authority.policy import (
    INCREASE,
    REDUCE,
    UNKNOWN,
    Action,
    Policy,
    authority_direction,
)

from .tokenfactory import AGENT_MODEL, FALLBACK_MODEL, TokenFactoryError

PRESERVE = "preserve"
SUPPORTED_KINDS = frozenset(
    {
        "set_limit",
        "add_merchant",
        "remove_merchant",
        "add_payee",
        "remove_payee",
        "block_category",
        "unblock_category",
        "remove_contact",
    }
)
ALLOWED_KEYS = frozenset({"kind", "setting", "value", "counterparty", "category", "rationale"})


class ChatClient(Protocol):
    def chat(self, model: str, messages: list[dict[str, Any]], **kw: Any) -> dict[str, Any]: ...


class PolicyProposalError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyProposal:
    action: Action
    direction: str
    rationale: str
    before: dict[str, Any]
    after: dict[str, Any]
    changed: bool
    requires_owner_confirmation: bool
    model: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "direction": self.direction,
            "rationale": self.rationale,
            "changed": self.changed,
            "requires_owner_confirmation": self.requires_owner_confirmation,
            "before": self.before,
            "after": self.after,
            "model": self.model,
        }


def _clean_text(value: Any, field: str, *, required: bool = False, max_len: int = 160) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise PolicyProposalError(f"{field} is required")
    if len(text) > max_len:
        raise PolicyProposalError(f"{field} is too long")
    return text


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise PolicyProposalError(f"{field} must be an integer")
    try:
        out = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyProposalError(f"{field} must be an integer") from exc
    if out < 0 or out > 100_000_000:
        raise PolicyProposalError(f"{field} is outside the supported range")
    return out


def _preview(policy: Policy, action: Action) -> tuple[dict[str, Any], dict[str, Any], bool]:
    before = policy.to_dict()
    after = policy.apply(action).to_dict()
    return before, after, before != after


def validate_policy_proposal(raw: dict[str, Any], policy: Policy, *, model: str | None = None) -> PolicyProposal:
    """Convert untrusted model JSON into a deterministic, preview-only proposal."""

    if not isinstance(raw, dict):
        raise PolicyProposalError("proposal must be a JSON object")
    unknown = set(raw) - ALLOWED_KEYS
    if unknown:
        raise PolicyProposalError("unknown proposal fields: " + ", ".join(sorted(unknown)))

    kind = _clean_text(raw.get("kind"), "kind", required=True, max_len=64)
    if kind not in SUPPORTED_KINDS:
        raise PolicyProposalError(f"unsupported policy operation: {kind!r}")

    setting = _clean_text(raw.get("setting"), "setting")
    counterparty = _clean_text(raw.get("counterparty"), "counterparty")
    category = _clean_text(raw.get("category"), "category")
    rationale = _clean_text(raw.get("rationale"), "rationale", max_len=400)
    value = _int(raw.get("value", 0), "value") if kind == "set_limit" else 0

    if kind == "set_limit":
        if not setting:
            raise PolicyProposalError("set_limit requires setting")
        if policy.setting_value(setting) is None:
            raise PolicyProposalError(f"unknown numeric policy setting: {setting!r}")
    elif kind in {"add_merchant", "remove_merchant", "add_payee", "remove_payee", "remove_contact"}:
        if not counterparty:
            raise PolicyProposalError(f"{kind} requires counterparty")
    elif kind in {"block_category", "unblock_category"} and not category:
        raise PolicyProposalError(f"{kind} requires category")

    action = Action(
        request_id="policy-proposal-" + secrets.token_hex(6),
        kind=kind,
        counterparty=counterparty,
        category=category,
        setting=setting,
        value=value,
    )
    direction = authority_direction(action, policy)
    if direction == UNKNOWN:
        raise PolicyProposalError("the deterministic authority engine cannot classify this proposal")

    before, after, changed = _preview(policy, action)
    if not changed:
        direction = PRESERVE

    return PolicyProposal(
        action=action,
        direction=direction,
        rationale=rationale,
        before=before,
        after=after,
        changed=changed,
        requires_owner_confirmation=(direction == INCREASE),
        model=model,
    )


def policy_diff(proposal: PolicyProposal) -> list[dict[str, Any]]:
    """Return a compact deterministic top-level/nested diff for owner review."""

    changes: list[dict[str, Any]] = []

    def walk(path: str, before: Any, after: Any) -> None:
        if before == after:
            return
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) | set(after)):
                walk(f"{path}.{key}" if path else key, before.get(key), after.get(key))
            return
        changes.append({"path": path, "before": before, "after": after})

    walk("", proposal.before, proposal.after)
    return changes


SYSTEM_PROMPT = """You translate an authenticated owner's plain-language Kinlock policy request into ONE proposed operation.

You are NOT an authorization system. You cannot apply a policy, approve an authority increase, or invent unsupported fields.
Return one JSON object only.

Allowed operations:
- set_limit: requires setting and integer value
- add_merchant / remove_merchant: requires counterparty
- add_payee / remove_payee: requires counterparty
- block_category / unblock_category: requires category
- remove_contact: requires counterparty containing the contact id

Allowed keys only: kind, setting, value, counterparty, category, rationale.
Do not return multiple operations. Do not use Markdown. Do not infer a contact id if the owner did not name one clearly.
For money, value is integer cents. For daily_count, value is an integer count.
If the request cannot be represented exactly by one allowed operation, return {"kind":"unsupported","rationale":"..."}.
"""


def _message_content(message: dict[str, Any]) -> str:
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise PolicyProposalError("Nemotron returned no JSON content")
    return content.strip()


def propose_with_nemotron(
    client: ChatClient,
    owner_request: str,
    policy: Policy,
    *,
    model: str = AGENT_MODEL,
    fallback_model: str = FALLBACK_MODEL,
) -> PolicyProposal:
    """Ask Nemotron for JSON, then distrust and validate every field deterministically."""

    request = owner_request.strip()
    if not request or len(request) > 1200:
        raise PolicyProposalError("owner request must be 1..1200 characters")

    policy_summary = {
        "owner": policy.owner,
        "limits": policy.to_dict()["limits"],
        "default_limits": policy.to_dict()["default_limits"],
        "owner_only_above_cents": policy.owner_only_above_cents,
        "known_merchants": sorted(policy.known_merchants),
        "known_payees": sorted(policy.known_payees),
        "blocked_categories": sorted(policy.blocked_categories),
        "contacts": [
            {"id": c.id, "name": c.name, "relation": c.relation, "ceiling_cents": c.ceiling_cents}
            for c in policy.contacts
        ],
    }
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(
                {"owner_request": request, "current_policy": policy_summary},
                sort_keys=True,
            ),
        },
    ]

    used_model = model
    try:
        message = client.chat(model, messages, temperature=0, response_format={"type": "json_object"})
    except (TokenFactoryError, OSError, TimeoutError):
        used_model = fallback_model
        message = client.chat(fallback_model, messages, temperature=0, response_format={"type": "json_object"})

    try:
        raw = json.loads(_message_content(message))
    except json.JSONDecodeError as exc:
        raise PolicyProposalError("Nemotron output was not valid JSON") from exc
    return validate_policy_proposal(raw, policy, model=used_model)
