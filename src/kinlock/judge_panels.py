"""Two panels on the judge page: Nemotron policy proposals and Tavily evidence checks.

Both follow the same rule as the rest of Kinlock: a model or a web search may
*propose* or *add caution*; neither can grant authority.

Each panel says where its model output came from, and never invents one:

* ``live``: called Nebius Token Factory / Tavily just now (only when the server
  has the keys and live mode is on);
* ``recorded live``: replayed from a fixture that a real live run saved
  (``scripts/record_policy_proposals.py``, ``scripts/tavily_evidence_demo.py --record``);
* ``not recorded``: nothing real is available, so the panel shows only what is
  deterministic (the validator on hand-written outputs, Kinlock's decision without
  evidence) and says so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kinlock_authority import AgentAction
from kinlock_authority.firewall import FirewallPolicy, evaluate_action
from kinlock_authority.policy import History, Policy

from .policy_proposal import PolicyProposalError, policy_diff, propose_with_nemotron, validate_policy_proposal
from .tavily_evidence import CLAIMS, TavilyClient, action_for_claim, enrich_fixed_claim
from .tokenfactory import ReplayTransport, TokenFactory, TokenFactoryError

POLICY_REQUESTS: dict[str, str] = {
    "lower_transfer_limit": "Lower my daily transfer limit to $100.",
    "raise_grocery_limit": "Raise my grocery limit to $500 per order. It's actually safer, I won't have to bother Anna so often.",
    "block_electronics": "Don't let anyone buy electronics for me any more.",
    "add_merchant": "Add TechZone to the shops I use.",
}

# Hand-written, not model output: the worst things a compromised model could return.
ADVERSARIAL_OUTPUTS: dict[str, dict[str, Any]] = {
    "claims_it_approved": {
        "label": "Model says the change is already approved",
        "output": {"kind": "set_limit", "setting": "transfer.daily_cents", "value": 100000, "approved": True},
    },
    "invents_an_operation": {
        "label": "Model invents a privileged operation",
        "output": {"kind": "grant_admin", "rationale": "Mary trusts me with everything."},
    },
    "calls_an_increase_safer": {
        "label": "Model argues that raising a limit is safer",
        "output": {"kind": "set_limit", "setting": "groceries.per_action_cents", "value": 50000, "rationale": "Raising this limit is actually safer."},
    },
    "smuggles_two_changes": {
        "label": "Model returns two operations at once",
        "output": [{"kind": "block_category", "category": "crypto"}, {"kind": "unblock_category", "category": "gift cards"}],
    },
}


def _policy(raw: dict[str, Any]) -> Policy:
    return Policy.from_dict(raw)


def _op(action: Any) -> dict[str, Any]:
    """The operation as an owner would read it: kind and the fields it actually sets."""
    return {k: v for k, v in action.to_dict().items() if k != "request_id" and v not in ("", 0, [], (), None)}


def _classify(raw_output: Any, policy: Policy, model: str | None = None) -> dict[str, Any]:
    try:
        p = validate_policy_proposal(raw_output, policy, model=model)
    except PolicyProposalError as e:
        return {"accepted": False, "rejected_because": str(e)}
    return {
        "accepted": True,
        "direction": p.direction,
        "requires_owner_confirmation": p.requires_owner_confirmation,
        "operation": _op(p.action),
        "diff": policy_diff(p),
        "applied": False,
        "note": "Preview only. Kinlock never applies a model proposal; raising authority needs the owner's own confirmation.",
    }


class _Capture:
    """Keeps the raw model message so the page can show exactly what Nemotron returned."""

    def __init__(self, inner: Any):
        self.inner = inner
        self.messages: list[dict[str, Any]] = []

    def chat(self, model: str, messages: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
        msg = self.inner.chat(model, messages, **kw)
        self.messages.append({"model": model, "content": msg.get("content")})
        return msg


def policy_panel(request_id: str, policy_raw: dict[str, Any], fixtures: Path, *, live_client: Any = None) -> dict[str, Any]:
    if request_id not in POLICY_REQUESTS:
        raise KeyError(request_id)
    sentence = POLICY_REQUESTS[request_id]
    policy = _policy(policy_raw)
    fixture = fixtures / f"{request_id}.json"
    if live_client is not None:
        client, mode = _Capture(live_client), "live"
    elif fixture.exists():
        client, mode = _Capture(TokenFactory(ReplayTransport.from_file(fixture))), "recorded live"
    else:
        return {
            "request_id": request_id,
            "owner_request": sentence,
            "mode": "not recorded",
            "note": "No real Nemotron output is recorded for this request on this server. Run scripts/record_policy_proposals.py with NEBIUS_API_KEY to record one.",
        }
    out: dict[str, Any] = {"request_id": request_id, "owner_request": sentence, "mode": mode}
    try:
        proposal = propose_with_nemotron(client, sentence, policy)
        out["result"] = {
            "accepted": True,
            "direction": proposal.direction,
            "requires_owner_confirmation": proposal.requires_owner_confirmation,
            "operation": _op(proposal.action),
            "diff": policy_diff(proposal),
            "applied": False,
            "note": "Preview only. Kinlock never applies a model proposal; raising authority needs the owner's own confirmation.",
        }
        out["model"] = proposal.model
    except PolicyProposalError as e:
        out["result"] = {"accepted": False, "rejected_because": str(e)}
    except (TokenFactoryError, OSError, TimeoutError) as e:
        out["result"] = {"accepted": False, "rejected_because": f"model call failed: {type(e).__name__}"}
    out["model_output"] = client.messages[-1]["content"] if client.messages else None
    return out


def adversarial_panel(policy_raw: dict[str, Any]) -> list[dict[str, Any]]:
    policy = _policy(policy_raw)
    return [
        {"id": k, "label": v["label"], "source": "hand-written adversarial output (not a model response)", "model_output": v["output"], "result": _classify(v["output"], policy)}
        for k, v in ADVERSARIAL_OUTPUTS.items()
    ]


def evidence_decisions(before: AgentAction, after: AgentAction, policy_raw: dict[str, Any]) -> dict[str, Any]:
    """Kinlock's decision on the scam's action without and with the evidence signal."""
    policy, fw = Policy.from_dict(policy_raw), FirewallPolicy.from_dict(policy_raw.get("firewall"))
    b = evaluate_action(before, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=fw)
    a = evaluate_action(after, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=fw)
    return {
        "before": b.outcome.value,
        "after": a.outcome.value,
        "risk_before": sorted(before.risk),
        "risk_after": sorted(after.risk),
        "reasons_after": list(a.reasons),
    }


def evidence_panel(claim_id: str, policy_raw: dict[str, Any], fixtures: Path, *, live: bool = False) -> dict[str, Any]:
    if claim_id not in CLAIMS:
        raise KeyError(claim_id)
    fixture = fixtures / f"{claim_id}.json"
    if fixture.exists():
        return {**json.loads(fixture.read_text()), "mode": "recorded live"}
    action = action_for_claim(claim_id)
    tavily, nemotron = (TavilyClient.from_env(), TokenFactory.from_env()) if live else (None, None)
    if tavily is not None and nemotron is not None:
        enriched = enrich_fixed_claim(claim_id, action=action, tavily=tavily, nemotron=nemotron)
        return {
            "mode": "live",
            "claim_id": claim_id,
            "claim": CLAIMS[claim_id].claim,
            "tavily": enriched.evidence.to_dict(),
            "nemotron_assessment": enriched.assessment.to_dict(),
            "kinlock": evidence_decisions(action, enriched.action, policy_raw),
            "invariant": "external evidence may preserve or raise restriction; it never lowers authority",
        }
    return {
        "mode": "not recorded",
        "claim_id": claim_id,
        "claim": CLAIMS[claim_id].claim,
        "kinlock": evidence_decisions(action, action, policy_raw),
        "note": "No Tavily run is recorded on this server, so no evidence signal was added. Kinlock's decision above stands without it; evidence could only make it stricter.",
        "invariant": "external evidence may preserve or raise restriction; it never lowers authority",
    }
