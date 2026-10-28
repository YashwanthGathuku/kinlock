"""Optional live Tavily evidence-enrichment demo.

This script makes a REAL Tavily Search API call and a REAL Nebius Token Factory
Nemotron call.  It has no replay fallback: if either key is missing, it exits
rather than pretending the integration ran.

Examples:
    TAVILY_API_KEY=... NEBIUS_API_KEY=... \
      python scripts/tavily_evidence_demo.py microsoft_anydesk

    python scripts/tavily_evidence_demo.py --list

The evidence layer is advisory/risk-only.  A conflict can add a scam signal;
supporting or unavailable evidence cannot remove risk or authorize an action.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kinlock.tavily_evidence import CLAIMS, TavilyClient, enrich_fixed_claim
from kinlock.tokenfactory import TokenFactory
from kinlock_authority import AgentAction
from kinlock_authority.firewall import FirewallPolicy, evaluate_action
from kinlock_authority.policy import History, Policy


def action_for(claim_id: str) -> AgentAction:
    if claim_id == "microsoft_anydesk":
        return AgentAction(
            "tavily-microsoft-anydesk",
            "access",
            "install_software",
            "AnyDesk",
            {"reason": "Microsoft support says remote access is required"},
            requester="caller:unknown",
        )
    if claim_id == "irs_gift_cards":
        return AgentAction(
            "tavily-irs-giftcards",
            "money",
            "purchase",
            "Gift Card Outlet",
            {"category": "gift cards", "item": "gift cards for IRS payment"},
            amount_cents=50000,
            requester="caller:irs",
        )
    if claim_id == "ftc_crypto_payment":
        return AgentAction(
            "tavily-government-crypto",
            "money",
            "purchase",
            "CryptoCash",
            {"category": "crypto", "item": "cryptocurrency payment"},
            amount_cents=50000,
            requester="caller:government",
        )
    raise ValueError(claim_id)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("claim", nargs="?", choices=sorted(CLAIMS))
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        for key, check in CLAIMS.items():
            print(f"{key}: {check.claim}")
        return
    if not args.claim:
        parser.error("choose a fixed claim or use --list")

    tavily = TavilyClient.from_env()
    nemotron = TokenFactory.from_env()
    if tavily is None:
        raise SystemExit("TAVILY_API_KEY is required; this demo has no fake/replay Tavily mode")
    if nemotron is None:
        raise SystemExit("NEBIUS_API_KEY is required; this demo has no fake/replay Nemotron mode")

    raw = json.loads((ROOT / "data" / "policy.example.json").read_text())
    policy = Policy.from_dict(raw)
    firewall = FirewallPolicy.from_dict(raw.get("firewall"))
    action = action_for(args.claim)
    before = evaluate_action(action, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=firewall)
    enriched = enrich_fixed_claim(args.claim, action=action, tavily=tavily, nemotron=nemotron)
    after = evaluate_action(enriched.action, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=firewall)

    out = {
        "schema": "kinlock.tavily-evidence-demo/1",
        "live": True,
        "claim": CLAIMS[args.claim].claim,
        "tavily": enriched.evidence.to_dict(),
        "nemotron_assessment": enriched.assessment.to_dict(),
        "kinlock": {
            "before": before.to_dict(),
            "after": after.to_dict(),
            "risk_before": sorted(action.risk),
            "risk_after": sorted(enriched.action.risk),
        },
        "invariant": "external evidence may preserve or raise restriction; it never lowers authority",
    }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
