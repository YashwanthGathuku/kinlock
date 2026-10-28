"""Live Tavily evidence enrichment: one real Tavily search plus one real Nemotron Nano call.

There is no fake mode. Without both keys the script exits instead of pretending
the integration ran. ``--record`` saves the live output so the judge page can
replay it, labelled as a recorded live run.

    TAVILY_API_KEY=... NEBIUS_API_KEY=... python scripts/tavily_evidence_demo.py microsoft_anydesk --record
    python scripts/tavily_evidence_demo.py --list

The evidence layer can only add a risk signal: a conflict raises restriction;
supporting, missing or unavailable evidence never lowers it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kinlock.judge_panels import evidence_decisions  # noqa: E402
from kinlock.tavily_evidence import CLAIMS, TavilyClient, action_for_claim, enrich_fixed_claim  # noqa: E402
from kinlock.tokenfactory import TokenFactory  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "tavily"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("claim", nargs="?", choices=sorted(CLAIMS))
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--record", action="store_true", help=f"save the live run to {FIXTURES.relative_to(ROOT)}/<claim>.json")
    a = ap.parse_args()
    if a.list:
        for key, check in CLAIMS.items():
            print(f"{key}: {check.claim}")
        return
    if not a.claim:
        ap.error("choose a fixed claim or use --list")
    tavily, nemotron = TavilyClient.from_env(), TokenFactory.from_env()
    if tavily is None:
        raise SystemExit("TAVILY_API_KEY is required; this demo has no fake or replay Tavily mode")
    if nemotron is None:
        raise SystemExit("NEBIUS_API_KEY is required; this demo has no fake or replay Nemotron mode")

    action = action_for_claim(a.claim)
    enriched = enrich_fixed_claim(a.claim, action=action, tavily=tavily, nemotron=nemotron)
    out = {
        "schema": "kinlock.tavily-evidence-run/1",
        "live": True,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "claim_id": a.claim,
        "claim": CLAIMS[a.claim].claim,
        "tavily": enriched.evidence.to_dict(),
        "nemotron_assessment": enriched.assessment.to_dict(),
        "kinlock": evidence_decisions(action, enriched.action, json.loads((ROOT / "data" / "policy.example.json").read_text())),
        "invariant": "external evidence may preserve or raise restriction; it never lowers authority",
    }
    text = json.dumps(out, indent=2, sort_keys=True)
    if a.record:
        FIXTURES.mkdir(parents=True, exist_ok=True)
        (FIXTURES / f"{a.claim}.json").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
