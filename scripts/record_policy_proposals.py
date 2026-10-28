"""Record real Nemotron policy proposals from Nebius Token Factory for the judge page.

    NEBIUS_API_KEY=... python scripts/record_policy_proposals.py            # all requests
    NEBIUS_API_KEY=... python scripts/record_policy_proposals.py lower_transfer_limit

Each request is sent to Nemotron 3 Ultra (Super as fallback) exactly as the page
would send it, and the raw exchange is saved to tests/fixtures/policy/<id>.json.
The page then replays it, labelled "recorded live". Without a key this exits; it
never writes a made-up response.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kinlock.judge_panels import POLICY_REQUESTS  # noqa: E402
from kinlock.policy_proposal import PolicyProposalError, propose_with_nemotron  # noqa: E402
from kinlock.tokenfactory import RecordingTransport, TokenFactory  # noqa: E402
from kinlock_authority.policy import Policy  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "policy"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("request", nargs="*", help=", ".join(sorted(POLICY_REQUESTS)))
    a = ap.parse_args()
    unknown = sorted(set(a.request) - set(POLICY_REQUESTS))
    if unknown:
        ap.error(f"unknown request(s): {', '.join(unknown)}")
    live = TokenFactory.from_env()
    if live is None:
        raise SystemExit("NEBIUS_API_KEY is required; nothing is recorded without a real model call")
    policy = Policy.from_dict(json.loads((ROOT / "data" / "policy.example.json").read_text()))
    for rid in a.request or list(POLICY_REQUESTS):
        client = TokenFactory(RecordingTransport(live.transport, FIXTURES / f"{rid}.json"))
        try:
            p = propose_with_nemotron(client, POLICY_REQUESTS[rid], policy)
            print(f"{rid}: {p.direction} {p.action.to_dict()} (model {p.model})")
        except PolicyProposalError as e:
            print(f"{rid}: rejected by the validator: {e}")


if __name__ == "__main__":
    main()
