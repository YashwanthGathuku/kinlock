from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_verified_causal_demo_is_reproducible_and_fail_closed():
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "verified_causal_demo.py"), "--json"], cwd=ROOT, text=True, capture_output=True, check=True)
    report = json.loads(proc.stdout)
    assert report["schema"] == "kinlock.verified-causal-demo/2"
    assert report["mode"] == "deterministic-local-no-model-calls"
    swarm, safe, identity = report["scenarios"]

    assert swarm["name"] == "compromised_swarm"
    assert len(swarm["attempts"]) == 4
    for attempt in swarm["attempts"]:
        assert attempt["theustad"]["ok"] is False
        assert attempt["commit_token_issued"] is False
        assert attempt["downstream_executed"] is False
    problems = " ".join(p for a in swarm["attempts"] for p in a["theustad"]["problems"])
    for expected in ("chain signature does not verify", "amplifies authority", "does not match the call", "not signed by Kinlock's gateway"):
        assert expected in problems
    assert swarm["forgeries_committed"] == 0
    assert swarm["legitimate"]["theustad"]["ok"] and swarm["legitimate"]["downstream_executed"]
    assert all(r["signed_by"] == "kinlock-gateway" and r["evidence_id"] for r in swarm["reads"])
    assert swarm["receipt_chain_ok"]

    assert safe["first"]["kinlock_outcome"] == "ALLOW" and safe["first"]["downstream_executed"]
    assert safe["replay_after_restart"]["downstream_executed"] is False
    assert safe["replay_after_restart"]["theustad"]["problems"][0].startswith("certificate replay")
    assert safe["second_effect_past_budget"]["downstream_executed"] is False
    assert safe["receipt_chain_ok"]

    assert identity["owner_surface"]["theustad"]["ok"] is True
    assert identity["owner_surface"]["kinlock_outcome"] == "OWNER"
    assert identity["owner_surface"]["ready_after_hours"] == 24.0
    assert identity["downstream_executed"] is False
    assert "category:identity" in identity["voice_request"]["clamped"]
