from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_verified_causal_demo_is_reproducible_and_fail_closed():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verified_causal_demo.py"), "--json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    report = json.loads(proc.stdout)
    assert report["mode"] == "deterministic-local-no-model-calls"
    attack, safe, identity = report["scenarios"]

    assert attack["name"] == "distributed_authority_amplification"
    assert attack["theustad"]["ok"] is False
    assert any("amplifies authority" in p for p in attack["theustad"]["problems"])
    assert attack["kinlock_commit_token_issued"] is False
    assert attack["downstream_executed"] is False

    assert safe["name"] == "verified_safe_transaction"
    assert safe["theustad_passed"] is True
    assert safe["kinlock_outcome"] == "ALLOW"
    assert safe["downstream_executed"] is True
    assert safe["receipt_chain_ok"] is True

    assert identity["name"] == "valid_proof_consequential_identity_change"
    assert identity["theustad"]["ok"] is True
    assert identity["kinlock_outcome"] == "OWNER"
    assert identity["downstream_executed"] is False
