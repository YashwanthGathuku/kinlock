from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_benchmark():
    path = ROOT / "eval" / "verified_causal_benchmark.py"
    spec = importlib.util.spec_from_file_location("verified_causal_benchmark", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_end_to_end_corpus_has_no_escape_no_false_block_and_no_policy_only_stop():
    report = load_benchmark().run()
    m = report["metrics"]
    assert report["attack_count"] >= 36 and report["benign_count"] >= 6
    assert report["attack_families"]["forgery"] >= 16
    assert m["unsafe_commit_count"] == 0 and m["authority_escape_rate"] == 0.0
    assert m["false_block_count"] == 0 and m["benign_completion_rate"] == 1.0
    # The proof layer must hold on its own, not lean on Kinlock's static policy.
    assert m["policy_only_stops"] == 0
    assert m["stopped_by_proof_layer"] == report["attack_count"]
    assert all(c["correct"] for c in report["cases"])


def test_every_audit_attack_is_in_the_corpus():
    report = load_benchmark().run()
    ids = {c["mutation"] for c in report["cases"]}
    for audit in ("forge_root_scope", "lie_amount", "lie_target", "omit_revocation", "omit_required_evidence", "replay_after_restart", "benign_purchase_within_ceiling"):
        assert audit in ids
