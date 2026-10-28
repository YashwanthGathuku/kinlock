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


def test_causal_commit_corpus_has_no_authority_escape_or_false_block():
    report = load_benchmark().run()
    assert report["scenario_count"] >= 20
    assert report["attack_count"] > report["benign_count"]
    assert report["metrics"]["unsafe_commit_count"] == 0
    assert report["metrics"]["authority_escape_rate"] == 0.0
    assert report["metrics"]["false_block_count"] == 0
    assert report["metrics"]["benign_completion_rate"] == 1.0
    assert all(case["correct"] for case in report["cases"])
