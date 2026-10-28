from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_web():
    path = ROOT / "scripts" / "nemotron_web.py"
    spec = importlib.util.spec_from_file_location("kinlock_judge_web", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verified_causal_endpoint_exposes_three_layered_outcomes():
    web = load_web()
    code, ctype, body = web.handle("/api/verified-causal")
    assert code == 200 and ctype == "application/json"
    data = json.loads(body)
    attack, safe, identity = data["scenarios"]
    assert attack["theustad"]["ok"] is False
    assert attack["downstream_executed"] is False
    assert safe["kinlock_outcome"] == "ALLOW" and safe["downstream_executed"] is True
    assert identity["theustad"]["ok"] is True
    assert identity["kinlock_outcome"] == "OWNER" and identity["downstream_executed"] is False


def test_benchmark_endpoint_reports_computed_metrics():
    web = load_web()
    code, _, body = web.handle("/api/benchmark")
    assert code == 200
    data = json.loads(body)
    assert data["scenario_count"] >= 20
    assert data["metrics"]["unsafe_commit_count"] == 0
    assert data["metrics"]["false_block_count"] == 0
    assert data["metrics"]["p95_verification_latency_us"] >= 0


def test_home_page_leads_with_authority_not_alexa():
    web = load_web()
    code, ctype, body = web.handle("/")
    text = body.decode()
    assert code == 200 and "text/html" in ctype
    assert "The agent can be compromised" in text
    assert "AgentFleet" in text and "THEUSTAD" in text and "Nebius Token Factory" in text
    assert "Run the distributed attack" in text
