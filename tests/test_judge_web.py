from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_web():
    path = ROOT / "scripts" / "nemotron_web.py"
    spec = importlib.util.spec_from_file_location("kinlock_judge_web", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WEB = load_web()


def get(path):
    code, ctype, body = WEB.handle(path)
    return code, ctype, (json.loads(body) if "json" in ctype else body.decode())


def test_verified_causal_endpoint_shows_forgeries_refused_and_proof_is_not_authorization():
    code, _, data = get("/api/verified-causal")
    assert code == 200
    swarm, safe, identity = data["scenarios"]
    assert swarm["forgeries_committed"] == 0 and all(not a["downstream_executed"] for a in swarm["attempts"])
    assert swarm["legitimate"]["downstream_executed"]
    assert safe["first"]["downstream_executed"] and not safe["replay_after_restart"]["downstream_executed"]
    assert identity["owner_surface"]["theustad"]["ok"] and identity["owner_surface"]["kinlock_outcome"] == "OWNER"
    assert WEB.handle("/api/verified-causal")[2] is WEB.handle("/api/verified-causal")[2]  # computed once


def test_benchmark_endpoint_reports_computed_end_to_end_metrics():
    code, _, data = get("/api/benchmark")
    assert code == 200
    assert data["metrics"]["unsafe_commit_count"] == 0
    assert data["metrics"]["policy_only_stops"] == 0
    assert data["verifier_latency"]["p95_us"] > 0


def test_nemotron_run_is_on_the_verified_path():
    code, _, d = get("/api/run?scenario=errand")
    assert code == 200 and d["live"] is False
    assert [s["outcome"] for s in d["steps"]] == ["ALLOW", "ALLOW"]
    assert all(s["proof"]["ok"] and s["proof"]["stage"] == "commit" for s in d["steps"])
    assert [c["tool"] for c in d["commits"]] == ["refill_prescription", "send_message"]
    code, _, h = get("/api/run?scenario=recovery_email_hijacked")
    step = h["steps"][0]
    assert step["outcome"] == "OWNER" and step["proof"]["ok"] is False and h["commits"] == []


def test_live_is_refused_without_keys(monkeypatch):
    monkeypatch.delenv("KINLOCK_DEMO_LIVE", raising=False)
    assert WEB.handle("/api/run?scenario=errand&live=1")[0] == 403
    assert WEB.handle("/api/policy?request=lower_transfer_limit&live=1")[0] == 403
    assert WEB.handle("/api/evidence?claim=microsoft_anydesk&live=1")[0] == 403


def test_policy_panels_never_invent_model_output():
    code, _, d = get("/api/policy?request=lower_transfer_limit")
    assert code == 200
    fixture = ROOT / "tests" / "fixtures" / "policy" / "lower_transfer_limit.json"
    assert d["mode"] == ("recorded live" if fixture.exists() else "not recorded")
    _, _, rows = get("/api/policy-adversarial")
    by = {r["id"]: r for r in rows}
    assert by["claims_it_approved"]["result"]["accepted"] is False
    assert by["invents_an_operation"]["result"]["accepted"] is False
    assert by["calls_an_increase_safer"]["result"]["requires_owner_confirmation"] is True
    assert by["smuggles_two_changes"]["result"]["accepted"] is False
    assert all("not a model response" in r["source"] for r in rows)


def test_evidence_panel_without_a_recorded_run_says_so_and_adds_nothing():
    code, _, d = get("/api/evidence?claim=microsoft_anydesk")
    assert code == 200
    if d["mode"] == "not recorded":
        assert d["kinlock"]["risk_after"] == d["kinlock"]["risk_before"]
        assert d["kinlock"]["before"] == d["kinlock"]["after"]


def test_home_page_matches_what_runs():
    code, ctype, text = get("/")
    assert code == 200 and "text/html" in ctype
    assert "The agent can be compromised" in text and "Nebius Token Factory" in text and "THEUSTAD" in text
    assert "Run the compromised swarm" in text
    assert "AgentFleet" not in text  # not part of the public runtime


def test_dockerfile_ships_every_file_the_web_demo_loads():
    docker = (ROOT / "Dockerfile").read_text()
    copied = " ".join(re.findall(r"^COPY (.+)$", docker, re.M))
    for needed in ("scripts/nemotron_web.py", "scripts/nemotron_web.html", "scripts/nemotron_demo.py", "scripts/verified_causal_demo.py", "eval", "data", "src", "tests/fixtures"):
        assert needed in copied, f"Dockerfile does not copy {needed}"
