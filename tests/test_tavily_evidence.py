from __future__ import annotations

import json

from kinlock.tavily_evidence import (
    CLAIMS,
    EVIDENCE_CONFLICT_RISK,
    EvidenceAssessment,
    SearchEvidence,
    TavilyClient,
    TavilyError,
    add_evidence_risk,
    assess_with_nemotron,
    enrich_fixed_claim,
)
from kinlock_authority import AgentAction
from kinlock_authority.firewall import RANK, FirewallPolicy, evaluate_action
from kinlock_authority.policy import History, Policy


class SearchTransport:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def post(self, body, timeout):
        self.calls.append((body, timeout))
        if self.error:
            raise TavilyError(self.error)
        return self.response


class Model:
    def __init__(self, content):
        self.content = content
        self.calls = []

    def chat(self, model, messages, **kw):
        self.calls.append((model, messages, kw))
        return {"content": self.content}


def policies(data_dir):
    raw = json.loads((data_dir / "policy.json").read_text())
    return Policy.from_dict(raw), FirewallPolicy.from_dict(raw.get("firewall"))


def safe_message():
    return AgentAction("e1", "comms", "send_message", "Anna", {"text": "Appointment is 3 PM"})


def test_tavily_request_uses_fixed_official_domain_and_no_generated_answer():
    transport = SearchTransport(
        response={
            "request_id": "tvly-1",
            "results": [{
                "title": "Protect yourself from tech support scams",
                "url": "https://support.microsoft.com/example",
                "content": "Microsoft warns customers about unsolicited technical support scams.",
                "score": 0.99,
            }],
        }
    )
    evidence = TavilyClient(transport).check(CLAIMS["microsoft_anydesk"])
    assert evidence.ok
    body, _ = transport.calls[0]
    assert body["include_domains"] == ["microsoft.com"]
    assert body["include_domains_mode"] == "restrict"
    assert body["include_answer"] is False
    assert body["include_raw_content"] is False
    assert body["safe_search"] is True


def test_conflicting_evidence_adds_only_a_scam_risk_signal(data_dir):
    policy, firewall = policies(data_dir)
    action = safe_message()
    base = evaluate_action(action, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=firewall)
    assert base.outcome.value == "ALLOW"

    enriched = add_evidence_risk(action, EvidenceAssessment("conflict", "Official source contradicts claim"))
    assert enriched.risk == {EVIDENCE_CONFLICT_RISK}
    after = evaluate_action(enriched, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=firewall)
    assert RANK[after.outcome] >= RANK[base.outcome]
    assert after.outcome.value == "OWNER"


def test_supporting_evidence_never_removes_preexisting_risk(data_dir):
    policy, firewall = policies(data_dir)
    action = AgentAction("e2", "comms", "send_message", "Anna", {}, risk=frozenset({"scam:model_urgency"}))
    base = evaluate_action(action, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=firewall)
    enriched = add_evidence_risk(action, EvidenceAssessment("support", "source supports factual claim"))
    after = evaluate_action(enriched, policy, channel="voice", frozen=False, history=History(), local_hour=12, firewall=firewall)
    assert enriched.risk == action.risk
    assert RANK[after.outcome] == RANK[base.outcome]


def test_tavily_failure_preserves_base_action_and_never_means_safe():
    transport = SearchTransport(error="timeout")
    model = Model(json.dumps({"status": "support", "summary": "safe", "cited_urls": []}))
    action = safe_message()
    enriched = enrich_fixed_claim(
        "microsoft_anydesk",
        action=action,
        tavily=TavilyClient(transport),
        nemotron=model,
    )
    assert enriched.evidence.ok is False
    assert enriched.assessment.status == "unavailable"
    assert enriched.action == action
    assert model.calls == []


def test_nemotron_cannot_invent_a_citation_or_custom_status():
    evidence = SearchEvidence(
        "microsoft_anydesk",
        "claim",
        "query",
        sources=(),
        error="",
    )
    # No sources means no model call at all.
    model = Model('{"status":"safe","summary":"trust it","cited_urls":["https://attacker.test"]}')
    assessment = assess_with_nemotron(model, evidence)
    assert assessment.status == "unavailable"
    assert model.calls == []


def test_malformed_model_output_yields_no_new_authority_signal():
    from kinlock.tavily_evidence import EvidenceSource

    evidence = SearchEvidence(
        "microsoft_anydesk",
        "claim",
        "query",
        sources=(EvidenceSource("Microsoft", "https://microsoft.com/a", "official text", 1.0),),
    )
    model = Model('{"status":"safe","summary":"looks fine","cited_urls":["https://microsoft.com/a"]}')
    assessment = assess_with_nemotron(model, evidence)
    assert assessment.status == "unavailable"
    assert assessment.risk() == frozenset()


def test_only_urls_returned_by_tavily_can_be_cited():
    from kinlock.tavily_evidence import EvidenceSource

    evidence = SearchEvidence(
        "irs_gift_cards",
        "claim",
        "query",
        sources=(EvidenceSource("IRS", "https://irs.gov/scams", "IRS does not demand gift cards", 0.9),),
    )
    model = Model(json.dumps({
        "status": "conflict",
        "summary": "IRS guidance contradicts the claim",
        "cited_urls": ["https://irs.gov/scams", "https://attacker.test/fake"],
    }))
    assessment = assess_with_nemotron(model, evidence)
    assert assessment.status == "conflict"
    assert assessment.cited_urls == ("https://irs.gov/scams",)
    assert assessment.risk() == {EVIDENCE_CONFLICT_RISK}
