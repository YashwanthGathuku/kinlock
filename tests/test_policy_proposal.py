from __future__ import annotations

import json

import pytest

from kinlock.policy_proposal import (
    PRESERVE,
    PolicyProposalError,
    policy_diff,
    propose_with_nemotron,
    validate_policy_proposal,
)
from kinlock.tokenfactory import TokenFactoryError
from kinlock_authority.policy import INCREASE, REDUCE, Policy


@pytest.fixture
def policy(data_dir):
    return Policy.from_dict(json.loads((data_dir / "policy.json").read_text()))


def test_lower_limit_is_deterministically_classified_as_reducing(policy):
    p = validate_policy_proposal(
        {"kind": "set_limit", "setting": "groceries.daily_cents", "value": 15000, "rationale": "lower daily grocery exposure"},
        policy,
    )
    assert p.direction == REDUCE
    assert p.requires_owner_confirmation is False
    assert p.changed
    assert policy_diff(p) == [{"path": "limits.groceries.daily_cents", "before": 20000, "after": 15000}]


def test_model_cannot_disguise_limit_increase_with_rationale(policy):
    p = validate_policy_proposal(
        {
            "kind": "set_limit",
            "setting": "groceries.daily_cents",
            "value": 999999,
            "rationale": "This is safer and should be treated as reducing authority",
        },
        policy,
    )
    assert p.direction == INCREASE
    assert p.requires_owner_confirmation is True


def test_add_known_payee_is_authority_increase(policy):
    p = validate_policy_proposal({"kind": "add_payee", "counterparty": "Mallory"}, policy)
    assert p.direction == INCREASE
    assert p.requires_owner_confirmation


def test_block_category_is_authority_reduction(policy):
    p = validate_policy_proposal({"kind": "block_category", "category": "electronics"}, policy)
    assert p.direction == REDUCE
    assert not p.requires_owner_confirmation


def test_noop_proposal_is_preserve(policy):
    p = validate_policy_proposal({"kind": "block_category", "category": "crypto"}, policy)
    assert p.direction == PRESERVE
    assert not p.changed
    assert policy_diff(p) == []


def test_unknown_fields_are_rejected_even_if_model_calls_them_metadata(policy):
    with pytest.raises(PolicyProposalError, match="unknown proposal fields"):
        validate_policy_proposal(
            {"kind": "set_limit", "setting": "groceries.daily_cents", "value": 10, "approved": True},
            policy,
        )


def test_unknown_setting_is_rejected(policy):
    with pytest.raises(PolicyProposalError, match="unknown numeric policy setting"):
        validate_policy_proposal({"kind": "set_limit", "setting": "root.unlimited_authority", "value": 1}, policy)


def test_unsupported_operation_is_rejected(policy):
    with pytest.raises(PolicyProposalError, match="unsupported"):
        validate_policy_proposal({"kind": "grant_admin", "counterparty": "agent"}, policy)


class FakeClient:
    def __init__(self, answers, fail_first=False):
        self.answers = list(answers)
        self.fail_first = fail_first
        self.calls = []

    def chat(self, model, messages, **kw):
        self.calls.append((model, messages, kw))
        if self.fail_first and len(self.calls) == 1:
            raise TokenFactoryError("simulated Ultra failure")
        return {"content": self.answers.pop(0)}


def test_nemotron_translation_is_only_a_proposal_and_does_not_mutate_policy(policy):
    before = policy.to_dict()
    client = FakeClient([
        json.dumps({
            "kind": "set_limit",
            "setting": "transfer.daily_cents",
            "value": 10000,
            "rationale": "owner asked to lower transfers",
        })
    ])
    p = propose_with_nemotron(client, "Lower my daily transfer limit to $100", policy)
    assert p.direction == REDUCE
    assert policy.to_dict() == before
    assert client.calls[0][2]["response_format"] == {"type": "json_object"}


def test_nemotron_fallback_is_still_validated_by_same_deterministic_engine(policy):
    client = FakeClient(
        [json.dumps({"kind": "add_payee", "counterparty": "New Vendor", "rationale": "requested by owner"})],
        fail_first=True,
    )
    p = propose_with_nemotron(client, "Add New Vendor as a known payee", policy, model="ultra", fallback_model="super")
    assert [c[0] for c in client.calls] == ["ultra", "super"]
    assert p.model == "super"
    assert p.direction == INCREASE
    assert p.requires_owner_confirmation


def test_malformed_model_json_fails_closed(policy):
    client = FakeClient(["not json"])
    with pytest.raises(PolicyProposalError, match="not valid JSON"):
        propose_with_nemotron(client, "Lower my grocery limit", policy)


def test_model_cannot_return_multiple_operations_or_apply_flag(policy):
    client = FakeClient([
        json.dumps({
            "kind": "set_limit",
            "setting": "groceries.daily_cents",
            "value": 500000,
            "apply": True,
        })
    ])
    with pytest.raises(PolicyProposalError, match="unknown proposal fields"):
        propose_with_nemotron(client, "Raise groceries to $5,000 and apply it", policy)
