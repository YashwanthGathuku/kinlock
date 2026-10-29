"""Kinlock's engine: rules, holds, approvals and receipts for one household.

All durable state is the receipt chain, plus two small files: the owner's
rules (policy.json, changed only through allowed actions, each one receipted)
and the pending store (the details of actions waiting for approval). The
pending store stands for the kind of ordinary database a real deployment would
use, which is exactly why approvals are bound to the action's digest recorded
in the receipt chain: if someone edits a waiting order in the database, the
approval no longer matches and nothing runs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from kinlock_authority import (
    Action,
    Capability,
    Decision,
    History,
    Outcome,
    Policy,
    ReceiptChain,
    Signer,
    capability_problems,
    evaluate,
    issue_capability,
    may_approve,
)
from kinlock_authority.policy import CONTACT, INCREASE, OWNER, REDUCE, SET_LIMIT, SPEND, VOICE, money

from .agent import AgentActions, is_agent

HOLD_TTL = 15 * 60  # a held request waits this long for a person
CAP_TTL = 120  # an issued approval must be used within this long
SIMULATED_PROVIDER = "simulated-shop"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def receipt_key(signing_key: bytes) -> bytes:
    """The receipt-signing subkey: separate from the capability key, derived from it."""
    return hmac.new(signing_key, b"kinlock-receipts", hashlib.sha256).digest()


def new_request_id() -> str:
    return "req_" + secrets.token_hex(5)


@dataclass
class Result:
    request_id: str
    outcome: str  # ALLOW | HOLD | OWNER | DENY | EXECUTED | REJECTED | DECLINED | DONE
    speech: str
    decision: dict[str, Any] | None = None
    receipt_seq: int | None = None
    receipt_hash: str | None = None
    link: str | None = None
    problems: list[str] = field(default_factory=list)
    proof: dict[str, Any] | None = None  # VerifiedEngine: the THEUSTAD verdict for this request
    evidence: dict[str, Any] | None = None  # Gateway: a signed evidence record for a read-only call

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class State:
    frozen: bool = False
    frozen_by: str | None = None
    history: History = field(default_factory=History)
    used_caps: set[str] = field(default_factory=set)
    held: dict[str, dict[str, Any]] = field(default_factory=dict)  # request_id -> held receipt data (open only)
    last_decided: dict[str, Any] | None = None
    receipts: int = 0


class Engine(AgentActions):
    def __init__(
        self,
        data_dir: Path,
        signing_key: bytes,
        public_url: str = "http://127.0.0.1:8770",
        notify: Callable[[str, str], None] | None = None,
        clock: Callable[[], float] = time.time,
        notify_owner: Callable[[str, str], None] | None = None,
        downstream: Any = None,
    ):
        self.data = Path(data_dir)
        # Receipts are HMAC-signed with a subkey of the signing key, so someone who can
        # edit receipts.jsonl cannot rewrite the chain and recompute the hashes.
        self.chain = ReceiptChain(self.data / "receipts.jsonl", key=receipt_key(signing_key))
        self.policy_path = self.data / "policy.json"
        self.pending_path = self.data / "pending.json"
        self.signer = Signer(signing_key)
        self.public_url = public_url.rstrip("/")
        self.notify = notify or (lambda title, link: None)
        # Tells the owner herself whenever a trusted contact decides one of her requests.
        self.notify_owner = notify_owner or (lambda title, link: None)
        self.clock = clock
        self.lock = threading.RLock()
        self.last_capability: Capability | None = None  # kept only so the simulator can stage a replay attack
        self.downstream = downstream  # carries out allowed agent actions (see downstream.py); None = record only

    # -- files -----------------------------------------------------------------------------
    def policy(self) -> Policy:
        return Policy.from_dict(json.loads(self.policy_path.read_text()))

    def _save_policy(self, p: Policy) -> None:
        # The firewall section is not part of the purchase Policy; keep it across rule changes.
        raw = json.loads(self.policy_path.read_text())
        out = p.to_dict()
        if "firewall" in raw:
            out["firewall"] = raw["firewall"]
        _atomic_write_json(self.policy_path, out)

    def _pending(self) -> dict[str, dict[str, Any]]:
        try:
            return json.loads(self.pending_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_pending(self, d: dict[str, dict[str, Any]]) -> None:
        _atomic_write_json(self.pending_path, d)

    def pending_action(self, request_id: str) -> Action | None:
        raw = self._pending().get(request_id)
        return Action.from_dict(raw["action"]) if raw and not is_agent(raw) else None

    # -- time ------------------------------------------------------------------------------
    def _local(self, policy: Policy) -> datetime:
        return datetime.fromtimestamp(self.clock(), ZoneInfo(policy.timezone))

    def _ts(self) -> str:
        return datetime.fromtimestamp(self.clock(), UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _append(self, kind: str, data: dict[str, Any]):
        return self.chain.append(kind, data, ts=self._ts())

    # -- state from receipts ---------------------------------------------------------------
    def state(self, policy: Policy | None = None) -> State:
        policy = policy or self.policy()
        tz = ZoneInfo(policy.timezone)
        today = self._local(policy).date()
        st = State()
        spent: dict[str, int] = {}
        count: dict[str, int] = {}
        for r in self.chain.receipts():
            st.receipts += 1
            d = r.data
            k = r.kind
            if k == "frozen":
                st.frozen, st.frozen_by = True, d.get("by")
            elif k == "unfrozen":
                st.frozen, st.frozen_by = False, None
            elif k == "decided":
                st.last_decided = {**d, "seq": r.seq, "hash": r.hash, "ts": r.ts}
            elif k == "held":
                st.held[d["request_id"]] = {**d, "seq": r.seq}
            elif k in ("executed", "declined", "cancelled", "expired"):
                st.held.pop(d.get("request_id", ""), None)
            if d.get("cap_id") and k in ("executed", "approval_rejected", "downstream_failed"):
                st.used_caps.add(d["cap_id"])
            if k == "executed" and d.get("kind") in ("purchase", "transfer"):
                when = datetime.fromisoformat(r.ts.replace("Z", "+00:00")).astimezone(tz).date()
                if when == today:
                    cat = Policy._norm(d.get("category") or "other")
                    spent[cat] = spent.get(cat, 0) + int(d.get("amount_cents", 0))
                    count[cat] = count.get(cat, 0) + 1
            if k == "executed" and d.get("kind") == "agent" and d.get("spend_category"):
                when = datetime.fromisoformat(r.ts.replace("Z", "+00:00")).astimezone(tz).date()
                if when == today:
                    cat = Policy._norm(d["spend_category"])
                    spent[cat] = spent.get(cat, 0) + int(d.get("amount_cents", 0))
                    count[cat] = count.get(cat, 0) + 1
        st.history = History(spent, count)
        return st

    # -- speech ----------------------------------------------------------------------------
    @staticmethod
    def _what(a: Action) -> str:
        if a.kind == "transfer":
            return f"a {money(a.amount_cents)} transfer to {a.counterparty}"
        thing = a.items[0] if len(a.items) == 1 else (f"your {a.category}" if a.category else "that order")
        return f"{thing} from {a.counterparty} for {money(a.amount_cents)}"

    def _speech(self, a: Action, d: Decision, policy: Policy, extra: str = "") -> str:
        reasons = d.reasons
        short = "; ".join(reasons[:2])
        if d.direction == SPEND:
            if d.outcome == Outcome.ALLOW:
                return f"Done. I ordered {self._what(a)}." if a.kind == "purchase" else f"Done. I sent {self._what(a)}."
            if d.outcome == Outcome.DENY:
                if any(c.code == "lock" and not c.ok for c in d.checks):
                    return "I can't do that. Your safety lock is on, so no purchases or transfers will go through. Only you can lift it, from your secure page."
                return f"I didn't do that. {reasons[0]}." if reasons else "I didn't do that."
            if d.outcome == Outcome.OWNER:
                return f"I've held {self._what(a)}. {reasons[0] if reasons else 'It needs you'}. Approve it from your secure page if it's really you."
            return f"I've held {self._what(a)}, because {short}. {extra}".strip()
        if d.direction == REDUCE:
            return extra or "Done."
        if d.direction == INCREASE:
            if d.outcome == Outcome.ALLOW:
                return extra or "Done."
            return "For your protection, voice can lower your limits or lock spending, but it can never raise a limit, add a shop or unlock spending. You can do that from your secure page."
        return "I can't do that one."

    # -- the main entry: someone asks for an action ----------------------------------------
    def request(self, action: Action, channel: str = VOICE, by: str | None = None) -> Result:
        with self.lock:
            policy = self.policy()
            if action.kind in ("purchase", "transfer"):
                # The category comes from the owner's merchant list, never from the caller,
                # so "a gift card, category: other" is judged as a gift card.
                action = replace(action, category=policy.resolve_category(action))
            st = self.state(policy)
            local = self._local(policy)
            d = evaluate(action, policy, channel=channel, frozen=st.frozen, history=st.history, local_hour=local.hour)
            by = by or channel
            dg = action.digest()
            r = self._append("decided", {"request_id": action.request_id, "channel": channel, "by": by, "action": action.to_dict(), "digest": dg, "decision": d.to_dict()})

            if d.outcome == Outcome.DENY:
                self._append("denied", {"request_id": action.request_id, "reasons": d.reasons})
                return Result(action.request_id, "DENY", self._speech(action, d, policy), d.to_dict(), r.seq, r.hash)

            if d.direction == REDUCE or (d.direction == INCREASE and d.outcome == Outcome.ALLOW):
                extra = self._apply_rule_action(action, by, policy)
                last = self._append("executed", {"request_id": action.request_id, "kind": action.kind, "digest": dg, "by": by})
                return Result(action.request_id, "DONE", self._speech(action, d, policy, extra), d.to_dict(), last.seq, last.hash)

            # Spending.
            if d.outcome == Outcome.ALLOW:
                last = self._execute(action, dg, by=f"rules ({by})")
                return Result(action.request_id, "ALLOW", self._speech(action, d, policy) + f" Receipt {last.seq}.", d.to_dict(), last.seq, last.hash)

            # HOLD or OWNER: park it and ask a person.
            contact = policy.contacts[0] if policy.contacts else None
            ok_for_contact, _ = may_approve(d, role=CONTACT, amount_cents=action.amount_cents, contact=contact)
            needs = "contact" if (d.outcome == Outcome.HOLD and contact and ok_for_contact) else "owner"
            token = secrets.token_urlsafe(24)
            pend = self._pending()
            pend[action.request_id] = {"action": action.to_dict(), "held_at": self.clock()}
            self._save_pending(pend)
            held = self._append("held", {
                "request_id": action.request_id,
                "digest": dg,
                "needs": needs,
                "contact_id": contact.id if (needs == "contact" and contact) else None,
                "link_sha256": _sha(token),
                "expires_at": self.clock() + HOLD_TTL,
                "reasons": d.reasons,
            })
            if needs == "contact" and contact:
                link = f"{self.public_url}/approve/{token}"
                self.notify(f"{policy.owner} is asking: {money(action.amount_cents)} at {action.counterparty}", link)
                extra = f"I've asked {contact.name} to approve this exact order."
            else:
                link = f"{self.public_url}/owner"
                extra = "Only you can approve it, from your secure page."
            return Result(action.request_id, d.outcome.value, self._speech(action, d, policy, extra), d.to_dict(), held.seq, held.hash, link=link)

    def _execute(self, action: Action, dg: str, by: str, cap_id: str | None = None):
        # The action provider is simulated: Kinlock records what would be bought or sent.
        pend = self._pending()
        if pend.pop(action.request_id, None) is not None:
            self._save_pending(pend)
        return self._append("executed", {
            "request_id": action.request_id,
            "kind": action.kind,
            "digest": dg,
            "amount_cents": action.amount_cents,
            "counterparty": action.counterparty,
            "category": action.category,
            "items": list(action.items),
            "by": by,
            "cap_id": cap_id,
            "provider": SIMULATED_PROVIDER,
        })

    def _apply_rule_action(self, action: Action, by: str, policy: Policy) -> str:
        k = action.kind
        if k == "freeze":
            self._append("frozen", {"by": by})
            n = self._cancel_all(by, "spending was frozen")
            contact = policy.contacts[0] if policy.contacts else None
            if contact:
                self.notify(f"{policy.owner} froze her spending", f"{self.public_url}/owner")
            told = f" and let {contact.name} know" if contact else ""
            waiting = f" I cancelled {n} waiting request{'s' if n != 1 else ''}{told}." if n else (f" I let {contact.name} know." if contact else "")
            return "Spending is frozen. No purchases or transfers will go through until you unlock it from your secure page." + waiting
        if k == "unfreeze":
            self._append("unfrozen", {"by": by})
            return "Spending is unlocked."
        if k == "cancel_pending":
            n = self._cancel_all(by, "cancelled on request") if not action.counterparty else self._cancel_one(action.counterparty, by)
            return f"Cancelled {n} waiting request{'s' if n != 1 else ''}." if n else "There was nothing waiting."
        before = policy.to_dict()
        after = policy.apply(action)
        self._save_policy(after)
        self._append("policy_changed", {"by": by, "action": action.to_dict(), "before_sha256": _sha(json.dumps(before, sort_keys=True)), "after": after.to_dict()})
        if k == SET_LIMIT:
            name = action.setting.replace("_cents", "").replace(".", " ").replace("_", " ")
            val = money(action.value) if action.setting.endswith("_cents") else str(action.value)
            return f"Done. Your {name} is now {val}."
        return "Done. Your rules are updated."

    def _cancel_all(self, by: str, reason: str) -> int:
        st = self.state()
        n = 0
        for rid in list(st.held):
            n += self._cancel_one(rid, by, reason)
        return n

    def _cancel_one(self, request_id: str, by: str, reason: str = "cancelled on request") -> int:
        pend = self._pending()
        pend.pop(request_id, None)
        self._save_pending(pend)
        if request_id in self.state().held:
            self._append("cancelled", {"request_id": request_id, "by": by, "reason": reason})
            return 1
        return 0

    # -- the trusted contact's page --------------------------------------------------------
    def _held_by_token(self, token: str) -> dict[str, Any] | None:
        h = _sha(token)
        for r in self.chain.receipts():
            if r.kind == "held" and (r.data.get("link_sha256") == h or h in (r.data.get("voter_links") or {})):
                return r.data
        return None

    def _voter_for(self, held: dict[str, Any], token: str) -> str:
        return (held.get("voter_links") or {}).get(_sha(token), "")

    def contact_view(self, token: str) -> dict[str, Any] | None:
        with self.lock:
            held = self._held_by_token(token)
            if not held:
                return None
            if is_agent(held):
                return self.agent_view(held, self._voter_for(held, token))
            policy = self.policy()
            st = self.state(policy)
            action = self.pending_action(held["request_id"])
            open_ = held["request_id"] in st.held
            contact = policy.contact(held.get("contact_id") or "")
            return {
                "request_id": held["request_id"],
                "open": open_ and action is not None and self.clock() <= held["expires_at"],
                "action": action.to_dict() if action else None,
                "digest": action.digest() if action else None,
                "reasons": held.get("reasons", []),
                "owner": policy.owner,
                "contact": contact.name if contact else None,
                "needs": held["needs"],
                "frozen": st.frozen,
            }

    def contact_decide(self, token: str, shown_digest: str, approve: bool, choice: str | None = None, comment: str = "") -> Result:
        held = self._held_by_token(token)
        if is_agent(held):
            return self._agent_contact_decide(token, held, shown_digest, choice or ("approve" if approve else "decline"), comment)
        res = self._contact_decide(token, shown_digest, approve)
        if res.outcome in ("EXECUTED", "DECLINED"):
            with self.lock:
                policy = self.policy()
                action = self._action_from_receipts(res.request_id)
                what = self._what(action) if action else "a request"
                held = self._held_by_token(token) or {}
                contact = policy.contact(held.get("contact_id") or "")
                who = contact.name if contact else "Your trusted contact"
                verb = "approved" if res.outcome == "EXECUTED" else "declined"
                title = f"{who} {verb} {what}"
                self._append("owner_notified", {"request_id": res.request_id, "by": f"contact:{contact.id}" if contact else "contact", "decision": verb, "title": title})
                self.notify_owner(title, f"{self.public_url}/owner")
        return res

    def _agent_contact_decide(self, token: str, held: dict[str, Any], shown_digest: str, choice: str, comment: str) -> Result:
        voter = self._voter_for(held, token)
        rid = held["request_id"]
        if choice not in ("approve", "decline", "pause", "resume"):
            return Result(rid, "REJECTED", "Unknown choice.", problems=["unknown choice"])
        if shown_digest != held["digest"]:
            with self.lock:
                res = self._reject(rid, None, ["The request changed after it was held, so the approval doesn't match it"], voter)
                self._cancel_one(rid, "kinlock", "details changed after it was held")
            return res
        res = self.agent_vote(rid, voter, choice, comment)
        if res.outcome in ("EXECUTED", "DECLINED", "RECORDED"):
            with self.lock:
                policy = self.policy()
                what = self._what_any(next((r.data for r in self.chain.receipts() if r.kind == "decided" and r.data.get("request_id") == rid), None))
                verb = {"approve": "approved", "decline": "declined", "pause": "paused", "resume": "resumed"}[choice]
                title = f"{self._who(voter, policy)} {verb}: {what}"
                self._append("owner_notified", {"request_id": rid, "by": voter, "decision": verb, "title": title})
                self.notify_owner(title, f"{self.public_url}/owner")
        return res

    def _action_from_receipts(self, request_id: str) -> Action | None:
        for r in self.chain.receipts():
            if r.kind == "decided" and r.data.get("request_id") == request_id and not is_agent(r.data):
                return Action.from_dict(r.data["action"])
        return None

    def contact_decisions(self) -> list[dict[str, Any]]:
        """Every approval or decline by a trusted contact, newest first, for the owner's page."""
        out = []
        for r in self.chain.receipts():
            if r.kind == "owner_notified":
                out.append({"seq": r.seq, "ts": r.ts, "request_id": r.data["request_id"], "by": r.data["by"], "decision": r.data["decision"], "title": r.data["title"]})
        return list(reversed(out))

    def _contact_decide(self, token: str, shown_digest: str, approve: bool) -> Result:
        with self.lock:
            held = self._held_by_token(token)
            if not held:
                return Result("", "REJECTED", "That link isn't valid.", problems=["unknown link"])
            rid = held["request_id"]
            policy = self.policy()
            st = self.state(policy)
            contact = policy.contact(held.get("contact_id") or "")
            if held["needs"] != "contact" or contact is None:
                return self._reject(rid, None, ["This request needs the owner herself"], "contact")
            if rid not in st.held:
                return self._reject(rid, None, ["This request is no longer waiting"], f"contact:{contact.id}")
            if self.clock() > held["expires_at"]:
                self._append("expired", {"request_id": rid})
                return self._reject(rid, None, ["This request expired"], f"contact:{contact.id}")
            action = self.pending_action(rid)
            current = action.digest() if action else None
            if current != held["digest"] or shown_digest != held["digest"]:
                res = self._reject(rid, None, ["The request changed after it was held, so the approval doesn't match it"], f"contact:{contact.id}")
                self._cancel_one(rid, "kinlock", "details changed after it was held")
                return res
            if not approve:
                self._append("declined", {"request_id": rid, "by": f"contact:{contact.id}"})
                pend = self._pending()
                pend.pop(rid, None)
                self._save_pending(pend)
                return Result(rid, "DECLINED", f"Declined. {policy.owner}'s request was not carried out.")
            cap = issue_capability(self.signer, request_id=rid, action_digest=held["digest"], approver=f"contact:{contact.id}", role=CONTACT, ceiling_cents=contact.ceiling_cents, now=self.clock(), ttl=CAP_TTL)
            self._append("approval_issued", {"request_id": rid, "cap_id": cap.cap_id, "approver": cap.approver, "expires_at": cap.expires_at, "digest": cap.action_digest})
            self.last_capability = cap
            return self.execute_with(cap)

    # -- the owner's page ------------------------------------------------------------------
    def owner_decide(self, request_id: str, approve: bool) -> Result:
        with self.lock:
            st = self.state()
            held = st.held.get(request_id)
            if not held:
                return Result(request_id, "REJECTED", "That request is no longer waiting.", problems=["not waiting"])
            if is_agent(held):
                return self.agent_vote(request_id, OWNER, "approve" if approve else "decline", role=OWNER)
            if self.clock() > held["expires_at"]:
                self._append("expired", {"request_id": request_id})
                pend = self._pending()
                pend.pop(request_id, None)
                self._save_pending(pend)
                return self._reject(request_id, None, ["This request expired"], "owner")
            if not approve:
                self._append("declined", {"request_id": request_id, "by": "owner"})
                pend = self._pending()
                pend.pop(request_id, None)
                self._save_pending(pend)
                return Result(request_id, "DECLINED", "Declined.")
            _ = self.policy()
            cap = issue_capability(self.signer, request_id=request_id, action_digest=held["digest"], approver="owner", role=OWNER, ceiling_cents=10**12, now=self.clock(), ttl=CAP_TTL)
            self._append("approval_issued", {"request_id": request_id, "cap_id": cap.cap_id, "approver": "owner", "expires_at": cap.expires_at, "digest": cap.action_digest})
            self.last_capability = cap
            return self.execute_with(cap)

    # -- releasing a held action with a capability ----------------------------------------
    def execute_with(self, cap: Capability) -> Result:
        if is_agent(self._pending().get(cap.request_id)):
            return self.execute_agent_with(cap)
        with self.lock:
            policy = self.policy()
            st = self.state(policy)
            action = self.pending_action(cap.request_id)
            held = st.held.get(cap.request_id)
            current = action.digest() if action else None
            amount = action.amount_cents if action else 0
            problems = capability_problems(self.signer, cap, request_id=cap.request_id, current_digest=current, amount_cents=amount, used=st.used_caps, now=self.clock())
            if held and current and held["digest"] != current and "The request changed after it was approved" not in problems:
                problems.append("The request changed after it was held")
            if not held and "That request is no longer waiting" not in problems:
                problems.append("That request is no longer waiting")
            if action and not problems:
                # The rules run again at the moment of release, with today's totals as they are now.
                d = evaluate(action, policy, channel=cap.role, frozen=st.frozen, history=st.history, local_hour=self._local(policy).hour)
                contact = policy.contact(cap.approver.split(":", 1)[1]) if cap.role == CONTACT else None
                ok, why = may_approve(d, role=cap.role, amount_cents=action.amount_cents, contact=contact)
                if not ok:
                    problems.append(why)
                if st.frozen:
                    problems.append("Spending is frozen")
            if problems:
                return self._reject(cap.request_id, cap.cap_id, sorted(set(problems)), cap.approver)
            last = self._execute(action, current, by=cap.approver, cap_id=cap.cap_id)
            return Result(cap.request_id, "EXECUTED", f"Approved and done: {self._what(action)}. Receipt {last.seq}.", None, last.seq, last.hash)

    def _reject(self, request_id: str, cap_id: str | None, problems: list[str], by: str) -> Result:
        r = self._append("approval_rejected", {"request_id": request_id, "cap_id": cap_id, "problems": problems, "by": by})
        return Result(request_id, "REJECTED", "Not carried out. " + " ".join(p.rstrip(".") + "." for p in problems), None, r.seq, r.hash, problems=problems)

    # -- simulator-only attacks (clearly labelled in the UI) -------------------------------
    def attack_tamper(self, request_id: str | None, amount_cents: int, counterparty: str) -> dict[str, Any]:
        """Edit a waiting order in the pending store, as someone with database access could."""
        with self.lock:
            pend = self._pending()
            rid = request_id or next(iter(pend), None)
            if not rid or rid not in pend:
                return {"ok": False, "detail": "Nothing is waiting to tamper with."}
            if is_agent(pend[rid]):
                pend[rid]["agent"]["target"] = counterparty
                self._save_pending(pend)
                return {"ok": True, "request_id": rid, "detail": f"The waiting action now points at {counterparty}."}
            pend[rid]["action"]["amount_cents"] = int(amount_cents)
            pend[rid]["action"]["counterparty"] = counterparty
            self._save_pending(pend)
            return {"ok": True, "request_id": rid, "detail": f"The waiting order now says {money(amount_cents)} at {counterparty}."}

    def attack_replay(self) -> Result:
        """Present the last approval again, as someone who copied it could."""
        if self.last_capability is None:
            return Result("", "REJECTED", "There is no approval to replay yet.", problems=["nothing to replay"])
        return self.execute_with(self.last_capability)

    # -- read models for pages and tools ---------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            policy = self.policy()
            st = self.state(policy)
            report = self.chain.verify()
            pend = self._pending()
            waiting = []
            for rid, h in st.held.items():
                entry = pend.get(rid, {})
                if is_agent(entry):
                    v = self.agent_view(h, OWNER)
                    waiting.append({"request_id": rid, "needs": h["needs"], "action": None, "agent": v["action"], "what": v["what"], "category": v["category"], "ready_at": v["ready_at"], "approvals": v["approvals"], "comments": v["comments"], "state": v["state"], "reasons": h.get("reasons", []), "digest": h["digest"]})
                    continue
                a = entry.get("action")
                waiting.append({"request_id": rid, "needs": h["needs"], "action": a, "reasons": h.get("reasons", []), "digest": h["digest"]})
            recent = list(self.chain.receipts())[-12:]
            return {
                "owner": policy.owner,
                "frozen": st.frozen,
                "today": {cat: {"spent_cents": c, "count": st.history.count.get(cat, 0), "daily_cents": policy.limits_for(cat).daily_cents} for cat, c in st.history.spent_cents.items()},
                "waiting": waiting,
                "last_decided": st.last_decided,
                "chain": {"ok": report.ok, "receipts": report.receipts, "head": report.head, "broken_at": report.broken_at, "reason": report.reason},
                "recent": [{"seq": r.seq, "ts": r.ts, "kind": r.kind, "data": r.data, "hash": r.hash} for r in reversed(recent)],
                "policy": policy.to_dict(),
                "provider": SIMULATED_PROVIDER,
                "contact_decisions": self.contact_decisions(),
            }
