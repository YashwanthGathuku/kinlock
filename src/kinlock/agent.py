"""The authority firewall inside the engine: actions in every category, not only payments.

An `AgentAction` (send a message, unlock a door, install an app, change a recovery
email...) goes through the same steps as a purchase: the fixed rules decide, a
receipt records the decision, anything held waits for the right people, and the
approval is a signed single-use capability bound to the action's digest. On top
of that, held agent actions can carry a cool-off and a quorum, and a supporter
can pause one. What actually performs an allowed action is the engine's
`downstream` (see downstream.py); with none connected, it is recorded only.

This is a mixin for `Engine`, kept in its own file so the purchase path in
engine.py stays as it was.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo

from kinlock_authority import (
    AgentAction,
    Capability,
    FirewallPolicy,
    Outcome,
    Vote,
    capability_problems,
    describe_action,
    evaluate_action,
    issue_capability,
    may_approve_action,
    release_problems,
    tally,
)
from kinlock_authority.firewall import MONEY, REDUCE
from kinlock_authority.policy import CONTACT, OWNER, VOICE

from .downstream import DownstreamError

if TYPE_CHECKING:
    from .engine import Engine as _E
    from .engine import Result

SCHEMA = "kinlock.action/1"
QUORUM_TTL = 24 * 3600  # a quorum vote stays open a day
CONFIRM_WINDOW = 3 * 24 * 3600  # after a cool-off ends, the owner has this long to confirm
CATEGORY_LABELS = {
    "money": "Money",
    "access": "Computer and remote access",
    "identity": "Accounts and identity",
    "data": "Personal information",
    "health": "Health",
    "home": "Home",
    "legal": "Legal",
    "comms": "Messages and calls",
}
REMOTE_ADVICE = " If someone on the phone asked for this, hang up. Real companies never ask to take over your computer."


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, "Something Kinlock doesn't recognise")


def is_agent(entry: dict[str, Any] | None) -> bool:
    return bool(entry) and entry.get("schema") == SCHEMA


class AgentActions:
    """Mixed into Engine. Uses the engine's chain, pending store, signer, clock and notifier."""

    downstream: Any = None

    # -- policy ----------------------------------------------------------------------------
    def firewall(self: _E) -> FirewallPolicy:
        import json

        return FirewallPolicy.from_dict(json.loads(self.policy_path.read_text()).get("firewall"))

    def _with_spend_category(self: _E, action: AgentAction, policy) -> AgentAction:
        if action.category != MONEY:
            return action
        legacy = action.legacy()
        resolved = policy.resolve_category(legacy)
        return AgentAction(**{**action.__dict__, "details": {**action.details, "category": resolved}})

    def _evaluate_agent(self: _E, action: AgentAction, channel: str, policy=None, st=None):
        policy = policy or self.policy()
        st = st or self.state(policy)
        return evaluate_action(action, policy, channel=channel, frozen=st.frozen, history=st.history, local_hour=self._local(policy).hour, firewall=self.firewall())

    # -- words -----------------------------------------------------------------------------
    def _agent_speech(self: _E, action: AgentAction, d, policy, extra: str = "") -> str:
        what = describe_action(action)
        reason = d.reasons[0] if d.reasons else ""
        remote = any(s.startswith("remote_tool:") for s in d.signals) or action.verb in ("grant_screen_control", "share_screen", "start_remote_session", "launch_remote_tool")
        if d.outcome == Outcome.ALLOW:
            return f"Done. I {what}." if d.direction == REDUCE else f"Done. I went ahead: {what}."
        if d.outcome == Outcome.DENY:
            if any(c.code == "lock" and not c.ok for c in d.checks):
                return f"I can't {what}. Your safety lock is on, so only things that make you safer will go through."
            return f"I won't {what}. {reason}." + (REMOTE_ADVICE if remote else "")
        held = f"I've held that: {what}. {reason}." if reason else f"I've held that: {what}."
        return f"{held} {extra}".strip() + (REMOTE_ADVICE if remote and d.outcome == Outcome.OWNER and "inbound_call" in d.signals else "")

    # -- the main entry ----------------------------------------------------------------------
    def request_agent(self: _E, action: AgentAction, channel: str = VOICE, by: str | None = None, call: dict[str, Any] | None = None) -> Result:
        """Decide one agent action. `call` is the downstream tool call to make if it runs."""
        from .engine import HOLD_TTL, Result, _sha

        with self.lock:
            policy = self.policy()
            action = self._with_spend_category(action, policy)
            st = self.state(policy)
            d = self._evaluate_agent(action, channel, policy, st)
            fw = self.firewall()
            by = by or channel
            dg = action.digest()
            r = self._append("decided", {"request_id": action.request_id, "schema": SCHEMA, "channel": channel, "by": by, "action": action.to_dict(), "digest": dg, "decision": d.to_dict(), "call": call})

            if d.outcome == Outcome.DENY:
                self._append("denied", {"request_id": action.request_id, "reasons": d.reasons})
                return Result(action.request_id, "DENY", self._agent_speech(action, d, policy), d.to_dict(), r.seq, r.hash)

            if d.outcome == Outcome.ALLOW:
                res = self._run_agent(action, dg, call, by=f"rules ({by})")
                if res.outcome == "FAILED":
                    return res
                speech = self._agent_speech(action, d, policy)
                return Result(action.request_id, "ALLOW" if d.direction != REDUCE else "DONE", f"{speech} Receipt {res.receipt_seq}.", d.to_dict(), res.receipt_seq, res.receipt_hash)

            # HOLD or OWNER: park it and ask the right people.
            now = self.clock()
            contact = policy.contacts[0] if policy.contacts else None
            links: dict[str, str] = {}  # token -> voter
            if d.quorum:
                needs = "quorum"
                for m in d.quorum.members:
                    if m != OWNER and may_approve_action(d, action, approver=m, role=CONTACT, contact=contact, firewall=fw)[0]:
                        links[secrets.token_urlsafe(24)] = m
            elif d.outcome == Outcome.HOLD and contact and may_approve_action(d, action, approver=f"contact:{contact.id}", role=CONTACT, contact=contact, firewall=fw)[0]:
                needs = "contact"
                links[secrets.token_urlsafe(24)] = f"contact:{contact.id}"
            else:
                needs = "owner"
            ready_at = now + d.cooloff_seconds
            if d.cooloff_seconds:
                expires = ready_at + CONFIRM_WINDOW
            elif d.quorum:
                expires = now + QUORUM_TTL
            else:
                expires = now + HOLD_TTL
            pend = self._pending()
            pend[action.request_id] = {"schema": SCHEMA, "agent": action.to_dict(), "call": call, "channel": channel, "held_at": now}
            self._save_pending(pend)
            held = self._append("held", {
                "request_id": action.request_id,
                "schema": SCHEMA,
                "digest": dg,
                "category": action.category,
                "needs": needs,
                "contact_id": contact.id if (needs == "contact" and contact) else None,
                "voter_links": {_sha(t): v for t, v in links.items()},
                "link_sha256": _sha(next(iter(links))) if needs == "contact" else None,
                "held_at": now,
                "ready_at": ready_at,
                "expires_at": expires,
                "reasons": d.reasons,
            })
            what = describe_action(action)
            link = f"{self.public_url}/owner"
            for t, voter in links.items():
                person = fw.person(voter)
                name = person.name if person else (contact.name if contact and voter == f"contact:{contact.id}" else voter)
                url = f"{self.public_url}/approve/{t}"
                link = url if needs == "contact" else link
                self.notify(f"{name}: {policy.owner} is asking to {what}", url)
            if needs == "contact" and contact:
                extra = f"I've asked {contact.name} to approve this exact action."
            elif needs == "quorum":
                extra = f"This needs {d.quorum.required} of your people to agree{', including you' if d.quorum.owner_final else ''}. I've asked them."
            else:
                extra = "Only you can approve it, from your secure page."
            if d.cooloff_seconds:
                extra += f" For your safety it can't happen for {self._duration(d.cooloff_seconds)}, and then only if you confirm it."
            return Result(action.request_id, d.outcome.value, self._agent_speech(action, d, policy, extra), d.to_dict(), held.seq, held.hash, link=link)

    @staticmethod
    def _duration(seconds: int) -> str:
        h = seconds // 3600
        if h and seconds % 3600 == 0:
            return f"{h} hours" if h != 1 else "an hour"
        return f"{max(1, seconds // 60)} minutes"

    def _run_agent(self: _E, action: AgentAction, dg: str, call: dict[str, Any] | None, by: str, cap_id: str | None = None) -> Result:
        """Carry out an allowed action through the downstream, and receipt what happened."""
        from .engine import SIMULATED_PROVIDER, Result

        pend = self._pending()
        if pend.pop(action.request_id, None) is not None:
            self._save_pending(pend)
        base = {"request_id": action.request_id, "schema": SCHEMA, "kind": "agent", "category": action.category, "verb": action.verb, "target": action.target, "digest": dg, "by": by, "cap_id": cap_id}
        if action.category == MONEY:
            base |= {"amount_cents": action.amount_cents, "spend_category": action.details.get("category") or "other"}
        if call and self.downstream is not None:
            try:
                out = self.downstream.call(call["tool"], dict(call.get("arguments") or {}))
            except DownstreamError as e:
                r = self._append("downstream_failed", {**base, "tool": call["tool"], "error": str(e)})
                return Result(action.request_id, "FAILED", f"Kinlock allowed it, but the service refused: {e}. Nothing was done.", None, r.seq, r.hash, problems=[str(e)])
            r = self._append("executed", {**base, "provider": "downstream", "tool": call["tool"], "result": str(out)[:200]})
        else:
            r = self._append("executed", {**base, "provider": SIMULATED_PROVIDER if not call else "none connected"})
        return Result(action.request_id, "EXECUTED", "", None, r.seq, r.hash)

    # -- votes and release -------------------------------------------------------------------
    def _votes(self: _E, request_id: str) -> list[Vote]:
        return [Vote(r.data["voter"], r.data["choice"], r.data.get("comment", "")) for r in self.chain.receipts() if r.kind == "vote" and r.data.get("request_id") == request_id]

    def agent_vote(self: _E, request_id: str, voter: str, choice: str, comment: str = "", role: str = CONTACT) -> Result:
        """Record one person's approve / decline / pause / resume, and release the action if that completes it."""
        from .engine import Result

        with self.lock:
            policy = self.policy()
            st = self.state(policy)
            held = st.held.get(request_id)
            raw = self._pending().get(request_id)
            if not held or not is_agent(raw):
                return Result(request_id, "REJECTED", "That request is no longer waiting.", problems=["not waiting"])
            if self.clock() > held["expires_at"]:
                self._append("expired", {"request_id": request_id})
                self._cancel_one(request_id, "kinlock", "expired")
                return self._reject(request_id, None, ["This request expired"], voter)
            action = AgentAction.from_dict(raw["agent"])
            if action.digest() != held["digest"]:
                res = self._reject(request_id, None, ["The request changed after it was held, so the approval doesn't match it"], voter)
                self._cancel_one(request_id, "kinlock", "details changed after it was held")
                return res
            d = self._evaluate_agent(action, raw.get("channel", VOICE), policy, st)
            fw = self.firewall()
            contact = policy.contact(voter.split(":", 1)[1]) if voter.startswith("contact:") else None
            if choice == "approve":
                ok, why = may_approve_action(d, action, approver=voter, role=role, contact=contact, firewall=fw)
                if not ok:
                    return self._reject(request_id, None, [why], voter)
                if voter == OWNER and self.clock() < held.get("ready_at", 0):
                    when = self._when(held["ready_at"], policy)
                    return Result(request_id, "WAITING", f"Not yet. For your safety this has a cool-off. You can confirm it after {when}.", problems=["cool-off"])
            self._append("vote", {"request_id": request_id, "voter": voter, "choice": choice, "comment": comment[:500]})
            votes = self._votes(request_id)
            t = tally(d, action, votes, firewall=fw)
            if t.state == "declined" or (choice == "decline" and (voter == OWNER or held["needs"] == "contact")):
                self._append("declined", {"request_id": request_id, "by": voter})
                pend = self._pending()
                pend.pop(request_id, None)
                self._save_pending(pend)
                return Result(request_id, "DECLINED", f"Declined. {policy.owner}'s request was not carried out." if voter != OWNER else "Declined.")
            problems = release_problems(d, action, votes, requested_at=held.get("held_at", held.get("ready_at", 0)), now=self.clock(), firewall=fw)
            if choice != "approve":
                word = {"pause": "Paused. Nothing will happen until you or the owner resume it.", "resume": "Resumed.", "decline": "Your no is recorded."}.get(choice, "Recorded.")
                if choice != "resume" or problems:
                    return Result(request_id, "RECORDED", word)
                # Resuming a hold that already has every approval it needs releases it,
                # on the authority of the approval that completed it (the owner's, when she's final).
                approvers = [v.voter for v in votes if v.choice == "approve"]
                if not approvers:
                    return Result(request_id, "RECORDED", word)
                voter = OWNER if OWNER in approvers else approvers[-1]
                contact = policy.contact(voter.split(":", 1)[1]) if voter.startswith("contact:") else None
            if problems:
                return Result(request_id, "RECORDED", "Your approval is recorded. " + " ".join(p + "." for p in problems), problems=problems)
            ceiling = 10**12 if voter == OWNER else (contact.ceiling_cents if contact else 0)
            cap = issue_capability(self.signer, request_id=request_id, action_digest=held["digest"], approver=voter, role=OWNER if voter == OWNER else CONTACT, ceiling_cents=max(ceiling, action.amount_cents if voter == OWNER else 0), now=self.clock(), ttl=120)
            self._append("approval_issued", {"request_id": request_id, "cap_id": cap.cap_id, "approver": voter, "expires_at": cap.expires_at, "digest": cap.action_digest})
            self.last_capability = cap
            return self.execute_agent_with(cap)

    def execute_agent_with(self: _E, cap: Capability) -> Result:
        from .engine import Result

        with self.lock:
            policy = self.policy()
            st = self.state(policy)
            raw = self._pending().get(cap.request_id)
            held = st.held.get(cap.request_id)
            action = AgentAction.from_dict(raw["agent"]) if is_agent(raw) else None
            current = action.digest() if action else None
            problems = capability_problems(self.signer, cap, request_id=cap.request_id, current_digest=current, amount_cents=action.amount_cents if action else 0, used=st.used_caps, now=self.clock())
            if not held and "That request is no longer waiting" not in problems:
                problems.append("That request is no longer waiting")
            if held and current and held["digest"] != current and "The request changed after it was approved" not in problems:
                problems.append("The request changed after it was held")
            if action and held and not problems:
                # The rules run again at release: a lock turned on meanwhile, or new limits, still count.
                d = self._evaluate_agent(action, raw.get("channel", VOICE), policy, st)
                problems += release_problems(d, action, self._votes(cap.request_id), requested_at=held.get("held_at", 0), now=self.clock(), firewall=self.firewall())
                if st.frozen and d.direction != REDUCE:
                    problems.append("The safety lock is on")
            if problems:
                return self._reject(cap.request_id, cap.cap_id, sorted(set(problems)), cap.approver)
            res = self._run_agent(action, current, raw.get("call"), by=cap.approver, cap_id=cap.cap_id)
            if res.outcome == "FAILED":
                return res
            return Result(cap.request_id, "EXECUTED", f"Approved and done: {describe_action(action)}. Receipt {res.receipt_seq}.", None, res.receipt_seq, res.receipt_hash)

    # -- reading back ------------------------------------------------------------------------
    def _when(self: _E, ts: float, policy=None) -> str:
        policy = policy or self.policy()
        t = datetime.fromtimestamp(ts, ZoneInfo(policy.timezone))
        today = self._local(policy).date()
        day = "today" if t.date() == today else ("tomorrow" if (t.date() - today).days == 1 else t.strftime("%A %B %-d"))
        return f"{t.strftime('%-I:%M %p')} {day}"

    def spoken_receipts(self: _E, count: int = 5) -> list[str]:
        """The most recent receipts, newest first, one plain sentence each, for reading aloud."""
        policy = self.policy()
        out: list[str] = []
        decided: dict[str, dict[str, Any]] = {}
        receipts = list(self.chain.receipts())
        for r in receipts:
            if r.kind == "decided":
                decided[r.data["request_id"]] = r.data
        for r in reversed(receipts):
            if len(out) >= count:
                break
            s = self._sentence(r, decided, policy)
            if s:
                out.append(s)
        return out

    def _what_any(self: _E, entry: dict[str, Any] | None) -> str:
        from kinlock_authority import Action

        if not entry:
            return "a request"
        if entry.get("schema") == SCHEMA:
            return describe_action(AgentAction.from_dict(entry["action"]))
        a = Action.from_dict(entry["action"])
        if a.kind in ("purchase", "transfer"):
            return ("buy " if a.kind == "purchase" else "send ") + self._what(a)
        return {"freeze": "turn the safety lock on", "unfreeze": "turn the safety lock off", "cancel_pending": "cancel what was waiting", "set_limit": "change a limit"}.get(a.kind, a.kind.replace("_", " "))

    def _sentence(self: _E, r, decided: dict[str, dict[str, Any]], policy) -> str | None:
        when = datetime.fromisoformat(r.ts.replace("Z", "+00:00")).astimezone(ZoneInfo(policy.timezone)).strftime("%-I:%M %p")
        d = r.data
        what = self._what_any(decided.get(d.get("request_id", "")))
        who = self._who(d.get("by") or d.get("voter") or "", policy)
        k = r.kind
        if k == "decided":
            verdict = {"ALLOW": "allowed", "HOLD": "held", "OWNER": "held for you", "DENY": "refused"}.get(d["decision"]["outcome"], "decided")
            return f"Receipt {r.seq}, {when}: Kinlock {verdict} a request to {what}."
        if k == "executed":
            how = "by the rules" if str(d.get("by", "")).startswith("rules") else f"approved by {who}"
            return f"Receipt {r.seq}, {when}: it was carried out, {how}: {what}."
        if k == "declined":
            return f"Receipt {r.seq}, {when}: {who} declined the request to {what}."
        if k == "cancelled":
            return f"Receipt {r.seq}, {when}: the request to {what} was cancelled."
        if k == "expired":
            return f"Receipt {r.seq}, {when}: the request to {what} expired without approval."
        if k == "frozen":
            return f"Receipt {r.seq}, {when}: the safety lock was turned on."
        if k == "unfrozen":
            return f"Receipt {r.seq}, {when}: the safety lock was turned off."
        if k == "vote":
            verb = {"approve": "approved", "decline": "said no to", "pause": "paused", "resume": "resumed"}.get(d["choice"], d["choice"])
            return f"Receipt {r.seq}, {when}: {who} {verb} the request to {what}."
        if k == "approval_rejected":
            return f"Receipt {r.seq}, {when}: an approval to {what} was refused, because {(d.get('problems') or ['it did not match'])[0].rstrip('.').lower()}."
        if k == "downstream_failed":
            return f"Receipt {r.seq}, {when}: the service refused to {what}."
        if k == "policy_changed":
            return f"Receipt {r.seq}, {when}: your rules were changed."
        return None

    def _who(self: _E, ident: str, policy) -> str:
        if ident in ("owner", OWNER):
            return "you"
        if ident.startswith("contact:"):
            c = policy.contact(ident.split(":", 1)[1])
            if c:
                return c.name
        p = self.firewall().person(ident)
        if p:
            return p.name
        if ident.startswith("voice"):
            return "your voice assistant"
        return ident or "someone"

    def agent_view(self: _E, held: dict[str, Any], voter: str) -> dict[str, Any]:
        policy = self.policy()
        st = self.state(policy)
        raw = self._pending().get(held["request_id"])
        action = AgentAction.from_dict(raw["agent"]) if is_agent(raw) else None
        fw = self.firewall()
        t = None
        if action:
            d = self._evaluate_agent(action, raw.get("channel", VOICE), policy, st)
            t = tally(d, action, self._votes(held["request_id"]), firewall=fw)
        return {
            "schema": SCHEMA,
            "request_id": held["request_id"],
            "open": held["request_id"] in st.held and action is not None and self.clock() <= held["expires_at"],
            "action": action.to_dict() if action else None,
            "what": describe_action(action) if action else "",
            "category": category_label(held.get("category", "")),
            "digest": action.digest() if action else None,
            "reasons": held.get("reasons", []),
            "owner": policy.owner,
            "voter": voter,
            "voter_name": self._who(voter, policy),
            "needs": held["needs"],
            "frozen": st.frozen,
            "ready_at": self._when(held["ready_at"]) if held.get("ready_at", 0) > self.clock() else None,
            "state": t.state if t else None,
            "approvals": [self._who(a, policy) for a in (t.approvals if t else ())],
            "comments": [(self._who(v, policy), c) for v, c in (t.comments if t else ())],
        }
