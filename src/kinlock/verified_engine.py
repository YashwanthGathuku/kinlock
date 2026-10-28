"""Kinlock engine variant whose every consequential effect must prove its authority.

The ordinary :class:`kinlock.engine.Engine` is unchanged. ``VerifiedEngine`` adds:

* **Owner intents, minted here.** ``mint_intent`` signs the root of the owner's
  task with ``K_intent``. A request that arrives on a low-assurance channel
  (voice, an agent) can only be granted what the owner's standing permissions
  already allow: owner-only categories (identity, legal) and anything without a
  standing permission are clamped out, and the clamp is receipted. Low-assurance
  channels may lower authority but never raise it; the same rule now covers intents.
* **Proof before effect.** On the autonomous ALLOW path the engine derives the
  effect from the call, has the THEUSTAD verifier check the staged certificate
  against it, and writes a ``verification_witness`` receipt before anything runs.
* **A real commit boundary.** The downstream is wrapped in a ``CommitGate``. The
  witness comes with a token bound to exactly this tool and these arguments; the
  gate refuses any call without one.
* **Durable state.** Consumed certificate nonces, per-intent effect counts and
  revocations live in the signed receipt chain, so they survive a restart.
* **Two ways to authority, both receipted.** A certificate under a signed owner
  intent (autonomous path), or an exact-action approval capability issued by the
  owner or a trusted contact (held path). Nothing else reaches the downstream.
"""

from __future__ import annotations

from typing import Any

from kinlock_authority.policy import OWNER, VOICE

from .engine import Engine, Result
from .theustad_verifier import REVOKED_FACT, norm
from .verified_runtime import (
    AuthorityScope,
    CommitGate,
    CommitTokenIssuer,
    EvidenceSigner,
    IntentMinter,
    TemporalContract,
    VerificationError,
    VerifiedExecutionGuard,
    derive_keys,
)

PROOF_SCHEMA = "kinlock.verified-action/2"


class VerifiedEngine(Engine):
    """Fail closed when an agent action can't prove a path to the owner's authority."""

    def __init__(self, data_dir, signing_key: bytes, public_url: str = "http://127.0.0.1:8770", *, tool_map: Any = None, commit_ttl: float = 30.0, **kwargs: Any):
        self._gate: CommitGate | None = None
        self.keys = derive_keys(signing_key)
        self.issuer = CommitTokenIssuer(self.keys.commit, ttl_seconds=commit_ttl)
        self.minter = IntentMinter(self.keys.intent)
        self.evidence_signer = EvidenceSigner(self.keys.evidence)
        self.tool_map = tool_map
        self._proofs: dict[str, dict[str, Any]] = {}
        super().__init__(data_dir, signing_key, public_url, **kwargs)
        self.execution_guard = VerifiedExecutionGuard(
            self.keys,
            self.issuer,
            state_facts=self.state_facts,
            consumed=self.certificate_consumed,
            effects_used=self.effects_used,
        )

    # -- the downstream is always behind the commit gate -----------------------------------------
    @property
    def downstream(self) -> CommitGate | None:
        return self._gate

    @downstream.setter
    def downstream(self, value: Any) -> None:
        if value is None or isinstance(value, CommitGate):
            self._gate = value
        else:
            self._gate = CommitGate(value, self.issuer, lambda: self.clock())

    # -- intents ----------------------------------------------------------------------------------
    def _clamp(self, scope: AuthorityScope, channel: str) -> tuple[AuthorityScope, list[str]]:
        """What a channel may grant. The owner's own surface grants what she asks; anything else
        is limited to her standing permissions and known targets."""
        if channel == OWNER:
            return scope, []
        fw = self.firewall()
        cats = {c for c in fw.standing if c not in fw.owner_only_categories}
        verbs = set().union(*(fw.standing[c] for c in cats)) if cats else set()
        known = set().union(*(fw.known_targets.get(c, frozenset()) for c in cats)) if cats else set()
        removed: list[str] = []

        def keep(values: tuple[str, ...], allowed: set[str], label: str) -> tuple[str, ...]:
            out = []
            for v in values:
                if v != "*" and norm(v) in allowed:
                    out.append(v)
                else:
                    removed.append(f"{label}:{v}")
            return tuple(out)

        tools = []
        for t in scope.tools:
            rule = self.tool_map.tools.get(t) if self.tool_map is not None else None
            if rule is not None and norm(rule.category) in cats and norm(rule.verb) in verbs:
                tools.append(t)
            else:
                removed.append(f"tool:{t}")
        if scope.max_amount_cents:
            removed.append(f"amount:{scope.max_amount_cents}")
        granted = AuthorityScope(
            tools=tuple(tools),
            categories=keep(scope.categories, cats, "category"),
            verbs=keep(scope.verbs, verbs, "verb"),
            targets=keep(scope.targets, known, "target"),
            max_amount_cents=0,
            max_delegation_depth=scope.max_delegation_depth,
            expires_at=scope.expires_at,
        )
        return granted, removed

    def mint_intent(
        self,
        *,
        purpose: str,
        scope: AuthorityScope,
        channel: str = VOICE,
        principal: str = OWNER,
        ttl: float = 600.0,
        max_effects: int = 1,
        required_evidence: tuple[str, ...] = (),
        temporal: TemporalContract = TemporalContract(),
    ) -> dict[str, Any]:
        """Sign the owner's intent. The token goes to the agent side; the key never does."""
        with self.lock:
            granted, removed = self._clamp(scope, channel)
            token = self.minter.mint(
                principal=principal,
                purpose=purpose,
                scope=granted,
                channel=channel,
                now=self.clock(),
                ttl=ttl,
                max_effects=max_effects,
                required_evidence=required_evidence,
                temporal=temporal,
            )
            root = token["root"]
            self._append(
                "intent_minted",
                {
                    "intent_id": root["intent_id"],
                    "channel": channel,
                    "principal": principal,
                    "purpose": root["purpose"],
                    "scope": root["scope"],
                    "max_effects": root["max_effects"],
                    "required_evidence": root["required_evidence"],
                    "temporal": root["temporal"],
                    "expires_at": root["expires_at"],
                    "clamped": removed,
                },
            )
            return token

    def revoke_intent(self, intent_id: str, by: str = OWNER) -> None:
        """Revoking only lowers authority, so any channel may do it."""
        with self.lock:
            self._append("intent_revoked", {"intent_id": intent_id, "by": by})

    # -- durable state the verifier reads ---------------------------------------------------------
    def state_facts(self, intent_id: str) -> frozenset[str]:
        facts: set[str] = set()
        for r in self.chain.receipts():
            if r.kind == "intent_revoked" and r.data.get("intent_id") == intent_id:
                facts.add(REVOKED_FACT)
        if self.state().frozen:
            facts.add("safety_lock")
        return frozenset(facts)

    def certificate_consumed(self, nonce: str) -> bool:
        return any(r.kind == "verification_witness" and r.data.get("certificate_nonce") == nonce for r in self.chain.receipts())

    def effects_used(self, intent_id: str) -> int:
        return sum(1 for r in self.chain.receipts() if r.kind == "verification_witness" and r.data.get("intent_id") == intent_id)

    # -- requests -----------------------------------------------------------------------------------
    def request_agent(self, action: Any, channel: str = VOICE, by: str | None = None, call: dict[str, Any] | None = None, certificate: dict[str, Any] | None = None) -> Result:
        with self.lock:
            if certificate is not None:
                try:
                    self.execution_guard.stage(action.request_id, certificate)
                except VerificationError:
                    pass  # an existing staged certificate stays; the verifier decides on it
            preview = self.execution_guard.preview(action.request_id, action, call, self.tool_map, self.clock())
            res = super().request_agent(action, channel, by, call=call)
            proof = self._proofs.pop(action.request_id, None)
            res.proof = proof or {"stage": "preview", **preview.to_dict()}
            if res.outcome not in ("ALLOW", "DONE", "EXECUTED"):
                # Held, owner-only, denied or failed: this certificate will never commit. A held
                # action is released later only by an exact-action approval capability.
                self.execution_guard.discard(action.request_id)
            if res.outcome in ("HOLD", "OWNER") and not preview.ok:
                # Whoever is asked to approve should know the agent couldn't prove the owner asked for this.
                self._append("unproven_request", {"request_id": action.request_id, "problems": list(preview.problems)[:10]})
            return res

    def _fail(self, action: Any, dg: str, call: dict[str, Any] | None, problems: tuple[str, ...] | list[str], speech: str) -> Result:
        problems = [str(p)[:500] for p in problems][:20]
        r = self._append(
            "verification_failed",
            {"request_id": action.request_id, "schema": PROOF_SCHEMA, "digest": dg, "tool": (call or {}).get("tool"), "problems": problems},
        )
        self._proofs[action.request_id] = {"stage": "commit", "ok": False, "problems": problems, "checks": []}
        return Result(action.request_id, "FAILED", speech, None, r.seq, r.hash, problems=problems)

    def _run_agent(self, action: Any, dg: str, call: dict[str, Any] | None, by: str, cap_id: str | None = None) -> Result:
        if call is None:
            return self._fail(action, dg, call, ["verified execution requires a concrete downstream call"], "Kinlock refused to commit this action because no verifiable downstream effect was supplied.")
        now = self.clock()
        try:
            if cap_id is not None:
                verdict = None
                token = self.execution_guard.authorize_approval(cap_id, action, call, self.tool_map, now)
            else:
                verdict, token = self.execution_guard.authorize(action.request_id, action, call, self.tool_map, now)
        except VerificationError as exc:
            return self._fail(action, dg, call, exc.problems, "The agent proposed an action, but the independent verifier could not prove the owner authorized it. Nothing was committed.")
        except Exception as exc:  # the verifier failing must never fail open
            return self._fail(action, dg, call, [f"verifier error: {type(exc).__name__}"], "The independent verifier was unavailable, so Kinlock refused to commit the action.")

        witness: dict[str, Any] = {
            "request_id": action.request_id,
            "schema": PROOF_SCHEMA,
            "digest": dg,
            "tool": call.get("tool"),
            "call_digest": token.call_digest,
            "commit_token_id": token.token_id,
            "basis": "approval_capability" if verdict is None else "owner_intent_certificate",
        }
        if verdict is None:
            witness["cap_id"] = cap_id
        else:
            witness.update(
                intent_id=verdict.intent_id,
                certificate_nonce=verdict.nonce,
                certificate_digest=verdict.certificate_digest,
                checks=list(verdict.checks),
                verifier=verdict.verifier,
            )
        proof = self._append("verification_witness", witness)
        self._proofs[action.request_id] = {"stage": "commit", "ok": True, "problems": [], **({} if verdict is None else verdict.to_dict()), "basis": witness["basis"], "commit_token_id": token.token_id}

        gate = self._gate
        if gate is not None:
            gate.arm(token)
        try:
            result = super()._run_agent(action, dg, call, by=by, cap_id=cap_id)
        finally:
            if gate is not None:
                gate.disarm()
        if result.receipt_hash:
            self._append(
                "verified_commit_result",
                {"request_id": action.request_id, "verification_receipt": proof.hash, "result_receipt": result.receipt_hash, "result": result.outcome},
            )
        return result
