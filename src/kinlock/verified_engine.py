"""Kinlock engine variant that requires an external execution proof.

The ordinary :class:`kinlock.engine.Engine` is intentionally unchanged.  This
subclass is the hackathon integration boundary: AgentFleet can stage work, but
an action reaches the existing Kinlock downstream only after the independent
verified-runtime guard accepts its proof-carrying certificate.
"""

from __future__ import annotations

from typing import Any

from .engine import Engine, Result
from .verified_runtime import VerificationError, VerifiedExecutionGuard


class VerifiedEngine(Engine):
    """Fail closed when an agent action lacks a valid causal execution proof."""

    def __init__(self, *args: Any, execution_guard: VerifiedExecutionGuard, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.execution_guard = execution_guard

    def _run_agent(
        self,
        action: Any,
        dg: str,
        call: dict[str, Any] | None,
        by: str,
        cap_id: str | None = None,
    ) -> Result:
        if call is None:
            r = self._append(
                "verification_failed",
                {
                    "request_id": action.request_id,
                    "schema": "kinlock.action/1",
                    "digest": dg,
                    "problem": "verified execution requires a concrete downstream call",
                },
            )
            return Result(
                action.request_id,
                "FAILED",
                "Kinlock refused to commit this action because no verifiable downstream effect was supplied.",
                None,
                r.seq,
                r.hash,
                problems=["missing downstream call"],
            )

        try:
            witness = self.execution_guard.authorize(action, call, now=self.clock())
        except VerificationError as exc:
            problem = str(exc)[:1000]
            r = self._append(
                "verification_failed",
                {
                    "request_id": action.request_id,
                    "schema": "kinlock.action/1",
                    "digest": dg,
                    "tool": call.get("tool"),
                    "problem": problem,
                },
            )
            return Result(
                action.request_id,
                "FAILED",
                "The agent proposed an action, but the independent verifier could not prove that it was authorized. Nothing was committed.",
                None,
                r.seq,
                r.hash,
                problems=[problem],
            )
        except Exception as exc:  # verifier failure itself must fail closed
            problem = f"verifier error: {type(exc).__name__}"
            r = self._append(
                "verification_failed",
                {
                    "request_id": action.request_id,
                    "schema": "kinlock.action/1",
                    "digest": dg,
                    "tool": call.get("tool"),
                    "problem": problem,
                },
            )
            return Result(
                action.request_id,
                "FAILED",
                "The independent verifier was unavailable, so Kinlock refused to commit the action.",
                None,
                r.seq,
                r.hash,
                problems=[problem],
            )

        proof = self._append(
            "verification_witness",
            {
                "request_id": action.request_id,
                "schema": "kinlock.action/1",
                "digest": dg,
                "tool": call.get("tool"),
                "verification": witness.to_dict(),
            },
        )
        result = super()._run_agent(action, dg, call, by=by, cap_id=cap_id)
        # Link the externally visible result back to the proof receipt without
        # changing the original engine's receipt semantics.
        if result.receipt_hash:
            self._append(
                "verified_commit_result",
                {
                    "request_id": action.request_id,
                    "verification_receipt": proof.hash,
                    "result_receipt": result.receipt_hash,
                    "result": result.outcome,
                },
            )
        return result
