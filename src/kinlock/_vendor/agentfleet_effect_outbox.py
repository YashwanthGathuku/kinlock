"""Public source-locked copy of AgentFleet's durable staged-effect outbox.

Canonical upstream during the hackathon:
  YashwanthGathuku/agent-orchestration-os@df242cacc055686e9214f371962b6a9a866dfff9
  python/fleet/effect_outbox.py blob a1be2235abc522f97ffc8addabdeb134aa56d14c

The outbox can stage, commit-record, or abort-record an effect. It deliberately
contains no network/tool execution primitive; Kinlock remains the commit authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64
SCHEMA = "fleet.effect-outbox/1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class EffectEnvelope:
    effect_id: str
    request_id: str
    effect_digest: str
    certificate_digest: str
    tool: str
    arguments: dict[str, Any]
    staged_at: float
    reversible: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "request_id": self.request_id,
            "effect_digest": self.effect_digest,
            "certificate_digest": self.certificate_digest,
            "tool": self.tool,
            "arguments": self.arguments,
            "staged_at": self.staged_at,
            "reversible": self.reversible,
        }


class OutboxError(RuntimeError):
    pass


class EffectOutbox:
    """Append-only staged-effect ledger; never executes the effect itself."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events

    def verify_chain(self) -> bool:
        prev = GENESIS
        for event in self._events():
            claimed = event.get("hash")
            body = {k: v for k, v in event.items() if k != "hash"}
            if body.get("previous_hash") != prev:
                return False
            actual = sha256(body)
            if actual != claimed:
                return False
            prev = actual
        return True

    def _append(self, kind: str, data: dict[str, Any], now: float | None = None) -> dict[str, Any]:
        with self._lock:
            events = self._events()
            previous = events[-1]["hash"] if events else GENESIS
            body = {
                "schema": SCHEMA,
                "seq": len(events) + 1,
                "kind": kind,
                "ts": time.time() if now is None else now,
                "previous_hash": previous,
                "data": data,
            }
            event = {**body, "hash": sha256(body)}
            text = "".join(json.dumps(e, sort_keys=True) + "\n" for e in [*events, event])
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
            return event

    def state(self, effect_id: str) -> str | None:
        state = None
        for event in self._events():
            if event.get("data", {}).get("effect_id") != effect_id:
                continue
            if event["kind"] == "staged":
                state = "STAGED"
            elif event["kind"] == "committed":
                state = "COMMITTED"
            elif event["kind"] == "aborted":
                state = "ABORTED"
        return state

    def stage(self, certificate: dict[str, Any], *, reversible: bool = False, now: float | None = None) -> EffectEnvelope:
        effect = dict(certificate.get("effect") or {})
        required = ("request_id", "tool", "arguments")
        if any(k not in effect for k in required):
            raise OutboxError("certificate does not contain a complete effect")
        effect_digest = sha256(effect)
        certificate_digest = sha256(certificate)
        effect_id = "effect_" + effect_digest[:20]
        current = self.state(effect_id)
        if current in {"STAGED", "COMMITTED"}:
            raise OutboxError(f"effect already {current.lower()}")
        envelope = EffectEnvelope(
            effect_id=effect_id,
            request_id=str(effect["request_id"]),
            effect_digest=effect_digest,
            certificate_digest=certificate_digest,
            tool=str(effect["tool"]),
            arguments=dict(effect.get("arguments") or {}),
            staged_at=time.time() if now is None else now,
            reversible=reversible,
        )
        self._append("staged", envelope.to_dict(), now=now)
        return envelope

    def commit(self, effect_id: str, *, verification_receipt: str, result_receipt: str, now: float | None = None) -> None:
        if self.state(effect_id) != "STAGED":
            raise OutboxError("only a staged effect can be committed")
        if not verification_receipt or not result_receipt:
            raise OutboxError("commit requires verifier and execution receipts")
        self._append(
            "committed",
            {
                "effect_id": effect_id,
                "verification_receipt": verification_receipt,
                "result_receipt": result_receipt,
            },
            now=now,
        )

    def abort(self, effect_id: str, *, reason: str, now: float | None = None) -> None:
        if self.state(effect_id) != "STAGED":
            raise OutboxError("only a staged effect can be aborted")
        self._append("aborted", {"effect_id": effect_id, "reason": reason[:1000]}, now=now)

    def staged(self) -> Iterator[EffectEnvelope]:
        staged: dict[str, EffectEnvelope] = {}
        terminal: set[str] = set()
        for event in self._events():
            data = event.get("data", {})
            eid = data.get("effect_id")
            if event["kind"] == "staged" and eid:
                staged[eid] = EffectEnvelope(**{k: data[k] for k in EffectEnvelope.__dataclass_fields__})
            elif event["kind"] in {"committed", "aborted"} and eid:
                terminal.add(eid)
        for eid, envelope in staged.items():
            if eid not in terminal:
                yield envelope
