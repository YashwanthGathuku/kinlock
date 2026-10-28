"""Kinlock as an MCP gateway: every consequential tool call goes through the firewall first.

An agent never calls the downstream service directly. It calls `use_tool` on
Kinlock with the downstream tool's name and arguments; Kinlock maps the tool to
an action (category, verb, target), lets the fixed rules decide, and only then
forwards the call. The mapping lives in a config file (data/gateway.example.json):

    {"tools": {"send_message": {"category": "comms", "verb": "send_message", "target": "to"}},
     "read_only": ["check_weather"]}

* A mapped tool is decided by its category's rules.
* A tool listed as read-only is forwarded at once (it changes nothing).
* Anything else, a tool nobody mapped, is treated as consequential and held for
  a person. Kinlock doesn't trust a downstream's own "read-only" claim.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kinlock_authority import AgentAction

from .downstream import Downstream, DownstreamError
from .engine import Engine, Result, new_request_id

UNMAPPED = "unmapped"


@dataclass(frozen=True)
class ToolRule:
    category: str
    verb: str
    target: str = ""  # the argument naming what is acted on; "=literal" for a fixed target
    amount: str = ""  # the argument holding a dollar amount (money tools)
    details: tuple[str, ...] | None = None  # arguments copied into details; None = all of them

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ToolRule:
        det = d.get("details")
        return cls(str(d["category"]), str(d["verb"]), str(d.get("target", "")), str(d.get("amount", "")), tuple(det) if det is not None else None)


@dataclass(frozen=True)
class GatewayConfig:
    tools: dict[str, ToolRule] = field(default_factory=dict)
    read_only: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GatewayConfig:
        return cls({k: ToolRule.from_dict(v) for k, v in (d.get("tools") or {}).items()}, frozenset(d.get("read_only") or ()))

    @classmethod
    def from_file(cls, path: Path) -> GatewayConfig:
        return cls.from_dict(json.loads(Path(path).read_text()))

    def action_for(self, tool: str, arguments: dict[str, Any], *, risk: frozenset[str] = frozenset(), requester: str = "") -> AgentAction:
        rule = self.tools.get(tool)
        if rule is None:
            # Nobody said what this tool does, so Kinlock can't judge it: a person decides.
            return AgentAction(new_request_id(), UNMAPPED, tool, "", {k: arguments[k] for k in sorted(arguments)}, risk, True, requester)
        if rule.target.startswith("="):
            target = rule.target[1:]
        else:
            target = str(arguments.get(rule.target, "")) if rule.target else ""
        keys = rule.details if rule.details is not None else tuple(k for k in arguments if k not in (rule.target, rule.amount))
        details = {k: arguments[k] for k in keys if k in arguments}
        amount = _cents(arguments.get(rule.amount, 0)) if rule.amount else 0
        return AgentAction(new_request_id(), rule.category, rule.verb, target, details, risk, True, requester, (), amount)

    def describe(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """What Kinlock will take this call to mean: the fields a certificate must match."""
        a = self.action_for(tool, arguments)
        return {"category": a.category, "verb": a.verb, "target": a.target, "amount_cents": a.amount_cents}


def _cents(value: Any) -> int:
    """Dollars from a tool argument to cents. NaN, infinities and negatives are refused, not guessed."""
    amount = float(value)
    if not math.isfinite(amount) or amount < 0:
        raise ValueError("amount must be a finite, non-negative number")
    return int(round(amount * 100))


class Gateway:
    def __init__(self, engine: Engine, downstream: Downstream | None, config: GatewayConfig):
        self.engine = engine
        self.downstream = downstream
        self.config = config
        engine.downstream = downstream
        # A VerifiedEngine derives each effect from the call through this same map.
        if getattr(engine, "tool_map", False) is None:
            engine.tool_map = config

    def guarded_tools(self) -> list[dict[str, Any]]:
        if self.downstream is None:
            return []
        out = []
        for t in self.downstream.list_tools():
            rule = self.config.tools.get(t.name)
            if t.name in self.config.read_only:
                how = "passes through (read-only)"
            elif rule:
                how = f"{rule.category}: {rule.verb.replace('_', ' ')}"
            else:
                how = "not mapped: held for a person"
            out.append({"name": t.name, "description": t.description, "guard": how})
        return out

    def call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        channel: str,
        by: str,
        risk: frozenset[str] = frozenset(),
        requester: str = "",
        certificate: dict[str, Any] | None = None,
        intent_id: str | None = None,
    ) -> Result:
        if self.downstream is None:
            return Result("", "REJECTED", "No service is connected to Kinlock, so there's nothing to call.", problems=["no downstream"])
        if tool in self.config.read_only:
            try:
                out = self.downstream.call(tool, arguments)
            except DownstreamError as e:
                return Result("", "FAILED", f"The service refused: {e}.", problems=[str(e)])
            # What a read-only tool returned becomes evidence only when Kinlock's gateway
            # signs it, bound to the intent it was read for. The agent can't sign it itself.
            signer = getattr(self.engine, "evidence_signer", None)
            evidence = None
            if signer is not None and intent_id:
                evidence = signer.sign(intent_id=intent_id, producer=by, source_tool=tool, request=dict(arguments), response=out, observed_at=self.engine.clock())
            return Result("", "PASSED", out, evidence=evidence)
        try:
            action = self.config.action_for(tool, arguments, risk=risk, requester=requester)
        except (TypeError, ValueError) as e:
            return Result("", "REJECTED", f"Kinlock couldn't read that request: {e}. Nothing was done.", problems=[str(e)])
        call = {"tool": tool, "arguments": dict(arguments)}
        if certificate is not None and hasattr(self.engine, "execution_guard"):
            return self.engine.request_agent(action, channel, by, call=call, certificate=certificate)
        return self.engine.request_agent(action, channel, by, call=call)
