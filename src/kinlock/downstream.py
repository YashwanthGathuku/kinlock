"""What actually carries out an action once Kinlock allows it.

Kinlock never talks to the outside world itself. An allowed action is handed to a
`Downstream`: in production, the service or MCP server that really sends the
message or unlocks the door; in tests and the demo, `FakeDownstream`, an
in-process stand-in that records every call and can be told to refuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class DownstreamError(Exception):
    """The downstream service refused or failed. Kinlock records it; nothing is retried."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    read_only: bool = False  # what the downstream claims; Kinlock trusts only its own config


class Downstream(Protocol):
    def list_tools(self) -> list[ToolSpec]: ...

    def call(self, name: str, arguments: dict[str, Any]) -> str: ...


FAKE_TOOLS = (
    ToolSpec("send_message", "Send a text message to someone."),
    ToolSpec("place_call", "Phone someone."),
    ToolSpec("unlock_front_door", "Unlock the smart lock on the front door."),
    ToolSpec("lock_front_door", "Lock the front door."),
    ToolSpec("install_app", "Install an app on the owner's computer."),
    ToolSpec("start_screen_share", "Let someone see and control the owner's screen."),
    ToolSpec("change_recovery_email", "Change the recovery email of an online account."),
    ToolSpec("refill_prescription", "Ask the pharmacy to refill a prescription."),
    ToolSpec("buy", "Buy something from a shop."),
    ToolSpec("check_weather", "Read the weather forecast.", read_only=True),
    ToolSpec("delete_photos", "Delete photos from the owner's library."),
)


@dataclass
class FakeDownstream:
    """An in-process downstream for tests and the demo. Nothing leaves the machine."""

    tools: tuple[ToolSpec, ...] = FAKE_TOOLS
    refuse: dict[str, str] = field(default_factory=dict)  # tool name -> refusal message
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def list_tools(self) -> list[ToolSpec]:
        return list(self.tools)

    def call(self, name: str, arguments: dict[str, Any]) -> str:
        if name not in {t.name for t in self.tools}:
            raise DownstreamError(f"The service has no tool called {name}")
        if name in self.refuse:
            raise DownstreamError(self.refuse[name])
        self.calls.append((name, dict(arguments)))
        if name == "check_weather":
            return "Sunny, high of 64."
        return f"(simulated) {name} done"
