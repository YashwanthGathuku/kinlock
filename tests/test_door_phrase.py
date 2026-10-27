"""The door route names the visitor, and the spoken description reads naturally.

It used to say "unlock the A Visitor Called Steve": the whole phrase became the name, and the
gateway mapped the visitor's name to the door's target.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kinlock.gateway import GatewayConfig
from kinlock.simulator import keyword_route
from kinlock_authority.firewall import describe_action


@pytest.mark.parametrize(
    ("said", "visitor"),
    [
        ("unlock the front door for a visitor called steve", "Steve"),
        ("open the door for a man named raj please", "Raj"),
        ("unlock the door for someone called rosa now", "Rosa"),
        ("please open the front door for the delivery man who is called sam", "Sam"),
        ("open the door for steve please", "Steve"),
        ("unlock the door for the plumber", "The Plumber"),
        ("unlock the front door", "someone at the door"),
    ],
)
def test_door_route_names_the_visitor(said: str, visitor: str) -> None:
    route, args = keyword_route(said)
    assert route == "use_tool" and args["tool"] == "unlock_front_door"
    assert args["arguments"] == {"visitor": visitor}


def test_door_description_reads_naturally() -> None:
    _, args = keyword_route("unlock the front door for a visitor called steve")
    action = GatewayConfig.from_file(Path(__file__).resolve().parents[1] / "data" / "gateway.example.json").action_for(args["tool"], args["arguments"])
    assert action.target == "front door" and action.details == {"visitor": "Steve"}
    text = describe_action(action)
    assert text.lower().startswith("unlock the front door for steve")
    assert "Visitor Called" not in text
