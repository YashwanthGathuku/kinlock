from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from kinlock.engine import Engine

ROOT = Path(__file__).resolve().parents[1]
KEY = b"k" * 32


class Clock:
    """A controllable clock: 10:00 in New York on Oct 22, 2026, unless moved."""

    def __init__(self) -> None:
        self.t = datetime(2026, 10, 22, 10, 0, tzinfo=ZoneInfo("America/New_York")).timestamp()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds

    def set_local_hour(self, hour: int) -> None:
        self.t = datetime(2026, 10, 22, hour, 0, tzinfo=ZoneInfo("America/New_York")).timestamp()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def outbox() -> list[tuple[str, str]]:
    return []


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    shutil.copy(ROOT / "data" / "policy.example.json", tmp_path / "policy.json")
    return tmp_path


@pytest.fixture
def engine(data_dir: Path, clock: Clock, outbox: list) -> Engine:
    return Engine(data_dir, KEY, "http://kinlock.test", notify=lambda t, link: outbox.append((t, link)), clock=clock)


def token_from(link: str) -> str:
    return link.rsplit("/", 1)[1]
