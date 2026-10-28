"""A small client for Nebius Token Factory, the OpenAI-compatible API serving NVIDIA Nemotron.

Kinlock uses three Nemotron models (ids verified with GET /v1/models on 27 Oct 2026):

* `AGENT_MODEL` (Nemotron 3 Ultra) plans and chains tool calls, and writes the
  spoken explanation and the caregiver summary.
* `SIGNAL_MODEL` (Nemotron 3 Nano) reads each tool call for scam cues. Its output
  can only add caution (see signals.py); it never grants anything.
* `FALLBACK_MODEL` (Nemotron 3 Super) stands in for Ultra if Ultra fails.

Only the standard library is used. The transport is pluggable so tests and the
offline demo replay recorded responses instead of calling the network:

* `HttpTransport` calls the API with `NEBIUS_API_KEY`.
* `RecordingTransport` wraps it and saves every exchange to a fixture file.
* `ReplayTransport` answers from such a file, in order, and checks the model id.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

BASE_URL = os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1")
AGENT_MODEL = os.environ.get("KINLOCK_AGENT_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b")
FALLBACK_MODEL = os.environ.get("KINLOCK_FALLBACK_MODEL", "nvidia/nemotron-3-super-120b-a12b")
SIGNAL_MODEL = os.environ.get("KINLOCK_SIGNAL_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")


class TokenFactoryError(Exception):
    """The API failed, timed out, or a replay ran out of recorded responses."""


class Transport(Protocol):
    def post(self, path: str, body: dict[str, Any], timeout: float) -> dict[str, Any]: ...


@dataclass
class HttpTransport:
    api_key: str
    base_url: str = BASE_URL

    def post(self, path: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
        req = urllib.request.Request(
            self.base_url.rstrip("/") + path,
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            raise TokenFactoryError(str(e)) from e


@dataclass
class RecordingTransport:
    inner: Transport
    path: Path
    exchanges: list[dict[str, Any]] = field(default_factory=list)

    def post(self, path: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
        t = time.monotonic()
        out = self.inner.post(path, body, timeout)
        self.exchanges.append({"path": path, "request": body, "response": out, "latency_s": round(time.monotonic() - t, 3)})
        self.save()
        return out

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        meta = {"recorded_live": True, "base_url": BASE_URL, "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        self.path.write_text(json.dumps({"meta": meta, "exchanges": self.exchanges}, indent=1))


@dataclass
class ReplayTransport:
    exchanges: list[dict[str, Any]]
    i: int = 0

    @classmethod
    def from_file(cls, path: Path) -> ReplayTransport:
        return cls(json.loads(Path(path).read_text())["exchanges"])

    def post(self, path: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
        if self.i >= len(self.exchanges):
            raise TokenFactoryError("replay: no more recorded responses")
        ex = self.exchanges[self.i]
        if ex["request"].get("model") != body.get("model") or ex["path"] != path:
            raise TokenFactoryError(f"replay: expected {ex['request'].get('model')} at step {self.i}, got {body.get('model')}")
        self.i += 1
        return ex["response"]


@dataclass
class TokenFactory:
    transport: Transport
    timeout: float = 90.0
    calls: list[dict[str, Any]] = field(default_factory=list)  # model, latency, usage: for the logs and the video

    @classmethod
    def from_env(cls) -> TokenFactory | None:
        key = os.environ.get("NEBIUS_API_KEY", "").strip()
        return cls(HttpTransport(key)) if key else None

    def chat(self, model: str, messages: list[dict[str, Any]], *, timeout: float | None = None, **kw: Any) -> dict[str, Any]:
        body = {"model": model, "messages": messages, **kw}
        t = time.monotonic()
        out = self.transport.post("/chat/completions", body, timeout or self.timeout)
        if not out.get("choices"):
            raise TokenFactoryError(f"no choices in response from {model}")
        self.calls.append({"model": out.get("model", model), "latency_s": round(time.monotonic() - t, 3), "usage": out.get("usage")})
        return out["choices"][0]["message"]
