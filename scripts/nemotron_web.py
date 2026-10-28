"""Kinlock judge demo: one small web page over the verified authority boundary.

GET /                               the page
GET /api/verified-causal            three deterministic Verified Causal Commit scenarios (computed once)
GET /api/benchmark                  the end-to-end adversarial benchmark (computed once at startup)
GET /api/scenarios                  Nemotron scenarios
GET /api/run?scenario=..&live=0|1   one Nemotron agent run on the verified path (recorded live replay by default)
GET /api/policy?request=..          a Nemotron policy proposal through the deterministic validator
GET /api/policy-adversarial         hand-written hostile model outputs through the same validator
GET /api/evidence?claim=..          a Tavily evidence check (recorded live, live, or "not recorded")
GET /healthz

Live calls happen only with KINLOCK_DEMO_LIVE=1 and the keys set, against fixed
scenarios and fixed requests, under an hourly budget. Visitors can't send prompts.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


demo = _load("nemotron_demo", HERE / "nemotron_demo.py")
verified_demo = _load("verified_causal_demo", HERE / "verified_causal_demo.py")
causal_benchmark = _load("verified_causal_benchmark", ROOT / "eval" / "verified_causal_benchmark.py")

from kinlock import judge_panels  # noqa: E402
from kinlock.tavily_evidence import CLAIMS  # noqa: E402
from kinlock.tokenfactory import TokenFactory, TokenFactoryError  # noqa: E402

POLICY = json.loads((ROOT / "data" / "policy.example.json").read_text())
FIXTURES = ROOT / "tests" / "fixtures"


class Budget:
    def __init__(self, per_hour: int, clock=time.monotonic):
        self.per_hour, self.clock, self.times, self.lock = per_hour, clock, [], threading.Lock()

    def take(self) -> bool:
        with self.lock:
            now = self.clock()
            self.times = [t for t in self.times if now - t < 3600]
            if len(self.times) >= self.per_hour:
                return False
            self.times.append(now)
            return True


class Once:
    """Compute a deterministic result once and serve it to every visitor."""

    def __init__(self, fn):
        self.fn, self.value, self.lock = fn, None, threading.Lock()

    def __call__(self):
        with self.lock:
            if self.value is None:
                self.value = json.dumps(self.fn()).encode()
            return self.value


def live_enabled() -> bool:
    return os.environ.get("KINLOCK_DEMO_LIVE") == "1" and bool(os.environ.get("NEBIUS_API_KEY"))


def tavily_live_enabled() -> bool:
    return live_enabled() and bool(os.environ.get("TAVILY_API_KEY"))


BUDGET = Budget(int(os.environ.get("KINLOCK_DEMO_LIVE_PER_HOUR", "30")))
PAGE = (HERE / "nemotron_web.html").read_text()
VERIFIED = Once(verified_demo.run_all)
BENCHMARK = Once(causal_benchmark.run)
ADVERSARIAL = Once(lambda: judge_panels.adversarial_panel(POLICY))


def _json(value) -> tuple[int, str, bytes]:
    return 200, "application/json", json.dumps(value).encode()


def _err(code: int, msg: str) -> tuple[int, str, bytes]:
    return code, "application/json", json.dumps({"error": msg}).encode()


def handle(path: str, budget: Budget = BUDGET) -> tuple[int, str, bytes]:
    u = urlparse(path)
    q = parse_qs(u.query)
    one = lambda k: (q.get(k) or [""])[0]  # noqa: E731
    if u.path == "/":
        return 200, "text/html; charset=utf-8", PAGE.encode()
    if u.path == "/healthz":
        return 200, "text/plain", b"ok"
    if u.path == "/api/verified-causal":
        return 200, "application/json", VERIFIED()
    if u.path == "/api/benchmark":
        return 200, "application/json", BENCHMARK()
    if u.path == "/api/scenarios":
        return _json({
            "live_enabled": live_enabled(),
            "tavily_live_enabled": tavily_live_enabled(),
            "scenarios": [{"name": n, "task": s["task"], "hijacked": bool(s.get("hijacked"))} for n, s in demo.SCENARIOS.items()],
            "policy_requests": judge_panels.POLICY_REQUESTS,
            "evidence_claims": {k: c.claim for k, c in CLAIMS.items()},
        })
    if u.path == "/api/run":
        name = one("scenario")
        if name not in demo.SCENARIOS:
            return _err(404, "unknown scenario")
        live = one("live") == "1"
        if live and not live_enabled():
            return _err(403, "live runs are off on this server")
        if live and not budget.take():
            return _err(429, "live run budget used up for this hour; try a replay")
        try:
            out = demo.run(name, live=live, quiet=True, record=False)
        except (TokenFactoryError, OSError, ValueError, KeyError, SystemExit) as e:
            return _err(502, f"run failed: {type(e).__name__}")
        return _json(out)
    if u.path == "/api/policy":
        rid = one("request")
        if rid not in judge_panels.POLICY_REQUESTS:
            return _err(404, "unknown request")
        live = one("live") == "1"
        if live and not live_enabled():
            return _err(403, "live runs are off on this server")
        if live and not budget.take():
            return _err(429, "live run budget used up for this hour")
        client = TokenFactory.from_env() if live else None
        return _json(judge_panels.policy_panel(rid, POLICY, FIXTURES / "policy", live_client=client))
    if u.path == "/api/policy-adversarial":
        return 200, "application/json", ADVERSARIAL()
    if u.path == "/api/evidence":
        claim = one("claim")
        if claim not in CLAIMS:
            return _err(404, "unknown claim")
        live = one("live") == "1"
        if live and not tavily_live_enabled():
            return _err(403, "live Tavily runs are off on this server")
        if live and not budget.take():
            return _err(429, "live run budget used up for this hour")
        return _json(judge_panels.evidence_panel(claim, POLICY, FIXTURES / "tavily", live=live))
    return 404, "text/plain", b"not found"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        code, ctype, body = handle(self.path)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # keep logs to one line, no query strings
        sys.stderr.write(f"{self.command} {urlparse(self.path).path} {args[1] if len(args) > 1 else ''}\n")


def main() -> None:
    host, port = os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "8080"))
    VERIFIED()
    BENCHMARK()  # computed before the first visitor, so every visitor sees the same numbers
    print(f"Kinlock judge demo on http://{host}:{port} (live Token Factory runs {'on' if live_enabled() else 'off'})", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
