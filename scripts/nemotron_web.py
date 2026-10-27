"""A small public web page for the Nemotron demo. Stdlib only.

GET /                       the page
GET /api/scenarios          scenario names and tasks
GET /api/run?scenario=NAME  replay of the recorded live run
GET /api/run?scenario=NAME&live=1
                            a fresh Token Factory run, only when KINLOCK_DEMO_LIVE=1 and NEBIUS_API_KEY is set;
                            limited to KINLOCK_DEMO_LIVE_PER_HOUR runs per hour (default 30) across all visitors.
GET /healthz

Only the fixed scenarios can run: visitors can't send their own prompts, and nothing is recorded to disk.
"""

from __future__ import annotations

import importlib.util
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("nemotron_demo", HERE / "nemotron_demo.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

from kinlock.tokenfactory import TokenFactoryError


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


def live_enabled() -> bool:
    return os.environ.get("KINLOCK_DEMO_LIVE") == "1" and bool(os.environ.get("NEBIUS_API_KEY"))


BUDGET = Budget(int(os.environ.get("KINLOCK_DEMO_LIVE_PER_HOUR", "30")))
PAGE = (HERE / "nemotron_web.html").read_text()


def handle(path: str, budget: Budget = BUDGET) -> tuple[int, str, bytes]:
    u = urlparse(path)
    q = parse_qs(u.query)
    if u.path == "/":
        return 200, "text/html; charset=utf-8", PAGE.encode()
    if u.path == "/healthz":
        return 200, "text/plain", b"ok"
    if u.path == "/api/scenarios":
        body = {"live_enabled": live_enabled(), "scenarios": [{"name": n, "task": s["task"], "hijacked": bool(s.get("hijacked"))} for n, s in demo.SCENARIOS.items()]}
        return 200, "application/json", json.dumps(body).encode()
    if u.path == "/api/run":
        name = (q.get("scenario") or [""])[0]
        if name not in demo.SCENARIOS:
            return 404, "application/json", b'{"error": "unknown scenario"}'
        live = (q.get("live") or ["0"])[0] == "1"
        if live and not live_enabled():
            return 403, "application/json", b'{"error": "live runs are off on this server"}'
        if live and not budget.take():
            return 429, "application/json", b'{"error": "live run budget used up for this hour; try a replay"}'
        try:
            out = demo.run(name, live=live, quiet=True, record=False)
        except (TokenFactoryError, OSError, ValueError, KeyError, SystemExit) as e:  # a Token Factory failure shouldn't take the page down
            return 502, "application/json", json.dumps({"error": f"run failed: {type(e).__name__}"}).encode()
        return 200, "application/json", json.dumps(out).encode()
    return 404, "text/plain", b"not found"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        code, ctype, body = handle(self.path)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host, port = os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "8080"))
    print(f"Kinlock Nemotron demo on http://{host}:{port} (live runs {'on' if live_enabled() else 'off'})", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
