"""A simulated Alexa+ experience that drives Kinlock's MCP server the way Alexa+ would.

The hackathon rules allow simulating Alexa+ in a web app. This page is a real
MCP client: it gets a client_credentials token and speaks JSON-RPC over
Streamable HTTP to /mcp with protocol 2025-11-25. Every call it makes is shown
with its timing.

The "assistant brain" that turns speech into a tool call is an
OpenAI-compatible model when KINLOCK_LLM_* is set; otherwise a small keyword
router stands in so the page works offline. Either way, the brain only fills in
a structured request. Kinlock's rules decide.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx2
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .auth import AuthServer
from .engine import Engine
from .notify import Notifier
from .settings import ROOT, Settings
from .shop import CATALOG

PROTOCOL = "2025-11-25"
SYSTEM_PROMPT = (
    "You are a voice assistant. Use the tools to act for the user and answer in at most two short spoken sentences, "
    "no lists, no markdown. Kinlock's replies are final: say them in your own words, never retry a held or refused "
    "action with different details, and never split an amount."
)
HELP = "I can order your usual groceries, buy something, send money, tell you your status, or freeze your spending."

WORDS = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90}


def parse_amount(u: str) -> float | None:
    m = re.search(r"\$?\s?(\d[\d,]*(?:\.\d{1,2})?)\s*(k|thousand|hundred)?", u)
    if m:
        v = float(m.group(1).replace(",", ""))
        mult = {"k": 1000, "thousand": 1000, "hundred": 100}.get(m.group(2) or "", 1)
        return v * mult
    m = re.search(r"\b(" + "|".join(WORDS) + r")(?:[ -](" + "|".join(WORDS) + r"))?\s+(hundred|thousand)\b", u)
    if m:
        base = WORDS[m.group(1)] + (WORDS[m.group(2)] if m.group(2) else 0)
        return float(base * (100 if m.group(3) == "hundred" else 1000))
    return None


KNOWN_NAMES = {m.lower(): m for m, *_ in CATALOG.values()} | {"fresh market": "Fresh Market", "cryptocash": "CryptoCash"}


def proper(name: str) -> str:
    n = name.strip()
    return KNOWN_NAMES.get(n.lower(), n.title())


def keyword_route(utterance: str) -> tuple[str | None, dict[str, Any]]:
    u = utterance.lower().strip()
    if re.search(r"\b(unfreeze|unlock|un-freeze|lift the lock|turn off the (safety )?lock|remove the lock)\b", u):
        return "unlock_spending", {}
    if re.search(r"\b(freeze|lock (my |all )?(spending|money|account)|stop (all )?(spending|payments|purchases))\b", u):
        return "freeze_spending", {}
    if re.search(r"\b(cancel)\b", u):
        return "cancel_waiting", {}
    if re.search(r"\blimit\b", u):
        cat = next((c for c in ("groceries", "pharmacy", "electronics", "transfer") if c in u), "groceries")
        kind = "daily_orders" if "orders" in u else ("per_order" if re.search(r"per (order|purchase)", u) else "daily_total")
        amt = parse_amount(u)
        return ("change_limit", {"category": cat, "limit": kind, "new_value": amt}) if amt is not None else (None, {})
    if re.search(r"\b(why|explain)\b", u):
        return "explain_last_decision", {}
    if re.search(r"\b(status|what'?s (going on|waiting)|anything waiting|how much (have i|did i) spen[dt])\b", u):
        return "safety_status", {}
    if re.search(r"\busual\b", u):
        return "order_usual", {"list_name": "pharmacy" if "pharmacy" in u or "prescription" in u else "groceries"}
    if re.search(r"\b(send|transfer|wire|pay)\b", u):
        m = re.search(r"\bto ([a-z0-9 ]+?)(?: now| right now| immediately| please)?$", u)
        return "request_transfer", {"payee": (m.group(1).strip().title() if m else "New Account"), "amount_dollars": parse_amount(u) or 900.0}
    for key, (merchant, cents, cat, item) in CATALOG.items():
        if key in u:
            amt = parse_amount(u)
            m = re.search(r"\bfrom ([a-z0-9' ]+?)(?: for|$)", u)
            return "request_purchase", {"merchant": proper(m.group(1)) if m else merchant, "amount_dollars": amt if amt else cents / 100, "category": cat, "item": item}
    if re.search(r"\b(buy|order|purchase|get me)\b", u):
        m = re.search(r"\bfrom ([a-z0-9' ]+?)(?: for|$)", u)
        amt = parse_amount(u)
        if m and amt:
            item = re.sub(r"^(please )?(buy|order|purchase|get me)\s+", "", u.split(" from ")[0]).strip() or "an item"
            return "request_purchase", {"merchant": proper(m.group(1)), "amount_dollars": amt, "category": "other", "item": item}
    return None, {}


@dataclass
class McpClient:
    url: str
    token_url: str
    resource: str
    client_id: str
    client_secret: str
    trace: list[dict[str, Any]] = field(default_factory=list)
    # Returns (access token, expires_in). When set, used instead of client_credentials,
    # so the simulator can act as an account-linked Alexa+ holding an owner token.
    token_fn: Callable[[], tuple[str, int]] | None = None
    _token: str | None = None
    _exp: float = 0.0

    async def _bearer(self, http: httpx2.AsyncClient) -> str:
        if self._token and time.time() < self._exp - 30:
            return self._token
        if self.token_fn is not None:
            tok, ttl = self.token_fn()
            self._token, self._exp = tok, time.time() + ttl
            return self._token
        r = await http.post(self.token_url, data={"grant_type": "client_credentials", "scope": "mcp:service", "resource": self.resource}, auth=(self.client_id, self.client_secret))
        r.raise_for_status()
        b = r.json()
        self._token, self._exp = b["access_token"], time.time() + int(b["expires_in"])
        return self._token

    async def rpc(self, http: httpx2.AsyncClient, method: str, params: dict[str, Any] | None = None, notify: bool = False) -> Any:
        headers = {"Authorization": f"Bearer {await self._bearer(http)}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": PROTOCOL}
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})}
        if not notify:
            msg["id"] = secrets.randbelow(10**9)
        t0 = time.perf_counter()
        r = await http.post(self.url, json=msg, headers=headers)
        entry: dict[str, Any] = {"method": method, "status": r.status_code, "ms": round((time.perf_counter() - t0) * 1000, 1)}
        if method == "tools/call" and params:
            entry["tool"], entry["arguments"] = params.get("name"), params.get("arguments", {})
        self.trace.append(entry)
        if notify:
            return None
        r.raise_for_status()
        body = r.json()
        if "error" in body:
            raise RuntimeError(body["error"].get("message", "MCP error"))
        return body["result"]

    async def initialize(self, http: httpx2.AsyncClient) -> str:
        res = await self.rpc(http, "initialize", {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "alexa-plus-simulator", "version": "0.1.0"}})
        await self.rpc(http, "notifications/initialized", notify=True)
        return res.get("protocolVersion", "")

    async def call(self, http: httpx2.AsyncClient, name: str, args: dict[str, Any]) -> str:
        res = await self.rpc(http, "tools/call", {"name": name, "arguments": args})
        return " ".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text").strip()


async def llm_turn(http: httpx2.AsyncClient, mcp: McpClient, history: list[dict[str, Any]]) -> str:
    base, key, model = os.environ["KINLOCK_LLM_BASE_URL"].rstrip("/"), os.environ["KINLOCK_LLM_API_KEY"], os.environ["KINLOCK_LLM_MODEL"]
    tools = (await mcp.rpc(http, "tools/list", {}))["tools"]
    fns = [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""), "parameters": t.get("inputSchema", {"type": "object"})}} for t in tools]
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, *history]
    for _ in range(3):
        r = await http.post(f"{base}/chat/completions", headers={"Authorization": f"Bearer {key}"}, json={"model": model, "messages": messages, "tools": fns, "temperature": 0}, timeout=30)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        calls = msg.get("tool_calls") or []
        if not calls:
            return (msg.get("content") or "").strip()
        messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
        for c in calls:
            text = await mcp.call(http, c["function"]["name"], json.loads(c["function"].get("arguments") or "{}"))
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": text})
    return "Sorry, I couldn't finish that."


def simulator_routes(settings: Settings, engine: Engine, notifier: Notifier, auth: AuthServer | None = None, owner_sessions: Any = None) -> list[Route]:
    """The simulator's routes. They act as the owner (and can wipe the demo), so unless
    settings.simulator_open (KINLOCK_SIMULATOR=1 on loopback) each needs an owner sign-in."""
    from .server import OWNER_COOKIE

    local = os.environ.get("KINLOCK_SIM_MCP_BASE", f"http://127.0.0.1:{settings.port}")
    sessions: dict[str, list[dict[str, Any]]] = {}

    def client() -> McpClient:
        client_id = os.environ.get("KINLOCK_SIM_CLIENT_ID", "simulator")
        # The simulator plays an Alexa+ the owner has linked, so it holds an owner token.
        token_fn = (lambda: auth.issue_owner_access(f"{client_id}-linked")) if auth is not None else None
        return McpClient(f"{local}/mcp", f"{local}/token", settings.resource, client_id, os.environ.get("KINLOCK_SIM_CLIENT_SECRET", ""), token_fn=token_fn)

    async def page(request: Request) -> HTMLResponse:
        return HTMLResponse((ROOT / "src" / "kinlock" / "sim.html").read_text())

    async def assist(request: Request) -> JSONResponse:
        body = await request.json()
        utterance = str(body.get("utterance", "")).strip()[:500]
        sid = str(body.get("session", ""))[:64] or "default"
        history = sessions.setdefault(sid, [])[-8:]
        mcp = client()
        async with httpx2.AsyncClient(timeout=15) as http:
            version = await mcp.initialize(http)
            history.append({"role": "user", "content": utterance})
            if os.environ.get("KINLOCK_LLM_BASE_URL"):
                reply, brain = await llm_turn(http, mcp, history), os.environ.get("KINLOCK_LLM_MODEL", "model")
            else:
                tool, args = keyword_route(utterance)
                reply = HELP if tool is None else await mcp.call(http, tool, args)
                brain = "keyword router (offline stand-in for Alexa+ understanding)"
        history.append({"role": "assistant", "content": reply})
        sessions[sid] = history
        return JSONResponse({"reply": reply, "protocol": version, "brain": brain, "trace": mcp.trace})

    async def state(request: Request) -> JSONResponse:
        snap = engine.snapshot()
        snap["last_notification"] = notifier.last()
        return JSONResponse(snap)

    async def attack(request: Request) -> JSONResponse:
        body = await request.json()
        kind = body.get("kind")
        if kind == "tamper":
            return JSONResponse(engine.attack_tamper(None, int(body.get("amount_cents", 850000)), str(body.get("counterparty", "CryptoCash"))))
        if kind == "replay":
            r = engine.attack_replay()
            return JSONResponse({"ok": r.outcome == "EXECUTED", "outcome": r.outcome, "detail": r.speech, "problems": r.problems})
        return JSONResponse({"ok": False, "detail": "unknown attack"}, status_code=400)

    async def reset(request: Request) -> JSONResponse:
        """Start a fresh demo take: empty receipts, nothing waiting, original rules."""
        with engine.lock:
            for name in ("receipts.jsonl", "pending.json", "outbox.jsonl", "owner_outbox.jsonl"):
                (settings.data / name).unlink(missing_ok=True)
            shutil.copy(ROOT / "data" / "policy.example.json", settings.data / "policy.json")
            engine.last_capability = None
            sessions.clear()
        return JSONResponse({"ok": True})

    def gated(handler: Callable[[Request], Any]) -> Callable[[Request], Any]:
        async def wrapper(request: Request) -> Response:
            if not settings.simulator_open and (owner_sessions is None or owner_sessions.csrf(request.cookies.get(OWNER_COOKIE)) is None):
                if request.method == "GET" and request.url.path == "/sim":
                    return RedirectResponse("/owner", status_code=303)
                return JSONResponse({"error": "sign in on /owner first"}, status_code=401)
            return await handler(request)

        return wrapper

    return [
        Route("/sim", gated(page)),
        Route("/sim/assist", gated(assist), methods=["POST"]),
        Route("/sim/state", gated(state)),
        Route("/sim/attack", gated(attack), methods=["POST"]),
        Route("/sim/reset", gated(reset), methods=["POST"]),
    ]
