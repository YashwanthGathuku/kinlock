"""Kinlock's MCP server for Alexa+, plus the trusted contact's and owner's pages.

Alexa+ understands what the owner says and calls these tools with structured
details. Kinlock's fixed rules, not the assistant, decide what happens. Voice
is the lowest-assurance channel: through it the owner can lower her authority
(freeze spending, cancel, lower a limit) but never raise it.

Transport: MCP Streamable HTTP at /mcp, protocol 2025-11-25, stateless, JSON
responses. Every tool answers from local files, so a voice round trip stays
well under Alexa+'s 500 ms limit.
"""

from __future__ import annotations

import contextvars
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from kinlock_authority import Action
from kinlock_authority.policy import OWNER, VOICE, money

from . import pages
from .auth import ACT_SCOPE, AuthServer, Grant, has_scope
from .engine import Engine, new_request_id
from .notify import Notifier
from .settings import Settings
from .shop import USUAL

current_grant: contextvars.ContextVar[Grant | None] = contextvars.ContextVar("current_grant", default=None)

INSTRUCTIONS = (
    "Kinlock guards actions that spend the owner's money or change her safety rules. Call these tools with the "
    "structured details the owner asked for, then say Kinlock's reply in your own short words. Kinlock's rules decide; "
    "you never do. Never retry a held or refused action with different details, split it into smaller amounts, or "
    "suggest a way around the rules. Voice can lower authority (freeze spending, cancel, lower a limit) but can never "
    "raise it: unlocking spending, raising a limit or approving a held action happens only on the owner's secure page "
    "or the trusted contact's phone."
)

NOT_LINKED = (
    "I can't do that from this connection. Spending and changing rules need the owner's own linked account; "
    "this one can only check status, freeze spending or cancel what's waiting."
)

LIMIT_NAMES = {"per_order": "per_action_cents", "daily_total": "daily_cents", "daily_orders": "daily_count"}


def cents(dollars: float) -> int:
    return int(round(float(dollars) * 100))


def build_mcp(engine: Engine) -> MCPServer:
    mcp = MCPServer("kinlock", title="Kinlock", instructions=INSTRUCTIONS, version="0.1.0")
    read_only = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
    acts = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
    lowers = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)

    def who() -> str:
        g = current_grant.get()
        return f"voice:{g.client_id}" if g else "voice"

    def not_linked() -> str | None:
        """Spending and rule changes need a token the owner linked herself (kinlock:act).
        A client_credentials (mcp:service) token can read status and lower authority only."""
        if has_scope(current_grant.get(), ACT_SCOPE):
            return None
        return NOT_LINKED

    @mcp.tool(title="Order the usual", annotations=acts)
    def order_usual(list_name: str = "groceries") -> str:
        """Order the owner's saved usual basket, such as her usual groceries. Kinlock's rules decide whether it goes through, is held for her trusted contact, or is refused."""
        if refusal := not_linked():
            return refusal
        merchant, amount, category, label = USUAL.get(list_name.lower().strip(), USUAL["groceries"])
        return engine.request(Action(new_request_id(), "purchase", amount, merchant, category, (label,)), VOICE, who()).speech

    @mcp.tool(title="Request a purchase", annotations=acts)
    def request_purchase(merchant: str, amount_dollars: float, category: str, item: str) -> str:
        """Ask to buy something. `merchant` is the shop, `amount_dollars` the total, `category` a plain word such as groceries, pharmacy, electronics or gift cards, `item` what is being bought. Kinlock's rules decide: run now, hold for the trusted contact, need the owner herself, or refuse."""
        if refusal := not_linked():
            return refusal
        return engine.request(Action(new_request_id(), "purchase", cents(amount_dollars), merchant.strip(), category.strip().lower(), (item.strip(),)), VOICE, who()).speech

    @mcp.tool(title="Request a transfer", annotations=acts)
    def request_transfer(payee: str, amount_dollars: float) -> str:
        """Ask to send money to a person or account. Transfers to anyone the owner hasn't approved before always need the owner herself."""
        if refusal := not_linked():
            return refusal
        return engine.request(Action(new_request_id(), "transfer", cents(amount_dollars), payee.strip(), "transfer"), VOICE, who()).speech

    @mcp.tool(title="Freeze spending", annotations=lowers)
    def freeze_spending(reason: str | None = None) -> str:
        """Lock all purchases and transfers at once and cancel anything waiting. Safe to call at any time; for example during a suspicious phone call."""
        return engine.request(Action(new_request_id(), "freeze"), VOICE, who()).speech

    @mcp.tool(title="Unlock spending", annotations=read_only)
    def unlock_spending() -> str:
        """Asks to lift the safety lock. By design, voice can never unlock spending; Kinlock will explain that the owner unlocks it from her secure page."""
        return engine.request(Action(new_request_id(), "unfreeze"), VOICE, who()).speech

    @mcp.tool(title="Change a spending limit", annotations=acts)
    def change_limit(category: str, limit: str, new_value: float) -> str:
        """Change one of the owner's limits. `limit` is per_order, daily_total (both in dollars) or daily_orders (a count). Lowering always works by voice; raising never does."""
        if refusal := not_linked():
            return refusal
        key = LIMIT_NAMES.get(limit.strip().lower())
        if key is None:
            return "I can change the per-order limit, the daily total or the number of orders per day."
        value = int(new_value) if key == "daily_count" else cents(new_value)
        return engine.request(Action(new_request_id(), "set_limit", setting=f"{category.strip().lower()}.{key}", value=value), VOICE, who()).speech

    @mcp.tool(title="Cancel what's waiting", annotations=lowers)
    def cancel_waiting() -> str:
        """Cancel every request that is waiting for approval."""
        return engine.request(Action(new_request_id(), "cancel_pending"), VOICE, who()).speech

    @mcp.tool(title="Safety status", annotations=read_only)
    def safety_status() -> str:
        """Say whether spending is locked, what was spent today against the limits, and what is waiting for approval."""
        s = engine.snapshot()
        parts = ["Your safety lock is on." if s["frozen"] else "Your safety lock is off."]
        for cat, t in sorted(s["today"].items()):
            parts.append(f"Today you've spent {money(t['spent_cents'])} on {cat}, of {money(t['daily_cents'])}.")
        if not s["today"]:
            parts.append("Nothing has been spent today.")
        w = s["waiting"]
        if w:
            a = w[0]["action"] or {}
            who_ = "you" if w[0]["needs"] == "owner" else "your trusted contact"
            parts.append(f"{len(w)} request{'s' if len(w) != 1 else ''} waiting; the first is {money(a.get('amount_cents', 0))} at {a.get('counterparty', 'a shop')}, waiting for {who_}.")
        else:
            parts.append("Nothing is waiting.")
        return " ".join(parts)

    @mcp.tool(title="Explain the last decision", annotations=read_only)
    def explain_last_decision() -> str:
        """Explain why Kinlock allowed, held or refused the most recent request, check by check."""
        d = engine.snapshot()["last_decided"]
        if not d:
            return "There's no decision to explain yet."
        dec = d["decision"]
        failed = [c["text"] for c in dec["checks"] if not c["ok"]]
        passed = [c["text"] for c in dec["checks"] if c["ok"]]
        verdict = {"ALLOW": "went through", "HOLD": "was held for your trusted contact", "OWNER": "needs you yourself", "DENY": "was refused"}[dec["outcome"]]
        why = ("; ".join(failed[:3]) + ".") if failed else ("every check passed: " + "; ".join(passed[:3]) + ".")
        return f"Your last request {verdict}. {why[0].upper() + why[1:]} Receipt {d['seq']}."

    return mcp


# -- owner sessions ---------------------------------------------------------------------------


@dataclass
class Sessions:
    ttl: int = 8 * 3600

    def __post_init__(self) -> None:
        self._s: dict[str, tuple[float, str]] = {}

    def new(self) -> str:
        token = secrets.token_urlsafe(32)
        self._s[token] = (time.time() + self.ttl, secrets.token_urlsafe(16))
        return token

    def csrf(self, token: str | None) -> str | None:
        if not token or token not in self._s:
            return None
        exp, csrf = self._s[token]
        if exp < time.time():
            self._s.pop(token, None)
            return None
        return csrf


def page_routes(settings: Settings, engine: Engine, auth: AuthServer, notifier: Notifier) -> list[Route]:
    sessions = Sessions()
    secure = settings.public_url.startswith("https://")
    COOKIE = "kinlock_owner"

    async def approve(request: Request) -> Response:
        token = request.path_params["token"]
        if request.method == "POST":
            form = await request.form()
            res = engine.contact_decide(token, str(form.get("digest", "")), str(form.get("decision", "")) == "approve")
            view = engine.contact_view(token)
            return HTMLResponse(pages.contact_result(res, view), status_code=200 if res.outcome in ("EXECUTED", "DECLINED") else 409)
        view = engine.contact_view(token)
        if view is None:
            return HTMLResponse(pages.shell("Kinlock", "<p>This link isn't valid.</p>"), status_code=404)
        return HTMLResponse(pages.contact_page(token, view))

    async def owner(request: Request) -> Response:
        csrf = sessions.csrf(request.cookies.get(COOKIE))
        if request.method == "POST" and csrf is None:
            form = await request.form()
            if auth.check_owner_passphrase(str(form.get("passphrase", ""))):
                resp = RedirectResponse("/owner", status_code=303)
                resp.set_cookie(COOKIE, sessions.new(), httponly=True, samesite="strict", secure=secure, max_age=sessions.ttl)
                return resp
            return HTMLResponse(pages.owner_signin(error=True), status_code=401)
        if csrf is None:
            return HTMLResponse(pages.owner_signin())
        return HTMLResponse(pages.owner_page(engine.snapshot(), csrf, request.query_params.get("msg", "")))

    async def owner_act(request: Request) -> Response:
        csrf = sessions.csrf(request.cookies.get(COOKIE))
        form = await request.form()
        if csrf is None or not secrets.compare_digest(str(form.get("csrf", "")), csrf):
            return PlainTextResponse("Sign in again.", status_code=403)
        op, rid = str(form.get("op", "")), str(form.get("request_id", ""))
        if op == "unfreeze":
            msg = engine.request(Action(new_request_id(), "unfreeze"), OWNER, "owner").speech
        elif op in ("approve", "deny"):
            msg = engine.owner_decide(rid, op == "approve").speech
        else:
            return PlainTextResponse("Unknown action.", status_code=400)
        from urllib.parse import quote

        return RedirectResponse(f"/owner?msg={quote(msg)}", status_code=303)

    async def receipts(request: Request) -> Response:
        if not settings.simulator and sessions.csrf(request.cookies.get(COOKIE)) is None:
            return RedirectResponse("/owner", status_code=303)
        return HTMLResponse(pages.receipts_page(engine))

    return [
        Route("/approve/{token}", approve, methods=["GET", "POST"]),
        Route("/owner", owner, methods=["GET", "POST"]),
        Route("/owner/act", owner_act, methods=["POST"]),
        Route("/receipts", receipts),
    ]


# -- ASGI composition --------------------------------------------------------------------------


class App:
    """Routes /mcp through the bearer check and everything else to the pages.

    The 401 for /mcp carries no WWW-Authenticate header, as Alexa+ asks; clients
    discover auth through the two well-known documents.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.notifier = Notifier(settings.ntfy_url, settings.outbox)
        self.owner_notifier = Notifier(settings.owner_ntfy_url, settings.owner_outbox)
        self.engine = Engine(settings.data, settings.signing_key, settings.public_url, notify=self.notifier, notify_owner=self.owner_notifier)
        self.auth = AuthServer.from_files(settings.public_url, settings.resource, settings.owner_passphrase_sha256, settings.clients_file)
        self.mcp = build_mcp(self.engine)
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "127.0.0.1", "localhost", settings.public_host],
            allowed_origins=[settings.public_url, "http://127.0.0.1:*", "http://localhost:*"],
        )
        self.mcp_app = self.mcp.streamable_http_app(json_response=True, stateless_http=True, transport_security=security)
        routes = [
            Route("/", lambda r: RedirectResponse("/sim" if settings.simulator else "/owner")),
            Route("/.well-known/oauth-authorization-server", lambda r: JSONResponse(self.auth.as_metadata())),
            Route("/.well-known/oauth-protected-resource", lambda r: JSONResponse(self.auth.prm_metadata())),
            Route("/.well-known/oauth-protected-resource/mcp", lambda r: JSONResponse(self.auth.prm_metadata())),
            Route("/authorize", self.auth.authorize, methods=["GET", "POST"]),
            Route("/token", self.auth.token, methods=["POST"]),
            Route("/healthz", lambda r: JSONResponse({"ok": True, "receipt_chain_ok": self.engine.chain.verify().ok})),
            *page_routes(settings, self.engine, self.auth, self.notifier),
        ]
        if settings.simulator:
            from .simulator import simulator_routes

            routes += simulator_routes(settings, self.engine, self.notifier, self.auth)
        self.side = Starlette(routes=routes)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.mcp_app(scope, receive, send)
            return
        if scope["type"] == "http" and scope["path"].rstrip("/") == "/mcp":
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            grant = self.auth.check_bearer(headers.get("authorization"))
            if grant is None:
                await JSONResponse({"error": "invalid_token"}, status_code=401)(scope, receive, send)
                return
            token = current_grant.set(grant)
            try:
                await self.mcp_app(scope, receive, send)
            finally:
                current_grant.reset(token)
            return
        await self.side(scope, receive, send)


def create_app() -> App:
    return App(Settings.from_env())


def main() -> None:
    import uvicorn

    settings = Settings.from_env()
    uvicorn.run(App(settings), host=os.environ.get("KINLOCK_HOST", "127.0.0.1"), port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
