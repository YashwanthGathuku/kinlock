"""A small OAuth 2.1 authorization server and bearer check, shaped to Alexa+.

Alexa+'s MCP add-on rules (Authentication page, retrieved Oct 20, 2026) ask for:
  * authorization server metadata at /.well-known/oauth-authorization-server,
    with S256 in code_challenge_methods_supported;
  * protected resource metadata (RFC 9728);
  * client_credentials for service access (scope mcp:service, no refresh token,
    expires_in <= 3600) and authorization_code + PKCE for user access;
  * the `resource` parameter equal to the MCP server's canonical URI;
  * client credentials via HTTP Basic or the POST body, never the query string;
  * 401 on unauthenticated MCP requests WITHOUT a WWW-Authenticate header;
  * no Dynamic Client Registration (clients are configured, not registered).

This server holds one owner. Tokens are random opaque strings; only their
SHA-256 is stored, so a dump of the store does not leak usable tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

ACCESS_TTL = 3600  # Alexa+: expires_in must be <= 3600
CODE_TTL = 120
REFRESH_TTL = 30 * 24 * 3600
SERVICE_SCOPE = "mcp:service"
READ_SCOPE = "kinlock:read"
ACT_SCOPE = "kinlock:act"  # spend money or change rules: only on a token the owner linked herself
USER_SCOPES = (READ_SCOPE, ACT_SCOPE)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def b64url_sha256(s: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(s.encode("ascii")).digest()).rstrip(b"=").decode()


PBKDF2_ITERATIONS = 600_000  # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
MAX_PASSPHRASE_FAILURES = 5  # wrong owner passphrases within FAILURE_WINDOW ...
FAILURE_WINDOW = 15 * 60
LOCKOUT_SECONDS = 5 * 60  # ... lock owner sign-in (page and account linking) for this long


def hash_passphrase(passphrase: str, iterations: int = PBKDF2_ITERATIONS, salt: bytes | None = None) -> str:
    """The stored form of the owner passphrase: pbkdf2_sha256$<iterations>$<salt hex>$<hash hex>."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_passphrase(stored: str, passphrase: str) -> bool:
    """Constant-time check against either stored form. A bare 64-character hex string is the
    older unsalted SHA-256 form, still accepted so existing var/.env files keep working."""
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters, salt, want = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), bytes.fromhex(salt), int(iters))
        except ValueError:
            return False
        return hmac.compare_digest(dk.hex(), want.lower())
    return hmac.compare_digest(sha256_hex(passphrase), stored.lower())


def has_scope(grant: Grant | None, scope: str) -> bool:
    """Whether a grant carries `scope`. Owner scopes (kinlock:*) count only when the owner
    granted them through the authorization-code flow; a service token never has them."""
    if grant is None or scope not in grant.scope.split():
        return False
    return scope == SERVICE_SCOPE or grant.subject == "owner"


@dataclass
class Client:
    client_id: str
    secret_sha256: str
    redirect_uris: list[str] = field(default_factory=list)
    grants: list[str] = field(default_factory=lambda: ["client_credentials", "authorization_code", "refresh_token"])

    def check_secret(self, secret: str) -> bool:
        return hmac.compare_digest(self.secret_sha256, sha256_hex(secret))


@dataclass
class Grant:
    client_id: str
    scope: str
    resource: str
    expires: float
    kind: str  # access | refresh | code
    subject: str  # "service" or "owner"
    redirect_uri: str | None = None
    challenge: str | None = None


@dataclass
class AuthServer:
    issuer: str  # e.g. https://example.trycloudflare.com
    resource: str  # canonical MCP URI, e.g. https://example.trycloudflare.com/mcp
    owner_passphrase_sha256: str
    clients: dict[str, Client]
    _store: dict[str, Grant] = field(default_factory=dict)
    clock: Callable[[], float] = time.time
    _failures: list[float] = field(default_factory=list)
    _locked_until: float = 0.0

    @classmethod
    def from_files(cls, issuer: str, resource: str, owner_passphrase_sha256: str, clients_file: Path) -> "AuthServer":
        raw = json.loads(Path(clients_file).read_text())
        clients = {c["client_id"]: Client(**c) for c in raw}
        return cls(issuer.rstrip("/"), resource, owner_passphrase_sha256, clients)

    # -- metadata -------------------------------------------------------------
    def as_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["client_credentials", "authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "scopes_supported": [SERVICE_SCOPE, *USER_SCOPES],
        }

    def prm_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SERVICE_SCOPE, *USER_SCOPES],
        }

    # -- store ----------------------------------------------------------------
    def _issue(self, grant: Grant) -> str:
        token = secrets.token_urlsafe(32)
        self._store[sha256_hex(token)] = grant
        return token

    def _take(self, token: str, kind: str) -> Grant | None:
        key = sha256_hex(token)
        g = self._store.get(key)
        if g is None or g.kind != kind:
            return None
        if g.expires < time.time():
            self._store.pop(key, None)
            return None
        if kind in ("code", "refresh"):
            self._store.pop(key, None)  # single use: codes always, refresh tokens rotate
        return g

    def check_bearer(self, authorization: str | None, required_scope: str | None = None) -> Grant | None:
        """The grant behind a bearer token, or None. With `required_scope`, also None
        unless the grant carries that scope (user scopes only count on owner grants)."""
        if not authorization or not authorization.startswith("Bearer "):
            return None
        g = self._take(authorization[7:].strip(), "access")
        if g is None or g.resource != self.resource:
            return None
        if required_scope is not None and not has_scope(g, required_scope):
            return None
        return g

    def issue_owner_access(self, client_id: str, scope: str = " ".join(USER_SCOPES)) -> tuple[str, int]:
        """Mint an owner access token in-process, for the simulator standing in for an
        account-linked Alexa+. Never reachable over HTTP; the simulator itself is gated."""
        return self._issue(Grant(client_id, scope, self.resource, time.time() + ACCESS_TTL, "access", "owner")), ACCESS_TTL

    # -- client authentication --------------------------------------------------
    def _client_from_request(self, request: Request, form: dict[str, str]) -> tuple[Client | None, str | None]:
        if "client_secret" in request.query_params or "client_id" in request.query_params:
            return None, "client credentials must not be sent in the query string"
        cid = secret = None
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            try:
                cid, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
            except Exception:
                return None, "malformed Basic credentials"
        elif "client_id" in form:
            cid, secret = form.get("client_id"), form.get("client_secret", "")
        client = self.clients.get(cid or "")
        if client is None or not client.check_secret(secret or ""):
            return None, "unknown client or wrong secret"
        return client, None

    # -- endpoints --------------------------------------------------------------
    async def token(self, request: Request) -> Response:
        form = {k: str(v) for k, v in (await request.form()).items()}
        client, err = self._client_from_request(request, form)
        if client is None:
            return JSONResponse({"error": "invalid_client", "error_description": err}, status_code=401)
        grant_type = form.get("grant_type", "")
        if grant_type not in client.grants:
            return JSONResponse({"error": "unauthorized_client"}, status_code=400)
        if grant_type != "refresh_token" and form.get("resource") != self.resource:
            return JSONResponse({"error": "invalid_target", "error_description": "resource must be the MCP server's canonical URI"}, status_code=400)

        if grant_type == "client_credentials":
            scope = form.get("scope", SERVICE_SCOPE)
            if scope != SERVICE_SCOPE:
                return JSONResponse({"error": "invalid_scope"}, status_code=400)
            access = self._issue(Grant(client.client_id, scope, self.resource, time.time() + ACCESS_TTL, "access", "service"))
            return JSONResponse({"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL, "scope": scope})

        if grant_type == "authorization_code":
            code = self._take(form.get("code", ""), "code")
            if code is None or code.client_id != client.client_id:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if form.get("redirect_uri") != code.redirect_uri:
                return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)
            verifier = form.get("code_verifier", "")
            if not (43 <= len(verifier) <= 128) or not hmac.compare_digest(b64url_sha256(verifier), code.challenge or ""):
                return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)
            return self._user_tokens(client.client_id, code.scope)

        if grant_type == "refresh_token":
            old = self._take(form.get("refresh_token", ""), "refresh")
            if old is None or old.client_id != client.client_id:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return self._user_tokens(client.client_id, old.scope)

        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    def _user_tokens(self, client_id: str, scope: str) -> JSONResponse:
        now = time.time()
        access = self._issue(Grant(client_id, scope, self.resource, now + ACCESS_TTL, "access", "owner"))
        refresh = self._issue(Grant(client_id, scope, self.resource, now + REFRESH_TTL, "refresh", "owner"))
        return JSONResponse({"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL, "refresh_token": refresh, "scope": scope})

    def _authorize_error(self, msg: str) -> HTMLResponse:
        return HTMLResponse(f"<!doctype html><p>Authorization failed: {html.escape(msg)}</p>", status_code=400)

    def _validate_authorize(self, p: dict[str, str]) -> tuple[Client | None, str | None]:
        client = self.clients.get(p.get("client_id", ""))
        if client is None or "authorization_code" not in client.grants:
            return None, "unknown client"
        if p.get("redirect_uri") not in client.redirect_uris:
            return None, "redirect_uri is not registered for this client"
        if p.get("response_type") != "code":
            return None, "response_type must be code"
        if p.get("code_challenge_method") != "S256" or not p.get("code_challenge"):
            return None, "PKCE with S256 is required"
        if p.get("resource") != self.resource:
            return None, "resource must be the MCP server's canonical URI"
        return client, None

    async def authorize(self, request: Request) -> Response:
        if request.method == "GET":
            p = {k: str(v) for k, v in request.query_params.items()}
            client, err = self._validate_authorize(p)
            if client is None:
                return self._authorize_error(err or "invalid request")
            hidden = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in p.items())
            return HTMLResponse(
                "<!doctype html><meta name=viewport content='width=device-width'><title>Link Kinlock</title>"
                "<body style='font-family:system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem'>"
                f"<h1 style='font-size:1.3rem'>Let {html.escape(client.client_id)} use Kinlock for you?</h1>"
                "<p>It can ask for actions and lower your limits. It can never raise a limit, unfreeze spending or approve a held action.</p>"
                f"<form method=post>{hidden}<label>Owner passphrase <input type=password name=passphrase autofocus required></label>"
                "<p><button>Allow</button></p></form></body>"
            )
        form = {k: str(v) for k, v in (await request.form()).items()}
        passphrase = form.pop("passphrase", "")
        client, err = self._validate_authorize(form)
        if client is None:
            return self._authorize_error(err or "invalid request")
        verdict = self.attempt_owner_passphrase(passphrase)
        if verdict == "locked":
            return HTMLResponse("<!doctype html><p>Too many wrong passphrases. Try again in a few minutes.</p>", status_code=429, headers={"Retry-After": str(self.lockout_remaining())})
        if verdict != "ok":
            return self._authorize_error("wrong passphrase")
        scope = form.get("scope") or " ".join(USER_SCOPES)
        code = self._issue(Grant(client.client_id, scope, self.resource, time.time() + CODE_TTL, "code", "owner", form["redirect_uri"], form["code_challenge"]))
        query = {"code": code, **({"state": form["state"]} if form.get("state") else {})}
        return RedirectResponse(f"{form['redirect_uri']}?{urlencode(query)}", status_code=302)

    def lockout_remaining(self) -> int:
        return max(0, int(self._locked_until - self.clock() + 0.999))

    def attempt_owner_passphrase(self, passphrase: str) -> str:
        """"ok", "wrong" or "locked". After MAX_PASSPHRASE_FAILURES wrong tries in
        FAILURE_WINDOW, every try (even the right one) is refused for LOCKOUT_SECONDS.
        The lock is for the one owner, not per address: it trades a few minutes' denial of
        service for making guessing impractical. The comparison is constant-time."""
        now = self.clock()
        if now < self._locked_until:
            return "locked"
        if verify_passphrase(self.owner_passphrase_sha256, passphrase):
            self._failures.clear()
            return "ok"
        self._failures = [t for t in self._failures if now - t < FAILURE_WINDOW] + [now]
        if len(self._failures) >= MAX_PASSPHRASE_FAILURES:
            self._locked_until = now + LOCKOUT_SECONDS
            self._failures.clear()
        return "wrong"

    def check_owner_passphrase(self, passphrase: str) -> bool:
        return self.attempt_owner_passphrase(passphrase) == "ok"


if __name__ == "__main__":
    import getpass

    print("KINLOCK_OWNER_PASSPHRASE_HASH=" + hash_passphrase(getpass.getpass("Owner passphrase: ")))
