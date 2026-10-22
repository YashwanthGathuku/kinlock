# Friction log

Recorded by Yashwanth Gathuku while building for the Alexa+ track, Oct 20–22, 2026. Entries 1–4 were found on Oct 20 while building the first version of this server's sign-in and transport layer, which Kinlock reuses; entry 5 came up building Kinlock itself on Oct 22. Format follows the hackathon rules: task, steps, expected versus actual, severity, workaround, suggestion.

## 1. A real Alexa+ add-on cannot be deployed without a Solutions Architect

- **Task:** Deploy the MCP server as an Alexa+ add-on and test it in the Alexa+ web simulator.
- **Steps:** Read the MCP Toolkit overview, the "Choose the proper integration approach" page, the quickstart, and "Set Up Your Development Environment".
- **Expected:** A public install path for the Alexa AI CLI, or a hackathon sandbox.
- **Actual:** `@alexa-ai/cli` installs from a private CodeArtifact registry. Access needs an IAM role in an Amazon-owned account and "the AWS account you provided to the Alexa Solutions Architect". The overview and approach pages never state eligibility, so this surfaces only at the setup step.
- **Severity:** Critical. It blocks the primary Alexa+ path for hackathon entrants.
- **Workaround:** Built the server to every documented add-on requirement and used the simulated Alexa+ path the rules allow.
- **Suggestion:** State eligibility on the overview page. Give hackathon entrants a time-boxed sandbox role, or a CLI build that deploys to the web simulator only.

## 2. The MCP SDK's built-in auth breaks Alexa+'s 401 rule

- **Task:** Protect `/mcp` the way the Alexa+ Authentication page asks.
- **Steps:** Tried the MCP Python SDK 2.3.0's bearer middleware (`RequireAuthMiddleware`).
- **Expected:** A configuration switch to omit `WWW-Authenticate`, since Alexa+ lists it in 401 responses as not yet supported.
- **Actual:** The middleware always sends `WWW-Authenticate`. The MCP 2025-11-25 spec allows either that header or well-known discovery, so Alexa+'s rule is legal, but the common SDK path violates it by default.
- **Severity:** Important. A server built from the SDK's auth example fails Alexa+ silently.
- **Workaround:** A small ASGI gate that returns 401 with no header, plus both RFC 9728 well-known documents (`src/kinlock/auth.py`, `src/kinlock/server.py`). Covered by `test_auth_documents_and_401_without_www_authenticate`.
- **Suggestion:** Say in the Authentication page that SDK auth middleware usually sends this header, and link a known-good snippet for the major SDKs.

## 3. Where client credentials come from is not on the Authentication page

- **Task:** Configure the Tier 1 `client_credentials` client Alexa+ will use.
- **Steps:** Read the Authentication page end to end.
- **Expected:** How Alexa+ receives a client ID and secret, given Dynamic Client Registration is not supported.
- **Actual:** The page specifies the token request in detail but defers registration and redirect URIs to the Account Linking page.
- **Severity:** Nice-to-have.
- **Workaround:** Clients are configured in `clients.json`; both grant types are implemented.
- **Suggestion:** One paragraph on the Authentication page: where the ID and secret are entered, and the redirect URI pattern to allowlist.

## 4. The hackathon's Alexa+ resources point only at generic MCP docs

- **Task:** Find the Alexa+-specific requirements from the hackathon Resources page.
- **Steps:** Followed the two Alexa+ links on the Resources page.
- **Expected:** Links to the Alexa+ MCP Toolkit, its Design Guide, the 500 ms latency limit and the auth rules.
- **Actual:** Both links go to generic MCP pages (Agent Skills, Streamable HTTP). The Alexa+ pages were found by web search.
- **Severity:** Important. Without them, an entrant can miss the latency and auth rules entirely.
- **Workaround:** Searched developer.amazon.com directly.
- **Suggestion:** Link the MCP Toolkit overview, Design Guide and Authentication pages from the Resources page.

## 5. No documented way for an add-on to ask a second person to confirm

- **Task:** Hold a risky purchase and ask the owner's chosen trusted contact to approve that exact purchase.
- **Steps:** Looked through the MCP Toolkit pages listed above for a way to route a confirmation to another household member or another device.
- **Expected:** A platform pattern for out-of-band or second-person confirmation, since purchases are listed among the creative Alexa+ ideas.
- **Actual:** I found nothing for this in the pages I read. Every confirmation I found is with the person speaking.
- **Severity:** Nice-to-have for this hackathon; important for any add-on that moves money for someone who may be pressured by a caller in the room.
- **Workaround:** Kinlock sends its own single-use approval link to the contact's phone (ntfy push, or an outbox file in the demo) and binds the approval to the action's digest.
- **Suggestion:** A documented "ask another household member" primitive, such as a card delivered to a chosen member's Alexa app, that an add-on can request and then verify.
