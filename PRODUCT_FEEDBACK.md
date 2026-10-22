# Product feedback (for the Devpost form)

By Yashwanth Gathuku.

**Tools used, and for what.** The Alexa+ MCP Toolkit documentation shaped the server: spec version, transport, latency budget and the OAuth tiers. The MCP specification 2025-11-25 and the MCP Python SDK 2.3.0 run the server, over Streamable HTTP, stateless, with JSON responses. The Alexa AI CLI was not usable; see FRICTION_LOG.md, entry 1.

**What worked well.** The Authentication page is precise where it is specific: the token request format, `expires_in` at most 3600, no refresh token for client credentials, and validation of the `resource` parameter. Those turned straight into tests. The 500 ms latency rule shaped Kinlock's design: every decision is made by fixed rules over local files, with no model call inside a voice request, so tool calls answered in roughly 5 to 11 milliseconds in our local runs. Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`) map well onto Kinlock's split between tools that only lower authority and tools that ask to spend.

**What needs work.** Eligibility for real deployment, first: the CLI needs an AWS account registered with an Alexa Solutions Architect, which an entrant discovers only at the setup step. The 401 rule (no `WWW-Authenticate`) clashes with common SDK defaults and deserves a warning. Client registration for Tier 1 is deferred to another page. And for anything that spends money, a documented way to ask a second household member to confirm would let add-ons protect people who are being pressured by a caller.

**Onboarding (zero to hello world).** For the MCP server: under an hour. For a live Alexa+ add-on: not reachable within the hackathon window, for the reason above.

**Would I build with Alexa+ again?** Yes, once deployment is open. As Alexa+ gets more agentic, the question of who may authorise what becomes the important one, and MCP's structured tool calls are exactly the seam where fixed rules can sit.
