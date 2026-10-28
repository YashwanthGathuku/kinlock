# Devpost submission draft: Best Apps and Agents

**Name:** Kinlock

**Tagline:** The agent can be compromised. Its authority cannot.

**Built by:** Yashwanth Gathuku

## Inspiration

AI agents are starting to send messages, install software, move money and change account settings for people. A model can be talked into anything by a caller, a poisoned email, a web page or another agent, and still produce a perfectly valid-looking tool call.

So the question isn't only "is this prompt malicious?" It's: **can this exact effect prove it came from authority the person actually gave?**

## What it does

Kinlock keeps intelligence and authority in separate systems.

1. The owner asks for something. **Kinlock signs her intent**: which tools, which people, how much, how many effects, which evidence is required, until when. A request made by voice can only be granted what her standing permissions already allow; identity and legal changes need her own secure page.
2. **NVIDIA Nemotron 3 Ultra**, on **Nebius Token Factory**, plans and calls tools. It holds the signed intent as a token, but no key. It can delegate narrower authority (each step chains an HMAC), and it can't widen what it was given.
3. Read-only tool results are **signed by Kinlock's gateway** as evidence for that intent. The agent can collect evidence, but it can't make any.
4. Every consequential call carries a certificate. The **THEUSTAD verifier**:
   - recomputes the chain from Kinlock's key;
   - checks every delegation narrowed;
   - derives the effect from the call that will actually run, not from what the certificate says;
   - checks the evidence;
   - reads revocation, the safety lock and the effect budget from Kinlock's own receipts.
5. **Kinlock's deterministic policy** decides ALLOW, HOLD, OWNER or DENY. **Nemotron 3 Nano** scam cues can only make it stricter. A valid proof is not authorization: an identity change still needs the owner and a 24-hour cool-off.
6. The downstream only runs a call that comes with a **single-use commit token bound to exactly that tool and those arguments**.
7. Every step is a signed, hash-linked receipt.

## The demo

**A compromised swarm tries four forgeries.** The owner asked, by voice, to check her Gmail recovery settings and tell Anna if anything looks wrong. A compromised agent tries four times to turn that into a recovery-email takeover:

1. It edits the signed intent.
2. It delegates authority its parent never had.
3. It describes the takeover as a message to Anna.
4. It forges the account-check evidence.

Each attempt fails the proof, and none gets a commit token. The legitimate message to Anna, backed by real gateway-signed evidence, commits.

**A safe transaction commits once.** Replaying its certificate after a restart fails, and so does a second effect past the intent's budget.

**Proof is not authorization.** The owner's own surface signs an identity change, so the proof passes. Kinlock still says OWNER, with a 24-hour cool-off. The same request made by voice is clamped before Kinlock signs anything.

**A real Nemotron agent on the same path.** These are recorded live Token Factory runs, from Oct 27 2026:

- An errand (refill a prescription, text Anna) commits twice through the gate.
- A hijacked agent tries to install AnyDesk for a fake Microsoft caller: DENY, and THEUSTAD FAIL.
- A hijacked agent tries a recovery-email change for a fake grandson: OWNER, and THEUSTAD FAIL. Nothing commits.

## Nebius and NVIDIA

| Role | Model on Nebius Token Factory | Purpose |
|---|---|---|
| Acting agent | `nvidia/Nemotron-3-Ultra-550b-a55b` | Multi-step planning and tool calls under a signed intent |
| Fallback | `nvidia/nemotron-3-super-120b-a12b` | Takes over if an Ultra call fails |
| Risk signals | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | Structured scam cues that can only raise restriction; also classifies Tavily evidence |

Calls go through the OpenAI-compatible Token Factory API. The repository has recorded live runs for deterministic replay. Fresh calls happen only when live mode is enabled with a key.

Nemotron also turns plain-language rule changes ("Lower my daily transfer limit to $100") into one proposed operation. Kinlock validates it strictly and classifies it deterministically. It never applies it, and raising authority needs the owner.

## How we built it

- **Kinlock** (Python): authority policy, MCP gateway, exact-action approvals, signed receipts, intent minting with the channel clamp, gateway evidence signing, the verified engine and the commit gate.
- **THEUSTAD verifier**: a standard-library-only checker for protocol `kinlock.verified-action/2`. It imports nothing from Kinlock's planner or policy.
- **Cross-language core**: the Python reference, ported to Rust and compiled to WebAssembly, then embedded in a Go MCP gateway with wazero. All three are held to 7,120 conformance vectors.
- **Docker image**: CI builds it and runs a judge-style smoke test against it on every push.

## Measured

An end-to-end benchmark runs 42 cases through the full path:

- 6 legitimate actions;
- 20 classic attacks: amplifying edges, broken ancestry, tampered evidence, temporal and binding violations;
- 16 forgeries a compromised builder would actually try: re-signed or edited root, stripped, reordered or collapsed chain, misdescribed effect, omitted revocation or evidence, self-signed or cross-intent evidence, replay after restart, overspend, voice-granted identity, direct downstream call, token reuse.

**Result:**

- 0 unsafe commits out of 36 attacks;
- all 36 stopped by the proof and commit layer on its own, without relying on Kinlock's policy;
- 6 of 6 legitimate actions completed.

CI fails on any regression. The corpus is synthetic and self-authored, and it measures the deterministic boundary, not model jailbreak resistance.

## Challenges

**Our first verifier proved the wrong thing.** v1 checked a certificate that the untrusted side wrote: an unsigned root, self-declared effect metadata, and evidence signed with a key the builder held. Its 24-case benchmark scored 0% escape, because every attack wrote its escalation where the verifier looked. When we wrote attacks the way a real compromised builder would, they passed:

- a $110 purchase under a $20 intent;
- a message to the wrong person;
- a revoked intent that still committed;
- a replay after restart.

We withdrew the number, moved every trust anchor into Kinlock, and turned each attack into a named regression test and a benchmark case.

**A strong model makes a safety demo look easy.** Well-instructed Ultra often refused the scam itself. We kept those runs and added labelled hijacked runs, to test the boundary for the case where the model has already lost.

## What we learned

A model deciding that another model is safe doesn't establish who authorized an irreversible effect. Consequential tool calls should be treated like transactions:

- sign the person's intent;
- let agents only narrow it;
- derive the effect from the call that will run;
- apply deterministic policy;
- commit once.

## Limitations

- Downstream services in the public demo are simulated.
- The benchmark is synthetic and self-authored.
- Keys are software HMAC keys inside the Kinlock process, not hardware-backed.
- Intents scope tools, targets and amounts, not the words of an allowed message.
- One effect per commit.
- The separate THEUSTAD repository still needs protocol v2.

## What's next

- An independent red team and model-in-the-loop trajectory benchmarks.
- Hardware-backed keys.
- Owner passkeys.
- Real downstream connectors.
- Proof DAGs for parallel delegation.

## Built during the hackathon

Kinlock's first commit was on **October 22, 2026**, within the submission period (Aug 26 – Oct 30, 2026). Everything above was built in that window.

## Links

- **Code:** https://github.com/YashwanthGathuku/kinlock
- **Demo:** add the public Nebius URL after `python scripts/smoke_test.py <url>` passes
- **Video:** add the public YouTube URL
- **Design:** `docs/VERIFIED_CAUSAL_COMMIT.md`
