# Devpost submission draft (Track 2: Best Apps & Agents)

**Name:** Kinlock

**Tagline:** An authority firewall that lets older adults use AI agents without handing scammers the keys.

## Inspiration
People over 60 reported $7.75 billion lost to fraud in 2025 (FBI IC3), and tech-support scams that end in a remote-access install are among the costliest. AI agents that can send money, install apps and change account settings for someone make this worse: a caller, a text or a poisoned email can now talk to the agent instead of the person. Banks add friction on payments, but an agent can do damage well outside a bank's payment rail.

## What it does
Kinlock sits between an agent and every tool it can use. Nemotron 3 Ultra, served by Nebius Token Factory, plans and calls tools in a multi-step loop. Before any call runs:
1. Nemotron 3 Nano reads the request and returns scam cues as JSON (urgency, secrecy, impersonation, remote access, gift cards, crypto, credential requests, threats, prompt injection).
2. A deterministic policy decides ALLOW, HOLD (a trusted contact approves), OWNER (only the owner, from a secure page, sometimes after a 24-hour wait) or DENY.
3. The decision is written as a signed, hash-chained receipt and returned to the agent as the tool result, so the agent adapts.
4. Nemotron then writes a plain spoken explanation for the owner and a summary for the caregiver.

The models can only make a decision stricter. If Nano misses a cue or returns bad JSON, the policy still decides. The agent has no approval tool.

## How we built it
Python with a stdlib OpenAI-compatible client for Token Factory (record and replay built in), the Kinlock engine and gateway, a Rust authority core that also runs in Go through WebAssembly, and a small web demo in a Docker container for Nebius Serverless AI endpoints. Models: `nvidia/Nemotron-3-Ultra-550b-a55b` (agent), `nvidia/nemotron-3-super-120b-a12b` (fallback), `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` (signals).

## Recorded live results (Oct 27, 2026)
- Errand (refill a prescription, text a known contact): both ALLOW.
- A fake Microsoft caller, with an agent told to obey what it reads: `install_app AnyDesk` → DENY.
- A fake grandson's text, same agent: `change_recovery_email` → OWNER, held with a 24-hour wait; nothing ran.
- With its normal instructions, Ultra refused both scams by itself. Kinlock is the layer that holds when an agent is fooled.

## Challenges
Getting a fair demo of the firewall: a well-instructed Ultra usually refuses scams, so we added a clearly labelled "hijacked" mode that stands in for a prompt-injected agent. Keeping the model's explanations factual took prompts that use only the receipts.

## Accomplishments
A property test checks that no model cue lowers a decision, across 9 cues × 9 actions × 3 channels. The full suite has 389 passing tests, and the cross-language core is checked against 7,120 conformance vectors.

## What we learned
A strong model is not a safety boundary on its own. Pairing it with a small fast classifier and a fixed policy gives you both judgement and guarantees.

## What's next
Real connectors (pharmacy, messaging, email), passkeys for the owner page, and a pilot with caregivers.

## What changed since Aug 26
All of Kinlock was built after Aug 26, 2026; the first commit is Oct 22, 2026. During the hackathon window we added:
- the Kinlock engine, the authority firewall, the MCP gateway and the Rust/WebAssembly core (Oct 22–27);
- Nemotron on Nebius Token Factory: Ultra agent loop with Super fallback, Nano scam-cue signals, spoken and caregiver summaries (Oct 27);
- recorded live fixtures, the raise-only property tests, and a web demo with a Dockerfile for Nebius Serverless AI endpoints (Oct 27).

## Links
- Code: https://github.com/YashwanthGathuku/kinlock
- Demo: (add the Nebius endpoint URL after deployment; see docs/DEPLOY_NEBIUS.md)
- Video: (add after recording)
