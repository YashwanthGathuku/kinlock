# Kinlock — 3-minute Nebius × NVIDIA video script

**Track:** Best Apps and Agents  
**Core line:** **The agent can be compromised. Its authority cannot.**

Use the judge-facing web demo (`python scripts/nemotron_web.py`, Docker, or the deployed public URL). The video is a pitch, not a tutorial. Start with the failure case immediately.

Do not call a recorded Token Factory replay "live." If live mode is used, say it is live. If replay mode is used, say it is a recorded live Token Factory response.

## Shot-by-shot

| Time | On screen | Voice-over |
|---|---|---|
| **0:00–0:08** | Hero: **The agent can be compromised. Its authority cannot.** Click **Run the distributed attack**. | **"What happens when every AI agent does its job correctly — but together they create an action the user never authorized?"** |
| **0:08–0:28** | Attack trace: message-reader → account-reader → planner → identity-worker → `change_recovery_email`. THEUSTAD shows `FAIL: delegation edge-escalate amplifies authority`. Red **COMMIT NOT ISSUED** banner. | **"Here, several harmless-looking agent steps compose into a Gmail recovery-email takeover. The planner tries to give the final worker identity-write authority that its parent never had. THEUSTAD rejects the causal proof. Kinlock never issues a commit. Nothing executes."** |
| **0:28–0:48** | Architecture: Nemotron → AgentFleet → THEUSTAD → Kinlock → Commit. Highlight each box as named. | **"Kinlock separates intelligence from authority. NVIDIA Nemotron 3 Ultra on Nebius Token Factory reasons and proposes tools. AgentFleet can plan and delegate. THEUSTAD independently verifies authority, provenance and temporal state. Kinlock alone applies deterministic owner policy. Only then can a one-time commit token exist."** |
| **0:48–1:05** | Click **Run a verified safe transaction**. THEUSTAD PASS → Kinlock ALLOW → downstream executed → receipt chain verified. | **"Proof does not mean everything is blocked. A valid, scoped message to a known contact passes the verifier, Kinlock allows it, and the simulated downstream executes."** |
| **1:05–1:22** | Click **Show owner-only identity change**. THEUSTAD PASS → Kinlock OWNER → no downstream execution. | **"And proof is not authorization. This identity change has a valid causal proof, but Kinlock still requires the owner and preserves the cool-off. THEUSTAD can prove a request; it cannot grant authority."** |
| **1:22–1:38** | Benchmark cards. Show scenario count, authority escape, benign completion, p95. | **"We test the deterministic proof boundary with 24 labeled certificate cases: 20 adversarial and 4 benign. On this GitHub Actions run: zero unsafe commits, zero false blocks, and 71.478 microseconds p95 verification. These numbers are for this small synthetic corpus — not a universal security claim."** |
| **1:38–2:02** | Nemotron section. Run/replay `tech_support_hijacked`: AnyDesk tool attempt → DENY. Show model labels Ultra + Nano. | **"Now the AI layer. Nemotron 3 Ultra is the acting agent. Nemotron 3 Nano extracts structured risk cues. In this recorded Token Factory run, a compromised agent follows a fake Microsoft caller and tries to install AnyDesk. Kinlock denies it. Model signals may make policy stricter; they can never make it looser."** |
| **2:02–2:22** | Run/replay `recovery_email_hijacked`: `change_recovery_email` → OWNER. | **"In another recorded run, a fake family message gets the compromised agent to attempt a recovery-email change. Kinlock returns OWNER and the action does not execute. The agent has no approval tool."** |
| **2:22–2:40** | Brief repo/CI view: green CI, benchmark workflow, `docs/VERIFIED_CAUSAL_COMMIT.md`, 7,120 vectors mention. | **"The Python authority reference is cross-checked through a Rust WebAssembly core and Go MCP gateway with 7,120 conformance vectors. The new causal-commit path is exercised in CI, and benchmark failures fail the workflow."** |
| **2:40–2:55** | Return to hero/architecture. Show Nebius + NVIDIA badges. | **"The point is not another scam classifier. Autonomous agents will sometimes be manipulated, mistaken, or compromised. Kinlock makes external effects prove where their authority came from before they can commit."** |
| **2:55–3:00** | Final line: **Models propose. Proof verifies. Kinlock authorizes.** | **"Models propose. Proof verifies. Kinlock authorizes."** |

## Exact benchmark evidence for the video

The measured run used in this script is frozen at:

`docs/benchmarks/verified-causal-commit-2026-10-28.json`

GitHub Actions run: `40706431792`  
Artifact: `verified-causal-commit-results` (`12823194785`)  
Artifact SHA-256: `541d7f336b172f1ef22170afc434cf08236e872df74669d9515c94e23a648df0`

Measured on that single GitHub-hosted Ubuntu / Python 3.12 run:

- 24 total labeled cases
- 20 adversarial / 4 benign
- 0 unsafe commits
- 0 false blocks
- 0% authority escape **on this corpus**
- 100% benign completion **on these four benign cases**
- 41.062 µs median verifier latency
- 71.478 µs p95 verifier latency

Always say the scope qualifier when showing the zero/100% numbers.

## What not to spend video time on

Do **not** explain OAuth, every policy category, every class, or the Alexa history. The repo contains those details. The video needs one unforgettable idea:

> **A compromised swarm can propose a forbidden effect, but it cannot manufacture the proof and authority required to commit it.**
