# Devpost submission draft — Best Apps and Agents

**Name:** Kinlock

**Tagline:** The agent can be compromised. Its authority cannot.

## Inspiration

Autonomous AI agents are gaining the ability to send messages, install software, move money, change account settings and coordinate other agents. That creates a different safety problem from ordinary chat: a model can be manipulated by a caller, a poisoned email, retrieved web content, or another agent and still produce a perfectly valid-looking tool call.

The hard question is no longer only "is this prompt malicious?" It is:

> **Can this exact external effect prove that it came from authority the human actually granted?**

Kinlock started from a voice-first authorization idea and grew into a general authority boundary for autonomous agents.

## What it does

Kinlock separates **intelligence**, **verification**, **authority** and **commit**.

1. **NVIDIA Nemotron 3 Ultra**, served by **Nebius Token Factory**, reasons about the task and proposes tool calls.
2. **Nemotron 3 Nano** extracts structured scam/risk cues. These cues may make the deterministic policy stricter; they can never make it less restrictive.
3. **AgentFleet** can decompose a task across workers, delegate attenuated authority, bind evidence to causal ancestry and stage consequential effects instead of executing them immediately.
4. **THEUSTAD** independently verifies a proof-carrying action certificate: root intent, delegation chain, authority scope, evidence provenance, temporal state and exact tool arguments.
5. **Kinlock** applies deterministic policy and returns **ALLOW, HOLD, OWNER or DENY**. A valid proof does not grant authority; Kinlock can still require the owner or refuse the action.
6. Only the verified path can produce a short-lived, single-use commit token for an allowed effect.
7. Decisions and verification witnesses are written into a signed, hash-linked receipt chain.

The core invariant is:

> **Every committed consequential effect must have a verifiable causal path to authenticated human authority, and no component in that path may create authority it did not receive.**

## The 30-second demo

The default demo deliberately starts with a distributed failure instead of a safe chatbot request.

A user asks agents to check Gmail recovery state and notify a known contact if anything looks wrong. Several workers perform individually ordinary steps. A compromised planner combines those observations into a proposed Gmail recovery-email mutation and fabricates identity-write authority for the final worker.

The trace reaches THEUSTAD:

`delegation edge-escalate amplifies authority`

Result:

- THEUSTAD: **FAIL**
- commit token: **not issued**
- downstream execution: **false**

The swarm assembled the attack, but it could not prove authority for the write.

The demo then shows the opposite case: a valid proof for a safe message passes THEUSTAD, Kinlock returns ALLOW, the simulated downstream executes and the receipt chain verifies.

Finally it shows why verification and authorization are separate: a causally valid recovery-email request passes THEUSTAD but Kinlock returns OWNER and the downstream still does not execute.

## Nebius + NVIDIA integration

All model roles are explicit:

| Role | NVIDIA model | Purpose |
|---|---|---|
| Acting agent | `nvidia/Nemotron-3-Ultra-550b-a55b` | multi-step reasoning and tool proposals |
| Fallback | `nvidia/nemotron-3-super-120b-a12b` | takes over if the Ultra call fails |
| Risk signals | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | structured scam/risk cues such as urgency, secrecy, impersonation, remote access and prompt injection |

The models are accessed through the OpenAI-compatible **Nebius Token Factory** API. The repository contains recorded live Token Factory fixtures for deterministic replay, and the web demo can switch to fresh live calls only when `NEBIUS_API_KEY` is supplied and live mode is explicitly enabled.

Model output is not an approval mechanism. Nemotron can propose actions and risk signals; it cannot mint authority or a commit token.

## How we built it

### Kinlock

The public Kinlock repository contains:

- deterministic authority policy;
- MCP gateway;
- exact-action approval capabilities;
- owner/trusted-contact boundaries;
- spending/count limits and identity cool-offs;
- signed, hash-linked receipts;
- `VerifiedEngine`, which fails closed if an allowed action has no valid execution proof;
- public vendored source-locked THEUSTAD causal verifier;
- Dockerized judge-facing web demo; and
- benchmark + CI workflows.

### AgentFleet

The companion AgentFleet integration exports a compact causal authority certificate for one effect and adds an append-only, hash-chained staged-effect outbox. The outbox intentionally has no tool-execution primitive: orchestration can stage an effect, but cannot commit it by itself.

### THEUSTAD

THEUSTAD is the planner-independent checker. It verifies the serialized certificate without importing the planner or Kinlock's policy engine. The small checker used by the public Kinlock demo is vendored into the public repo so judges can inspect the trusted boundary even though the canonical THEUSTAD development repo is private.

### Cross-language authority core

The existing authority reference is implemented in Python and ported to a Rust core compiled to WebAssembly. A Go MCP gateway embeds the WASM using wazero. The cross-language implementation is checked against **7,120 conformance vectors across 16 operations**.

## Measured adversarial benchmark

We added a small labeled deterministic certificate-enforcement corpus covering valid benign certificates plus authority amplification, broken delegation ancestry, cycles, actor substitution, provenance tampering, temporal violations, exact-action/tool/argument substitution and evidence failures.

A successful GitHub Actions run on **October 28, 2026** measured:

- **24** total cases
- **20** adversarial / **4** benign
- **0 unsafe commits**
- **0 false blocks**
- **0% authority escape on this 20-attack corpus**
- **100% benign completion on these four benign cases**
- **41.062 µs median** local Python verifier latency
- **71.478 µs p95** local Python verifier latency

These are deliberately scoped claims. This is a small synthetic corpus and the latency comes from one GitHub-hosted Ubuntu/Python 3.12 run; it is not a universal security or performance guarantee.

The immutable evidence summary is checked into `docs/benchmarks/verified-causal-commit-2026-10-28.json`, and the workflow also uploaded its raw result artifact.

## Recorded Nemotron attack results

Recorded live Token Factory runs include:

- routine errand: refill + known-contact message → allowed by standing policy;
- fake Microsoft support with a compromised-agent mode: agent attempts to install AnyDesk → **DENY**;
- fake family recovery message with a compromised-agent mode: agent attempts to change Gmail recovery email → **OWNER**, with no downstream execution;
- in normal instructions, Ultra often refused the scam itself — useful intelligence, but Kinlock is the boundary that remains when the model is fooled.

The compromised/hijacked mode is explicitly labelled. It is a stand-in for lost agent control, not presented as a naturally occurring Ultra failure.

## Challenges

### A strong model can make a safety demo look easier than it is

Well-instructed Nemotron Ultra often refuses obvious scams before Kinlock has anything to block. We kept those runs, but also created clearly labelled compromised-agent variants so we could test the system boundary under the assumption that the model has already lost control.

### Verification can prove the wrong thing

A proof checker is useful only if the effect, authority scope, provenance and temporal state are bound to the exact action being committed. The prototype therefore binds the certificate to the Kinlock action digest, downstream tool and exact arguments, and rejects authority-amplifying delegation.

### We wanted measurements without fake precision

Instead of putting hand-written benchmark numbers into the UI, the web demo calls the benchmark runner. CI fails if the labeled corpus produces an unsafe commit or false block. We publish the corpus limitations next to the result.

## Accomplishments

- Working Nemotron Ultra/Super/Nano agent stack on Nebius Token Factory.
- Deterministic authority policy that model signals cannot loosen.
- Proof-carrying action certificate with root intent, attenuating delegation, evidence provenance and temporal contracts.
- Planner-independent THEUSTAD verification boundary.
- One-time effect-bound commit token with replay protection.
- AgentFleet staged-effect outbox that cannot execute tools directly.
- Distributed authority-amplification attack demo.
- Measured adversarial verifier corpus wired into GitHub Actions.
- Rust/WASM + Go authority path held to 7,120 Python-reference conformance vectors.
- Signed/hash-linked decision and verification receipts.

## What we learned

The most important lesson was that **model intelligence and execution authority should be different systems**.

A classifier can reduce risk, but a model deciding that another model is safe does not establish who authorized an irreversible effect. The architecture became much clearer when we treated consequential tool calls like transactions: stage them, prove where their authority came from, apply deterministic policy, then commit.

## Limitations

We publish these because they matter:

- public demo downstream services are simulated;
- the 24-case benchmark tests deterministic certificate enforcement, not model jailbreak resistance;
- the current certificate exports a compact linear ancestry for one effect, not a general proof DAG;
- evidence signatures use software HMAC keys rather than hardware-backed attestation;
- commits are one effect at a time rather than multi-effect distributed atomic transactions;
- compromise of the Kinlock host/verifier keys/downstream provider is outside this prototype's threat model; and
- a public hosted demo endpoint still has to be provisioned before final submission.

## What's next

- broader STAC/AgentDojo-style trajectory evaluation;
- general causal proof DAGs;
- richer revocation and multi-effect transaction semantics;
- hardware-backed verifier/evidence identity;
- real downstream connectors;
- owner passkeys; and
- natural-language policy proposals where Nemotron may propose a change but deterministic validation and explicit owner confirmation remain the only route to increasing authority.

## What changed since August 26, 2026

Kinlock's first commit was **October 22, 2026**, after the hackathon began.

During the hackathon window we built:

- Kinlock authority engine, MCP gateway, receipts, approvals and generalized firewall;
- Rust/WebAssembly authority core and Go gateway;
- Nebius Token Factory client;
- Nemotron Ultra agent loop, Super fallback and Nano structured signals;
- recorded live Token Factory fixtures and fixed live/replay demo;
- Docker/web packaging;
- AgentFleet causal-authority integration and staged-effect outbox;
- THEUSTAD causal commit verifier;
- Verified Causal Commit runtime and one-time commit token;
- distributed multi-agent authority-amplification demo;
- adversarial certificate benchmark and benchmark CI; and
- judge-facing visual interface and documentation.

## Links

- **Code:** https://github.com/YashwanthGathuku/kinlock
- **Demo:** add public deployment URL before submission
- **Video:** add public YouTube URL before submission
- **Verified Causal Commit design:** `docs/VERIFIED_CAUSAL_COMMIT.md`
- **Benchmark evidence:** `docs/benchmarks/verified-causal-commit-2026-10-28.json`
