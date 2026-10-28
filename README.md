# Kinlock

[![CI](https://github.com/YashwanthGathuku/kinlock/actions/workflows/ci.yml/badge.svg)](https://github.com/YashwanthGathuku/kinlock/actions/workflows/ci.yml)
[![Verified Causal Commit Benchmark](https://github.com/YashwanthGathuku/kinlock/actions/workflows/verified-causal-benchmark.yml/badge.svg)](https://github.com/YashwanthGathuku/kinlock/actions/workflows/verified-causal-benchmark.yml)

## The agent can be compromised. Its authority cannot.

**Kinlock is a verified authority firewall for autonomous AI agents.**

Built for the **Nebius × NVIDIA Global AI Hackathon — Best Apps and Agents** track.

NVIDIA Nemotron can reason, plan and propose tools. AgentFleet can decompose work across agents. THEUSTAD can verify the causal execution proof. **None of them can grant themselves authority.** Kinlock makes the final deterministic ALLOW / HOLD / OWNER / DENY decision, and a consequential external effect is eligible to execute only through a verified one-time commit path.

**Hackathon stack**

- **Nebius Token Factory** — serves the NVIDIA models used by the agent at runtime.
- **NVIDIA Nemotron 3 Ultra** — primary agent reasoning and tool planning.
- **NVIDIA Nemotron 3 Super** — fallback reasoning model.
- **NVIDIA Nemotron 3 Nano** — fast structured scam/risk-signal extraction.
- **AgentFleet** — multi-agent planning/delegation integration and staged-effect outbox.
- **THEUSTAD** — planner-independent causal proof verifier.
- **Kinlock** — deterministic authority policy, owner/trusted-contact controls, signed receipts and commit boundary.
- **Rust/WASM authority core + Go MCP gateway** — cross-language enforcement path backed by 7,120 conformance vectors.

> **Current deployment status:** the Docker/web demo runs locally and the repository contains Nebius deployment instructions. A public hosted endpoint must be added before final Devpost submission. Recorded Token Factory fixtures are clearly labeled; live mode requires `NEBIUS_API_KEY`.

---

## 30-second demo

The strongest demo is not a chatbot conversation. It is an **agent compromise**.

```text
Suspicious / poisoned context
          |
          v
    Nemotron agent
          |
          v
     AgentFleet
  several local steps
          |
          v
proposed consequential effect
          |
          v
      THEUSTAD
 authority / provenance /
 temporal proof fails
          |
     NO COMMIT TOKEN
          |
          v
       Kinlock
 deterministic authority
          |
          v
   NOTHING EXECUTES
```

Run the deterministic proof demo:

```bash
python scripts/verified_causal_demo.py
python scripts/verified_causal_demo.py --json
```

It contains three complementary cases:

1. **Distributed authority amplification** — several ordinary-looking agent steps compose into a recovery-email mutation. The final worker has authority its parent never had. THEUSTAD rejects the causal proof; no commit token is issued; nothing reaches the downstream.
2. **Verified safe transaction** — valid evidence and attenuating delegation support a message to a known contact. THEUSTAD passes; Kinlock allows; the fake downstream executes; the signed receipt chain verifies.
3. **Valid proof, consequential identity action** — the causal proof itself is valid, but Kinlock still returns `OWNER` and preserves its identity cool-off. **Proof validity is not authorization.**

The intended takeaway:

> **The models may be wrong, manipulated or compromised. The effect boundary still has to prove authority.**

---

## Why another LLM guardrail is not enough

A classifier can answer “does this request look suspicious?” That is useful, but it does not solve the systems problem.

Kinlock is designed around failures that can span time and agents:

- one worker reads a message;
- another reads account state;
- a planner combines the observations;
- a later worker proposes an irreversible tool call;
- each local step may look reasonable;
- the **composition** can still exceed the user's authority.

The security question is therefore not only:

```text
Is this tool call malicious?
```

It is:

```text
Can this exact proposed effect prove a valid causal path
from authenticated human intent, through every delegation
and piece of evidence, without increasing authority?
```

That is the purpose of **Verified Causal Commit**.

---

# Verified Causal Commit

Full design/threat-model document: [`docs/VERIFIED_CAUSAL_COMMIT.md`](docs/VERIFIED_CAUSAL_COMMIT.md)

## Architecture

```text
Human / owner intent
        |
        v
+------------------+
| NVIDIA Nemotron  |  reason, plan, propose
+--------+---------+
         |
         v
+------------------+
|    AgentFleet    |  decompose, attenuate delegation,
|                  |  bind evidence, stage effects
+--------+---------+
         |
         | kinlock.verified-action/1
         v
+------------------+
|     THEUSTAD     |  independent proof checker
|                  |  ancestry + scope + provenance + time
+--------+---------+
         |
         | verification witness
         v
+------------------+
|      Kinlock     |  deterministic policy / owner authority
+--------+---------+
         |
         | short-lived one-time commit token
         v
+------------------+
| Downstream tool  |  external effect
+------------------+
```

## Core invariants

### Authority conservation

For every delegation:

```text
Authority(child) ⊆ Authority(parent)
```

The prototype scope binds:

- tools;
- categories;
- verbs;
- targets;
- amount ceiling;
- delegation depth; and
- expiration.

A child cannot create authority its parent did not possess.

### Bound provenance

Evidence is not trusted because text says it is trusted. A structured evidence record includes producer, source tool, request/response hashes, timestamp, parent evidence and a signature. Editing signed provenance fields invalidates the proof.

### Temporal contracts

A certificate may include `not_before`, expiry, required facts and forbidden facts. This lets the verifier enforce ordering/cooling/revocation properties deterministically.

### Exact effect binding

The proof is bound to:

- the Kinlock action digest;
- downstream tool name; and
- exact tool arguments.

Changing the arguments after verification fails closed.

### Proof before effect

The ordinary `Engine` remains unchanged. `VerifiedEngine` adds the commit boundary and calls the verifier immediately before the existing downstream execution path.

If proof is absent, malformed, expired, amplified or inconsistent:

```text
FAILED
commit token = none
downstream calls = 0
```

### Single-use commit

A valid proof produces a short-lived HMAC-signed commit token bound to the effect digest. It is consumed before external execution and cannot be replayed.

---

# AgentFleet integration

The companion AgentFleet work is isolated in:

```text
YashwanthGathuku/agent-orchestration-os
branch: kinlock-integration
PR: #12
```

It adds:

```text
python/fleet/causal_authority.py
python/fleet/effect_outbox.py
```

`CausalCertificateBuilder` exports only the causal ancestry needed to justify one effect. It rejects obvious authority amplification before export, but **its output is still treated as untrusted** and is independently checked by THEUSTAD.

The effect outbox is append-only and hash chained. Importantly, it has **no method that executes an external tool**. AgentFleet can stage a side effect; Kinlock owns the final execution authority.

AgentFleet already contains an ACRFence postcondition/crash-resume fence. The two ideas have different jobs:

```text
Effect outbox / Verified Causal Commit
    prevents execution before authority is proven

ACRFence
    protects postcondition/idempotent crash-resume behavior
```

---

# THEUSTAD integration

The companion THEUSTAD work is isolated in:

```text
YashwanthGathuku/theustad
branch: causal-commit-verifier
PR: #5
```

The canonical checker accepts a plain serialized `kinlock.verified-action/1` certificate. It does **not** import Kinlock's planner or policy engine.

Because the upstream THEUSTAD repository is private during this hackathon, the small verifier used by the public runtime is inspectable here:

```text
src/kinlock/_vendor/theustad_causal_commit.py
src/kinlock/theustad_bridge.py
```

The source-lock metadata is documented in [`docs/VERIFIED_CAUSAL_COMMIT.md`](docs/VERIFIED_CAUSAL_COMMIT.md).

---

# Adversarial benchmark

The labeled corpus lives at:

```text
eval/causal_commit_corpus.json
```

Run:

```bash
python eval/verified_causal_benchmark.py
python eval/verified_causal_benchmark.py --write eval/results/latest.json
```

Current corpus categories include:

- valid benign certificates;
- tool/category/target/delegation-depth amplification;
- broken causal ancestry;
- delegation cycles;
- actor substitution;
- provenance response/source/signature tampering;
- premature, expired and revoked temporal state;
- missing temporal preconditions;
- action/tool/argument substitution;
- missing evidence;
- invalid evidence ancestry; and
- duplicate evidence identifiers.

The runner computes from the actual run:

```text
authority_escape_rate
unsafe_commit_count
benign_completion_rate
false_block_count
verdict_accuracy
median_verification_latency_us
p95_verification_latency_us
```

No benchmark number is hard-coded into the UI.

`.github/workflows/verified-causal-benchmark.yml` fails if the labeled corpus produces an unsafe commit or false block and uploads the measured report plus demo JSON as a workflow artifact.

**Limit:** this benchmark evaluates the deterministic proof boundary, not Nemotron jailbreak resistance. A broader AgentDojo/STAC-derived corpus is future work.

---

# Nemotron on Nebius Token Factory

Kinlock runs an NVIDIA Nemotron agent whose consequential tool calls go through the authority firewall.

| Role | Model | Purpose |
|---|---|---|
| Agent | `nvidia/Nemotron-3-Ultra-550b-a55b` | Plans and calls tools in an agent loop. It has no approval tool. |
| Fallback | `nvidia/nemotron-3-super-120b-a12b` | Takes over if an Ultra call fails. |
| Signals | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | Produces structured scam/risk cues such as urgency, secrecy, impersonation, remote access, gift cards, crypto, credential requests and prompt injection. |

Runtime flow:

```text
Nemotron Ultra proposes a tool call
        |
        v
Nemotron Nano extracts structured risk cues
        |
        v
cues become scam:model_* signals
        |
        v
Kinlock deterministic policy
        |
  ALLOW / HOLD / OWNER / DENY
        |
        v
signed receipt returned to Ultra
        |
        v
Ultra adapts / explains result
```

**Model-derived signals may only preserve or raise restriction. They cannot lower the deterministic policy result.** If Nano misses a cue or returns malformed JSON, it does not grant more authority.

Setup:

```bash
export NEBIUS_API_KEY=...
python scripts/nemotron_demo.py
python scripts/nemotron_demo.py --live
python scripts/nemotron_demo.py --live --scenario tech_support_hijacked
```

The checked-in fixtures are recorded Token Factory responses and identify themselves as recorded. Live mode is explicit.

Current scenarios include:

- `errand` — refill + known-contact message;
- `tech_support` — fake Microsoft support caller;
- `tech_support_hijacked` — compromised-agent variant that tries AnyDesk;
- `injection` / `injection_hijacked` — malicious retrieved email;
- `recovery_email_hijacked` — compromised agent attempts a Gmail recovery-email change.

In the recorded attack runs, the compromised agent can propose the dangerous tool. The deterministic policy still decides whether it can happen.

---

# Judge-facing web demo

```bash
python scripts/nemotron_web.py
# open http://localhost:8080
```

Or:

```bash
docker build -t kinlock .
docker run -p 8080:8080 kinlock
```

The first page now leads with:

1. the distributed causal attack;
2. AgentFleet → THEUSTAD → Kinlock architecture;
3. measured benchmark metrics;
4. the safe verified commit;
5. the valid-proof-but-OWNER identity case; and
6. recorded/live Nebius Token Factory scenarios.

API endpoints used by the page:

```text
GET /api/verified-causal
GET /api/benchmark
GET /api/scenarios
GET /api/run?scenario=...
GET /healthz
```

Live Token Factory runs are disabled unless both `KINLOCK_DEMO_LIVE=1` and `NEBIUS_API_KEY` are present. The live endpoint is rate limited and visitors can only select fixed scenarios; they cannot inject arbitrary prompts.

Nebius deployment instructions: [`docs/DEPLOY_NEBIUS.md`](docs/DEPLOY_NEBIUS.md)

---

# The deterministic authority firewall

Verified Causal Commit does **not** replace the existing Kinlock firewall. It adds proof before execution.

Every consequential request is an action:

```text
category
verb
target
details
risk signals
channel
```

Kinlock returns one of:

```text
ALLOW   execute if the verified commit boundary also passes
HOLD    wait for a trusted person
OWNER   only the owner can release it, possibly after a cool-off
DENY    never execute
```

Examples:

| Category | Examples | Guard |
|---|---|---|
| money | purchase, transfer, freeze | per-action/daily/count limits, known merchant/payee rules |
| access | install software, screen sharing | remote-access restrictions and owner boundary |
| identity | recovery email/phone, password, 2FA | owner-only + cool-off |
| home | door/alarm/access codes | known vs unknown visitor authority |
| legal | sign, power of attorney, beneficiary | quorum + owner-final policy |
| data / health / comms | documents, refills, messages | standing permissions; unknown targets wait |

Core directionality invariant:

> **Low-assurance channels may lower authority but never raise it.**

Voice/service channels can freeze, cancel, revoke and tighten. They cannot unfreeze, raise limits or self-approve consequential changes.

There is deliberately **no agent approval tool**.

---

# Exact-action capabilities and receipts

Trusted-contact approval is bound to the exact action digest. It is:

- signed;
- single use;
- expiring;
- ceiling limited; and
- rechecked against policy at release time.

Changing the held action invalidates the approval.

Every decision is written into a hash-linked receipt chain and HMAC signed. Editing old receipt content or recomputing only the hash chain does not produce a valid signed history.

`VerifiedEngine` adds `verification_witness` and `verified_commit_result` receipts so a judge can see the proof boundary before the downstream result.

---

# MCP gateway

Kinlock exposes an MCP authority gateway. `data/gateway.example.json` maps downstream tools to authority actions.

- mapped consequential tools go through Kinlock;
- read-only tools may pass;
- unmapped tools are held;
- downstream refusal is receipted;
- any trusted-core error fails closed.

Action protocol: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)

MCP spec target: **2025-11-25 Streamable HTTP**.

---

# Python reference → Rust/WASM core → Go gateway

Kinlock does not rely on one language implementation silently drifting from another.

- **Python** is the reference implementation used by the service/demo.
- **Rust** ports the trusted `kinlock-authority` deciding core and uses `#![forbid(unsafe_code)]`.
- The Rust core is compiled to `wasm32-unknown-unknown`.
- **Go** embeds the WASM through wazero and exposes a standalone MCP authority gateway.

`kinlock-authority/conformance/` contains **7,120 vectors over 16 operations** recorded from the reference implementation. Python, Rust and Go/WASM are expected to reproduce them. CI also verifies the vendored authority source/vectors against their locked upstream revision.

```bash
cd go
go test ./...
go build ./cmd/kinlock-gateway
```

---

# Run locally

Python 3.11+.

```bash
pip install -e .
python scripts/run_demo.py
```

For the Nebius/NVIDIA judge demo:

```bash
python scripts/nemotron_web.py
```

For the causal proof demo:

```bash
python scripts/verified_causal_demo.py
```

For the adversarial corpus:

```bash
python eval/verified_causal_benchmark.py
```

Run tests:

```bash
pytest -q
```

---

# Security properties exercised in tests

The repository tests cover, among other things:

- routine actions vs held/owner-only actions;
- exact-action approval binding;
- forged/replayed/expired capabilities;
- post-hold mutation;
- freeze/revoke/lower-authority directionality;
- split spending / daily totals / count limits;
- receipt tampering;
- service-token scope;
- remote-access scam scenarios;
- identity cool-off;
- known vs unknown visitor access;
- legal quorum/conflict-of-interest rules;
- unmapped MCP tools;
- cross-language authority conformance;
- model signals unable to lower restrictions;
- authority-amplifying delegation;
- signed provenance tampering;
- broken causal ancestry;
- temporal-contract failure;
- action/tool/argument swaps after proof construction;
- missing proof fail-closed behavior;
- commit-token replay; and
- the complete judge-facing causal demo.

The branch's GitHub Actions result is the source of truth for current pass/fail status; this README intentionally does not hard-code a test-count that can become stale.

---

# What is real and what is simulated

| Real in the prototype | Simulated / bounded in the public demo |
|---|---|
| Nemotron Token Factory calls in live mode | Recorded responses in default replay mode |
| Deterministic policy decisions | Gmail/bank/shop/home-provider effects |
| Agent loop + tool proposals | Fake downstream service records calls instead of changing real accounts |
| THEUSTAD proof verification | Hardware-backed verifier identity is not implemented |
| Causal certificate and signed evidence prototype | Evidence signing uses HMAC rather than hardware attestation |
| Single-use commit token | Multi-effect distributed atomic transaction is not implemented yet |
| Signed/hash-linked receipts | Alexa+ visual client is historical/simulated |
| Rust/WASM conformance core | Public Nebius deployment is pending until endpoint provisioning is completed |

---

# Limitations

This is a hackathon/research prototype, not a production security boundary.

Current limitations include:

1. the public downstream services are fake;
2. the deterministic causal benchmark does not measure model jailbreak resistance;
3. one certificate currently exports a compact linear ancestry for one effect, not a general proof DAG;
4. evidence/proof keys are prototype software keys, not hardware-backed attestation;
5. commit is one-effect-at-a-time rather than a multi-effect atomic transaction;
6. the AgentFleet and THEUSTAD canonical upstream integrations are in separate draft branches/PRs during development;
7. the current benchmark corpus is synthetic and must be expanded before making broad production-safety claims; and
8. compromise of the Kinlock host, verifier keys or downstream provider is outside this prototype's threat model.

Publishing these limitations is intentional. The goal is a falsifiable systems claim, not a claim that an agent can never fail.

---

# What changed during the Nebius × NVIDIA hackathon

Kinlock itself was first committed on **October 22, 2026**, after the hackathon start date.

Nebius/NVIDIA-specific and current hackathon work includes:

- Nebius Token Factory client;
- Nemotron Ultra agent loop;
- Nemotron Super fallback;
- Nemotron Nano structured risk signals;
- recorded live Token Factory fixtures;
- fixed live/replay web demo and Docker packaging;
- recovery-email and hijacked-agent attack scenarios;
- Verified Causal Commit certificate schema;
- THEUSTAD planner-independent verifier integration;
- AgentFleet attenuating-delegation certificate emitter;
- AgentFleet staged-effect outbox;
- bound evidence provenance;
- temporal contracts;
- exact effect binding;
- one-time commit tokens;
- distributed multi-agent authority-amplification demo;
- adversarial causal-commit benchmark; and
- the new judge-facing visual demo.

---

# Earlier Alexa+ origin

Kinlock originally started as a voice-first authorization prototype: a user-owned policy layer for purchases and other consequential Alexa-style actions. That earlier interface is why the repository still contains an Alexa+ simulator, OAuth/account-linking paths and voice-oriented scenarios.

For this hackathon the scope expanded into a **general autonomous-agent authority boundary**. Alexa is now one possible client, not the product definition.

The core principle survived the transition:

> **Stopping should be easier than spending, and intelligence should never imply authority.**

---

# Research positioning

Kinlock does not claim to invent capability attenuation, runtime verification, temporal contracts, proof-carrying actions, provenance or transactional staging individually.

The research/engineering hypothesis is the **commit boundary**:

```text
valid root intent
+ attenuating delegation
+ causally bound evidence
+ temporal state
+ exact effect binding
+ independent verification
+ deterministic authority policy
= eligible to commit
```

Recent research that shaped this direction is listed and discussed in [`docs/VERIFIED_CAUSAL_COMMIT.md`](docs/VERIFIED_CAUSAL_COMMIT.md).

---

# License

Apache-2.0. See [`LICENSE`](LICENSE).
