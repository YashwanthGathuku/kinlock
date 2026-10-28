# Verified Causal Commit

> **The agent can be compromised. Its authority cannot.**

Verified Causal Commit is Kinlock's experimental execution boundary for multi-agent systems. It separates **planning** from **authority** and **authority** from **commit**.

This document describes the implementation on the `verified-causal-commit` branch. It is intentionally precise about what is implemented, what is simulated, and what remains research work.

## The problem

A single tool call can look reasonable while the **trajectory that produced it is not**. In a multi-agent system, different workers may each perform locally benign operations while their composition creates an unauthorized effect. A prompt-injected planner can also try to:

- delegate authority it never received;
- splice untrusted observations into a trusted decision;
- replay an old approval;
- change tool arguments after a safety check;
- execute before a cooling period or prerequisite is satisfied; or
- exploit the gap between an agent saying "verified" and an external effect actually happening.

Kinlock's existing deterministic authority firewall remains the final policy authority. Verified Causal Commit adds a proof boundary **before an allowed effect is executed**.

## Architecture

```text
Human / owner intent
        |
        v
+------------------+
| NVIDIA Nemotron  |  reason, plan, propose tools
+--------+---------+
         |
         v
+------------------+
|    AgentFleet    |  decompose, delegate, stage effects,
|                  |  bind evidence to causal ancestry
+--------+---------+
         |
         | proof-carrying action certificate
         v
+------------------+
|     THEUSTAD     |  planner-independent verification
|                  |  authority + provenance + temporal state
+--------+---------+
         |
         | verification witness
         v
+------------------+
|      Kinlock     |  deterministic ALLOW/HOLD/OWNER/DENY
|                  |  owner authority + limits + cool-offs
+--------+---------+
         |
         | one-time commit token
         v
+------------------+
|  Downstream tool |  real effect (simulated in public demo)
+------------------+
```

**Important:** a successful THEUSTAD proof is *not* an authorization. It only proves that the proposed action has a valid causal/authority certificate. Kinlock can still HOLD, require OWNER, or DENY it.

## Implemented invariants

### 1. Authority conservation

For every delegation edge:

```text
Authority(child) subset-of Authority(parent)
```

The current scope contains explicit bounds for:

- tools;
- action categories;
- verbs;
- targets;
- amount ceiling;
- delegation depth; and
- expiration.

A child cannot introduce a tool, category, target, amount, lifetime, or delegation depth the parent did not possess.

### 2. Root-intent ancestry

The effect actor must have a continuous delegation path back to the authenticated root principal. Broken ancestry and cycles fail closed.

### 3. Cryptographically bound evidence provenance

Evidence is represented as a structured record containing:

```text
evidence_id
producer
source_tool
request_hash
response_hash
observed_at
parent_evidence[]
integrity label
confidentiality label
signature
```

Changing a signed field invalidates the provenance signature. A string inside model context that merely says `source=trusted` is not provenance.

### 4. Temporal contracts

A certificate may require:

- `not_before`;
- expiration;
- required facts; and
- forbidden facts.

This supports rules such as cooling periods and revocation state without asking an LLM to decide whether time/order constraints were satisfied.

### 5. Exact effect binding

The proof is bound to:

- Kinlock action digest;
- downstream tool name; and
- exact downstream arguments.

A tool-argument swap after verification fails closed.

### 6. Proof before effect

`VerifiedEngine` calls the execution guard immediately before Kinlock's existing downstream execution path. Missing proof, invalid proof, or verifier failure returns `FAILED`; the downstream is not called.

### 7. Single-use commit token

A verified certificate produces a short-lived HMAC-signed commit token bound to the effect digest. The token is consumed before the external side effect. Reuse is rejected.

### 8. Models cannot increase authority

The existing Kinlock invariant still applies: model-derived signals can preserve or increase restriction; they cannot lower a deterministic restriction or mint new authority.

## AgentFleet integration

Canonical upstream implementation during the hackathon:

- repository: `YashwanthGathuku/agent-orchestration-os`
- branch: `kinlock-integration`
- draft PR: `#12`

AgentFleet adds:

- `python/fleet/causal_authority.py` — emits `kinlock.verified-action/1` certificates;
- `python/fleet/effect_outbox.py` — append-only hash-chained staged-effect ledger.

The outbox intentionally has **no tool execution method**. It can stage, commit-record, or abort-record an effect. A consumer such as Kinlock must verify and execute externally.

This complements AgentFleet's existing ACRFence crash-resume/postcondition fence: the outbox prevents a planned external effect from executing before authorization, while ACRFence protects idempotent recovery/postcondition handling.

## THEUSTAD integration

Canonical upstream implementation during the hackathon:

- repository: `YashwanthGathuku/theustad`
- branch: `causal-commit-verifier`
- draft PR: `#5`
- upstream commit used for the public source lock: `6aca7311c8c4850bd7fb8772a066a569a611b90b`
- upstream `theustadlib/causal_commit.py` Git blob: `17b232f3d3dfd306cb0bfe51b644c7701d686702`

Because the THEUSTAD repository is private, Kinlock contains a small public, inspectable, source-locked checker under:

```text
src/kinlock/_vendor/theustad_causal_commit.py
```

`src/kinlock/theustad_bridge.py` serializes the certificate and invokes that independent checker. The verifier does not import Kinlock's planner or policy engine.

## Public demo scenarios

Run:

```bash
python scripts/verified_causal_demo.py
python scripts/verified_causal_demo.py --json
```

### A. Distributed authority amplification

Human intent allows checking account recovery state and notifying Anna.

Several workers perform individually ordinary steps. A compromised planner then constructs a recovery-email mutation and fabricates a delegation that grants identity-write authority the parent never possessed.

Expected result:

```text
AgentFleet-style trajectory: attack assembled
THEUSTAD: FAIL (authority amplification)
Kinlock commit token: NOT ISSUED
Downstream: NOT EXECUTED
```

### B. Verified safe transaction

A signed evidence record supports an allowed message to Anna.

Expected result:

```text
THEUSTAD: PASS
Kinlock: ALLOW
Commit token: single use
Fake downstream: EXECUTED
Receipt chain: verifies
```

### C. Valid proof, consequential identity action

The certificate itself is internally valid and explicitly includes identity authority.

Expected result:

```text
THEUSTAD: PASS
Kinlock: OWNER
24-hour identity cool-off / owner policy remains in force
Downstream: NOT EXECUTED
```

This scenario is important: **proof validity is not policy authorization**.

## Adversarial benchmark

The public corpus is:

```text
eval/causal_commit_corpus.json
```

The runner is:

```bash
python eval/verified_causal_benchmark.py
```

It currently includes labeled cases for:

- valid benign certificates;
- tool/category/target/delegation-depth amplification;
- broken delegation ancestry and cycles;
- effect-actor substitution;
- signed provenance tampering;
- erased provenance signature;
- premature/expired/revoked temporal state;
- missing temporal preconditions;
- action/tool/argument substitution;
- missing evidence;
- invalid evidence ancestry; and
- duplicate evidence IDs.

Metrics are computed from the run:

- authority escape rate;
- unsafe commit count;
- benign completion rate;
- false-block count;
- verdict accuracy;
- median verifier latency; and
- p95 verifier latency.

`.github/workflows/verified-causal-benchmark.yml` fails if the current labeled corpus produces any unsafe commit or false block and uploads the measured JSON as a GitHub Actions artifact.

## Judge-facing web demo

The existing public Nemotron demo server now exposes:

```text
GET /api/verified-causal
GET /api/benchmark
```

The first page leads with the causal commit attack, architecture, and measured verifier metrics. Recorded/live Nebius Token Factory scenarios remain available below it.

## Threat model

The prototype assumes the verifier key and Kinlock signing/commit keys are outside the agent's writable state. It is designed to tolerate a planner or worker that:

- is prompt injected;
- follows malicious retrieved text;
- proposes unauthorized tools;
- fabricates delegation metadata;
- tampers with signed evidence fields;
- changes action arguments after planning; or
- replays a consumed commit token.

It does **not** currently claim protection against compromise of the Kinlock host, theft of verifier/commit signing keys, kernel-level compromise, arbitrary code execution inside the trusted verifier process, or compromise of the real downstream provider itself.

## What this does not claim

Verified Causal Commit combines ideas from a fast-moving research area. Kinlock does **not** claim to have invented capability attenuation, temporal logic, provenance, proof-carrying actions, transactional staging, or information-flow control individually.

The engineering/research hypothesis being tested is that a practical agent runtime becomes substantially easier to reason about when these controls converge at **one commit boundary**:

```text
valid root intent
+ attenuating delegation
+ bound evidence provenance
+ temporal state
+ exact effect binding
+ independent verification
+ deterministic authority policy
= eligible to commit
```

The current implementation uses a compact linear causal ancestry for one effect. A general DAG proof, formal theorem/proof assistant model, richer revocation semantics, multi-effect atomic transactions, and broader external benchmarks remain future work.

## Research that shaped the design

The architecture was informed by recent work on system-level agent security, including:

- **Cordon: Semantic Transactions for Tool-Using LLM Agents** — staged effects / transaction semantics.
- **Proof-Carrying Agent Actions** — planner-independent action certificates.
- **Formal runtime verification for tool-using agents** — temporal/provenance checks and the danger of unbound provenance claims.
- **ContrAgent** — temporal contracts compiled to deterministic runtime monitors.
- **STAC** — attacks that emerge from compositions of individually plausible actions.
- **CaMeL** and related system-level prompt-injection defenses — separate trusted control from untrusted data.
- **Fides / information-flow work** — explicit integrity/confidentiality provenance.
- **AISI multi-agent control research** — distributed/fragmented attacks that evade per-agent monitoring.
- **NVIDIA system-level agent security research** — constrain what models can observe/decide rather than treating model judgment as the authority boundary.

These references motivate the threat model; the claims in this repository are limited to the behavior exercised by code/tests/benchmarks here.

## Current limitations

1. The public downstream services are fakes; no real Gmail/account mutation occurs in the demo.
2. The deterministic benchmark tests the trusted proof boundary, not Nemotron jailbreak robustness.
3. The current causal certificate exports a linear ancestry for one effect rather than a general proof DAG.
4. Evidence signatures use an HMAC prototype rather than a hardware-backed identity/attestation system.
5. Commit is one-effect-at-a-time; multi-effect atomic rollback is not yet implemented.
6. The THEUSTAD private-repo GitHub Actions runner failed before emitting workflow steps on the current draft PR; Kinlock's public CI independently exercises the vendored verifier boundary.
7. The benchmark corpus is synthetic and intentionally small; broader AgentDojo/STAC-derived evaluation is still needed before any production safety claim.

## One-sentence invariant

> **Every committed consequential effect must have a verifiable causal path to authenticated human authority, and no component in that path may create authority it did not receive.**
