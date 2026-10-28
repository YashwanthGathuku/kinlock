# Verified Causal Commit (protocol v2)

> **The agent can be compromised. Its authority cannot.**

Verified Causal Commit is Kinlock's execution boundary for agents. It separates three things that agent systems usually blur together:

- **planning**: what a model proposes;
- **authority**: what the owner actually granted;
- **commit**: the moment an external effect happens.

This document describes protocol `kinlock.verified-action/2`. It says what v1 got wrong, what v2 enforces and where, and what is still out of scope.

## Threat model

The agent side is assumed compromised: the model, any orchestrator, every worker and the certificate builder. It may follow injected instructions, edit anything it holds, invent delegations or evidence, misdescribe effects, replay old material and call any API it can reach.

Trusted:

- the Kinlock process and its signing key;
- the owner's own surface;
- the trusted contacts' approval links;
- the downstream adapter behind the commit gate.

Out of scope:

- compromise of the Kinlock host or its keys;
- kernel-level attacks;
- a malicious downstream provider;
- the content of an allowed message, since intents scope who, what tool and how much, not the words.

## What v1 got wrong

v1's verifier was correct about internal consistency, but every field it checked was written by the untrusted side:

| v1 weakness | Consequence (measured in the Oct 28 audit) |
|---|---|
| Root intent unsigned; anyone could write its scope | A forged root with identity authority passed THEUSTAD (A1) |
| Delegation edges unsigned | The delegation check reduced to "effect ⊆ root scope", with the root from the attacker |
| Effect category, verb, target and amount self-declared, never compared to the action | $110 executed under a $20 intent (A2); a message for Anna went to Raj (A3) |
| Temporal contract and facts written by the builder | A revoked intent still committed (A4) |
| `required_evidence` chosen by the builder; the builder held the evidence key | Zero evidence passed (A5); evidence could be forged |
| Replay state in memory; commit token issued and consumed in one function | A certificate replayed after a restart (A6); the token was ceremonial |
| Action digest taken after Kinlock enriched money actions | Every honest money action failed the verified path (A2b) |

The v1 benchmark (24 cases, 0% escape) only tested attacks that wrote their escalation where the verifier looked. Five consistent forgeries added to it all passed, a 20% escape rate. That result was withdrawn.

## What v2 enforces

### 1. Kinlock mints the root

`VerifiedEngine.mint_intent` builds the root:

```text
schema, intent_id, principal, purpose, channel, issued_at, expires_at,
scope {tools, categories, verbs, targets, max_amount_cents, max_delegation_depth, expires_at},
max_effects, required_evidence, temporal {not_before, required_facts, forbidden_facts}, nonce
```

It signs the root: `sig_0 = HMAC(K_intent, root)`. The token handed to the agent side is `{root, edges: [], sig: sig_0}`. `K_intent` never leaves Kinlock.

**Channel clamp.** A request that arrives on a low-assurance channel (voice, an agent) is limited to the owner's standing permissions:

- categories with standing verbs, minus owner-only categories;
- those verbs;
- known targets;
- tools whose gateway mapping falls inside those;
- no money.

Anything removed is listed in the `intent_minted` receipt. Identity and legal authority can only come from the owner's own surface.

### 2. Delegation is a caveat chain

To delegate, the holder appends an edge and re-keys:

```text
sig_i = HMAC(sig_{i-1}, canonical(edge_i))
```

Anyone holding a token can append. Without `K_intent` nobody can change the root, remove an edge, reorder edges or splice chains, because the verifier recomputes `sig_n` from the root. This is the Macaroons construction (Birgisson et al., NDSS 2014).

Each edge must still narrow its parent on every axis:

- tools, categories, verbs, targets;
- amount ceiling;
- delegation depth;
- lifetime.

It must also continue the path (its parent is the previous child), with no cycles and no future-dated or expired edges.

### 3. The effect is derived, not declared

Before verifying, Kinlock maps the call it is about to execute through the gateway's tool map. The result must match the action Kinlock evaluated on category, verb, target and amount: an action that says "Anna" can't carry a call to Raj.

The certificate's effect fields must equal that derived effect, and scope is checked against the **derived** values. A certificate that says "$15" for a $110 call, or "Anna" for a call to Raj, fails.

### 4. Evidence is signed at the gateway

When a read-only tool passes through `Gateway.call` with an `intent_id`, Kinlock signs a record:

```text
schema, evidence_id, intent_id, producer, source_tool, request_hash, response_hash, observed_at, parent_evidence
```

It is signed with `K_evidence`. The agent side receives records but not the key.

The verifier accepts a record only if:

- the signature verifies;
- it belongs to this intent;
- it isn't from the future;
- its parents appear earlier.

The **signed root** fixes which evidence kinds (`source_tool`) an effect needs; the certificate can't remove them.

### 5. Time, revocation and budget come from trusted state

- `not_before`, `required_facts` and `forbidden_facts` are in the signed root.
- Facts are the union of:
  - Kinlock state: `intent_revoked`, from an `intent_revoked` receipt; `safety_lock`, while frozen;
  - the kinds of valid evidence.
- A revoked intent always fails.
- `max_effects` is signed. Effects used are counted from `verification_witness` receipts.
- Consumed certificate nonces are read from the same receipts, so a restart forgets nothing.

### 6. The commit gate

`VerifiedEngine` wraps its downstream in `CommitGate`. On success the guard issues a token: `HMAC(K_commit, {token_id, call_digest, basis, issued_at, expires_at})`. Here `call_digest = sha256({tool, arguments})` and `basis` is `certificate:<nonce>` or `approval:<cap_id>`. The engine arms the gate with that token and calls through it.

The gate refuses any call that comes with:

- no token;
- a bad signature;
- a different call digest;
- an expired token;
- a token it has already consumed.

Calling the downstream directly, or re-arming a consumed token, fails.

### 7. Two roads to authority

- **Autonomous:** certificate + Kinlock policy ALLOW → `verification_witness` (basis `owner_intent_certificate`) → token → gate.
- **Held, then released:** Kinlock policy HOLD or OWNER parks the action. An exact-action approval capability from a trusted contact, a quorum or the owner releases it. The release writes a `verification_witness` (basis `approval_capability`) and goes through the gate.

Nothing else reaches the downstream. **A valid proof is not authorization:** it still goes through policy. An owner-signed identity change gets OWNER and a 24-hour cool-off.

## Where it lives

| File | Side | What |
|---|---|---|
| `src/kinlock/theustad_verifier.py` | trusted, independent | The verifier. Standard library only; imports nothing from Kinlock's planner or policy (a test checks this) |
| `src/kinlock/verified_runtime.py` | trusted | Key derivation, `IntentMinter`, `EvidenceSigner`, `VerifiedExecutionGuard`, `CommitTokenIssuer`, `CommitGate` |
| `src/kinlock/verified_engine.py` | trusted | `VerifiedEngine`: minting and clamp, durable state from receipts, request and commit path |
| `src/kinlock/gateway.py` | trusted | Tool map, evidence signing for reads, passes certificates to the engine |
| `src/kinlock/certificate_builder.py` | untrusted | What an agent can do with a token: `delegate`, `add_evidence`, `build` |
| `src/kinlock/nemotron_agent.py` | untrusted | The Nemotron agent loop, building a certificate for each consequential call |

## Receipts

Each step leaves a signed, hash-chained receipt:

| Receipt | When |
|---|---|
| `intent_minted` | Kinlock signs an intent: scope, clamp, budget, evidence kinds, temporal contract |
| `intent_revoked` | The owner, or any channel, revokes; this only lowers authority |
| `decided` | Kinlock policy decision for each request |
| `unproven_request` | A held or owner-only request whose certificate didn't verify, so the approver knows the agent couldn't prove it was asked |
| `verification_failed` | Proof or binding refused at commit, with the problems |
| `verification_witness` | Proof accepted (or approval basis), certificate nonce, call digest, commit token id |
| `executed` / `downstream_failed` | The gated downstream result |
| `verified_commit_result` | Links the witness to the result |

## Evaluation

`eval/verified_causal_benchmark.py` runs 42 cases end to end:

- 6 legitimate;
- 20 classic attacks;
- 16 forgeries from the threat model above.

Current result: 0 unsafe commits. All 36 attacks are stopped by the proof and commit layer on its own (`policy_only_stops = 0`), and 6 of 6 legitimate actions complete. CI fails on any regression. `tests/test_verified_runtime.py` has each audit attack as a named test (`test_A1` … `test_A6`, `test_A2b`).

## Still open

- An independent red team, and trajectory benchmarks (AgentDojo, STAC-style) with a real model in the loop.
- Hardware-backed keys and verifier identity.
- A general proof DAG for parallel delegation; multi-effect atomic commits.
- Constraining the content of allowed messages, not just their target.
- Syncing protocol v2 back to the separate THEUSTAD repository, which still carries v1.

## One-sentence invariant

> **Every committed effect carries either a Kinlock-signed owner intent that only narrowed on its way to the call that actually runs, or an exact-action approval from a person, and it commits once.**
