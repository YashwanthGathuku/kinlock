# Kinlock pitch video: script and storyboard

Output: `kinlock_pitch_final.mp4`, 1280x720, 146 s, voiceover (edge-tts en-US-AriaNeural) with burned-in captions.
Built by `scripts/pitch_video/build_pitch.py`. Each segment's length is its own voiceover clip plus 0.35 s, so screen and narration stay in sync.

```
python scripts/pitch_video/build_pitch.py --evidence <dir with run_log.json and shots/> --out kinlock_pitch_final.mp4
```

## Where every on-screen fact comes from
* Hook and "same call, live agent": `tests/fixtures/nemotron/recovery_email_hijacked.json` — Nemotron 3 Ultra responses recorded live on Nebius Token Factory, replayed through the real runtime and THEUSTAD verifier at build time.
* Delegation chain, THEUSTAD table, commit token, terminal output: `scripts/verified_causal_demo.py` (and `--json`), run at build time. This is a **deterministic local run with no model calls**, and the video labels it so. The attacker address there is `attacker@protonmail.com`; the live fixture's is `josh.newphone@protonmail.com`. They are separate runs.
* AnyDesk DENY and Nano cues: `tests/fixtures/nemotron/tech_support_hijacked.json`, replayed.
* Evidence segment: screenshots and `run_log.json` from the Oct 29 2026 live real-world run (see `docs/LIVE_TEST_LOG.md`). The builder asserts R4 = refill ALLOW + buy HOLD and R5 = send_message ALLOW before using them.
* Problem statistics: FBI IC3, 2024 Elder Fraud Report (147,127 complaints from people 60+, $4.885 billion losses; tech support $982,440,006). https://www.ic3.gov/AnnualReport/Reports/2024_Elder_Fraud_Report.pdf

## Deliberately left out
* "AgentFleet": not part of this runtime, so the video does not name it. The chain shown is Kinlock's own signed delegation (caveat) chain: owner -> planner -> identity worker, with reader agents supplying gateway-signed evidence.
* THEUSTAD check names map to the on-screen labels as: root intent = `root_intent_time`; provenance = `kinlock_signed_intent_chain` + `gateway_signed_evidence`; temporal state = `temporal_contract_from_state`; effect binding = `effect_derived_and_within_intent`; delegation scope = `authority_conservation`.

## Storyboard
| Start | Length | Beat | Narration |
|---|---|---|---|
| 0:00.0 | 6.7s | Hook: compromised agent proposes change_recovery_email (live fixture A6) | The AI agent has been compromised. It wants to change Grandma's recovery email. |
| 0:06.7 | 8.1s | Delegation chain + AUTHORITY AMPLIFICATION (verified_causal_demo.py, deterministic) | In a chain of agents, a planner hands an identity worker power the owner never gave. Authority amplification. |
| 0:14.8 | 7.3s | THEUSTAD certificate check -> FAIL | THEUSTAD checks the certificate. Four checks pass. Delegation scope fails. |
| 0:22.1 | 9.3s | COMMIT TOKEN NOT ISSUED / DOWNSTREAM EXECUTION BLOCKED + live-run proof | No commit token. Execution blocked. In the live Nemotron run, the call failed too, and was held for the owner. |
| 0:31.4 | 9.3s | Tagline | The agent was compromised. The action still did not happen. Kinlock: the authority firewall for AI agents. |
| 0:40.7 | 15.6s | A4 AnyDesk DENY with Nano cues (live fixture) | A fake tech support call. The hijacked agent tries to install AnyDesk. Nemotron Nano flags impersonation, remote access, secrecy, threat and urgency. Kinlock denies it, and tells her to hang up. |
| 0:56.3 | 19.4s | Problem + who it helps (FBI IC3 2024 Elder Fraud Report) | Why it matters. In 2024, Americans over sixty reported four point nine billion dollars in fraud losses to the FBI. Nearly a billion of that was tech support scams. Kinlock is built for older and blind people who use voice assistants, and for the caregivers who look out for them. |
| 1:15.7 | 21.5s | Architecture: Ultra + Nano on Nebius Token Factory -> THEUSTAD -> policy -> commit token | The architecture. Nemotron Ultra on Nebius Token Factory plans the tool calls. Nemotron Nano reads each call for scam cues, and can only add caution. THEUSTAD verifies the certificate, Kinlock's policy decides, and only a commit token lets a tool run. Every step gets a hash-chained receipt. |
| 1:37.1 | 15.2s | Evidence (Oct 29 live video): R4 refill ALLOW / water bill HOLD | We ran 8 live real-world scenarios on Nebius Token Factory and kept the failures. In a real errand, the prescription refill was allowed. The forty-two dollar water bill was held for her daughter, because City Water is a new shop. |
| 1:52.3 | 15.8s | Evidence: R5 Dr Patel ALLOW, receipts 8/8, R8 bug fixed | Sending her blood pressure log to Doctor Patel was allowed, inside her signed intent. Receipt chains verified: 8 of 8. One bug we found, a spoken summary claiming a firewall decision that never happened, is now fixed and tested. |
| 2:08.1 | 11.7s | Honest limits | To be clear: downstream tools are simulated, and live model results vary from run to run. The delegation demo is deterministic. We publish the misses too. |
| 2:19.8 | 6.3s | Close | Intelligence can fail. Authority still holds. Kinlock. |
