# Kinlock: 3-minute video script (Nebius × NVIDIA, Best Apps and Agents)

**Core line:** The agent can be compromised. Its authority cannot.

Record the judge page (the deployed URL, or `python scripts/nemotron_web.py`). This is a pitch, not a tutorial, so open on the attack. Say "recorded live Token Factory run" for replays and "live" only for live calls. Every sentence below maps to something the page does.

| Time | On screen | Voice-over |
|---|---|---|
| **0:00–0:10** | Hero. Click **Run the compromised swarm**. | "What happens when an AI agent is compromised halfway through a task, and tries to use your authority for something you never asked for?" |
| **0:10–0:40** | Attack table: four rows, THEUSTAD FAIL, no commit token, not run. Then the green legitimate row. | "Mary asked, by voice, to check her Gmail recovery settings and tell Anna if anything looks wrong. A compromised agent tries four ways to turn that into a recovery-email takeover. It edits the intent Kinlock signed, delegates authority it never had, describes the takeover as a message to Anna, and forges the account-check evidence. Every attempt fails the proof. None gets a commit token. The legitimate message, backed by evidence Kinlock's gateway signed, goes through." |
| **0:40–1:00** | Trust zones. Highlight left (untrusted) then right (trusted). | "Kinlock keeps intelligence and authority apart. Nemotron 3 Ultra on Nebius Token Factory plans and proposes, holding only a signed intent, no key. It can narrow that authority as it delegates, never widen it. THEUSTAD derives the effect from the real call and checks it. Kinlock's policy decides, and only a single-use token opens the downstream." |
| **1:00–1:15** | Click **Run a verified safe transaction**. | "A safe message commits once. Replay the same certificate after a restart: refused. Try a second effect past the intent's budget: refused." |
| **1:15–1:30** | Click **Show owner-only identity change**. | "And a valid proof is not permission. Mary's own page signs an identity change, so the proof passes, but Kinlock still asks her, with a 24-hour cool-off. The same request by voice is clamped before Kinlock signs anything." |
| **1:30–2:05** | Nemotron section. Run `errand`, then `recovery_email_hijacked`. Point at THEUSTAD per step and "Commits through the gate". | "Now a real Nemotron agent, in recorded live Token Factory runs. The errand, a refill and a text to Anna, passes the proof and commits twice through the gate. Then a hijacked agent obeys a fake grandson and tries to change the recovery email. Kinlock says OWNER, THEUSTAD says it's outside the intent, and nothing commits. Nemotron 3 Nano's scam cues can only make a decision stricter." |
| **2:05–2:25** | Benchmark cards. | "We test the boundary end to end with 42 cases: 36 attacks, including 16 forgeries written the way a compromised agent really would, and 6 legitimate actions. Zero unsafe commits, every attack stopped by the proof layer on its own, and every legitimate action completed. It's a synthetic corpus we wrote ourselves, and we say so." |
| **2:25–2:45** | Policy panel: click "Raise my grocery limit…" (recorded output if present), then the hostile-outputs table. | "Nemotron can also turn a sentence into a rule change. But its output is untrusted. Kinlock validates it, classifies it, and never applies it: raising a limit needs Mary herself, however safe the model says it is." |
| **2:45–3:00** | Back to the hero. | "Models propose. Kinlock signs. THEUSTAD verifies. Only proven authority commits." |

## If you have the keys before recording

- `NEBIUS_API_KEY=... python scripts/record_policy_proposals.py` gives the policy panel real recorded Nemotron output. Say "recorded live".
- `TAVILY_API_KEY=... NEBIUS_API_KEY=... python scripts/tavily_evidence_demo.py microsoft_anydesk --record` lets the evidence panel show a real Tavily run. Claim the Tavily bonus only after this has run.

## Don't say

- "100% secure", "can't be hacked", or any number without its corpus.
- "Live" for a replay.
- That AgentFleet runs in this demo: it doesn't.
- That it runs on Alexa: the Alexa+ client in the repo is historical and simulated.
