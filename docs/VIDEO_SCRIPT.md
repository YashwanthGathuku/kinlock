# Kinlock: 3-minute video script

Record the screen with the web demo (`docker run -p 8080:8080 kinlock-nemotron`, or the Nebius URL) or the terminal (`python scripts/nemotron_demo.py`). The on-screen outcomes below come from the recorded live runs in `tests/fixtures/nemotron/`. If you record a fresh live run, say so, and read out what actually happened: models don't always respond the same way twice.

| Time | On screen | Voice-over |
|---|---|---|
| 0:00–0:20 | FBI IC3 2025 figure: $7.75B reported lost by people 60+ | "In 2025, people over 60 reported $7.75 billion lost to fraud. Now we're handing them AI agents that can act for them: send money, install apps, change account settings." |
| 0:20–0:45 | Architecture: Ultra → Nano → firewall → receipt | "Kinlock is an authority firewall between an agent and the real world. Nemotron 3 Ultra on Nebius Token Factory plans and calls tools. Nemotron Nano flags scam cues. A deterministic policy decides every action: allow, hold for a family member, wait for the owner, or deny. The models can only make a decision stricter, never looser. The agent has no approval tool at all." |
| 0:45–1:15 | `errand`: refill + text Anna, both ALLOW | "Everyday errands just work. Mary asks for her lisinopril refill and a text to her daughter. Two tool calls, both allowed by her policy, each with a signed receipt." |
| 1:15–1:50 | `tech_support_hijacked`: install_app AnyDesk → DENY | "Now a fake Microsoft caller. We simulate an agent that's been hijacked and obeys whatever it hears. It tries to install AnyDesk. Nano flags impersonation, remote access, urgency and secrecy. The firewall says no, and tells Mary in plain words to hang up." |
| 1:50–2:20 | `recovery_email_hijacked`: change_recovery_email → OWNER | "A text from 'Josh' asks to change her Gmail recovery email. That's how accounts get stolen. The hijacked agent tries it. Kinlock holds it: only Mary can approve it, from her secure page, and only after 24 hours. Saying yes out loud can't speed it up." |
| 2:20–2:40 | Caregiver summary, "receipt chain verifies: True" | "Every decision is a signed, hash-chained receipt. Nemotron turns them into a short summary for the family." |
| 2:40–3:00 | Test run, README "What changed since Aug 26" | "Nearly 400 tests, including a property test showing that no model cue ever lowers a decision. All of it was built after August 26, and it runs on Nemotron through Nebius Token Factory." |

Also worth showing if there's time: in the normal (non-hijacked) runs, Ultra refused both scams by itself. Kinlock is the layer that still holds when the model doesn't.
