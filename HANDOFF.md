# Handoff: Kinlock, Amazon "Build, Ship, Shape" (Alexa+ track)

Owner: Yashwanth Gathuku (Ash). Last updated Oct 22, 2026.
Deadline: **Oct 23, 2026, 12:00 PT**. Target: submit by 9:00 PT.
Full plan, research and decisions: the Claude doc "Kinlock: Amazon plan and handoff" (https://claude.ai/artifact/4Su7ZrmPiwTwnzMRrdcZfR).

## Resume prompt (paste into a new session)

```text
I'm Yashwanth (Ash). Continue my Amazon "Build, Ship, Shape" hackathon entry, Alexa+ track. Deadline: Oct 23, 2026, 12:00 PT; I aim to submit by 9:00 PT.

The entry is Kinlock: an MCP server for Alexa+ that puts rules the owner set between a voice assistant and anything that spends money. Voice can lower authority (freeze, cancel, lower a limit) but never raise it; a trusted contact approves one exact action with a signed, single-use, expiring approval; rules run again at release; every decision is a hash-chained receipt. The Alexa+ screen and the shop are simulated and labelled.

Repos (attach them to this session):
- github.com/YashwanthGathuku/kinlock (main entry; read HANDOFF.md and README.md first; 39 tests)
- github.com/YashwanthGathuku/kinlock-authority (open-source library for the Open Source mini challenge; 10 tests)

Plan and decisions: the Claude doc "Kinlock: Amazon plan and handoff" (https://claude.ai/artifact/4Su7ZrmPiwTwnzMRrdcZfR).

Rules: don't change scope or rename; don't claim it runs on a real Echo, detects fraud, or any unmeasured number. Nebius waits until Amazon is submitted.

First: run the tests, then tell me which steps in "Steps left" are still open and do the next one.
```

## What Kinlock is, in five lines

1. Alexa+ understands a request and calls Kinlock's MCP tools with a structured action.
2. A pure function over the owner's rules decides: ALLOW, HOLD (trusted contact may approve), OWNER (only the owner), or DENY.
3. Voice and the trusted contact can only lower authority (freeze, cancel, lower a limit); raising it needs the owner's secure page.
4. Approvals are HMAC capabilities over the action's digest: single use, 2-minute expiry, capped at the contact's ceiling, rules re-run at release.
5. Every decision is a receipt in a hash chain.

## Status

| Piece | State |
| --- | --- |
| Code, tests (39), README, FRICTION_LOG.md, PRODUCT_FEEDBACK.md | Done, on `main` |
| kinlock-authority library (10 tests) | Done, on its own repo |
| Repos public, description and topics | Ash to confirm |
| Demo video (< 3:00, public on YouTube) | Ash records |
| Devpost text | ChatGPT drafts, Claude checks against the code |
| Submission | Ash, by 9:00 PT Oct 23 |

## Steps left

- [ ] Confirm both repos are Public; add description and topics.
- [ ] Run locally: `pip install -e .`, `python scripts/run_demo.py`, open http://127.0.0.1:8770/sim.
- [ ] Record the video (scene plan in the Claude doc). Before midnight Eastern, or set `"night_hours": null` in `data/policy.example.json` and click "New take".
- [ ] Upload to YouTube, Public, no music.
- [ ] Devpost draft checked against "What we won't claim" (below).
- [ ] Submit: Alexa+ track, repo URL, video URL, friction log, product feedback, Open Source fields (contribution URL github.com/YashwanthGathuku/kinlock-authority, username YashwanthGathuku).
- [ ] Open the Devpost page and video in a private window to check they load.

## What we won't claim

- That it runs on a real Echo or is live on Alexa+ (deployment needs Amazon's Solutions Architect access).
- That it detects fraud.
- Any unmeasured number. Measured: 39 + 10 tests pass; tool calls about 5 to 11 ms in local runs.
- That the offline keyword router is Alexa's understanding.

## Decisions (final for this submission)

- Kinlock replaces the Oct 20 developer-fleet add-on (git4agents-alexa) as the Amazon entry.
- Name Kinlock: "Countersign" is used by an Aug 2026 hackathon project with a close idea.
- Open Source mini challenge via the separate library; AWS Builder skipped (one mini prize per project; needs AWS spend and deploy time).
- Simulated Alexa+ screen and shop, labelled on screen and in the README.
- Nebius (due Oct 30) starts only after this is submitted.
