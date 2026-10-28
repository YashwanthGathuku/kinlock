# Handoff: Kinlock, Nebius × NVIDIA Global AI Hackathon (Best Apps and Agents)

Owner: Yashwanth Gathuku (Ash). Updated Oct 28, 2026.
Deadline: **Oct 30, 2026, 10:00 PT** (check the Devpost page; submit by 09:00 PT).

## Where things stand

| Piece | State |
|---|---|
| Verified Causal Commit v2 (signed intents, caveat chain, derived binding, gateway evidence, commit gate) | Done, on this branch / main after merge |
| Audit attacks A1–A6 + A2b | Fixed; named regression tests in `tests/test_verified_runtime.py` |
| End-to-end benchmark (42 cases) | Done; enforced in CI |
| Nemotron scenarios on the verified path | Done (recorded live Token Factory runs, Oct 27) |
| Policy-proposal and Tavily panels on the judge page | Wired; show "not recorded" until a real run is recorded |
| Docker image + judge-style smoke test | Done; CI job `docker` |
| Public Nebius endpoint | **Ash**: needs a Nebius Cloud project (`docs/DEPLOY_NEBIUS.md`) |
| Recorded policy proposals / Tavily run | **Ash**: needs `NEBIUS_API_KEY` / `TAVILY_API_KEY` |
| Video (≤ 3:00, public YouTube) | **Ash**: script in `docs/VIDEO_SCRIPT.md` |
| Devpost text | Draft in `docs/DEVPOST.md`; feedback draft in `docs/NEBIUS_FEEDBACK.md` |

## Steps left, in order

1. Merge the PR once CI is green.
2. Optional, with keys: `python scripts/record_policy_proposals.py` and `python scripts/tavily_evidence_demo.py microsoft_anydesk --record`, then commit the fixtures.
3. Build and push the image, create the Nebius endpoint (`docs/DEPLOY_NEBIUS.md`).
4. `python scripts/smoke_test.py https://<public-url>` from a machine not signed in to Nebius. All lines `ok`.
5. Record the video from the public URL; upload to YouTube as Public.
6. Fill Devpost from `docs/DEVPOST.md`: demo URL, video URL, repo, track, Nebius/NVIDIA feedback.
7. Check the official rules on projects entered in other contests (Kinlock was built for the Amazon Alexa+ entry first).
8. Open the Devpost page and video in a private window. Submit.

## What we won't claim

- "100% secure", or any number without its corpus and limits.
- "Live" for a recorded replay.
- A Tavily integration that hasn't been recorded or run live.
- That AgentFleet runs in this demo, or that Kinlock runs on a real Alexa device.
