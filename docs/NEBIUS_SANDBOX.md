# Running Kinlock in a Nebius Sandbox

Nebius Token Factory Sandboxes (ConTree) run code in isolated microVMs and
authenticate with the same Token Factory API key that serves Nemotron, plus
the project ID. `scripts/run_on_nebius_sandbox.sh` uploads a clean export of
this repo, installs it on the `python:3.12` image, and runs the full test
suite, all six Nemotron replay scenarios, and the attack audit.

## Result (2026-10-29, operation 01a18794-6558-7749-b124-b3a640bff4e2)

- pytest: 451 passed, 1 skipped
- Nemotron replay: all 6 scenarios complete, receipt chain ok
- attack audit: 12 of 12 findings fixed
- sandbox run time: 14.2 s

## Why the web demo is not served from a Sandbox

Sandboxes expose no inbound port or public URL. The networking guide offers
only `networking.enabled=false` and says ingress needs confirmation from the
Sandboxes team. The public demo needs a host with ingress; see
`docs/DEPLOY_NEBIUS.md`.
