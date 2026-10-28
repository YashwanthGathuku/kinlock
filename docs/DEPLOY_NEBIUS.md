# Deploy Kinlock on Nebius Serverless AI

Kinlock's judge demo is one small CPU container (`Dockerfile` at the repository root). The NVIDIA models run on **Nebius Token Factory**, so the web container does not need a GPU.

The public page includes:

- the deterministic **Verified Causal Commit** scenarios: compromised swarm, safe transaction, valid proof that still needs the owner;
- the end-to-end adversarial benchmark, computed by the container at startup;
- recorded live Nemotron Token Factory runs, all on the verified path;
- the policy-proposal and Tavily evidence panels; and
- optional fresh live calls when explicitly enabled.

It works **without any API key**. The deterministic scenarios and the benchmark run inside the container. Nemotron scenarios replay checked-in responses labelled "recorded live Token Factory run". The policy and evidence panels show recorded live output where it exists, and otherwise say "not recorded".

Fresh model calls require both:

```text
KINLOCK_DEMO_LIVE=1
NEBIUS_API_KEY=...
```

(plus `TAVILY_API_KEY` for live evidence checks). Visitors can only pick fixed scenarios, requests and claims; they can't send prompts. Live calls share an hourly budget, `KINLOCK_DEMO_LIVE_PER_HOUR` (default 30).

## Current status

- The image is built and smoke-tested in CI (`.github/workflows/ci.yml`, job `docker`) with `scripts/smoke_test.py`.
- The benchmark contract (0 unsafe commits, 0 false blocks, every attack stopped by the proof layer) is enforced in CI.
- **No public Nebius endpoint URL is recorded in this repository yet.** Don't put a placeholder URL in Devpost: deploy, run the smoke test against it, then add it.

A Token Factory API key can call models, but it can't create Nebius AI Cloud infrastructure. Provisioning an endpoint needs a Nebius Cloud project, networking and a container registry.

## 1. Build and test the exact image

From the repository root:

```bash
docker build -t kinlock-nebius-demo .
docker run --rm -p 8080:8080 kinlock-nebius-demo
```

Check it from another shell, the way a judge would:

```bash
python scripts/smoke_test.py http://localhost:8080
```

Every line should say `ok`. Then open `http://localhost:8080` and click through:

1. compromised swarm: four forgeries refused, the legitimate message commits;
2. verified safe transaction: commits once, replay and overspend refused;
3. identity change: proof passes, Kinlock returns OWNER, nothing runs;
4. benchmark cards load;
5. `errand` and `recovery_email_hijacked` show THEUSTAD per step;
6. the policy and evidence panels load.

## 2. Optional: verify fresh Token Factory mode locally

```bash
export NEBIUS_API_KEY=...
export KINLOCK_DEMO_LIVE=1
python scripts/nemotron_web.py
```

Or with Docker:

```bash
docker run --rm -p 8080:8080 \
  -e KINLOCK_DEMO_LIVE=1 \
  -e NEBIUS_API_KEY \
  kinlock-nebius-demo
```

Run one fixed live scenario from the page and make sure it is labelled **live**, not replay.

## 3. Push the image

A public GHCR image is one option:

```bash
docker tag kinlock-nebius-demo ghcr.io/yashwanthgathuku/kinlock-nebius:demo
docker push ghcr.io/yashwanthgathuku/kinlock-nebius:demo
```

The GHCR package must be readable by the Nebius endpoint. A Nebius Container Registry image is also fine.

## 4. Store secrets

For replay-only judging, no model secret is required by the web container.

For fresh live Token Factory calls, create a secret environment variable in Nebius:

```text
NEBIUS_API_KEY
```

Do not put the key in the image, repository, Devpost text or browser JavaScript.

## 5. Create the Serverless AI endpoint

CPU is sufficient because model inference remains on Token Factory.

Replace the image and subnet values with resources from the selected Nebius project:

```bash
nebius ai endpoint create \
  --name kinlock-verified-agent-demo \
  --image ghcr.io/yashwanthgathuku/kinlock-nebius:demo \
  --platform cpu-d3 --preset 4vcpu-16gb \
  --container-port 8080 \
  --public --auth none \
  --disk-size 20Gi \
  --subnet-id <SUBNET_ID>
```

For live Token Factory calls, also configure:

```text
KINLOCK_DEMO_LIVE=1
KINLOCK_DEMO_LIVE_PER_HOUR=30
NEBIUS_API_KEY=<secret>
```

Keep the public site replay-only if exposing a live model key creates unacceptable spend/rate-limit risk. The replay mode still demonstrates real recorded Token Factory outputs and the deterministic verifier/benchmark runs on the deployed container itself.

## 6. Verify the public endpoint as a judge would

Get the public URL from the Nebius endpoint status, then, from a machine or browser that is **not signed in to your cloud account**:

```bash
python scripts/smoke_test.py https://<host>
```

Then open the home page in a private window and run all three proof scenarios plus at least one Nemotron scenario.

Only after that should the URL be added to:

- Devpost **Try it out** / demo link;
- `docs/DEVPOST.md`;
- README hero; and
- the YouTube description.

## Optional Tavily bonus integration

Kinlock contains an optional **real runtime** Tavily evidence check in `scripts/tavily_evidence_demo.py`. It is intentionally separate from the primary safety guarantee.

It requires:

```text
TAVILY_API_KEY
NEBIUS_API_KEY
```

and makes fixed official-domain searches followed by a Nemotron evidence classification. A contradictory result can add `scam:evidence_conflict`; evidence can never remove risk or authorize an action.

Run it, and record it for the page, before claiming Tavily in the final submission:

```bash
TAVILY_API_KEY=... NEBIUS_API_KEY=... \
python scripts/tavily_evidence_demo.py microsoft_anydesk --record
```

Commit `tests/fixtures/tavily/microsoft_anydesk.json` so the deployed page shows it as a recorded live run. Do the same for the policy panel with `NEBIUS_API_KEY=... python scripts/record_policy_proposals.py`.

If this live call has not been successfully run and shown in the submitted product/video, **do not claim the Tavily prize integration merely because the code exists.**

## References

- Nebius CLI installation: https://docs.nebius.com/cli/install
- Nebius `ai endpoint create`: https://docs.nebius.com/cli/reference/ai/endpoint/create
- Serverless endpoints quickstart: https://docs.nebius.com/serverless/quickstart/endpoints
- Endpoint management: https://docs.nebius.com/serverless/endpoints/manage
- Tavily Search API: https://docs.tavily.com/documentation/api-reference/endpoint/search
