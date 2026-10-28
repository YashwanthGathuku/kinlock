# Deploy Kinlock on Nebius Serverless AI

Kinlock's judge demo is one small CPU container (`Dockerfile` at the repository root). The NVIDIA models run on **Nebius Token Factory**, so the web container does not need a GPU.

The public page now includes:

- the deterministic **Verified Causal Commit** distributed-attack demo;
- the measured causal-verifier benchmark;
- the AgentFleet → THEUSTAD → Kinlock architecture;
- recorded live Nemotron Token Factory attack/safe scenarios; and
- optional fresh live Token Factory runs when explicitly enabled.

By default, the site is useful **without any API key**: deterministic causal scenarios and the benchmark run locally in the container, while Nemotron scenarios replay checked-in responses that are clearly labelled as recorded live Token Factory output.

Fresh model calls require both:

```text
KINLOCK_DEMO_LIVE=1
NEBIUS_API_KEY=...
```

Visitors may choose only fixed scenarios. They cannot submit arbitrary prompts. Live calls are globally rate-limited by `KINLOCK_DEMO_LIVE_PER_HOUR` (default 30).

## Current status

- Docker/web packaging exists in the repository.
- The Verified Causal Commit path and its benchmark are exercised by GitHub Actions.
- A successful October 28 benchmark run is frozen at `docs/benchmarks/verified-causal-commit-2026-10-28.json`.
- **A public Nebius endpoint URL is not yet recorded in this repository.** Do not put a placeholder URL in Devpost; deploy and verify it first.

A Token Factory API key can call models, but it cannot itself create Nebius AI Cloud infrastructure. Endpoint provisioning needs access to a Nebius Cloud tenant/project, networking and a container image registry.

## 1. Build and test the exact image

From the repository root:

```bash
docker build -t kinlock-nebius-demo .
docker run --rm -p 8080:8080 kinlock-nebius-demo
```

Verify from another shell/browser:

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/api/verified-causal
curl -fsS http://localhost:8080/api/benchmark
```

Expected `/healthz` response:

```text
ok
```

Open `http://localhost:8080` and verify:

1. distributed authority attack → THEUSTAD FAIL → no commit;
2. verified safe transaction → Kinlock ALLOW → simulated downstream executes;
3. valid identity proof → Kinlock OWNER → no downstream;
4. benchmark cards load;
5. recorded Nemotron scenarios load.

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

Obtain the public endpoint URL from Nebius endpoint status, then test it from a browser/session that is **not logged into your cloud account**.

Check:

```text
https://<host>/healthz
https://<host>/api/verified-causal
https://<host>/api/benchmark
```

Then use the home page from a private/incognito browser and run all three causal scenarios plus at least one recorded Nemotron scenario.

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

Run locally before claiming Tavily in the final submission:

```bash
TAVILY_API_KEY=... NEBIUS_API_KEY=... \
python scripts/tavily_evidence_demo.py microsoft_anydesk
```

If this live call has not been successfully run and shown in the submitted product/video, **do not claim the Tavily prize integration merely because the code exists.**

## References

- Nebius CLI installation: https://docs.nebius.com/cli/install
- Nebius `ai endpoint create`: https://docs.nebius.com/cli/reference/ai/endpoint/create
- Serverless endpoints quickstart: https://docs.nebius.com/serverless/quickstart/endpoints
- Endpoint management: https://docs.nebius.com/serverless/endpoints/manage
- Tavily Search API: https://docs.tavily.com/documentation/api-reference/endpoint/search
