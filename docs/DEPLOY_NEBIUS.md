# Deploying the Nemotron demo on Nebius Serverless AI endpoints

The demo is one small container (`Dockerfile` at the repo root): a stdlib web page over the Nemotron agent and the authority firewall. By default it replays the recorded live Token Factory runs, so it needs no key. With `KINLOCK_DEMO_LIVE=1` and `NEBIUS_API_KEY` it also runs fresh live calls, limited to `KINLOCK_DEMO_LIVE_PER_HOUR` (default 30) for all visitors together. Visitors can only pick the fixed scenarios; they can't send their own prompts.

## Status

- The image builds and runs locally (checked Oct 27, 2026): `/healthz`, the page, replays, a live run with the key, and a 403 for live runs when they're off.
- **Not deployed yet.** A Serverless AI endpoint is a Nebius AI Cloud resource. Creating one needs a Nebius AI Cloud login or service account, a project and a subnet, and a registry the endpoint can pull from. The Token Factory API key (`NEBIUS_API_KEY`) can't do any of that, and we didn't try a temporary public tunnel from the build machine either, because its network blocks Cloudflare tunnels.

## Remaining steps (about 15 minutes)

1. Install the Nebius CLI following https://docs.nebius.com/cli/install, then sign in with `nebius profile create` (opens a browser; pick your tenant and project).
2. Build the image and push it somewhere public or to a Nebius Container Registry:
   ```bash
   docker build -t ghcr.io/yashwanthgathuku/kinlock-nemotron:demo .
   docker push ghcr.io/yashwanthgathuku/kinlock-nemotron:demo   # needs `docker login ghcr.io`; then make the package public
   ```
3. Store the Token Factory key as a secret (only if you want live runs), using the console: Serverless AI → Endpoints → Create endpoint → Secret environment variables → Create secret, key `NEBIUS_API_KEY`.
4. Create the endpoint (CPU is enough; the models run on Token Factory). Replace `<SUBNET_ID>`:
   ```bash
   nebius ai endpoint create \
     --name kinlock-nemotron-demo \
     --image ghcr.io/yashwanthgathuku/kinlock-nemotron:demo \
     --platform cpu-d3 --preset 4vcpu-16gb \
     --container-port 8080 --public --auth none \
     --disk-size 20Gi \
     --env KINLOCK_DEMO_LIVE=1 --env KINLOCK_DEMO_LIVE_PER_HOUR=30 \
     --env-secret NEBIUS_API_KEY=<secret name> \
     --subnet-id <SUBNET_ID>
   ```
   Leave out the two `KINLOCK_DEMO_LIVE` env lines and `--env-secret` for a replay-only demo.
5. The `https://` URL is in the endpoint's `status.public_endpoints` (`nebius ai endpoint get <id>`). Check `https://<host>/healthz` returns `ok`, then put the URL in the Devpost "Try it out" links.
6. Stop the endpoint after judging to stop CPU billing.

References: [nebius ai endpoint create](https://docs.nebius.com/cli/reference/ai/endpoint/create), [Serverless endpoints quickstart](https://docs.nebius.com/serverless/quickstart/endpoints), [Managing endpoints](https://docs.nebius.com/serverless/endpoints/manage).

## Run it locally

```bash
docker build -t kinlock-nemotron .
docker run --rm -p 8080:8080 kinlock-nemotron                                  # replays only
docker run --rm -p 8080:8080 -e KINLOCK_DEMO_LIVE=1 -e NEBIUS_API_KEY kinlock-nemotron   # live runs on
# open http://localhost:8080
```
If `pip install` can't resolve hosts during the build, try `docker build --network host`.
