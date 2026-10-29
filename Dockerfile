# Kinlock judge demo: one small CPU container. The NVIDIA models run on Nebius Token Factory.
# Replays recorded live Token Factory runs by default. For live runs set KINLOCK_DEMO_LIVE=1 and NEBIUS_API_KEY
# (and TAVILY_API_KEY for the evidence panel).
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
COPY eval ./eval
COPY scripts/nemotron_web.py scripts/nemotron_web.html scripts/nemotron_demo.py scripts/verified_causal_demo.py scripts/real_world_scenarios.py ./scripts/
COPY tests/fixtures ./tests/fixtures
RUN pip install --no-cache-dir . && useradd -m app
USER app
ENV PORT=8080 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8080\")}/healthz',timeout=2)"
CMD ["python", "scripts/nemotron_web.py"]
