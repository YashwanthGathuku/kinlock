# Kinlock Nemotron demo: a small web page over the Nemotron agent and the authority firewall.
# Replays recorded live Token Factory runs by default. For live runs set KINLOCK_DEMO_LIVE=1 and NEBIUS_API_KEY.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
COPY scripts/nemotron_demo.py scripts/nemotron_web.py scripts/nemotron_web.html ./scripts/
COPY tests/fixtures/nemotron ./tests/fixtures/nemotron
RUN pip install --no-cache-dir . && useradd -m app
USER app
ENV PORT=8080 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "scripts/nemotron_web.py"]
