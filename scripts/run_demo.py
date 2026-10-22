"""Run Kinlock locally with the simulated Alexa+ page. Works on Windows, macOS and Linux.

    python scripts/run_demo.py

The first run creates var/.env with a random owner passphrase and simulator
secret (kept out of git). Then open http://127.0.0.1:8770/sim.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VAR = ROOT / "var"


def main() -> None:
    VAR.mkdir(exist_ok=True)
    env_file = VAR / ".env"
    if not env_file.exists():
        passphrase = secrets.token_urlsafe(12)
        sim_secret = secrets.token_urlsafe(24)
        (VAR / "clients.json").write_text(json.dumps([{"client_id": "simulator", "secret_sha256": hashlib.sha256(sim_secret.encode()).hexdigest(), "redirect_uris": [], "grants": ["client_credentials"]}]))
        env_file.write_text(
            f"KINLOCK_OWNER_PASSPHRASE={passphrase}\n"
            f"KINLOCK_OWNER_PASSPHRASE_SHA256={hashlib.sha256(passphrase.encode()).hexdigest()}\n"
            "KINLOCK_SIM_CLIENT_ID=simulator\n"
            f"KINLOCK_SIM_CLIENT_SECRET={sim_secret}\n"
        )
        try:
            os.chmod(env_file, 0o600)
        except OSError:
            pass
        print("Created var/.env. Your owner passphrase is in that file (KINLOCK_OWNER_PASSPHRASE).")
    for line in env_file.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)
    sys.path.insert(0, str(ROOT / "src"))
    print("Kinlock is starting. Open http://127.0.0.1:8770/sim")
    from kinlock.server import main as serve

    serve()


if __name__ == "__main__":
    main()
