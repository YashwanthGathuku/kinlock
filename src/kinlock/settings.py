from __future__ import annotations

import ipaddress
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def is_loopback(host: str) -> bool:
    host = host.strip().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Settings:
    public_url: str  # canonical base URL, no trailing slash
    data: Path
    clients_file: Path
    owner_passphrase_sha256: str
    signing_key: bytes
    ntfy_url: str | None
    simulator: bool
    port: int
    owner_ntfy_url: str | None = None  # where the owner hears about her trusted contact's decisions
    host: str = "127.0.0.1"  # the address the server binds to (KINLOCK_HOST)

    @property
    def simulator_open(self) -> bool:
        """The simulator and receipts are open without signing in only when the simulator is
        switched on (KINLOCK_SIMULATOR=1) AND the server is bound to, and published at, loopback."""
        return self.simulator and is_loopback(self.host) and is_loopback(self.public_host.rsplit(":", 1)[0] if self.public_host.count(":") == 1 else self.public_host)

    @property
    def resource(self) -> str:
        return f"{self.public_url}/mcp"

    @property
    def public_host(self) -> str:
        return self.public_url.split("://", 1)[-1].split("/", 1)[0]

    @property
    def outbox(self) -> Path:
        return self.data / "outbox.jsonl"

    @property
    def owner_outbox(self) -> Path:
        return self.data / "owner_outbox.jsonl"

    @classmethod
    def from_env(cls) -> "Settings":
        data = Path(os.environ.get("KINLOCK_DATA", ROOT / "var"))
        data.mkdir(parents=True, exist_ok=True)
        # KINLOCK_OWNER_PASSPHRASE_HASH holds the salted PBKDF2 form (python -m kinlock.auth).
        # KINLOCK_OWNER_PASSPHRASE_SHA256 (bare SHA-256 hex) still works, for older setups.
        passphrase_hash = os.environ.get("KINLOCK_OWNER_PASSPHRASE_HASH") or os.environ.get("KINLOCK_OWNER_PASSPHRASE_SHA256", "")
        if not passphrase_hash:
            raise SystemExit("Set KINLOCK_OWNER_PASSPHRASE_HASH (run: python -m kinlock.auth); see README.")
        policy = data / "policy.json"
        if not policy.exists():
            shutil.copy(ROOT / "data" / "policy.example.json", policy)
        key_file = Path(os.environ.get("KINLOCK_SIGNING_KEY_FILE", data / "signing.key"))
        if not key_file.exists():
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(32))
        port = int(os.environ.get("KINLOCK_PORT", "8770"))
        return cls(
            public_url=os.environ.get("KINLOCK_PUBLIC_URL", f"http://127.0.0.1:{port}").rstrip("/"),
            data=data,
            clients_file=Path(os.environ.get("KINLOCK_CLIENTS", data / "clients.json")),
            owner_passphrase_sha256=passphrase_hash,
            signing_key=key_file.read_bytes(),
            ntfy_url=os.environ.get("KINLOCK_NTFY_URL") or None,
            simulator=os.environ.get("KINLOCK_SIMULATOR", "0") == "1",  # off unless asked for
            port=port,
            owner_ntfy_url=os.environ.get("KINLOCK_OWNER_NTFY_URL") or None,
            host=os.environ.get("KINLOCK_HOST", "127.0.0.1"),
        )
