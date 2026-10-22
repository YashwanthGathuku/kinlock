from __future__ import annotations

import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


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

    @property
    def resource(self) -> str:
        return f"{self.public_url}/mcp"

    @property
    def public_host(self) -> str:
        return self.public_url.split("://", 1)[-1].split("/", 1)[0]

    @property
    def outbox(self) -> Path:
        return self.data / "outbox.jsonl"

    @classmethod
    def from_env(cls) -> "Settings":
        data = Path(os.environ.get("KINLOCK_DATA", ROOT / "var"))
        data.mkdir(parents=True, exist_ok=True)
        passphrase_hash = os.environ.get("KINLOCK_OWNER_PASSPHRASE_SHA256", "")
        if not passphrase_hash:
            raise SystemExit("Set KINLOCK_OWNER_PASSPHRASE_SHA256 (sha256 hex of the owner passphrase); see README.")
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
            simulator=os.environ.get("KINLOCK_SIMULATOR", "1") == "1",
            port=port,
        )
