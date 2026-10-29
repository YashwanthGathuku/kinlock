"""Delivery of approval links to the trusted contact's phone.

With KINLOCK_NTFY_URL set (an ntfy topic the contact subscribes to), the link
is pushed there. Otherwise it goes to an outbox file, so the demo and tests can
see exactly what would have been sent. The destination is fixed by the owner's
configuration: nothing said to the assistant can change where a link goes.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


class Notifier:
    def __init__(self, ntfy_url: str | None, outbox: Path):
        self.ntfy_url = ntfy_url
        self.outbox = Path(outbox)

    def __call__(self, title: str, link: str) -> None:
        self.outbox.parent.mkdir(parents=True, exist_ok=True)
        with self.outbox.open("a") as fh:
            fh.write(json.dumps({"at": datetime.now(UTC).isoformat(), "title": title, "link": link}) + "\n")
        if self.ntfy_url:
            # Off the request path, so a slow push service can't slow a voice reply.
            threading.Thread(target=self._push, args=(title, link), daemon=True).start()

    def _push(self, title: str, link: str) -> None:
        req = urllib.request.Request(self.ntfy_url, data=title.encode(), headers={"Title": "Kinlock", "Click": link, "Tags": "lock"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 (configured URL only)
                resp.read()
        except OSError:
            pass

    def last(self) -> dict | None:
        try:
            lines = self.outbox.read_text().strip().splitlines()
            return json.loads(lines[-1]) if lines else None
        except FileNotFoundError:
            return None
