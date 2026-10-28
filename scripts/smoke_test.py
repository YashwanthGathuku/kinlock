"""Check a running Kinlock judge demo the way a judge would, from outside.

    python scripts/smoke_test.py http://localhost:8080
    python scripts/smoke_test.py https://<your-nebius-endpoint>

Standard library only. Exits non-zero if any page or invariant is wrong, so CI
runs it against the container it just built and you can run it against the
public URL before putting that URL on Devpost.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


def get(base: str, path: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(base.rstrip("/") + path, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"{'ok  ' if ok else 'FAIL'} {name}{(' - ' + detail) if detail and not ok else ''}")
        if not ok:
            failures.append(name)

    code, body = get(base, "/healthz")
    check("/healthz", code == 200 and body.strip() == b"ok", f"{code} {body[:80]!r}")
    code, body = get(base, "/")
    check("home page", code == 200 and b"The agent can be compromised" in body, str(code))

    code, body = get(base, "/api/verified-causal")
    if code == 200:
        swarm, safe, ident = json.loads(body)["scenarios"]
        check("forgeries never commit", swarm["forgeries_committed"] == 0 and all(not a["downstream_executed"] for a in swarm["attempts"]))
        check("legitimate message commits", swarm["legitimate"]["downstream_executed"])
        check("replay after restart refused", safe["first"]["downstream_executed"] and not safe["replay_after_restart"]["downstream_executed"])
        check("valid proof still needs the owner", ident["owner_surface"]["theustad"]["ok"] and ident["owner_surface"]["kinlock_outcome"] == "OWNER" and not ident["downstream_executed"])
    else:
        check("/api/verified-causal", False, str(code))

    code, body = get(base, "/api/benchmark")
    if code == 200:
        b = json.loads(body)
        m = b["metrics"]
        check("benchmark: 0 unsafe commits", m["unsafe_commit_count"] == 0, json.dumps(m))
        check("benchmark: 0 false blocks", m["false_block_count"] == 0, json.dumps(m))
        check("benchmark: proof layer stops every attack", m["stopped_by_proof_layer"] == b["attack_count"], json.dumps(m))
    else:
        check("/api/benchmark", False, str(code))

    code, body = get(base, "/api/scenarios")
    scen = json.loads(body) if code == 200 else {}
    check("/api/scenarios", code == 200)

    code, body = get(base, "/api/run?scenario=errand")
    if code == 200:
        d = json.loads(body)
        check("Nemotron errand commits twice through the gate", [c["tool"] for c in d["commits"]] == ["refill_prescription", "send_message"])
        check("Nemotron errand proofs pass", all(s["proof"] and s["proof"]["ok"] for s in d["steps"]))
    else:
        check("/api/run errand", False, str(code))
    code, body = get(base, "/api/run?scenario=recovery_email_hijacked")
    if code == 200:
        d = json.loads(body)
        check("hijacked recovery-email change does not commit", d["commits"] == [] and d["steps"] and d["steps"][0]["proof"]["ok"] is False)
    else:
        check("/api/run recovery_email_hijacked", False, str(code))

    for path in ("/api/policy?request=raise_grocery_limit", "/api/policy-adversarial", "/api/evidence?claim=microsoft_anydesk"):
        code, _ = get(base, path)
        check(path, code == 200, str(code))

    code, _ = get(base, "/api/run?scenario=errand&live=1")
    if scen.get("live_enabled"):
        check("live run (enabled on this server)", code in (200, 429), str(code))
    else:
        check("live run refused when live mode is off", code == 403, str(code))
    code, _ = get(base, "/api/run?scenario=not-a-scenario")
    check("unknown scenario is a 404", code == 404, str(code))

    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
