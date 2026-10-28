"""Check that src/kinlock_authority is an exact copy of upstream kinlock-authority.

Kinlock vendors the library rather than installing it, so the add-on runs
from a plain checkout with no network fetch at install time. The price is
drift, and this script catches it.

    python scripts/check_vendored_authority.py
        Check the vendored files against vendor/kinlock-authority.lock.json (the
        upstream commit and a SHA-256 per file). Needs no network. Fails if
        anyone edits the vendored copy without syncing it from upstream.

    python scripts/check_vendored_authority.py --upstream ../kinlock-authority
        Also compare byte for byte with an upstream checkout. CI checks out the
        locked commit and runs this.

    python scripts/check_vendored_authority.py --sync ../kinlock-authority
        Copy the upstream files in and rewrite the lock (records the checkout's
        HEAD commit). Run this when you deliberately take a new upstream version.

Exit code 0 means in sync; 1 lists every difference.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "src" / "kinlock_authority"
LOCK = ROOT / "vendor" / "kinlock-authority.lock.json"
UPSTREAM_REPO = "https://github.com/YashwanthGathuku/kinlock-authority"


def _files(pkg: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(pkg.glob("*.py"))}


def problems_against_lock(vendored: Path = VENDORED, lock_path: Path = LOCK) -> list[str]:
    if not lock_path.exists():
        return [f"missing lock file {lock_path}"]
    lock = json.loads(lock_path.read_text())
    want, have = lock["files"], _files(vendored)
    out = [f"{n}: vendored file not in upstream lock" for n in sorted(set(have) - set(want))]
    out += [f"{n}: upstream file missing from vendored copy" for n in sorted(set(want) - set(have))]
    out += [f"{n}: vendored copy differs from upstream {lock['commit'][:12]}" for n in sorted(set(want) & set(have)) if want[n] != have[n]]
    return out


def problems_against_upstream(upstream: Path, vendored: Path = VENDORED) -> list[str]:
    pkg = upstream / "src" / "kinlock_authority"
    if not pkg.is_dir():
        return [f"{pkg} is not a kinlock-authority checkout"]
    want, have = _files(pkg), _files(vendored)
    if want == have:
        return []
    names = sorted(set(want) | set(have))
    return [f"{n}: differs from upstream checkout {upstream}" for n in names if want.get(n) != have.get(n)]


def sync(upstream: Path) -> None:
    pkg = upstream / "src" / "kinlock_authority"
    for old in VENDORED.glob("*.py"):
        old.unlink()
    for f in sorted(pkg.glob("*.py")):
        shutil.copy2(f, VENDORED / f.name)
    commit = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    LOCK.parent.mkdir(exist_ok=True)
    LOCK.write_text(json.dumps({"repo": UPSTREAM_REPO, "commit": commit, "files": _files(VENDORED)}, indent=2) + "\n")
    print(f"Synced src/kinlock_authority from {upstream} at {commit}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream", type=Path, help="path to a kinlock-authority checkout to compare against")
    ap.add_argument("--sync", type=Path, help="copy from this kinlock-authority checkout and rewrite the lock")
    args = ap.parse_args(argv)
    if args.sync:
        sync(args.sync)
    errs = problems_against_lock()
    if args.upstream:
        errs += problems_against_upstream(args.upstream)
    for e in errs:
        print("OUT OF SYNC:", e, file=sys.stderr)
    if not errs:
        print("src/kinlock_authority matches upstream kinlock-authority.")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
