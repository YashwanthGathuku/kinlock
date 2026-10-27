"""The vendored kinlock_authority must be an exact copy of upstream."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_vendored_authority", ROOT / "scripts" / "check_vendored_authority.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_vendored_copy_matches_the_upstream_lock():
    assert check.problems_against_lock() == []
    lock = json.loads(check.LOCK.read_text())
    assert len(lock["commit"]) == 40 and lock["repo"].endswith("/kinlock-authority")


def test_an_edit_to_the_vendored_copy_is_caught(tmp_path):
    pkg = tmp_path / "kinlock_authority"
    shutil.copytree(check.VENDORED, pkg, ignore=shutil.ignore_patterns("__pycache__"))
    (pkg / "policy.py").write_text((pkg / "policy.py").read_text() + "\n# local tweak\n")
    errs = check.problems_against_lock(pkg)
    assert errs and "policy.py" in errs[0]
    up = tmp_path / "up" / "src"
    shutil.copytree(check.VENDORED, up / "kinlock_authority", ignore=shutil.ignore_patterns("__pycache__"))
    assert check.problems_against_upstream(tmp_path / "up", pkg) == ["policy.py: differs from upstream checkout " + str(tmp_path / "up")]


def test_an_extra_or_missing_file_is_caught(tmp_path):
    pkg = tmp_path / "kinlock_authority"
    shutil.copytree(check.VENDORED, pkg, ignore=shutil.ignore_patterns("__pycache__"))
    (pkg / "extra.py").write_text("")
    (pkg / "canonical.py").unlink()
    errs = check.problems_against_lock(pkg)
    assert any("extra.py" in e for e in errs) and any("canonical.py" in e for e in errs)


@pytest.mark.skipif(not os.environ.get("KINLOCK_AUTHORITY_SRC"), reason="set KINLOCK_AUTHORITY_SRC to an upstream checkout (CI does)")
def test_vendored_copy_matches_an_upstream_checkout():
    assert check.problems_against_upstream(Path(os.environ["KINLOCK_AUTHORITY_SRC"])) == []
