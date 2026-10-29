"""Every finding from the Oct 28 2026 audit stays fixed."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_audit_attack_is_fixed():
    spec = importlib.util.spec_from_file_location("audit_attacks", ROOT / "eval" / "audit_attacks.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rows = {r["id"]: r for r in mod.run()}
    assert set(rows) == {"A1", "A2", "A2b", "A3", "A4", "A5", "A6", "E1", "E2", "E3", "E4", "E5"}
    assert rows["A2b"]["now_executed"] is True  # the honest purchase commits
    for aid, r in rows.items():
        assert r["fixed"], (aid, r)
        if aid != "A2b":
            assert r["now_executed"] is False and r["now_theustad"] == "FAIL", (aid, r)
