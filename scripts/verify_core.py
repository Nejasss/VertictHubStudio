#!/usr/bin/env python3
"""Audits and imports all 34 Core PyObfuscator modules + studio_bridge."""
import ast
import hashlib
import importlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS_PY = os.path.join(ROOT, "app", "src", "main", "assets", "python")
sys.path.insert(0, ASSETS_PY)

import studio_bridge  # noqa: E402


def main() -> int:
    manifest_path = os.path.join(ASSETS_PY, "vh", "core_manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)["manifest"]["files"]

    assert len(manifest) == 34, f"Expected 34 core modules, found {len(manifest)}"

    for fname, meta in sorted(manifest.items()):
        fpath = os.path.join(ASSETS_PY, "vh", "core", fname)
        assert os.path.isfile(fpath), f"Missing core module: {fname}"
        raw = open(fpath, "rb").read()
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == meta["sha256"], f"SHA-256 mismatch for {fname}"
        ast.parse(raw.decode("utf-8"), filename=fname)

    res = json.loads(studio_bridge.verify_core_modules())
    assert res["ok"] and res["all_verified"], f"Core verification failed: {res}"
    print(f"[OK] All {res['verified_count']}/{res['total']} Core modules verified and importable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
