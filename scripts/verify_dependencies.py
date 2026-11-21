#!/usr/bin/env python3
"""Validates offline_packages/dependency_manifest.json."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    dep_path = os.path.join(ROOT, "offline_packages", "dependency_manifest.json")
    with open(dep_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["target_runtime"] == "CPython 3.14.10"
    assert data["target_abi"] == "arm64-v8a"
    assert data["offline_guaranteed"] is True
    names = {d["name"] for d in data["dependencies"]}
    for req in ("cpython-android-aarch64", "pycryptodome", "libverticthub_jni.so", "vh-core-pyobfuscator"):
        assert req in names, f"Missing required dependency entry: {req}"

    print(f"[OK] Dependency manifest verified ({len(data['dependencies'])} entries).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
