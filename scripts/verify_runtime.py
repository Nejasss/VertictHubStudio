#!/usr/bin/env python3
"""Validates runtime specification and Android JNI / Manifest offline guarantees."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    spec_path = os.path.join(ROOT, "runtime", "python-3.14.10", "RUNTIME_SPEC.json")
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)

    assert spec["version"] == "3.14.10", f"Unexpected version: {spec['version']}"
    assert spec["android_abi"] == "arm64-v8a", f"Unexpected ABI: {spec['android_abi']}"
    assert (
        spec["official_package_sha256"]
        == "423c80b957330cf0ebb92b9b20f2294c292144a441bdb0ceb8c69d14928e569b"
    ), "SHA-256 mismatch in RUNTIME_SPEC.json"

    manifest_xml = os.path.join(ROOT, "app", "src", "main", "AndroidManifest.xml")
    with open(manifest_xml, "r", encoding="utf-8") as f:
        xml_txt = f.read()
    assert "android.permission.INTERNET" not in xml_txt, "INTERNET permission must not exist"
    assert 'android:extractNativeLibs="true"' in xml_txt, "extractNativeLibs must be true"

    print("[OK] Runtime spec CPython 3.14.10 ARM64 & offline manifest verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
