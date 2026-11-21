#!/usr/bin/env python3
"""Packages cross-compiled PyCryptodome ARM64 extensions into jniLibs/arm64-v8a."""
import os
import shutil
import sys


def main() -> int:
    ws = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
    crypto_root = os.path.join(ws, "app", "src", "main", "assets", "python", "site-packages", "Crypto")
    jnilibs = os.path.join(ws, "app", "src", "main", "jniLibs", "arm64-v8a")
    os.makedirs(jnilibs, exist_ok=True)

    count = 0
    for root, _, files in os.walk(crypto_root):
        for fn in sorted(files):
            if fn.endswith(".so"):
                full = os.path.join(root, fn)
                clean_name = fn.split(".")[0] + ".so"
                clean_full = os.path.join(root, clean_name)
                if full != clean_full:
                    os.rename(full, clean_full)
                rel_pkg = os.path.relpath(root, os.path.dirname(crypto_root)).replace(os.sep, "_")
                mod_stem = clean_name[:-3]
                jni_so = os.path.join(jnilibs, f"libvh_crypto_{rel_pkg}_{mod_stem}.so")
                shutil.copy2(clean_full, jni_so)
                count += 1

    raw_api = os.path.join(crypto_root, "Util", "_raw_api.py")
    with open(raw_api, "r", encoding="utf-8") as f:
        src = f.read()

    hook = (
        '    native_dir = os.environ.get("VH_NATIVE_LIB_DIR", "").strip()\n'
        '    if native_dir:\n'
        '        jni_cand = os.path.join(native_dir, "libvh_crypto_" + name.replace(".", "_") + ".so")\n'
        '        if os.path.isfile(jni_cand):\n'
        '            return load_lib(jni_cand, cdecl)\n'
    )
    target = "    for ext in extension_suffixes:"
    if target not in src:
        print("ERROR: load_pycryptodome_raw_lib anchor not found in _raw_api.py", file=sys.stderr)
        return 1

    if "libvh_crypto_" not in src:
        src = src.replace(target, hook + "\n" + target, 1)
        with open(raw_api, "w", encoding="utf-8") as f:
            f.write(src)

    print(f"[OK] Packaged {count} PyCryptodome ARM64 extensions into jniLibs/arm64-v8a.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
