#!/usr/bin/env python3
"""
libpython_fetch.py - Offline Local Shared Library Locator for VertictHub Studio.
"""
import os
import sys


def _find_libpython_dir(python_root: str, major: int, minor: int) -> str | None:
    so_prefix = f"libpython{major}.{minor}.so"
    for sub in ("lib", "lib64", ""):
        lib_dir = os.path.join(python_root, sub) if sub else python_root
        if not os.path.isdir(lib_dir):
            continue
        try:
            for entry in os.listdir(lib_dir):
                if entry == so_prefix or entry.startswith(so_prefix + "."):
                    return lib_dir
        except OSError:
            continue
    return None


def find_local_libpython_dir(major: int, minor: int) -> str | None:
    candidates = []
    for env_key in ("VH_LOCAL_LIBPYTHON_DIR", "VH_NATIVE_LIB_DIR", "PYTHONHOME"):
        val = os.environ.get(env_key, "").strip()
        if val:
            candidates.append(val)
    if sys.prefix:
        candidates.append(sys.prefix)
    for root in candidates:
        found = _find_libpython_dir(root, major, minor)
        if found:
            return found
    return None


def main() -> None:
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: libpython_fetch.py <major> <minor>\n")
        sys.exit(2)
    try:
        major = int(sys.argv[1])
        minor = int(sys.argv[2])
    except ValueError:
        sys.stderr.write("major and minor must be integers\n")
        sys.exit(2)

    lib_dir = find_local_libpython_dir(major, minor)
    if not lib_dir:
        sys.stderr.write(
            f"Offline Mode: libpython{major}.{minor}.so tidak ditemukan di direktori native lokal.\n"
        )
        sys.exit(1)
    print(lib_dir)
    sys.exit(0)


if __name__ == "__main__":
    main()
