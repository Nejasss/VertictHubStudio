"""
runtime_fetch.py - Offline Local Runtime Locator for VertictHub Studio.

Preserves exact public API (`RuntimeFetchError`, `find_cached_python`,
`download_and_cache_python`, `ensure_python`) for 100% offline Android ARM64
operation without network requests.
"""
import os
import platform
import sys

CACHE_ROOT = os.path.join(os.path.expanduser("~"), ".vh_runtimes")


class RuntimeFetchError(RuntimeError):
    pass


def _arch_triple() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system != "linux":
        raise RuntimeFetchError(
            f"Platform '{platform.system()}' tidak didukung (target: Android ARM64)."
        )
    if machine in ("aarch64", "arm64"):
        return "aarch64-linux-android"
    if machine in ("x86_64", "amd64"):
        return "x86_64-unknown-linux-gnu"
    raise RuntimeFetchError(
        f"Arsitektur '{machine}' tidak didukung (target wajib: aarch64/arm64)."
    )


def _candidate_runtime_roots(major: int, minor: int) -> list[str]:
    roots = []
    for key in ("VH_LOCAL_RUNTIME_DIR", "PYTHONHOME"):
        val = os.environ.get(key, "").strip()
        if val:
            roots.append(val)
    if sys.prefix:
        roots.append(sys.prefix)
    system = platform.system().lower()
    machine = platform.machine().lower()
    roots.append(os.path.join(CACHE_ROOT, f"{major}.{minor}-{system}-{machine}", "python"))
    return roots


def find_cached_python(major: int, minor: int) -> str | None:
    if sys.version_info[:2] == (major, minor):
        if sys.executable and os.path.isfile(sys.executable) and os.access(sys.executable, os.X_OK):
            return sys.executable
        if sys.prefix and os.path.isdir(sys.prefix):
            embedded_bin = os.path.join(sys.prefix, "bin", f"python{major}.{minor}")
            if os.path.isfile(embedded_bin):
                return embedded_bin
            return sys.executable or sys.prefix

    for root in _candidate_runtime_roots(major, minor):
        for rel in (os.path.join("bin", f"python{major}.{minor}"), os.path.join("bin", "python3")):
            cand = os.path.join(root, rel)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def download_and_cache_python(major: int, minor: int, progress_cb=None) -> str:
    already = find_cached_python(major, minor)
    if already:
        if progress_cb:
            progress_cb(1, 1)
        return already
    checked = ", ".join(_candidate_runtime_roots(major, minor))
    raise RuntimeFetchError(
        f"Offline Mode aktif: runtime Python {major}.{minor} tidak tersedia secara lokal "
        f"(aktif: {sys.version_info.major}.{sys.version_info.minor}). "
        f"Direktori diperiksa: [{checked}]."
    )


def ensure_python(major: int, minor: int, progress_cb=None) -> str:
    cached = find_cached_python(major, minor)
    if cached:
        return cached
    return download_and_cache_python(major, minor, progress_cb=progress_cb)
