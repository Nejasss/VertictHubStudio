"""First-run setup untuk private key signing launcher.

Tujuannya adalah pengalaman CLI tanpa export manual. Keypair default dibuat satu
kali di ~/.pyobf/, tidak pernah ditanam ke launcher, dan tidak pernah diganti
otomatis. Override melalui PYOBF_MANIFEST_SIGNING_KEY tetap didukung untuk
workflow build terpisah atau CI.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .launch_integrity import ManifestSigningError, generate_ed25519_keypair


DEFAULT_KEY_DIR = Path("~/.pyobf").expanduser()
DEFAULT_PRIVATE_KEY = DEFAULT_KEY_DIR / "release-private.pem"
DEFAULT_PUBLIC_KEY = DEFAULT_KEY_DIR / "release-public.pem"
ENVIRONMENT_KEY = "PYOBF_MANIFEST_SIGNING_KEY"


class SigningKeySetupError(ValueError):
    """Kesalahan saat menemukan atau menyiapkan keypair signing build host."""


def _assert_regular_private_key(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SigningKeySetupError(f"Signing key tidak dapat diakses: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SigningKeySetupError(f"Signing key harus berupa file biasa, bukan symlink: {path}")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise SigningKeySetupError(
            f"Permission private key terlalu longgar ({oct(stat.S_IMODE(info.st_mode))}). "
            f"Jalankan: chmod 600 {path}"
        )


def _secure_mkdir(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise SigningKeySetupError(f"Direktori key tidak aman: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def ensure_signing_key() -> tuple[str, str]:
    """Mengembalikan `(private_key_path, status)` dan membuat key default bila perlu.

    `status` bernilai `override`, `existing`, atau `created` agar CLI dapat
    menampilkan tindakan yang terjadi tanpa pernah menampilkan isi private key.
    """
    override = os.environ.get(ENVIRONMENT_KEY, "").strip()
    if override:
        path = Path(override).expanduser().resolve()
        if not path.is_file():
            raise SigningKeySetupError(f"Signing key override tidak ditemukan: {path}")
        _assert_regular_private_key(path)
        return str(path), "override"

    _secure_mkdir(DEFAULT_KEY_DIR)
    private_path = DEFAULT_PRIVATE_KEY
    public_path = DEFAULT_PUBLIC_KEY
    private_exists = private_path.exists()
    public_exists = public_path.exists()

    if private_exists:
        _assert_regular_private_key(private_path)
        if public_exists and (public_path.is_symlink() or not public_path.is_file()):
            raise SigningKeySetupError(f"Public key tidak aman: {public_path}")
        return str(private_path), "existing"
    if public_exists:
        raise SigningKeySetupError(
            f"Public key ada tetapi private key tidak ada di {DEFAULT_KEY_DIR}. "
            "Menolak membuat key baru agar trust chain lama tidak tertimpa."
        )

    try:
        generate_ed25519_keypair(str(private_path), str(public_path))
    except ManifestSigningError as exc:
        raise SigningKeySetupError(str(exc)) from exc
    _assert_regular_private_key(private_path)
    return str(private_path), "created"
