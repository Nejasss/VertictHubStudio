"""Primitif integritas dan autentikasi artefak untuk launcher.

Modul ini berfokus pada penandatanganan rilis yang dapat diaudit. Private key
hanya dipakai saat build dan tidak pernah ditanam dalam launcher; launcher
hanya memuat public key dan signature manifest. Ini melindungi integritas
artefak dari penggantian oleh pihak yang tidak memegang private key, tetapi
tidak mengklaim dapat menyembunyikan kode yang akhirnya harus berjalan di
perangkat pengguna.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import PurePath
from typing import Mapping


class ManifestSigningError(ValueError):
    """Dilempar ketika key atau manifest tidak memenuhi kontrak signing."""


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def validate_artifact_name(name: str) -> str:
    """Membatasi nama artefak pada basename biasa agar tidak ada path traversal."""
    if not isinstance(name, str) or not name or name in {".", ".."}:
        raise ManifestSigningError("Nama artefak harus berupa basename tidak kosong.")
    path = PurePath(name)
    if path.name != name or "/" in name or "\\" in name or "\x00" in name:
        raise ManifestSigningError(f"Nama artefak tidak aman: {name!r}")
    return name


def build_manifest(main_name: str, main_bytes: bytes, extra_files: Mapping[str, bytes] | None = None) -> dict[str, object]:
    """Membuat manifest deterministik untuk artefak launcher yang akan diekstrak."""
    artifacts: dict[str, dict[str, object]] = {}
    combined = [(main_name, main_bytes), *sorted((extra_files or {}).items())]
    for name, value in combined:
        safe_name = validate_artifact_name(name)
        if not isinstance(value, bytes):
            raise ManifestSigningError(f"Konten {safe_name!r} wajib bytes.")
        if safe_name in artifacts:
            raise ManifestSigningError(f"Nama artefak duplikat: {safe_name!r}")
        artifacts[safe_name] = {
            "sha256": hashlib.sha256(value).hexdigest(),
            "size": len(value),
        }
    return {"format": 1, "artifacts": artifacts}


def load_private_key(private_key_path: str) -> str:
    """Membaca private key PEM dari berkas lokal yang dikelola pembuat rilis."""
    if not private_key_path:
        raise ManifestSigningError("Path private key signing wajib diberikan.")
    with open(private_key_path, "r", encoding="utf-8") as handle:
        return handle.read()


def generate_ed25519_keypair(private_key_path: str, public_key_path: str) -> None:
    """Membuat keypair Ed25519 PEM dengan permission private key ketat di POSIX."""
    try:
        from Crypto.PublicKey import ECC
    except ImportError as exc:  # pragma: no cover - bergantung environment build
        raise ManifestSigningError("PyCryptodome diperlukan untuk key Ed25519.") from exc
    private_path = os.path.abspath(private_key_path)
    public_path = os.path.abspath(public_key_path)
    if os.path.exists(private_path) or os.path.exists(public_path):
        raise ManifestSigningError("Menolak menimpa berkas key yang sudah ada.")
    key = ECC.generate(curve="Ed25519")
    private_pem = key.export_key(format="PEM")
    public_pem = key.public_key().export_key(format="PEM")
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(private_pem)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(private_path)
        except OSError:
            pass
        raise
    with open(public_path, "x", encoding="utf-8") as handle:
        handle.write(public_pem)


def sign_manifest(manifest: Mapping[str, object], private_key_pem: str) -> dict[str, str]:
    """Menandatangani manifest kanonis dan mengembalikan payload verifikasi publik."""
    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import eddsa
    except ImportError as exc:  # pragma: no cover - bergantung environment build
        raise ManifestSigningError("PyCryptodome diperlukan untuk signing Ed25519.") from exc
    try:
        key = ECC.import_key(private_key_pem)
    except (ValueError, TypeError) as exc:
        raise ManifestSigningError("Private key PEM tidak valid.") from exc
    if not key.has_private() or key.curve != "Ed25519":
        raise ManifestSigningError("Private key harus berupa Ed25519 private key.")
    payload = _canonical_json(manifest)
    signature = eddsa.new(key, mode="rfc8032").sign(payload)
    return {
        "manifest": payload.decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": key.public_key().export_key(format="PEM"),
    }


def verify_signed_manifest(manifest_json: str, signature_b64: str, public_key_pem: str) -> dict[str, object]:
    """Memverifikasi signature dan format manifest; dipakai dalam test build."""
    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import eddsa
        payload = manifest_json.encode("ascii")
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        key = ECC.import_key(public_key_pem)
        eddsa.new(key, mode="rfc8032").verify(payload, signature)
        manifest = json.loads(manifest_json)
    except Exception as exc:
        raise ManifestSigningError("Manifest signature tidak valid.") from exc
    if _canonical_json(manifest) != payload:
        raise ManifestSigningError("Manifest tidak dalam format kanonis.")
    if manifest.get("format") != 1 or not isinstance(manifest.get("artifacts"), dict):
        raise ManifestSigningError("Format manifest tidak didukung.")
    for name, metadata in manifest["artifacts"].items():
        validate_artifact_name(name)
        if not isinstance(metadata, dict) or not isinstance(metadata.get("sha256"), str):
            raise ManifestSigningError("Metadata artefak tidak valid.")
        if not isinstance(metadata.get("size"), int) or metadata["size"] < 0:
            raise ManifestSigningError("Ukuran artefak tidak valid.")
    return manifest
