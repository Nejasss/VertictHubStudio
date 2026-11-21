#!/usr/bin/env python3
"""Sign dan verifikasi integritas source tree core/ milik project ini sendiri.

BEDA dengan generate_manifest_keys.py / core/launch_integrity.py: modul itu
menandatangani ARTEFAK LAUNCHER yang PyObfuscator hasilkan untuk end user -
melindungi output tool ini. Skrip ini melindungi hal yang berbeda: source
code TOOL ITU SENDIRI (semua file di core/), supaya perubahan diam-diam pada
core/*.py - baik oleh orang lain yang pinjam device kamu, versi lama yang
ketimpa tanpa sadar, atau file yang korup - bisa TERDETEKSI, bukan luput.

APA YANG INI **TIDAK** KLAIM:
Kalau seseorang punya akses tulis ke direktori project ini, mereka juga bisa
mengedit skrip ini sendiri (menghapus pemanggilan verify, membuat manifest
palsu, dst). Ini BUKAN proteksi terhadap penyerang yang punya kendali penuh
atas mesin kamu - itu di luar jangkauan apa pun yang berjalan sebagai kode
Python biasa di mesin yang sama. Yang ini BERIKAN: sebuah tripwire - deteksi
yang jelas dan dapat diverifikasi kapan pun kamu (atau proses build/CI
lain) menjalankan `verify` secara terpisah dari sesi kerja yang mungkin
sudah dikompromikan, menggunakan HANYA public key (private key tidak
pernah perlu ada di device yang menjalankan verify).

Alur pakai:
    # Sekali, di device tepercaya, simpan private key JAUH dari project ini:
    python3 verify_core_integrity.py sign \\
        --private ~/.pyobf/core-integrity-private.pem \\
        --public  ~/.pyobf/core-integrity-public.pem \\
        --manifest core_manifest.json

    # Setiap kali sebelum build (atau di awal sesi kerja baru), verifikasi:
    python3 verify_core_integrity.py verify \\
        --public core-integrity-public.pem \\
        --manifest core_manifest.json

`sign` MEMBUAT keypair baru jika belum ada (menolak menimpa yang sudah ada -
lihat core/launch_integrity.generate_ed25519_keypair). `verify` HANYA butuh
public key - aman untuk disimpan bersama core_manifest.json di repo/project
itu sendiri, karena public key tidak bisa dipakai untuk membuat signature
palsu, hanya untuk memeriksanya.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.launch_integrity import (
    ManifestSigningError,
    generate_ed25519_keypair,
    load_private_key,
)

# Kept intentionally independent from core.launch_integrity's
# validate_artifact_name/build_manifest: those two are specifically
# designed for a FLAT set of launcher artifacts extracted by a
# hostile-input-safe extractor (they reject any "/" in a name at
# all, since a launcher artifact should never legitimately be inside
# a subdirectory). core/*.py is a real directory TREE
# (core/ssl_pinning.py, etc.) - relative subdirectory paths are the
# NORMAL case here, not something to reject outright. The path
# safety check below still guards against the actual attack
# (traversal outside CORE_DIR via "..", absolute paths, or symlink
# escapes) - it just allows legitimate relative subpaths, which
# validate_artifact_name deliberately does not.

CORE_DIR = Path(__file__).resolve().parent / "core"


def _canonical_json(value: dict) -> bytes:
    # Mirrors core.launch_integrity._canonical_json exactly (same
    # sort_keys/separators/ensure_ascii) so the same sign/verify
    # helpers below produce byte-identical, reproducible output
    # regardless of dict insertion order - required for a signature
    # over this payload to verify deterministically every time.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _safe_relative_py_files(root: Path) -> list[Path]:
    """Every *.py file under root, as paths safely relative to root.

    Walks the real, resolved filesystem tree (not manifest-declared
    names) so there is nothing for a crafted manifest to lie about -
    the file list itself comes from what is actually on disk right
    now, in both sign and verify. Follows no symlinks (Path.rglob
    does not follow symlinked directories by default, and any
    symlinked *.py file is explicitly rejected below) precisely so a
    symlink cannot point outside root and have this tool checksum
    something living elsewhere on disk without saying so.
    """
    root = root.resolve()
    if not root.is_dir():
        raise SystemExit(f"core dir not found: {root}")
    out = []
    for p in sorted(root.rglob("*.py")):
        if p.is_symlink():
            raise SystemExit(f"refusing to include symlink in manifest (not a real file): {p}")
        resolved = p.resolve()
        try:
            rel = resolved.relative_to(root)
        except ValueError:
            # Can only happen via a symlinked parent directory
            # resolving outside root - already excluded above by
            # rglob not following symlinked dirs, but checked again
            # here defensively rather than trusting that alone.
            raise SystemExit(f"refusing to include path that escapes {root}: {p}")
        out.append(rel)
    return out


def build_core_manifest(core_dir: Path = CORE_DIR) -> dict:
    """Deterministic manifest: relative path -> {sha256, size} for
    every core/*.py file currently on disk."""
    files = {}
    for rel in _safe_relative_py_files(core_dir):
        data = (core_dir / rel).read_bytes()
        files[rel.as_posix()] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    return {"format": 1, "files": files}


def sign_core_manifest(manifest: dict, private_key_pem: str) -> dict:
    """Signs a core-tree manifest with the same Ed25519/eddsa
    primitives core.launch_integrity.sign_manifest uses for launcher
    manifests - deliberately NOT calling sign_manifest itself, since
    that function's docstring and internal shape are specific to the
    launcher-artifact manifest format (a different dict shape from
    the one build_core_manifest above produces: "files" here vs
    "artifacts" there) - reusing it directly would silently sign the
    wrong shape or require reshaping this manifest to fake the
    other's contract, which is more fragile than the few duplicated
    lines below."""
    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import eddsa
    except ImportError as exc:
        raise ManifestSigningError("PyCryptodome diperlukan untuk signing Ed25519.") from exc
    try:
        key = ECC.import_key(private_key_pem)
    except (ValueError, TypeError) as exc:
        raise ManifestSigningError("Private key PEM tidak valid.") from exc
    if not key.has_private() or key.curve != "Ed25519":
        raise ManifestSigningError("Private key harus berupa Ed25519 private key.")
    import base64
    payload = _canonical_json(manifest)
    signature = eddsa.new(key, mode="rfc8032").sign(payload)
    return {
        "manifest": json.loads(payload.decode("ascii")),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_core_manifest_signature(manifest: dict, signature_b64: str, public_key_pem: str) -> None:
    """Raises ManifestSigningError if the signature doesn't verify
    against this exact manifest content. Does NOT compare against
    the live filesystem - see verify_core_tree for that half."""
    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import eddsa
        import base64
        payload = _canonical_json(manifest)
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        key = ECC.import_key(public_key_pem)
        eddsa.new(key, mode="rfc8032").verify(payload, signature)
    except Exception as exc:
        raise ManifestSigningError("Manifest signature tidak valid.") from exc
    if manifest.get("format") != 1 or not isinstance(manifest.get("files"), dict):
        raise ManifestSigningError("Format manifest tidak didukung.")


def verify_core_tree(manifest: dict, core_dir: Path = CORE_DIR) -> list[str]:
    """Compares the (already signature-verified) manifest's recorded
    hashes against the CURRENT real files on disk. Returns a list of
    human-readable problem descriptions - empty list means clean.
    Deliberately returns findings rather than raising on the first
    one, so a single verify run reports every discrepancy at once
    (e.g. one added file AND one modified file both show up in one
    report), rather than requiring repeated re-runs to discover them
    one at a time."""
    problems = []
    recorded = manifest["files"]
    on_disk = {rel.as_posix(): rel for rel in _safe_relative_py_files(core_dir)}

    for rel_str, meta in sorted(recorded.items()):
        if rel_str not in on_disk:
            problems.append(f"MISSING: {rel_str} (recorded in manifest, not found on disk)")
            continue
        data = (core_dir / on_disk[rel_str]).read_bytes()
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != meta.get("sha256"):
            problems.append(
                f"MODIFIED: {rel_str} (expected sha256 {meta.get('sha256')}, got {actual_sha})"
            )
        elif len(data) != meta.get("size"):
            # Extremely unlikely to trigger independent of the sha256
            # check above (would require a hash collision), kept as
            # a cheap, purely-defensive second signal rather than as
            # the primary check.
            problems.append(f"SIZE MISMATCH: {rel_str}")

    for rel_str in sorted(on_disk):
        if rel_str not in recorded:
            problems.append(f"UNTRACKED: {rel_str} (present on disk, not in signed manifest)")

    return problems


def cmd_sign(args: argparse.Namespace) -> int:
    private_path = Path(args.private).expanduser().resolve()
    public_path = Path(args.public).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()

    if not private_path.exists() or not public_path.exists():
        if private_path.exists() or public_path.exists():
            print("error: hanya salah satu dari private/public key ada - keduanya harus baru atau keduanya sudah ada", file=sys.stderr)
            return 1
        print(f"Membuat keypair Ed25519 baru:\n  private: {private_path}\n  public : {public_path}")
        try:
            generate_ed25519_keypair(str(private_path), str(public_path))
        except ManifestSigningError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if os.name != "nt":
            os.chmod(private_path, 0o600)
    else:
        print(f"Memakai keypair yang sudah ada:\n  private: {private_path}\n  public : {public_path}")

    manifest = build_core_manifest()
    private_key_pem = load_private_key(str(private_path))
    try:
        signed = sign_core_manifest(manifest, private_key_pem)
    except ManifestSigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    manifest_path.write_text(
        json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Manifest tertanda tangan ditulis ke: {manifest_path}")
    print(f"  {len(manifest['files'])} file di-checksum dari core/")
    print(f"\nSimpan {public_path.name} + {manifest_path.name} bersama project ini (aman, publik).")
    print(f"Simpan {private_path.name} DI LUAR project ini - jangan pernah commit/distribusikan.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    public_path = Path(args.public).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()

    if not public_path.exists():
        print(f"error: public key tidak ditemukan: {public_path}", file=sys.stderr)
        return 2
    if not manifest_path.exists():
        print(f"error: manifest tidak ditemukan: {manifest_path}", file=sys.stderr)
        return 2

    public_key_pem = public_path.read_text(encoding="utf-8")
    try:
        signed = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: manifest bukan JSON valid: {exc}", file=sys.stderr)
        return 2
    if not isinstance(signed, dict) or "manifest" not in signed or "signature_b64" not in signed:
        print("error: struktur manifest tidak dikenali (harus punya 'manifest' dan 'signature_b64')", file=sys.stderr)
        return 2

    try:
        verify_core_manifest_signature(signed["manifest"], signed["signature_b64"], public_key_pem)
    except ManifestSigningError as exc:
        print(f"[TAMPERED/INVALID] Signature manifest TIDAK valid: {exc}", file=sys.stderr)
        print("Manifest ini tidak bisa dipercaya - mungkin dipalsukan, atau public key salah.", file=sys.stderr)
        return 1

    problems = verify_core_tree(signed["manifest"])
    if problems:
        print("[TAMPERED] core/ TIDAK cocok dengan manifest bertanda tangan:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print(f"[OK] core/ cocok persis dengan manifest bertanda tangan ({len(signed['manifest']['files'])} file, semua verified).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_sign = sub.add_parser("sign", help="Buat/pakai keypair, checksum core/, tulis manifest bertanda tangan.")
    p_sign.add_argument("--private", required=True, help="Path private key PEM (dibuat jika belum ada). SIMPAN DI LUAR project ini.")
    p_sign.add_argument("--public", required=True, help="Path public key PEM (dibuat jika belum ada).")
    p_sign.add_argument("--manifest", required=True, help="Path output manifest JSON bertanda tangan.")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verifikasi core/ saat ini terhadap manifest bertanda tangan (hanya perlu public key).")
    p_verify.add_argument("--public", required=True, help="Path public key PEM.")
    p_verify.add_argument("--manifest", required=True, help="Path manifest JSON bertanda tangan.")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
