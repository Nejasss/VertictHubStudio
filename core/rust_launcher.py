"""Backend eksperimen launcher Rust native ELF.

Backend ini memindahkan proses extract/decrypt/run ke executable Rust. Ia tidak
menggunakan marshal atau interpreter Python pada jalur runtime launcher. Build
harus dilakukan pada host/ABI target; untuk Termux gunakan `pkg install rust clang`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Mapping

from .crypto import build_fragment_chain, random_key, split_key_with_junk, xor_encrypt
from .launch_integrity import validate_artifact_name


class RustLauncherBuildError(RuntimeError):
    """Toolchain Cargo/Rust atau build launcher tidak tersedia."""


def _bytes(items: bytes) -> str:
    return ", ".join(f"0x{x:02x}" for x in items)


def _artifact_archive(main_name: str, main_bytes: bytes, extra_files: Mapping[str, bytes]) -> tuple[bytes, list[tuple[str, bytes, int]]]:
    records = [(validate_artifact_name(main_name), main_bytes), *sorted(extra_files.items())]
    archive = bytearray(b"RXL1")
    archive += len(records).to_bytes(2, "big")
    expected: list[tuple[str, bytes, int]] = []
    for name, data in records:
        encoded = name.encode("utf-8")
        if len(encoded) > 255:
            raise RustLauncherBuildError("Nama artefak terlalu panjang untuk launcher Rust.")
        archive += len(encoded).to_bytes(1, "big") + encoded
        archive += len(data).to_bytes(8, "big") + data
        expected.append((name, hashlib.sha256(data).digest(), len(data)))
    return bytes(archive), expected


def _rust_source(*, container: bytes, key_parts: list[bytes], key_seed: bytes, key_tags: list[bytes],
                 expected: list[tuple[str, bytes, int]], main_name: str, lock_name: str,
                 gate_env_name: str | None, gate_token: str | None, gate_mask: bytes | None) -> str:
    part_rows = ",\n    ".join(f"&[{_bytes(part)}]" for part in key_parts)
    tag_rows = ",\n    ".join(f"&[{_bytes(tag)}]" for tag in key_tags)
    records = ",\n    ".join(
        f"({json.dumps(name)}, &[{_bytes(digest)}], {size}usize)" for name, digest, size in expected
    )
    token_enc = xor_encrypt(gate_token.encode("utf-8"), gate_mask) if gate_token and gate_mask else b""
    return f'''use aes_gcm::{{Aes256Gcm, KeyInit, Nonce}};
use aes_gcm::aead::Aead;
use sha2::{{Digest, Sha256}};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const SEALED: &[u8] = &[{_bytes(container)}];
const PARTS: &[&[u8]] = &[
    {part_rows}
];
const SEED: &[u8] = &[{_bytes(key_seed)}];
const TAGS: &[&[u8]] = &[
    {tag_rows}
];
const EXPECTED: &[(&str, &[u8], usize)] = &[
    {records}
];
const MAIN_NAME: &str = {json.dumps(main_name)};
const LOCK_NAME: &str = {json.dumps(lock_name)};
const GATE_NAME: &str = {json.dumps(gate_env_name or "")};
const GATE_ENC: &[u8] = &[{_bytes(token_enc)}];

fn die(msg: &str) -> ! {{ eprintln!("rust launcher: {{}}", msg); std::process::exit(1) }}
fn sha(data: &[u8]) -> [u8; 32] {{ let mut h = Sha256::new(); h.update(data); h.finalize().into() }}
fn safe_name(name: &str) -> bool {{ !name.is_empty() && !name.contains('/') && !name.contains('\\\\') && name != "." && name != ".." }}

fn recover_key() -> Vec<u8> {{
    let mut state = SEED.to_vec();
    let mut choices: Vec<&[u8]> = PARTS.to_vec();
    let mut picked: Vec<&[u8]> = Vec::new();
    for want in TAGS {{
        let mut found = None;
        for (i, candidate) in choices.iter().enumerate() {{
            let mut data = state.clone(); data.extend_from_slice(candidate);
            let d = sha(&data);
            if d[..want.len()] == **want {{ found = Some((i, d)); break; }}
        }}
        let Some((i, digest)) = found else {{ die("fragment chain invalid") }};
        state = digest.to_vec(); picked.push(choices.remove(i));
    }}
    let mut key = Vec::new(); for part in picked {{ key.extend_from_slice(part); }}
    if key.len() != 32 {{ die("invalid key length") }}
    key
}}

fn main() {{
    if !LOCK_NAME.is_empty() {{
        let exe = env::current_exe().unwrap_or_else(|_| die("cannot resolve executable"));
        if exe.file_name().and_then(|s| s.to_str()) != Some(LOCK_NAME) {{ die("filename lock rejected") }}
    }}
    if SEALED.len() < 28 {{ die("container truncated") }}
    let key = recover_key();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap_or_else(|_| die("cipher init failed"));
    let plaintext = cipher.decrypt(Nonce::from_slice(&SEALED[..12]), &SEALED[12..])
        .unwrap_or_else(|_| die("container authentication failed"));
    if plaintext.len() < 6 || &plaintext[..4] != b"RXL1" {{ die("archive format invalid") }}
    let count = u16::from_be_bytes([plaintext[4], plaintext[5]]) as usize;
    let mut cursor = 6usize;
    let work = env::temp_dir().join(format!(".rx-{{}}-{{}}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&work).unwrap_or_else(|_| die("temporary directory failed"));
    let mut main_path: Option<PathBuf> = None;
    for _ in 0..count {{
        if cursor >= plaintext.len() {{ die("archive truncated") }}
        let nlen = plaintext[cursor] as usize; cursor += 1;
        if cursor + nlen + 8 > plaintext.len() {{ die("archive malformed") }}
        let name = std::str::from_utf8(&plaintext[cursor..cursor+nlen]).unwrap_or_else(|_| die("archive name invalid")); cursor += nlen;
        if !safe_name(name) {{ die("artifact name rejected") }}
        let size = u64::from_be_bytes(plaintext[cursor..cursor+8].try_into().unwrap()) as usize; cursor += 8;
        if cursor + size > plaintext.len() {{ die("artifact data truncated") }}
        let data = &plaintext[cursor..cursor+size]; cursor += size;
        let expected = EXPECTED.iter().find(|item| item.0 == name).unwrap_or_else(|| die("artifact unexpected"));
        if expected.2 != data.len() || sha(data).as_slice() != expected.1 {{ die("artifact hash rejected") }}
        let path = work.join(name);
        let mut file = fs::File::create(&path).unwrap_or_else(|_| die("artifact write failed"));
        file.write_all(data).unwrap_or_else(|_| die("artifact write failed"));
        #[cfg(unix)] {{ use std::os::unix::fs::PermissionsExt; fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap_or_else(|_| die("artifact chmod failed")); }}
        if name == MAIN_NAME {{ main_path = Some(path); }}
    }}
    let main_path = main_path.unwrap_or_else(|| die("main artifact missing"));
    let mut command = Command::new(&main_path); command.args(env::args().skip(1));
    if !GATE_NAME.is_empty() {{
        let mask = sha(&key);
        let mut block = mask;
        let mut stream: Vec<u8> = Vec::with_capacity(GATE_ENC.len());
        while stream.len() < GATE_ENC.len() {{
            block = sha(&block);
            stream.extend_from_slice(&block);
        }}
        let token: Vec<u8> = GATE_ENC.iter().enumerate().map(|(i,b)| b ^ stream[i]).collect();
        command.env(GATE_NAME, String::from_utf8(token).unwrap_or_else(|_| die("gate invalid")));
    }}
    let status = command.status().unwrap_or_else(|_| die("child execution failed"));
    let _ = fs::remove_dir_all(&work);
    std::process::exit(status.code().unwrap_or(1));
}}
'''


def build_rust_launcher(binary_path: str, output_path: str, *, embedded_name: str | None = None,
                        lock_filename: bool = False, expected_filename: str | None = None,
                        extra_files: Mapping[str, bytes] | None = None,
                        gate_env_name: str | None = None, gate_token: str | None = None) -> str:
    cargo = shutil.which("cargo")
    if not cargo:
        raise RustLauncherBuildError("Cargo/Rust belum tersedia. Di Termux: pkg install rust clang")
    raw = Path(binary_path).read_bytes()
    name = validate_artifact_name(embedded_name or os.path.basename(binary_path))
    archive, expected = _artifact_archive(name, raw, dict(extra_files or {}))
    key = random_key(32)
    nonce = random_key(12)
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(archive)
    container = nonce + ciphertext + tag
    parts, real_indices = split_key_with_junk(key, n_real_chunks=4, n_junk_chunks=5)
    seed, tags = build_fragment_chain(parts, real_indices)
    lock_name = expected_filename if lock_filename and expected_filename else ""
    source = _rust_source(container=container, key_parts=parts, key_seed=seed, key_tags=tags,
                          expected=expected, main_name=name, lock_name=lock_name,
                          gate_env_name=gate_env_name, gate_token=gate_token,
                          gate_mask=hashlib.sha256(key).digest() if gate_token else None)
    with tempfile.TemporaryDirectory(prefix="pyobf-rust-") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text('''[package]\nname = "pyobf_rust_launcher"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\naes-gcm = "0.10"\nsha2 = "0.10"\n''', encoding="utf-8")
        (root / "src" / "main.rs").write_text(source, encoding="utf-8")
        result = subprocess.run([cargo, "build", "--release", "--offline"], cwd=root, capture_output=True, text=True)
        if result.returncode != 0:
            result = subprocess.run([cargo, "build", "--release"], cwd=root, capture_output=True, text=True)
        artifact = root / "target" / "release" / "pyobf_rust_launcher"
        if result.returncode != 0 or not artifact.is_file():
            detail = (result.stderr or result.stdout or "Cargo tidak menghasilkan launcher").strip()
            raise RustLauncherBuildError(f"Build Rust launcher gagal: {detail}")
        Path(output_path).write_bytes(artifact.read_bytes())
        os.chmod(output_path, 0o700)
    return output_path
