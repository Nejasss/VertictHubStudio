"""
studio_bridge.py - JNI Entrypoint Bridge for VertictHub Studio (Android ARM64).
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import json
import os
import platform
import shutil
import sys
import tempfile
import time
import traceback

EXPECTED_CORE_MODULES = [
    "__init__",
    "antidebug",
    "antisandbox",
    "ast_integrity",
    "attribute_obfuscation",
    "bootstrap",
    "constant_protection",
    "control_flow",
    "crypto",
    "cython_build",
    "cython_guard",
    "data_flow_obfuscation",
    "embed_build",
    "expression_obfuscation",
    "function_transformation",
    "hook_detection",
    "identifier_rename",
    "import_obfuscation",
    "junk",
    "launch_integrity",
    "leak_scan",
    "libpython_fetch",
    "native_decryptor_build",
    "native_launcher",
    "native_worker_compat",
    "obfuscator",
    "packer",
    "runtime_fetch",
    "rust_launcher",
    "signing_autosetup",
    "ssl_pinning",
    "string_enc",
    "unicode_names",
    "worker_gate_compat",
]


def _ok(payload: dict) -> str:
    return json.dumps({"ok": True, **payload}, ensure_ascii=False)


def _err(stage: str, exc: Exception | str, recovery: str = "") -> str:
    if isinstance(exc, Exception):
        msg = f"{type(exc).__name__}: {exc}"
        tb = traceback.format_exc()
    else:
        msg = str(exc)
        tb = ""
    return json.dumps(
        {
            "ok": False,
            "stage": stage,
            "error": msg,
            "traceback": tb,
            "recovery": recovery,
        },
        ensure_ascii=False,
    )


def get_runtime_info() -> str:
    try:
        vi = sys.version_info
        version_str = f"{vi.major}.{vi.minor}.{vi.micro}"
        machine = platform.machine()
        stdlib_ok = all(
            importlib.util.find_spec(mod) is not None
            for mod in ("ast", "marshal", "zlib", "hashlib", "hmac", "json", "sqlite3", "ctypes")
        )
        return _ok(
            {
                "python_version": version_str,
                "python_full": sys.version,
                "version_info": [vi.major, vi.minor, vi.micro, vi.releaselevel],
                "is_3_14_10": (vi.major, vi.minor, vi.micro) == (3, 14, 10),
                "architecture": machine,
                "is_arm64": machine.lower() in ("aarch64", "arm64"),
                "platform": sys.platform,
                "prefix": sys.prefix,
                "executable": sys.executable,
                "sys_path": list(sys.path),
                "stdlib_verified": stdlib_ok,
                "offline_mode": True,
            }
        )
    except Exception as exc:
        return _err("runtime_info", exc, "Periksa ekstraksi stdlib CPython 3.14.10 ke internal storage.")


def verify_core_modules() -> str:
    results = []
    passed = 0
    for mod_name in EXPECTED_CORE_MODULES:
        fqn = "vh.core" if mod_name == "__init__" else f"vh.core.{mod_name}"
        t0 = time.perf_counter()
        try:
            mod = importlib.import_module(fqn)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            public_symbols = [
                k for k, v in vars(mod).items()
                if not k.startswith("_") and callable(v)
            ]
            results.append(
                {
                    "module": mod_name,
                    "fqn": fqn,
                    "status": "VERIFIED",
                    "load_ms": elapsed_ms,
                    "public_callables": public_symbols[:12],
                    "file": getattr(mod, "__file__", ""),
                }
            )
            passed += 1
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            results.append(
                {
                    "module": mod_name,
                    "fqn": fqn,
                    "status": "FAILED",
                    "load_ms": elapsed_ms,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    all_verified = passed == len(EXPECTED_CORE_MODULES)
    return _ok(
        {
            "all_verified": all_verified,
            "total": len(EXPECTED_CORE_MODULES),
            "verified_count": passed,
            "failed_count": len(EXPECTED_CORE_MODULES) - passed,
            "modules": results,
        }
    )


def verify_dependencies() -> str:
    deps = []
    crypto_available = False
    crypto_details = {}

    t0 = time.perf_counter()
    try:
        import Crypto
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA256
        from Crypto.Random import get_random_bytes
        from Crypto.Util.Padding import pad, unpad
        from Crypto.PublicKey import ECC

        key = get_random_bytes(32)
        iv = get_random_bytes(16)
        plaintext = b"VertictHub-Studio-ARM64-CPython-3.14.10-SelfTest"
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
        digest = SHA256.new(pt).hexdigest()
        ecc_key = ECC.generate(curve="Ed25519")

        assert pt == plaintext, "AES-256-CBC round-trip mismatch"
        assert len(digest) == 64, "SHA256 digest length invalid"
        assert ecc_key.curve == "Ed25519", "Ed25519 keygen invalid"

        crypto_available = True
        crypto_details = {
            "version": getattr(Crypto, "__version__", "bundled"),
            "aes_256_cbc_roundtrip": True,
            "sha256_digest": digest,
            "ed25519_supported": True,
            "test_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        deps.append(
            {
                "name": "pycryptodome",
                "category": "Native Python Extension",
                "version": getattr(Crypto, "__version__", "3.21.0"),
                "abi": "arm64-v8a / cp314",
                "status": "VERIFIED",
                "details": crypto_details,
            }
        )
    except Exception as exc:
        crypto_details = {"error": f"{type(exc).__name__}: {exc}"}
        deps.append(
            {
                "name": "pycryptodome",
                "category": "Native Python Extension",
                "version": "required",
                "abi": "arm64-v8a / cp314",
                "status": "MISSING_OR_INVALID",
                "details": crypto_details,
            }
        )

    for std_mod in ("ast", "marshal", "zlib", "hashlib", "hmac", "secrets", "sqlite3", "ctypes"):
        spec = importlib.util.find_spec(std_mod)
        deps.append(
            {
                "name": std_mod,
                "category": "Python Standard Library",
                "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "abi": "arm64-v8a",
                "status": "VERIFIED" if spec is not None else "FAILED",
                "details": {"origin": getattr(spec, "origin", "") if spec else "not found"},
            }
        )

    for tool in ("clang", "gcc", "cython", "cargo", "rustc"):
        found_path = shutil.which(tool)
        deps.append(
            {
                "name": tool,
                "category": "Native Compiler / Toolchain (Optional)",
                "version": "local" if found_path else "not installed on device",
                "abi": "aarch64",
                "status": "AVAILABLE" if found_path else "NOT_INSTALLED_ON_DEVICE",
                "details": {"path": found_path or ""},
            }
        )

    return _ok(
        {
            "crypto_available": crypto_available,
            "crypto_details": crypto_details,
            "dependencies": deps,
        }
    )


def analyze_ast(source_code: str, filename: str = "script.py") -> str:
    try:
        from vh.core import ast_integrity, constant_protection

        t0 = time.perf_counter()
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError as syn:
            return _ok(
                {
                    "valid_syntax": False,
                    "filename": filename,
                    "syntax_error": {
                        "message": syn.msg,
                        "lineno": syn.lineno or 1,
                        "offset": syn.offset or 0,
                        "text": (syn.text or "").rstrip("\n"),
                    },
                }
            )

        integrity_report = ast_integrity.validate_source(source_code, stage="analyze_ast")
        const_inv = constant_protection.scan_constants(source_code)

        imports = []
        functions = []
        classes = []
        node_count = 0

        for node in ast.walk(tree):
            node_count += 1
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or "."
                for alias in node.names:
                    imports.append(f"{mod}.{alias.name}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(
                    {
                        "name": node.name,
                        "lineno": node.lineno,
                        "async": isinstance(node, ast.AsyncFunctionDef),
                        "args": [a.arg for a in node.args.args],
                    }
                )
            elif isinstance(node, ast.ClassDef):
                methods = [
                    n.name for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                classes.append(
                    {
                        "name": node.name,
                        "lineno": node.lineno,
                        "methods": methods,
                    }
                )

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return _ok(
            {
                "valid_syntax": True,
                "filename": filename,
                "line_count": len(source_code.splitlines()),
                "byte_size": len(source_code.encode("utf-8")),
                "sha256": hashlib.sha256(source_code.encode("utf-8")).hexdigest(),
                "ast_node_count": node_count,
                "imports": sorted(set(imports)),
                "functions": functions,
                "classes": classes,
                "protected_constants_candidates": len(getattr(const_inv, "entries", [])),
                "has_future_imports": getattr(integrity_report, "has_future_imports", False),
                "analysis_ms": elapsed_ms,
            }
        )
    except Exception as exc:
        return _err("analyze_ast", exc, "Periksa sintaks file Python input.")


def run_obfuscation(source_code: str, filename: str = "script.py", config_json: str = "{}") -> str:
    try:
        from vh.core import obfuscator, ast_integrity, leak_scan

        t0 = time.perf_counter()
        raw_cfg = json.loads(config_json) if config_json else {}

        pins = raw_cfg.get("ssl_pin_sha256", [])
        if isinstance(pins, str):
            pins = [p.strip() for p in pins.split(",") if p.strip()]

        recheck_min = int(raw_cfg.get("recheck_min_sec", 4))
        recheck_max = int(raw_cfg.get("recheck_max_sec", 9))
        if recheck_max < recheck_min:
            recheck_max = recheck_min

        cfg = obfuscator.ObfuscationConfig(
            encrypt_strings=bool(raw_cfg.get("encrypt_strings", True)),
            min_string_len=int(raw_cfg.get("min_string_len", 1)),
            junk_intensity=int(raw_cfg.get("junk_intensity", 6)),
            anti_debug=bool(raw_cfg.get("anti_debug", True)),
            anti_vpn=bool(raw_cfg.get("anti_vpn", False)),
            strict_network_check=bool(raw_cfg.get("strict_network_check", False)),
            rename_identifiers=bool(raw_cfg.get("rename_identifiers", True)),
            lock_filename=bool(raw_cfg.get("lock_filename", False)),
            require_launcher_gate=True,
            inject_decoy_methods=bool(raw_cfg.get("inject_decoy_methods", True)),
            periodic_recheck=bool(raw_cfg.get("periodic_recheck", False)),
            enable_version_fallback=False,
            enable_antisandbox=bool(raw_cfg.get("enable_antisandbox", False)),
            antisandbox_threshold=int(raw_cfg.get("antisandbox_threshold", 6)),
            bytecode_integrity_check=bool(raw_cfg.get("bytecode_integrity_check", False)),
            recheck_interval_range=(recheck_min, recheck_max),
            cjk_identifiers=bool(raw_cfg.get("cjk_identifiers", False)),
            ssl_pin_sha256=pins,
            hook_detection=bool(raw_cfg.get("hook_detection", False)),
            control_flow_obfuscation=bool(raw_cfg.get("control_flow_obfuscation", False)),
            constant_protection=bool(raw_cfg.get("constant_protection", False)),
            expression_obfuscation=bool(raw_cfg.get("expression_obfuscation", False)),
            import_obfuscation=bool(raw_cfg.get("import_obfuscation", False)),
            attribute_obfuscation=bool(raw_cfg.get("attribute_obfuscation", False)),
            function_transformation=bool(raw_cfg.get("function_transformation", False)),
            data_flow_obfuscation=bool(raw_cfg.get("data_flow_obfuscation", False)),
        )

        gate_info = obfuscator.generate_gate_info()
        obf_source = obfuscator.obfuscate_source(
            source_code,
            config=cfg,
            expected_filename=os.path.basename(filename),
            gate_info=gate_info,
        )

        ast_integrity.validate_source(obf_source, stage="run_obfuscation")

        vocab = leak_scan.extract_sensitive_vocabulary(source_code)
        with tempfile.NamedTemporaryFile("w", suffix=".py", encoding="utf-8", delete=False) as tf:
            tf.write(obf_source)
            tmp_out = tf.name
        try:
            scan_res = leak_scan.scan_binary_for_leaks(tmp_out, vocab)
            leak_report = leak_scan.format_report(scan_res, os.path.basename(filename))
        finally:
            try:
                os.remove(tmp_out)
            except OSError:
                pass

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        active_passes = [
            name for name, enabled in [
                ("identifier_rename", cfg.rename_identifiers),
                ("string_encryption", cfg.encrypt_strings),
                ("constant_protection", cfg.constant_protection),
                ("control_flow", cfg.control_flow_obfuscation),
                ("data_flow", cfg.data_flow_obfuscation),
                ("expression_obfuscation", cfg.expression_obfuscation),
                ("function_transformation", cfg.function_transformation),
                ("attribute_obfuscation", cfg.attribute_obfuscation),
                ("import_obfuscation", cfg.import_obfuscation),
                ("decoy_methods", cfg.inject_decoy_methods),
                ("junk_injection", cfg.junk_intensity > 0),
                ("anti_debug_diag", cfg.anti_debug),
                ("antisandbox_diag", cfg.enable_antisandbox),
                ("hook_detection", cfg.hook_detection),
                ("ssl_pinning", bool(cfg.ssl_pin_sha256)),
                ("cjk_identifiers", cfg.cjk_identifiers),
            ]
            if enabled
        ]

        return _ok(
            {
                "obfuscated_source": obf_source,
                "input_bytes": len(source_code.encode("utf-8")),
                "output_bytes": len(obf_source.encode("utf-8")),
                "output_sha256": hashlib.sha256(obf_source.encode("utf-8")).hexdigest(),
                "active_passes": active_passes,
                "gate_env_name": gate_info["env_name"],
                "gate_token": gate_info["token"],
                "leak_report": leak_report,
                "elapsed_ms": elapsed_ms,
            }
        )
    except Exception as exc:
        return _err(
            "obfuscate",
            exc,
            "Periksa sintaks kode sumber atau nonaktifkan pass AST lanjutan bila terjadi konflik.",
        )


def run_build(
    source_code: str,
    filename: str = "app.py",
    build_mode: str = "packed_loader",
    options_json: str = "{}",
) -> str:
    try:
        from vh.core import obfuscator, packer, launch_integrity, leak_scan

        t0 = time.perf_counter()
        opts = json.loads(options_json) if options_json else {}
        base_name = os.path.basename(filename) or "app.py"
        stem = os.path.splitext(base_name)[0]

        if build_mode == "packed_loader":
            cfg = obfuscator.ObfuscationConfig(
                encrypt_strings=bool(opts.get("encrypt_strings", True)),
                rename_identifiers=bool(opts.get("rename_identifiers", True)),
                junk_intensity=int(opts.get("junk_intensity", 6)),
                anti_debug=bool(opts.get("anti_debug", True)),
                constant_protection=bool(opts.get("constant_protection", True)),
                lock_filename=bool(opts.get("lock_filename", False)),
                require_launcher_gate=True,
                enable_version_fallback=False,
            )
            gate = obfuscator.generate_gate_info()
            packed_py = obfuscator.obfuscate_source(
                source_code,
                config=cfg,
                expected_filename=f"{stem}_protected.py",
                gate_info=gate,
            )
            compile(packed_py, f"<{stem}_packed.py>", "exec")
            return _ok(
                {
                    "build_mode": build_mode,
                    "status": "SUCCESS",
                    "artifact_filename": f"{stem}_protected.py",
                    "artifact_content": packed_py,
                    "artifact_bytes": len(packed_py.encode("utf-8")),
                    "artifact_sha256": hashlib.sha256(packed_py.encode("utf-8")).hexdigest(),
                    "gate_env_name": gate["env_name"],
                    "gate_token": gate["token"],
                    "log": (
                        f"[OK] AST Obfuscation + Gate binding selesai\n"
                        f"[OK] Bytecode marshal + HKDF-SHA256 multi-fragment XOR packer selesai\n"
                        f"[OK] Kompilasi sintaks loader terverifikasi (CPython {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro})\n"
                        f"[INFO] Gate Env: {gate['env_name']}={gate['token']}\n"
                        f"[INFO] Ukuran output: {len(packed_py.encode('utf-8'))} bytes"
                    ),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )

        if build_mode == "signed_bundle":
            key_dir = opts.get("key_dir") or os.path.join(tempfile.gettempdir(), "vh_studio_keys")
            os.makedirs(key_dir, mode=0o700, exist_ok=True)
            priv_path = os.path.join(key_dir, "release-private.pem")
            pub_path = os.path.join(key_dir, "release-public.pem")
            if not (os.path.isfile(priv_path) and os.path.isfile(pub_path)):
                launch_integrity.generate_ed25519_keypair(priv_path, pub_path)

            cfg = obfuscator.ObfuscationConfig(
                encrypt_strings=True,
                rename_identifiers=True,
                junk_intensity=int(opts.get("junk_intensity", 6)),
                anti_debug=bool(opts.get("anti_debug", True)),
                lock_filename=bool(opts.get("lock_filename", False)),
                require_launcher_gate=True,
                enable_version_fallback=False,
            )
            gate = obfuscator.generate_gate_info()
            packed_py = obfuscator.obfuscate_source(
                source_code,
                config=cfg,
                expected_filename=f"{stem}_protected.py",
                gate_info=gate,
            )
            packed_bytes = packed_py.encode("utf-8")

            manifest = launch_integrity.build_manifest(f"{stem}_protected.py", packed_bytes)
            priv_pem = launch_integrity.load_private_key(priv_path)
            sig_b64 = launch_integrity.sign_manifest(manifest, priv_pem)
            with open(pub_path, "r", encoding="utf-8") as pf:
                pub_pem = pf.read()

            manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
            verified = launch_integrity.verify_signed_manifest(manifest_json, sig_b64, pub_pem)
            if not verified:
                raise RuntimeError("Verifikasi tanda tangan Ed25519 gagal pasca-signing.")

            bundle_doc = json.dumps(
                {
                    "manifest": manifest,
                    "signature_ed25519_b64": sig_b64,
                    "public_key_pem": pub_pem,
                    "artifact_name": f"{stem}_protected.py",
                    "gate_env_name": gate["env_name"],
                    "gate_token": gate["token"],
                },
                indent=2,
            )
            return _ok(
                {
                    "build_mode": build_mode,
                    "status": "SUCCESS",
                    "artifact_filename": f"{stem}_protected.py",
                    "artifact_content": packed_py,
                    "manifest_filename": f"{stem}_manifest.signed.json",
                    "manifest_content": bundle_doc,
                    "artifact_bytes": len(packed_bytes),
                    "artifact_sha256": hashlib.sha256(packed_bytes).hexdigest(),
                    "gate_env_name": gate["env_name"],
                    "gate_token": gate["token"],
                    "log": (
                        f"[OK] Loader terenkripsi berhasil dibuat ({len(packed_bytes)} bytes)\n"
                        f"[OK] Keypair Ed25519 lokal dimuat dari {key_dir}\n"
                        f"[OK] Manifest deterministik ditandatangani & diverifikasi (Ed25519 VALID)\n"
                        f"[INFO] Gate Env: {gate['env_name']}={gate['token']}"
                    ),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )

        if build_mode == "leak_audit":
            vocab = leak_scan.extract_sensitive_vocabulary(source_code)
            with tempfile.NamedTemporaryFile("w", suffix=".py", encoding="utf-8", delete=False) as tf:
                tf.write(source_code)
                tmp_in = tf.name
            try:
                res = leak_scan.scan_binary_for_leaks(tmp_in, vocab)
                report_txt = leak_scan.format_report(res, base_name)
            finally:
                try:
                    os.remove(tmp_in)
                except OSError:
                    pass
            return _ok(
                {
                    "build_mode": build_mode,
                    "status": "SUCCESS",
                    "artifact_filename": f"{stem}_leak_audit.txt",
                    "artifact_content": report_txt,
                    "artifact_bytes": len(report_txt.encode("utf-8")),
                    "artifact_sha256": hashlib.sha256(report_txt.encode("utf-8")).hexdigest(),
                    "log": report_txt,
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )

        if build_mode == "rust_launcher":
            from Crypto.Cipher import AES
            from vh.core import rust_launcher
            from vh.core.crypto import build_fragment_chain, random_key, split_key_with_junk

            cfg = obfuscator.ObfuscationConfig(
                encrypt_strings=bool(opts.get("encrypt_strings", True)),
                rename_identifiers=bool(opts.get("rename_identifiers", True)),
                junk_intensity=int(opts.get("junk_intensity", 6)),
                anti_debug=bool(opts.get("anti_debug", True)),
                constant_protection=bool(opts.get("constant_protection", True)),
                require_launcher_gate=True,
                enable_version_fallback=False,
            )
            gate = obfuscator.generate_gate_info()
            packed_py = obfuscator.obfuscate_source(
                source_code,
                config=cfg,
                expected_filename=f"{stem}_protected.py",
                gate_info=gate,
            )
            payload_bytes = packed_py.encode("utf-8")
            archive, expected = rust_launcher._artifact_archive(f"{stem}_protected.py", payload_bytes, {})
            key = random_key(32)
            nonce = random_key(12)
            ciphertext, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(archive)
            container = nonce + ciphertext + tag
            parts, real_indices = split_key_with_junk(key, n_real_chunks=4, n_junk_chunks=5)
            seed, tags = build_fragment_chain(parts, real_indices)
            lock_name = f"{stem}_launcher" if opts.get("lock_filename") else ""
            rs_source = rust_launcher._rust_source(
                container=container,
                key_parts=parts,
                key_seed=seed,
                key_tags=tags,
                expected=expected,
                main_name=f"{stem}_protected.py",
                lock_name=lock_name,
                gate_env_name=gate["env_name"],
                gate_token=gate["token"],
                gate_mask=hashlib.sha256(key).digest(),
            )
            cargo_toml = (
                '[package]\n'
                f'name = "{stem}_launcher"\n'
                'version = "0.1.0"\n'
                'edition = "2021"\n\n'
                '[dependencies]\n'
                'aes-gcm = "0.10"\n'
                'sha2 = "0.10"\n'
            )
            return _ok(
                {
                    "build_mode": build_mode,
                    "status": "SUCCESS",
                    "artifact_filename": f"{stem}_rust_launcher.rs",
                    "artifact_content": rs_source,
                    "manifest_filename": "Cargo.toml",
                    "manifest_content": cargo_toml,
                    "artifact_bytes": len(rs_source.encode("utf-8")),
                    "artifact_sha256": hashlib.sha256(rs_source.encode("utf-8")).hexdigest(),
                    "log": (
                        f"[OK] Payload terenkripsi & dibungkus ke crate Rust ({len(rs_source.encode('utf-8'))} bytes)\n"
                        f"[INFO] Toolchain cargo/rustc tidak ada di sandbox APK -> sumber Rust siap kompilasi diekspor\n"
                        f"[INFO] Kompilasi di Termux: pkg install rust clang && cargo build --release"
                    ),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )

        if build_mode == "cython_native":
            from vh.core import cython_build

            cfg = obfuscator.ObfuscationConfig(
                encrypt_strings=bool(opts.get("encrypt_strings", True)),
                rename_identifiers=bool(opts.get("rename_identifiers", True)),
                junk_intensity=int(opts.get("junk_intensity", 6)),
                anti_debug=bool(opts.get("anti_debug", True)),
                constant_protection=bool(opts.get("constant_protection", True)),
                lock_filename=bool(opts.get("lock_filename", False)),
                require_launcher_gate=True,
                enable_version_fallback=False,
            )
            gate = obfuscator.generate_gate_info()
            obf_src = obfuscator.obfuscate_source(
                source_code,
                config=cfg,
                expected_filename=f"{stem}_protected.py",
                gate_info=gate,
            )
            module_preamble, pyx_body = cython_build._extract_future_imports(obf_src)
            prelude = cython_build._build_disable_coredump_prelude()
            pyx_source = module_preamble + prelude + pyx_body

            build_sh = (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "# Install di Termux: pkg install python clang cython\n"
                f"cython --embed -3 -o {stem}.c {stem}.pyx\n"
                f"clang -Os -fvisibility=hidden -ffunction-sections -fdata-sections "
                f"-Wl,--gc-sections -w $(python3-config --includes) {stem}.c "
                f"$(python3-config --ldflags --embed) -o {stem}_cython\n"
                f"strip --strip-all {stem}_cython || true\n"
                f"echo '[OK] Built ./{stem}_cython'\n"
                f"echo '[RUN] {gate['env_name']}={gate['token']} ./{stem}_cython'\n"
            )
            return _ok(
                {
                    "build_mode": build_mode,
                    "status": "SUCCESS",
                    "artifact_filename": f"{stem}.pyx",
                    "artifact_content": pyx_source,
                    "manifest_filename": f"build_{stem}_cython.sh",
                    "manifest_content": build_sh,
                    "artifact_bytes": len(pyx_source.encode("utf-8")),
                    "artifact_sha256": hashlib.sha256(pyx_source.encode("utf-8")).hexdigest(),
                    "gate_env_name": gate["env_name"],
                    "gate_token": gate["token"],
                    "log": (
                        f"[OK] Sumber Cython (.pyx) + anti-coredump RLIMIT_CORE prelude berhasil dibuat ({len(pyx_source.encode('utf-8'))} bytes)\n"
                        f"[INFO] Toolchain cython/clang tidak ada di sandbox APK -> file .pyx + script kompilasi diekspor\n"
                        f"[INFO] Kompilasi di Termux: bash build_{stem}_cython.sh\n"
                        f"[INFO] Gate Env: {gate['env_name']}={gate['token']}"
                    ),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )

        if build_mode == "c_embed":
            import marshal
            import random
            from vh.core import embed_build
            from vh.core.crypto import build_fragment_chain, random_key, xor_encrypt

            cfg = obfuscator.ObfuscationConfig(
                encrypt_strings=bool(opts.get("encrypt_strings", True)),
                rename_identifiers=bool(opts.get("rename_identifiers", True)),
                junk_intensity=int(opts.get("junk_intensity", 6)),
                anti_debug=bool(opts.get("anti_debug", True)),
                constant_protection=bool(opts.get("constant_protection", True)),
                lock_filename=bool(opts.get("lock_filename", False)),
                require_launcher_gate=True,
                enable_version_fallback=False,
            )
            gate = obfuscator.generate_gate_info()
            obf_src = obfuscator.obfuscate_source(
                source_code,
                config=cfg,
                expected_filename=f"{stem}_protected.py",
                gate_info=gate,
            )
            code_obj = compile(obf_src, f"<{stem}>", "exec")
            blob = marshal.dumps(code_obj)
            key = random_key(32)
            enc = xor_encrypt(blob, key)
            payload_hash = hashlib.sha256(blob).hexdigest()
            ciphertext_hash = hashlib.sha256(enc).hexdigest()
            lock_name = f"{stem}_embed" if opts.get("lock_filename") else ""

            frag_len = 8
            real_frags = [key[i:i + frag_len].ljust(frag_len, b"\x00") for i in range(0, len(key), frag_len)]
            junk_frags = [os.urandom(frag_len) for _ in range(random.randint(5, 9))]
            all_frags = real_frags + junk_frags
            order = list(range(len(all_frags)))
            random.shuffle(order)
            shuffled = [all_frags[i] for i in order]
            real_pos = [order.index(i) for i in range(len(real_frags))]
            key_seed, key_tags = build_fragment_chain(shuffled, real_pos, tag_len=4)

            n_frags = len(shuffled)
            n_tags = len(key_tags)
            tag_len = len(key_tags[0]) if key_tags else 4
            frags_rows = ",\n".join("    {" + embed_build._c_byte_array(f) + "}" for f in shuffled)
            tags_rows = ",\n".join("    {" + embed_build._c_byte_array(t) + "}" for t in key_tags)

            used = set()
            (v_payload, v_payload_len, v_key, v_hash, v_ct_hash, v_lock_name,
             fn_ks, fn_xor, fn_hex, fn_hash_eq, fn_basename_eq, fn_watchdog) = embed_build._rand_names(12, used)
            (v_keyfrags, v_keyseed, v_keytags, fn_pickkey) = embed_build._rand_names(4, used)

            c_source = (
                "#define PY_SSIZE_T_CLEAN\n"
                "#include <Python.h>\n"
                "#include <stdio.h>\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "#include <stdint.h>\n"
                "#include <pthread.h>\n"
                "#include <unistd.h>\n"
                "#include <time.h>\n\n"
                + embed_build._SHA256_C
                + f"\nstatic const unsigned char {v_keyfrags}[{n_frags}][{frag_len}] = {{\n{frags_rows}\n}};\n"
                + f"static const unsigned char {v_keyseed}[32] = {{{embed_build._c_byte_array(key_seed)}}};\n"
                + f"static const unsigned char {v_keytags}[{n_tags}][{tag_len}] = {{\n{tags_rows}\n}};\n"
                + f"static const unsigned char {v_payload}[] = {{{embed_build._c_byte_array(enc)}}};\n"
                + f"static const size_t {v_payload_len} = sizeof({v_payload});\n"
                + f'static const char {v_hash}[] = "{payload_hash}";\n'
                + f'static const char {v_ct_hash}[] = "{ciphertext_hash}";\n'
                + f'static const char {v_lock_name}[] = "{lock_name}";\n\n'
                + f"static void {fn_pickkey}(unsigned char *out_key) {{\n"
                + f"    unsigned char state[32];\n"
                + f"    memcpy(state, {v_keyseed}, 32);\n"
                + f"    int used_flag[{n_frags}] = {{0}};\n"
                + f"    for (int t = 0; t < {n_tags}; t++) {{\n"
                + f"        int found = -1;\n"
                + f"        unsigned char digest[32];\n"
                + f"        for (int c = 0; c < {n_frags}; c++) {{\n"
                + f"            if (used_flag[c]) continue;\n"
                + f"            unsigned char buf[32 + {frag_len}];\n"
                + f"            memcpy(buf, state, 32);\n"
                + f"            memcpy(buf + 32, {v_keyfrags}[c], {frag_len});\n"
                + f"            sha256(buf, 32 + {frag_len}, digest);\n"
                + f"            if (memcmp(digest, {v_keytags}[t], {tag_len}) == 0) {{ found = c; break; }}\n"
                + f"        }}\n"
                + f"        if (found < 0) {{ memset(out_key, 0, 32); return; }}\n"
                + f"        used_flag[found] = 1;\n"
                + f"        memcpy(out_key + (t * {frag_len}), {v_keyfrags}[found], {frag_len});\n"
                + f"        memcpy(state, digest, 32);\n"
                + f"    }}\n"
                + f"}}\n\n"
                + f"static int {fn_basename_eq}(const char *argv0) {{\n"
                + f"    if ({v_lock_name}[0] == '\\0') return 1;\n"
                + f"    const char *base = argv0;\n"
                + f"    for (const char *p = argv0; *p; p++) {{\n"
                + f"        if (*p == '/' || *p == '\\\\') base = p + 1;\n"
                + f"    }}\n"
                + f"    return strcmp(base, {v_lock_name}) == 0;\n"
                + f"}}\n\n"
                + f"static void {fn_ks}(const unsigned char *key, unsigned char *out, size_t out_len) {{\n"
                + f"    unsigned char block[32];\n"
                + f"    memcpy(block, key, 32);\n"
                + f"    size_t filled = 0;\n"
                + f"    while (filled < out_len) {{\n"
                + f"        unsigned char digest[32];\n"
                + f"        sha256(block, 32, digest);\n"
                + f"        memcpy(block, digest, 32);\n"
                + f"        size_t take = out_len - filled;\n"
                + f"        if (take > 32) take = 32;\n"
                + f"        memcpy(out + filled, digest, take);\n"
                + f"        filled += take;\n"
                + f"    }}\n"
                + f"}}\n\n"
                + f"static unsigned char *{fn_xor}(const unsigned char *data, size_t len, const unsigned char *key) {{\n"
                + f"    unsigned char *ks = malloc(len);\n"
                + f"    unsigned char *out = malloc(len);\n"
                + f"    if (!ks || !out) exit(1);\n"
                + f"    {fn_ks}(key, ks, len);\n"
                + f"    for (size_t i = 0; i < len; i++) out[i] = data[i] ^ ks[i];\n"
                + f"    free(ks);\n"
                + f"    return out;\n"
                + f"}}\n\n"
                + f"static void {fn_hex}(const unsigned char *digest, char *out_hex) {{\n"
                + f'    static const char hexchars[] = "0123456789abcdef";\n'
                + f"    for (int i = 0; i < 32; i++) {{\n"
                + f"        out_hex[i * 2] = hexchars[(digest[i] >> 4) & 0xf];\n"
                + f"        out_hex[i * 2 + 1] = hexchars[digest[i] & 0xf];\n"
                + f"    }}\n"
                + f"    out_hex[64] = '\\0';\n"
                + f"}}\n\n"
                + f"static int {fn_hash_eq}(const unsigned char *data, size_t len, const char *expected_hex) {{\n"
                + f"    unsigned char digest[32];\n"
                + f"    sha256(data, len, digest);\n"
                + f"    char hex[65];\n"
                + f"    {fn_hex}(digest, hex);\n"
                + f"    return strcmp(hex, expected_hex) == 0;\n"
                + f"}}\n\n"
                + f"static void *{fn_watchdog}(void *arg) {{\n"
                + f"    (void)arg;\n"
                + f"    for (;;) {{\n"
                + f"        struct timespec ts;\n"
                + f"        ts.tv_sec = 3 + (time(NULL) % 4);\n"
                + f"        ts.tv_nsec = 0;\n"
                + f"        nanosleep(&ts, NULL);\n"
                + f"        if (!{fn_hash_eq}({v_payload}, {v_payload_len}, {v_ct_hash})) _exit(1);\n"
                + f"    }}\n"
                + f"    return NULL;\n"
                + f"}}\n\n"
                + f"int main(int argc, char **argv) {{\n"
                + f"    if (argc < 1 || !{fn_basename_eq}(argv[0])) return 1;\n"
                + f"    unsigned char {v_key}[32];\n"
                + f"    {fn_pickkey}({v_key});\n"
                + f"    unsigned char *dec = {fn_xor}({v_payload}, {v_payload_len}, {v_key});\n"
                + f"    if (!{fn_hash_eq}(dec, {v_payload_len}, {v_hash})) {{ free(dec); return 1; }}\n"
                + f"    pthread_t _wd;\n"
                + f"    if (pthread_create(&_wd, NULL, {fn_watchdog}, NULL) == 0) pthread_detach(_wd);\n"
                + f"    wchar_t *prog_name = Py_DecodeLocale(argv[0], NULL);\n"
                + f"    Py_SetProgramName(prog_name);\n"
                + f"    Py_Initialize();\n"
                + f"    PyObject *code_bytes = PyBytes_FromStringAndSize((const char *)dec, (Py_ssize_t){v_payload_len});\n"
                + f"    free(dec);\n"
                + f"    if (!code_bytes) {{ PyErr_Print(); Py_Finalize(); return 1; }}\n"
                + f'    PyObject *marshal_mod = PyImport_ImportModule("marshal");\n'
                + f'    PyObject *loads_fn = PyObject_GetAttrString(marshal_mod, "loads");\n'
                + f"    PyObject *code_obj = PyObject_CallFunctionObjArgs(loads_fn, code_bytes, NULL);\n"
                + f"    Py_DECREF(code_bytes); Py_DECREF(loads_fn); Py_DECREF(marshal_mod);\n"
                + f"    if (!code_obj) {{ PyErr_Print(); Py_Finalize(); return 1; }}\n"
                + f'    PyObject *main_mod = PyImport_AddModule("__main__");\n'
                + f"    PyObject *main_dict = PyModule_GetDict(main_mod);\n"
                + f"    PyObject *res = PyEval_EvalCode(code_obj, main_dict, main_dict);\n"
                + f"    Py_DECREF(code_obj);\n"
                + f"    int rc = 0;\n"
                + f"    if (!res) {{ PyErr_Print(); rc = 1; }} else {{ Py_DECREF(res); }}\n"
                + f"    if (Py_FinalizeEx() < 0) rc = 120;\n"
                + f"    PyMem_RawFree(prog_name);\n"
                + f"    return rc;\n"
                + f"}}\n"
            )
            build_sh = (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "# Install di Termux: pkg install python clang\n"
                f"clang -Os -fvisibility=hidden -w $(python3-config --includes) {stem}_embed.c "
                f"$(python3-config --ldflags --embed) -lpthread -o {stem}_embed\n"
                f"strip --strip-all {stem}_embed || true\n"
                f"echo '[OK] Built ./{stem}_embed'\n"
                f"echo '[RUN] {gate['env_name']}={gate['token']} ./{stem}_embed'\n"
            )
            return _ok(
                {
                    "build_mode": build_mode,
                    "status": "SUCCESS",
                    "artifact_filename": f"{stem}_embed.c",
                    "artifact_content": c_source,
                    "manifest_filename": f"build_{stem}_embed.sh",
                    "manifest_content": build_sh,
                    "artifact_bytes": len(c_source.encode("utf-8")),
                    "artifact_sha256": hashlib.sha256(c_source.encode("utf-8")).hexdigest(),
                    "gate_env_name": gate["env_name"],
                    "gate_token": gate["token"],
                    "log": (
                        f"[OK] C-Embed source ({len(blob)} bytes bytecode marshal terenkripsi + key-fragment chain) berhasil dibuat ({len(c_source.encode('utf-8'))} bytes)\n"
                        f"[INFO] Toolchain clang/libpython-dev tidak ada di sandbox APK -> sumber C + script build diekspor\n"
                        f"[INFO] Kompilasi di Termux: bash build_{stem}_embed.sh\n"
                        f"[INFO] Gate Env: {gate['env_name']}={gate['token']}"
                    ),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )

        if build_mode == "native_launcher":
            import random
            from vh.core import native_launcher
            from vh.core.crypto import build_fragment_chain, random_key, xor_encrypt

            cfg = obfuscator.ObfuscationConfig(
                encrypt_strings=bool(opts.get("encrypt_strings", True)),
                rename_identifiers=bool(opts.get("rename_identifiers", True)),
                junk_intensity=int(opts.get("junk_intensity", 6)),
                anti_debug=bool(opts.get("anti_debug", True)),
                constant_protection=bool(opts.get("constant_protection", True)),
                lock_filename=bool(opts.get("lock_filename", False)),
                require_launcher_gate=True,
                enable_version_fallback=False,
            )
            gate = obfuscator.generate_gate_info()
            packed_py = obfuscator.obfuscate_source(
                source_code,
                config=cfg,
                expected_filename=f"{stem}_protected.py",
                gate_info=gate,
            )
            raw_payload = packed_py.encode("utf-8")
            key = random_key(32)
            enc = xor_encrypt(raw_payload, key)
            payload_hash = hashlib.sha256(raw_payload).hexdigest()
            lock_name = f"{stem}_launcher" if opts.get("lock_filename") else ""

            frag_len = 8
            real_frags = [key[i:i + frag_len].ljust(frag_len, b"\x00") for i in range(0, len(key), frag_len)]
            junk_frags = [os.urandom(frag_len) for _ in range(random.randint(5, 9))]
            all_frags = real_frags + junk_frags
            order = list(range(len(all_frags)))
            random.shuffle(order)
            shuffled = [all_frags[i] for i in order]
            real_pos = [order.index(i) for i in range(len(real_frags))]
            key_seed, key_tags = build_fragment_chain(shuffled, real_pos, tag_len=4)

            gt_bytes = gate["token"].encode("utf-8")
            gt_key = random_key(32)
            gt_enc = xor_encrypt(gt_bytes, gt_key)
            gt_real = [gt_key[i:i + frag_len].ljust(frag_len, b"\x00") for i in range(0, len(gt_key), frag_len)]
            gt_junk = [os.urandom(frag_len) for _ in range(random.randint(5, 9))]
            gt_all = gt_real + gt_junk
            gt_ord = list(range(len(gt_all)))
            random.shuffle(gt_ord)
            gt_shuf = [gt_all[i] for i in gt_ord]
            gt_pos = [gt_ord.index(i) for i in range(len(gt_real))]
            gt_seed, gt_tags = build_fragment_chain(gt_shuf, gt_pos, tag_len=4)

            used = set()
            (v_payload, v_payload_len, v_key, v_hash, v_cachedir, v_name,
             fn_ks, fn_xor, fn_hex, fn_extract, fn_hash_eq) = native_launcher._rand_names(11, used)
            (v_lock_name, fn_basename_eq) = native_launcher._rand_names(2, used)
            (v_gate_env,) = native_launcher._rand_names(1, used)
            (v_keyfrags, v_keyseed, v_keytags, fn_pickkey) = native_launcher._rand_names(4, used)
            (v_gt_enc, v_gt_enc_len, v_gt_keyfrags, v_gt_keyseed, v_gt_keytags,
             fn_gt_pickkey, v_gt_buf) = native_launcher._rand_names(7, used)

            cache_dir_name = "." + native_launcher._rand_identifier(10)
            frags_rows = ",\n".join("    {" + native_launcher._c_byte_array(f) + "}" for f in shuffled)
            tags_rows = ",\n".join("    {" + native_launcher._c_byte_array(t) + "}" for t in key_tags)
            gt_frags_rows = ",\n".join("    {" + native_launcher._c_byte_array(f) + "}" for f in gt_shuf)
            gt_tags_rows = ",\n".join("    {" + native_launcher._c_byte_array(t) + "}" for t in gt_tags)
            gate_env_c = gate["env_name"].replace("\\", "\\\\").replace('"', '\\"')

            c_source = (
                "#include <stdio.h>\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "#include <stdint.h>\n"
                "#include <unistd.h>\n"
                "#include <sys/stat.h>\n\n"
                + native_launcher._SHA256_C
                + f"\nstatic const unsigned char {v_keyfrags}[{len(shuffled)}][{frag_len}] = {{\n{frags_rows}\n}};\n"
                + f"static const unsigned char {v_keyseed}[32] = {{{native_launcher._c_byte_array(key_seed)}}};\n"
                + f"static const unsigned char {v_keytags}[{len(key_tags)}][{len(key_tags[0])}] = {{\n{tags_rows}\n}};\n"
                + f"static const unsigned char {v_payload}[] = {{{native_launcher._c_byte_array(enc)}}};\n"
                + f"static const size_t {v_payload_len} = sizeof({v_payload});\n"
                + f'static const char {v_hash}[] = "{payload_hash}";\n'
                + f'static const char {v_cachedir}[] = "{cache_dir_name}";\n'
                + f'static const char {v_name}[] = "{stem}_protected.py";\n'
                + f'static const char {v_lock_name}[] = "{lock_name}";\n'
                + f'static const char {v_gate_env}[] = "{gate_env_c}";\n\n'
                + f"static const unsigned char {v_gt_keyfrags}[{len(gt_shuf)}][{frag_len}] = {{\n{gt_frags_rows}\n}};\n"
                + f"static const unsigned char {v_gt_keyseed}[32] = {{{native_launcher._c_byte_array(gt_seed)}}};\n"
                + f"static const unsigned char {v_gt_keytags}[{len(gt_tags)}][{len(gt_tags[0])}] = {{\n{gt_tags_rows}\n}};\n"
                + f"static const unsigned char {v_gt_enc}[] = {{{native_launcher._c_byte_array(gt_enc)}}};\n"
                + f"static const size_t {v_gt_enc_len} = sizeof({v_gt_enc});\n\n"
                + f"static void {fn_pickkey}(unsigned char *out_key) {{\n"
                + f"    unsigned char state[32];\n"
                + f"    memcpy(state, {v_keyseed}, 32);\n"
                + f"    int used_flag[{len(shuffled)}] = {{0}};\n"
                + f"    for (int t = 0; t < {len(key_tags)}; t++) {{\n"
                + f"        int found = -1;\n"
                + f"        unsigned char digest[32];\n"
                + f"        for (int c = 0; c < {len(shuffled)}; c++) {{\n"
                + f"            if (used_flag[c]) continue;\n"
                + f"            unsigned char buf[32 + {frag_len}];\n"
                + f"            memcpy(buf, state, 32);\n"
                + f"            memcpy(buf + 32, {v_keyfrags}[c], {frag_len});\n"
                + f"            sha256(buf, 32 + {frag_len}, digest);\n"
                + f"            if (memcmp(digest, {v_keytags}[t], {len(key_tags[0])}) == 0) {{ found = c; break; }}\n"
                + f"        }}\n"
                + f"        if (found < 0) {{ memset(out_key, 0, 32); return; }}\n"
                + f"        used_flag[found] = 1;\n"
                + f"        memcpy(out_key + (t * {frag_len}), {v_keyfrags}[found], {frag_len});\n"
                + f"        memcpy(state, digest, 32);\n"
                + f"    }}\n"
                + f"}}\n\n"
                + f"static void {fn_gt_pickkey}(unsigned char *out_key) {{\n"
                + f"    unsigned char state[32];\n"
                + f"    memcpy(state, {v_gt_keyseed}, 32);\n"
                + f"    int used_flag[{len(gt_shuf)}] = {{0}};\n"
                + f"    for (int t = 0; t < {len(gt_tags)}; t++) {{\n"
                + f"        int found = -1;\n"
                + f"        unsigned char digest[32];\n"
                + f"        for (int c = 0; c < {len(gt_shuf)}; c++) {{\n"
                + f"            if (used_flag[c]) continue;\n"
                + f"            unsigned char buf[32 + {frag_len}];\n"
                + f"            memcpy(buf, state, 32);\n"
                + f"            memcpy(buf + 32, {v_gt_keyfrags}[c], {frag_len});\n"
                + f"            sha256(buf, 32 + {frag_len}, digest);\n"
                + f"            if (memcmp(digest, {v_gt_keytags}[t], {len(gt_tags[0])}) == 0) {{ found = c; break; }}\n"
                + f"        }}\n"
                + f"        if (found < 0) {{ memset(out_key, 0, 32); return; }}\n"
                + f"        used_flag[found] = 1;\n"
                + f"        memcpy(out_key + (t * {frag_len}), {v_gt_keyfrags}[found], {frag_len});\n"
                + f"        memcpy(state, digest, 32);\n"
                + f"    }}\n"
                + f"}}\n\n"
                + f"static int {fn_basename_eq}(const char *argv0) {{\n"
                + f"    if ({v_lock_name}[0] == '\\0') return 1;\n"
                + f"    const char *base = argv0;\n"
                + f"    for (const char *p = argv0; *p; p++) {{\n"
                + f"        if (*p == '/' || *p == '\\\\') base = p + 1;\n"
                + f"    }}\n"
                + f"    return strcmp(base, {v_lock_name}) == 0;\n"
                + f"}}\n\n"
                + f"static void {fn_ks}(const unsigned char *key, unsigned char *out, size_t out_len) {{\n"
                + f"    unsigned char block[32];\n"
                + f"    memcpy(block, key, 32);\n"
                + f"    size_t filled = 0;\n"
                + f"    while (filled < out_len) {{\n"
                + f"        unsigned char digest[32];\n"
                + f"        sha256(block, 32, digest);\n"
                + f"        memcpy(block, digest, 32);\n"
                + f"        size_t take = out_len - filled;\n"
                + f"        if (take > 32) take = 32;\n"
                + f"        memcpy(out + filled, digest, take);\n"
                + f"        filled += take;\n"
                + f"    }}\n"
                + f"}}\n\n"
                + f"static unsigned char *{fn_xor}(const unsigned char *data, size_t len, const unsigned char *key) {{\n"
                + f"    unsigned char *ks = malloc(len);\n"
                + f"    unsigned char *out = malloc(len);\n"
                + f"    if (!ks || !out) exit(1);\n"
                + f"    {fn_ks}(key, ks, len);\n"
                + f"    for (size_t i = 0; i < len; i++) out[i] = data[i] ^ ks[i];\n"
                + f"    free(ks);\n"
                + f"    return out;\n"
                + f"}}\n\n"
                + f"static void {fn_hex}(const unsigned char *digest, char *out_hex) {{\n"
                + f'    static const char hexchars[] = "0123456789abcdef";\n'
                + f"    for (int i = 0; i < 32; i++) {{\n"
                + f"        out_hex[i * 2] = hexchars[(digest[i] >> 4) & 0xf];\n"
                + f"        out_hex[i * 2 + 1] = hexchars[digest[i] & 0xf];\n"
                + f"    }}\n"
                + f"    out_hex[64] = '\\0';\n"
                + f"}}\n\n"
                + f"static int {fn_hash_eq}(const unsigned char *data, size_t len, const char *expected_hex) {{\n"
                + f"    unsigned char digest[32];\n"
                + f"    sha256(data, len, digest);\n"
                + f"    char hex[65];\n"
                + f"    {fn_hex}(digest, hex);\n"
                + f"    return strcmp(hex, expected_hex) == 0;\n"
                + f"}}\n\n"
                + f"static char *{fn_extract}(void) {{\n"
                + f'    const char *home = getenv("HOME");\n'
                + f'    if (!home) home = "/tmp";\n'
                + f"    static char dir[4096];\n"
                + f"    static char target[4096];\n"
                + f'    snprintf(dir, sizeof(dir), "%s/%s", home, {v_cachedir});\n'
                + f"    mkdir(dir, 0700);\n"
                + f'    snprintf(target, sizeof(target), "%s/%s", dir, {v_name});\n'
                + f'    FILE *existing = fopen(target, "rb");\n'
                + f"    if (existing) {{\n"
                + f"        fseek(existing, 0, SEEK_END);\n"
                + f"        long sz = ftell(existing);\n"
                + f"        fseek(existing, 0, SEEK_SET);\n"
                + f"        if (sz > 0) {{\n"
                + f"            unsigned char *buf = malloc((size_t)sz);\n"
                + f"            if (buf && fread(buf, 1, (size_t)sz, existing) == (size_t)sz) {{\n"
                + f"                if ({fn_hash_eq}(buf, (size_t)sz, {v_hash})) {{\n"
                + f"                    free(buf); fclose(existing); return target;\n"
                + f"                }}\n"
                + f"            }}\n"
                + f"            free(buf);\n"
                + f"        }}\n"
                + f"        fclose(existing);\n"
                + f"    }}\n"
                + f"    unsigned char {v_key}[32];\n"
                + f"    {fn_pickkey}({v_key});\n"
                + f"    unsigned char *dec = {fn_xor}({v_payload}, {v_payload_len}, {v_key});\n"
                + f'    FILE *out = fopen(target, "wb");\n'
                + f"    if (!out) {{ free(dec); exit(1); }}\n"
                + f"    fwrite(dec, 1, {v_payload_len}, out);\n"
                + f"    fclose(out);\n"
                + f"    free(dec);\n"
                + f"    chmod(target, 0700);\n"
                + f"    return target;\n"
                + f"}}\n\n"
                + f"int main(int argc, char **argv) {{\n"
                + f"    if (argc < 1 || !{fn_basename_eq}(argv[0])) return 1;\n"
                + f"    char *target = {fn_extract}();\n"
                + f"    unsigned char {v_gt_buf}_key[32];\n"
                + f"    {fn_gt_pickkey}({v_gt_buf}_key);\n"
                + f"    unsigned char *{v_gt_buf}_dec = {fn_xor}({v_gt_enc}, {v_gt_enc_len}, {v_gt_buf}_key);\n"
                + f"    char {v_gt_buf}[{len(gt_enc)} + 1];\n"
                + f"    memcpy({v_gt_buf}, {v_gt_buf}_dec, {len(gt_enc)});\n"
                + f"    {v_gt_buf}[{len(gt_enc)}] = '\\0';\n"
                + f"    free({v_gt_buf}_dec);\n"
                + f"    setenv({v_gate_env}, {v_gt_buf}, 1);\n"
                + f"    memset({v_gt_buf}, 0, sizeof({v_gt_buf}));\n"
                + f"    memset({v_gt_buf}_key, 0, sizeof({v_gt_buf}_key));\n"
                + f"    char **new_argv = malloc(sizeof(char *) * (argc + 2));\n"
                + f"    if (!new_argv) return 1;\n"
                + f'    new_argv[0] = "python3";\n'
                + f"    new_argv[1] = target;\n"
                + f"    for (int i = 1; i < argc; i++) new_argv[i + 1] = argv[i];\n"
                + f"    new_argv[argc + 1] = NULL;\n"
                + f'    execvp("python3", new_argv);\n'
                + f'    perror("execvp");\n'
                + f"    free(new_argv);\n"
                + f"    return 1;\n"
                + f"}}\n"
            )
            build_sh = (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "# Install di Termux: pkg install clang python\n"
                f"clang -Os -fvisibility=hidden -ffunction-sections -fdata-sections "
                f"-Wl,--gc-sections -w -o {stem}_launcher {stem}_launcher.c\n"
                f"strip --strip-all {stem}_launcher || true\n"
                f"echo '[OK] Built ./{stem}_launcher (gate token tertanam terenkripsi)'\n"
            )
            return _ok(
                {
                    "build_mode": build_mode,
                    "status": "SUCCESS",
                    "artifact_filename": f"{stem}_launcher.c",
                    "artifact_content": c_source,
                    "manifest_filename": f"build_{stem}_launcher.sh",
                    "manifest_content": build_sh,
                    "artifact_bytes": len(c_source.encode("utf-8")),
                    "artifact_sha256": hashlib.sha256(c_source.encode("utf-8")).hexdigest(),
                    "log": (
                        f"[OK] Native C Launcher stub (payload + gate token terenkripsi fragment-chain) berhasil dibuat ({len(c_source.encode('utf-8'))} bytes)\n"
                        f"[INFO] Toolchain clang/gcc tidak ada di sandbox APK -> sumber C + script build diekspor\n"
                        f"[INFO] Kompilasi di Termux: bash build_{stem}_launcher.sh"
                    ),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )

        return _err("run_build", f"Mode build tidak dikenal: {build_mode}")
    except Exception as exc:
        return _err(
            "run_build",
            exc,
            "Gunakan mode 'packed_loader' atau 'signed_bundle' yang berjalan 100% di CPython 3.14.10 ARM64 tanpa compiler C/Rust eksternal.",
        )
