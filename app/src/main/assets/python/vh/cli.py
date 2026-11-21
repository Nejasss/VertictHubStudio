#!/usr/bin/env python3
"""
VertictHub PyObfuscator - CLI
A Python source obfuscator with string encryption, junk-code
injection, marshal+XOR bytecode packing, anti-debug/anti-tamper
runtime checks, and one-click PyInstaller binary builds.
"""
import os
import re
import sys
import random
import string
import threading
import time
import itertools
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.obfuscator import (
    ObfuscationConfig, obfuscate_file, obfuscate_file_for_cython,
    obfuscate_file_for_embed, generate_gate_info,
)
from core import cython_build
from core import cython_guard
from core import embed_build
from core import bootstrap
from core import native_launcher
from core import rust_launcher
from core import packer
from core import leak_scan
from core.signing_autosetup import SigningKeySetupError, ensure_signing_key
from core_integrity_autosetup import CoreIntegrityError, initialize_core_integrity
import build as buildmod


def _print_constant_protection_report(config) -> None:
    """Print the source-level Constant Protection audit captured by the core."""
    report = getattr(config, "constant_protection_report", None)
    if report is None:
        return
    print("\n[Constant Protection]")
    print(f"  Literal transformed : {report.transformed_count}")
    if report.transformed_by_type:
        print("  By type             : " + ", ".join(
            f"{name}={count}" for name, count in report.transformed_by_type.items()
        ))
    if report.skipped_by_reason:
        print("  Skipped             : " + ", ".join(
            f"{name}={count}" for name, count in report.skipped_by_reason.items()
        ))
    print(f"  Gate-key masking    : {'ON' if report.gate_key_mixing else 'OFF (basic fallback)'}")
    print("  Note                : runtime values can still be recovered; not a secret vault.")


def _print_expression_obfuscation_report(config) -> None:
    """Print the condition-expression transformation counts for this build."""
    report = getattr(config, "expression_obfuscation_report", None)
    if report is None:
        return
    print("\n[Expression Obfuscation]")
    print(f"  Tests transformed   : {report.transformed_tests}")
    print(f"  De Morgan           : {report.demorgan_tests}")
    print(f"  Double negation     : {report.double_negation_tests}")
    if report.transformed_by_context:
        print("  By context          : " + ", ".join(
            f"{name}={count}" for name, count in report.transformed_by_context.items()
        ))
    print(f"  Already normalized  : {report.skipped_already_normalized}")
    print("  Scope               : truth-test contexts only; value expressions are preserved.")


def _print_import_obfuscation_report(config) -> None:
    """Print supported and skipped import rewrites for this build."""
    report = getattr(config, "import_obfuscation_report", None)
    if report is None:
        return
    print("\n[Import Obfuscation]")
    print(f"  Statements rewritten: {report.transformed_total}")
    print(f"  Aliases rewritten   : {report.transformed_aliases}")
    if report.skipped_relative_imports:
        print(f"  Relative skipped    : {report.skipped_relative_imports}")
    if report.skipped_star_imports:
        print(f"  Star imports skipped: {report.skipped_star_imports}")
    if report.skipped_dotted_aliases:
        print(f"  Dotted alias skipped: {report.skipped_dotted_aliases}")
    if report.skipped_shadowed_builtins:
        print("  Whole module skipped: source binds __import__")
    if report.parse_failed:
        print("  Warning             : source parse/compile failed; original source retained")
    print("  Scope               : supported absolute imports; unsupported forms are preserved.")

def _print_attribute_obfuscation_report(config) -> None:
    """Print the conservative instance-field obfuscation report."""
    report = getattr(config, "attribute_obfuscation_report", None)
    if report is None:
        return
    print("\n[Attribute Obfuscation]")
    print(f"  Classes transformed : {report.classes_transformed}/{report.classes_seen}")
    print(f"  Attributes renamed  : {report.attributes_transformed}")
    print(f"  Accesses rewritten  : {report.accesses_transformed}")
    print(f"  Ambiguous skipped   : {report.skipped_ambiguous_attributes}")
    print(f"  Classes skipped     : {report.skipped_classes}")
    if report.skip_reasons:
        for reason, count in sorted(report.skip_reasons.items()):
            print(f"    - {reason}: {count}")
    print("  Scope               : proven local instance fields only; dynamic/public patterns are preserved.")


def _print_function_transformation_report(config) -> None:
    """Print conservative function-body extraction results."""
    report = getattr(config, "function_transformation_report", None)
    if report is None:
        return
    print("\n[Function Transformation]")
    print(f"  Functions seen      : {report.functions_seen}")
    print(f"  Functions split     : {report.functions_split}")
    print(f"  Helpers generated   : {report.helpers_generated}")
    print(f"  Assignments moved   : {report.assignments_moved}")
    if report.skipped_by_reason:
        print("  Skipped             : " + ", ".join(
            f"{name}={count}" for name, count in sorted(report.skipped_by_reason.items())
        ))
    print("  Scope               : top-level sync functions with safe straight-line assignment prefixes.")
    print("  Note                : helper frames can change tracebacks/line introspection.")


def _print_native_worker_compat_report(config) -> None:
    """Print automatic self-worker compatibility patches for Cython embeds."""
    report = getattr(config, "native_worker_compat_report", None)
    if report is None:
        return
    print("\n[Native Worker Compatibility]")
    print(f"  Functions scanned   : {report.functions_scanned}")
    print(f"  Functions patched   : {report.functions_patched}")
    print(f"  Commands patched    : {report.commands_patched}")
    print(f"  File paths patched  : {report.path_references_patched}")
    if report.skipped_by_reason:
        print("  Skipped             : " + ", ".join(
            f"{name}={count}" for name, count in sorted(report.skipped_by_reason.items())
        ))
    print("  Scope               : resolves the outer launcher path for script, temp-extension, and Cython embed modes.")


def _print_worker_gate_forwarding_report(config) -> None:
    """Report launcher-gate forwarding to Root/Shizuku worker children."""
    report = getattr(config, "worker_gate_forwarding_report", None)
    if report is None:
        return
    print("\n[Root Worker Gate Forwarding]")
    print(f"  Functions patched   : {report.functions_patched}/{report.functions_scanned}")
    print(f"  Child callsites     : {report.callsites_patched}")
    print(f"  Gate configured     : {'yes' if report.gate_configured else 'no'}")
    if report.skipped_by_reason:
        print("  Skipped             : " + ", ".join(
            f"{name}={count}" for name, count in sorted(report.skipped_by_reason.items())
        ))
    print("  Scope               : forwards the verified per-build gate only to Touch Engine scan/worker child processes; token values are not logged.")


def _print_data_flow_report(config) -> None:
    """Print local assignment-flow reshaping results."""
    report = getattr(config, "data_flow_obfuscation_report", None)
    if report is None:
        return
    print("\n[Data Flow Obfuscation]")
    print(f"  Functions seen      : {report.functions_seen}")
    print(f"  Functions changed   : {report.functions_transformed}")
    print(f"  Temporary routes    : {report.temporary_routes}")
    print(f"  Tuple routes        : {report.tuple_routes}")
    print(f"  Skipped functions   : {report.skipped_functions}")
    if report.skipped_by_reason:
        print("  Skip reasons        : " + ", ".join(
            f"{name}={count}" for name, count in sorted(report.skipped_by_reason.items())
        ))
    print("  Scope               : simple function-local assignments; reflective/async/generator scopes are skipped.")


@contextmanager
def spinner(message: str, pct_start: int = None, pct_end: int = None):
    """
    Shows an animated "[NN%] message... <spinner char>" line on stdout
    for the duration of the `with` block, then clears it and prints a
    plain "[NN%] message... done" line. Used to wrap the long, silent
    subprocess.run() calls this CLI makes (pip install, cython
    compile, gcc link, pyinstaller build) - those give no progress
    output of their own for small-to-medium projects, so without
    this the terminal just sits with a static line for anywhere from
    a few seconds to a couple of minutes, which is indistinguishable
    from a hang to someone watching it.

    pct_start/pct_end: when both are given, the displayed percentage
    is pct_start while the block is running and jumps to pct_end the
    moment it actually finishes - e.g. spinner("Compiling", 20, 70)
    shows "[20%] Compiling... ⠋" throughout the whole compile, then
    "[70%] Compiling... done" only once compilation has genuinely
    completed. This is NOT a smoothly animated fake percentage - the
    number never climbs on its own while a step is still running,
    because neither cython, gcc, nor pip expose a real progress
    fraction worth interpolating, and a number that visibly climbs
    without real data behind it is worse than an honest "still on
    this step" indicator. What IS real here: pct_start/pct_end mark
    genuine boundaries between pipeline stages this file already
    knows the shape of (e.g. "[0/2] obfuscating" then "[2/2]
    compiling"), so the jump from pct_start to pct_end reflects an
    actual stage of work finishing, not a guess. Pass no pct_start/
    pct_end for steps outside a percent-tracked sequence (falls back
    to a plain unlabelled spinner).
    Safe to nest visually with the surrounding "[N/M] ..." step
    prints already used throughout this file; call it AFTER printing
    the step line, not instead of it.
    """
    show_pct = pct_start is not None and pct_end is not None
    prefix = f"[{pct_start}%] " if show_pct else ""
    done_prefix = f"[{pct_end}%] " if show_pct else ""

    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    stop = threading.Event()

    def _spin():
        for frame in itertools.cycle(frames):
            if stop.is_set():
                break
            sys.stdout.write(f"\r{prefix}{message}... {frame} ")
            sys.stdout.flush()
            stop.wait(0.08)

    # Spinner glyphs need a UTF-8 capable stream - if stdout can't
    # encode them (some restricted terminals), fall back to a plain
    # static line instead of crashing the whole CLI over cosmetics.
    try:
        message.encode(sys.stdout.encoding or "utf-8")
        supports_spinner = True
    except (UnicodeEncodeError, LookupError):
        supports_spinner = False

    if not supports_spinner:
        print(f"{prefix}{message}...")
        yield
        print(f"{done_prefix}{message}... done")
        return

    t = threading.Thread(target=_spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join(timeout=1)
        sys.stdout.write(f"\r{done_prefix}{message}... done" + " " * 10 + "\n")
        sys.stdout.flush()


BANNER = r"""
 __     __        _   _      _   _   _       _
 \ \   / /__ _ __| |_(_) ___| |_| | | |_   _| |__
  \ \ / / _ \ '__| __| |/ __| __| |_| | | | | '_ \
   \ V /  __/ |  | |_| | (__| |_|  _  | |_| | |_) |
    \_/ \___|_|   \__|_|\___|\__|_| |_|\__,_|_.__/
        PyObfuscator - protect your python code
"""

DEFAULTS = {
    "encrypt_strings": True,
    "control_flow_obfuscation": False,  # conservative state-machine flattening; opt-in
    "constant_protection": False,  # immutable literal reconstruction; opt-in
    "expression_obfuscation": False,  # truth-test expression reshaping; opt-in
    "import_obfuscation": False,  # dynamic rewrite for supported absolute imports; opt-in
    "attribute_obfuscation": False,  # conservative local instance-field renaming; opt-in
    "function_transformation": False,  # safe top-level function-prefix extraction; opt-in
    "data_flow_obfuscation": False,  # function-local assignment routing; opt-in
    "min_string_len": 1,
    "junk_intensity": 6,
    "anti_debug": True,
    "anti_vpn": False,
    "rename_identifiers": True,
    "inject_decoy_methods": True,  # splice fake methods into real classes, using
                                    # the same naming format as renamed real methods
    "periodic_recheck": True,  # re-check TracerPid/debugger-API/process-name/Frida
                                # every few seconds in the background, not just at startup
    "enable_version_fallback": False,  # .py launcher only: auto-download+re-exec under a
                                        # matching portable Python if versions mismatch
    "enable_antisandbox": False,  # refuse to run if multiple sandbox/analysis-VM signals
                                   # agree at once - OFF by default, real false-positive
                                   # risk on modest-but-legitimate hardware, see antisandbox.py
    "antisandbox_threshold": 6,
    "ensure_libpython_fallback": False,  # Opt-in saja: fallback ini menyisipkan logic
                                          # download runtime ke payload launcher Cython.
                                          # Aktifkan hanya bila target tidak punya libpython
                                          # yang sesuai dan Anda menerima dependency jaringan.
    "lock_filename": False,
    "onefile": True,
    "console": True,
    "wrap_single_file": True,
    "wrap_mode": "py",  # "py" (bootstrap), "native" (C ELF), atau "rust" (Rust ELF eksperimen)
    "cython_guard": True,  # wrap Cython-mode binaries with a periodic self-integrity guard process
    "cython_guard_memory_check": False,  # guard ALSO periodically reads the running child's
                                           # LIVE memory (/proc/<pid>/mem) and compares its
                                           # executable segment against the file on disk, catching
                                           # in-memory patching (e.g. a debugger NOPing out a
                                           # check) that the disk-hash check alone can't see. OFF
                                           # by default and only takes effect when cython_guard is
                                           # also on: unverified on Android/Termux (needs
                                           # /proc/<pid>/mem read access to another process, which
                                           # SELinux/app-sandboxing or yama.ptrace_scope could
                                           # restrict differently than on desktop Linux, similar in
                                           # spirit to the cython_anti_ptrace lesson above) - but
                                           # designed to fail SAFE if that access isn't available
                                           # (falls back to disk-hash-only silently, never treats
                                           # "can't check memory" as itself suspicious), so a
                                           # denial should just mean no extra protection, not a
                                           # broken program - test the actual output binary before
                                           # relying on this in production.
    "cython_anti_ptrace": False,  # inject ptrace(PTRACE_TRACEME) self-trace ONLY (menu 3 only).
                                   # OFF by default: confirmed to break stdin/input() on at
                                   # least one real Android/Termux device (input() raises
                                   # EOFError immediately, before the user can type anything -
                                   # PTRACE_TRACEME's interaction with Android's process/zygote
                                   # sandboxing appears to disrupt the terminal's stdin fd in a
                                   # way that doesn't happen on desktop Linux). Safe on desktop
                                   # Linux in testing so far, but the failure mode on Android is
                                   # severe enough (breaks ALL interactive input, not just a
                                   # debugger-detection edge case) that this needs to be an
                                   # explicit opt-in until it's verified safe across more devices.
    "cython_disable_coredump": True,  # inject setrlimit(RLIMIT_CORE, 0) ONLY (menu 3 only) -
                                        # blocks crash-triggered core-dump memory snapshots.
                                        # Split off from cython_anti_ptrace specifically because
                                        # it's a plain rlimit call with no ptrace/stdin
                                        # interaction, so it doesn't share that flag's
                                        # Android/Termux input-breaking failure mode - ON by
                                        # default unless a future report shows otherwise.
    "require_launcher_gate": True,  # binary refuses to run unless started via its own launcher
                                     # (blocks "found the extracted binary's path, ran it directly,
                                     # skipped the launcher and every check that only lives there")
                                     # only has any effect when wrap_single_file is also on - see
                                     # _maybe_wrap_single_file's warning if it's on with wrap off.
    "self_integrity_check": True,  # native launcher mode only: self-hashes its own compiled
                                    # bytes at build time, refuses to run if the file on disk
                                    # was patched (NOP'd/edited) since - detects STATIC tampering
    "bytecode_integrity_check": False,  # detects RUNTIME tampering (a debugger/Frida patching
                                         # a function's bytecode while the process is running) -
                                         # off by default, can false-positive on some legitimate
                                         # dynamic patterns (see antidebug.py docs)
    "cjk_identifiers": False,  # generate every randomized identifier (renamed vars/funcs/
                               # classes, string-decrypt header names) as random CJK (Han)
                               # characters instead of plain ASCII "_abc123"-style names -
                               # see core/unicode_names.py. OFF by default: newer, less
                               # battle-tested naming mode, and unverified against a real
                               # Cython toolchain (see that module's docstring). Has no
                               # effect on the gate env var name, which always stays ASCII.
    "ssl_pin_sha256": [],  # list of SHA-256 SPKI (public-key) fingerprints for HTTPS
                            # certificate pinning - see core/ssl_pinning.py. Covers `requests`,
                            # `urllib3`, stdlib `http.client`/`urllib.request`, AND (via
                            # SSLContext.wrap_socket/wrap_bio) aiohttp, httpx, and raw
                            # socket+ssl. Empty = feature off (no source injected, zero
                            # overhead). IMPORTANT: this pins EVERY HTTPS connection in the
                            # whole process against the SAME fixed pin list, globally - it
                            # has no per-hostname scoping. If the program talks to more than
                            # one distinct HTTPS host (your own API AND a third-party SDK's
                            # API, e.g. python-telegram-bot calling api.telegram.org), only
                            # pinning YOUR OWN domain's fingerprint here will cause every
                            # OTHER host's connection to fail with "certificate pin
                            # mismatch" - confirmed happening in practice against a real
                            # build. Either add every distinct host's fingerprint this
                            # program actually connects to, or leave this off entirely for
                            # multi-host programs. OFF by default because there's no
                            # sensible default pin to ship - the user must generate real
                            # fingerprint(s) for their own server first (menu option guides
                            # through this), and shipping a build with pinning on but a wrong/
                            # placeholder pin breaks 100% of that program's HTTPS traffic.
    "hook_detection": False,  # checks requests.Session.send / urllib3.connection.
                               # HTTPSConnection.connect / http.client.HTTPSConnection.connect /
                               # ssl.SSLContext.wrap_socket / ssl.SSLContext.wrap_bio (the last
                               # two also cover aiohttp/httpx - see core/ssl_pinning.py's own
                               # note on those) for signs of external monkey-patching (e.g. a
                               # sitecustomize.py-injected hook reading request/response bodies
                               # before pinning ever matters) - see core/hook_detection.py.
                               # Does NOT cover sys.addaudithook-based monitoring, or
                               # PYTHONPATH injection that cleans up its own traces before the
                               # target's code runs - see that module's own docstring for the
                               # full, honest list of what's out of reach. OFF by default:
                               # newer, narrower feature - test the actual output before
                               # relying on it.
    "cleanup_after_run": False,  # bootstrap.py .py-launcher wrap only (menu 1/2's
                                  # wrap_single_file step): delete the extracted main binary
                                  # and every extra file (e.g. a Cython build's __cyinner
                                  # companion) from the launcher's cache dir under ~,
                                  # immediately after the wrapped program exits - success or
                                  # failure, the real exit code still propagates either way.
                                  # OFF by default: the cache dir persists the extracted
                                  # binary across runs on purpose, so a later run of the same
                                  # launcher skips re-extracting it (faster, especially for a
                                  # large binary on slow storage like Termux/Android). Turning
                                  # this ON trades that speed for not leaving a plaintext,
                                  # fully-decrypted copy of the binary sitting on disk
                                  # indefinitely after the program closes - the one place in
                                  # this whole project's protections (AES-GCM, the fragment
                                  # chain, .so symbol stripping, the gate token, SSL pinning)
                                  # that none of them cover, since all of those only apply
                                  # while the binary is still encrypted inside the .py or
                                  # during the brief window it's actually running.
}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input("\n[Enter untuk lanjut] ")


def _maybe_wrap_single_file(binary_path: str, outdir: str, name: str, gate_info: dict = None,
                             ensure_libpython_version: tuple = None,
                             native_decryptor: bool = False):
    """
    Returns the path of whatever file ends up being the actual final
    distributable artifact: the wrapped launcher's path if wrapping
    succeeded, or binary_path unchanged if wrapping is off/failed.
    Used by the post-build leak scan to know which file to check -
    scanning the raw binary when it actually got replaced by a
    launcher wrapper would check the wrong file.

    ensure_libpython_version: pass (major, minor) when binary_path is
    a Cython/embed build (dynamically links libpythonX.Y.so) so the
    native launcher (only meaningful in "native" wrap mode - the .py
    wrap mode doesn't compile anything, so it has no equivalent check
    to add) can auto-detect+fetch a matching libpython on machines
    that don't already have one. See native_launcher.build_native_launcher's
    docstring for the full mechanism. None (default) for PyInstaller
    binaries, which never need this.
    """
    if not DEFAULTS["wrap_single_file"] or not binary_path:
        if gate_info:
            print("[WARNING] require_launcher_gate aktif tapi 'Bungkus jadi 1 file' OFF -")
            print("          binary mentah ini TIDAK BISA dijalankan sendirian (gate check")
            print("          akan selalu gagal tanpa launcher). Aktifkan opsi 7 di Settings,")
            print("          atau matikan lock/gate kalau memang mau distribusi binary mentah.")
        return binary_path

    # cython_guard leaves a companion "__cyinner" child binary next
    # to the guard - if present, it MUST be carried along and
    # extracted to the same directory as the main binary, or the
    # guard's execv() call fails to find it once relocated (this is
    # exactly what caused the "execv: Permission denied"/ENOENT bug
    # report: the guard got embedded and extracted, but the child
    # never did, so there was nothing for it to exec).
    companion_path = binary_path + "__cyinner"
    has_companion = os.path.isfile(companion_path)
    companion_bytes = None
    if has_companion:
        with open(companion_path, "rb") as f:
            companion_bytes = f.read()

    mode = DEFAULTS.get("wrap_mode", "py")
    if mode == "rust":
        launcher_path = os.path.join(outdir, name)
        tmp_binary_path = binary_path + "__inner"
        try:
            os.replace(binary_path, tmp_binary_path)
            extra_files = {os.path.basename(companion_path): companion_bytes} if has_companion else None
            rust_launcher.build_rust_launcher(
                tmp_binary_path, launcher_path, embedded_name=name,
                lock_filename=DEFAULTS["lock_filename"], expected_filename=name,
                extra_files=extra_files,
                gate_env_name=(gate_info or {}).get("env_name"),
                gate_token=(gate_info or {}).get("token"),
            )
            os.remove(tmp_binary_path)
            if has_companion:
                os.remove(companion_path)
            print(f"[OK] Dibungkus jadi 1 launcher Rust (ELF): {launcher_path}")
            print("     Integrity: container AEAD + hash artefak + filename-lock bila aktif.")
            print("     Catatan: build Rust harus dilakukan pada ABI/arsitektur target; Cython child tetap membutuhkan libpython target.")
            print(f"     Jalanin cukup dengan: {launcher_path}")
            return launcher_path
        except rust_launcher.RustLauncherBuildError as e:
            if os.path.exists(tmp_binary_path) and not os.path.exists(binary_path):
                os.replace(tmp_binary_path, binary_path)
            print(f"[WARNING] Gagal bungkus Rust ({e}), binary mentah tetap ada di: {binary_path}")
            return binary_path
        except Exception as e:
            if os.path.exists(tmp_binary_path) and not os.path.exists(binary_path):
                os.replace(tmp_binary_path, binary_path)
            print(f"[WARNING] Gagal bungkus Rust ({e}), binary mentah tetap ada di: {binary_path}")
            return binary_path

    if mode == "native":
        launcher_path = os.path.join(outdir, name)
        tmp_binary_path = binary_path + "__inner"
        try:
            os.replace(binary_path, tmp_binary_path)
            extra_files = None
            if has_companion:
                extra_files = {os.path.basename(companion_path): companion_bytes}
            native_launcher.build_native_launcher(
                tmp_binary_path, launcher_path, embedded_name=name,
                lock_filename=DEFAULTS["lock_filename"], expected_filename=name,
                extra_files=extra_files,
                gate_env_name=(gate_info or {}).get("env_name"),
                gate_token=(gate_info or {}).get("token"),
                ensure_libpython_version=ensure_libpython_version,
                self_integrity_check=DEFAULTS.get("self_integrity_check", True),
            )
            os.remove(tmp_binary_path)
            if has_companion:
                os.remove(companion_path)
            print(f"[OK] Dibungkus jadi 1 launcher native (ELF): {launcher_path}")
            print("     Integrity: self-check native fail-closed aktif.")
            print("     Signing manifest Ed25519 tersedia pada wrapper .py; mode native memakai self-integrity ELF.")
            print(f"     Jalanin cukup dengan: {launcher_path}")
            print("     (auto extract + auto chmod +x + auto run sendiri, TANPA python source apapun)")
            return launcher_path
        except native_launcher.ToolchainError as e:
            os.replace(tmp_binary_path, binary_path)
            print(f"[WARNING] Gagal bungkus native ({e}), binary mentah tetap ada di: {binary_path}")
            return binary_path
        except Exception as e:
            if os.path.exists(tmp_binary_path) and not os.path.exists(binary_path):
                os.replace(tmp_binary_path, binary_path)
            print(f"[WARNING] Gagal bungkus native ({e}), binary mentah tetap ada di: {binary_path}")
            return binary_path

    launcher_path = os.path.join(outdir, f"{name}.py")
    try:
        manifest_private_key_path, signing_key_status = ensure_signing_key()
    except SigningKeySetupError as exc:
        print(f"[ERROR] Signed launcher tidak dibuat: {exc}")
        return binary_path
    try:
        extra_files = None
        if has_companion:
            extra_files = {os.path.basename(companion_path): companion_bytes}
        bootstrap.wrap_binary_as_py(
            binary_path, launcher_path, embedded_name=name,
            lock_filename=DEFAULTS["lock_filename"], extra_files=extra_files,
            gate_env_name=(gate_info or {}).get("env_name"),
            gate_token=(gate_info or {}).get("token"),
            ensure_libpython_version=ensure_libpython_version,
            manifest_private_key_path=manifest_private_key_path,
            native_decryptor=native_decryptor,
            cleanup_after_run=DEFAULTS["cleanup_after_run"],
        )
        os.remove(binary_path)
        if has_companion:
            os.remove(companion_path)
        print(f"[OK] Dibungkus jadi 1 file signed: {launcher_path}")
        if native_decryptor:
            print("     Decryptor native opaque: aktif (raw ELF tidak ditulis langsung pada source Python).")
        print(f"     Signing key: {signing_key_status} ({manifest_private_key_path})")
        print(f"     Jalanin cukup dengan: python {launcher_path}")
        print("     (auto extract + auto chmod +x + auto run sendiri, ga perlu langkah manual)")
        return launcher_path
    except Exception as e:
        print(f"[WARNING] Gagal bungkus jadi 1 file ({e}), binary mentah tetap ada di: {binary_path}")
        return binary_path


def _sanitize_module_name(s: str) -> str:
    """
    Cython/Python module names must be valid identifiers - no hyphens,
    spaces, or other symbols. This sanitizes a user-given name so it's
    safe to use as the .pyx filename (which Cython uses as the module
    name). The user-facing binary output name is left untouched -
    only the intermediate .pyx file needs this.
    """
    out = re.sub(r"[^0-9a-zA-Z_]", "_", s)
    if not out or out[0].isdigit():
        out = "_" + out
    return out


def _random_module_name(n: int = 12) -> str:
    """
    Cython --embed bakes the .pyx module name AND its filename into
    the compiled binary as plain C string literals (used for
    __file__, the module docstring, and traceback machinery) - these
    end up sitting readable in the binary's .rodata section even
    after `strip`, since they're live data the program uses, not
    debug symbols. A predictable name like "vh_<binary>_src" is
    exactly the kind of fixed, tool-identifying string a `strings`
    scan or static signature would key on. Generating a random
    identifier per build means every output binary has a different,
    meaningless module name with nothing to fingerprint across runs.
    """
    first = random.choice(string.ascii_lowercase)
    rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=n - 1))
    return first + rest


def menu_obfuscate_only():
    clear()
    print(BANNER)
    src = input("Path file .py yang mau di-obfuscate: ").strip().strip('"')
    if not os.path.isfile(src):
        print("File tidak ditemukan.")
        return pause()
    out = input("Output path (default: <nama>_obf.py): ").strip()
    if not out:
        base = os.path.splitext(os.path.basename(src))[0]
        out = os.path.join(os.path.dirname(src) or ".", f"{base}_obf.py")

    # require_launcher_gate is now MANDATORY for ALL .py-launcher-
    # producing menus (this menu, and menu 2/3 below whenever they
    # invoke obfuscate_file/packer.pack for their intermediate .py
    # loader) - see obfuscate_source's/packer.pack()'s docstrings for
    # why: without it, the AES payload key is fully recoverable by
    # static analysis alone (confirmed happening in practice against
    # a real build). DEFAULTS["require_launcher_gate"] can still be
    # toggled OFF in Settings, but doing so no longer has any effect
    # on whether this menu actually enforces it - it just changes
    # whether OTHER protections (native-launcher self-hash, etc) also
    # get the token wired in for free.
    use_gate = True
    gate_info = generate_gate_info()

    cfg = ObfuscationConfig(
        encrypt_strings=DEFAULTS["encrypt_strings"],
        min_string_len=DEFAULTS["min_string_len"],
        junk_intensity=DEFAULTS["junk_intensity"],
        anti_debug=DEFAULTS["anti_debug"],
        anti_vpn=DEFAULTS["anti_vpn"],
        rename_identifiers=DEFAULTS["rename_identifiers"],
        inject_decoy_methods=DEFAULTS["inject_decoy_methods"],
        periodic_recheck=DEFAULTS["periodic_recheck"],
        lock_filename=DEFAULTS["lock_filename"],
        enable_version_fallback=DEFAULTS["enable_version_fallback"],
        enable_antisandbox=DEFAULTS["enable_antisandbox"],
        bytecode_integrity_check=DEFAULTS["bytecode_integrity_check"],
        antisandbox_threshold=DEFAULTS["antisandbox_threshold"],
        cjk_identifiers=DEFAULTS["cjk_identifiers"],
        ssl_pin_sha256=DEFAULTS["ssl_pin_sha256"],
        hook_detection=DEFAULTS["hook_detection"],
        control_flow_obfuscation=DEFAULTS["control_flow_obfuscation"],
        constant_protection=DEFAULTS["constant_protection"],
        expression_obfuscation=DEFAULTS["expression_obfuscation"],
        import_obfuscation=DEFAULTS["import_obfuscation"],
        attribute_obfuscation=DEFAULTS["attribute_obfuscation"],
        function_transformation=DEFAULTS["function_transformation"],
        data_flow_obfuscation=DEFAULTS["data_flow_obfuscation"],
        require_launcher_gate=use_gate,
    )
    try:
        with spinner("Obfuscating source", 0, 100):
            out_path, used_gate = obfuscate_file(src, out, cfg, gate_info=gate_info)
        print(f"\n[OK] Obfuscated source tersimpan di: {out_path}")
        _print_constant_protection_report(cfg)
        _print_expression_obfuscation_report(cfg)
        _print_import_obfuscation_report(cfg)
        _print_attribute_obfuscation_report(cfg)
        _print_function_transformation_report(cfg)
        _print_data_flow_report(cfg)
        _print_native_worker_compat_report(cfg)
        _print_worker_gate_forwarding_report(cfg)
        if used_gate:
            print()
            print("[PENTING] Menu ini gak punya launcher otomatis - kalau mau jalanin file ini,")
            print(f"          kamu HARUS set environment variable ini dulu setiap kali run:")
            print(f"          export {used_gate['env_name']}={used_gate['token']}")
            print(f"          python {out_path}")
            print("          Tanpa itu, isi payload/string di dalam file gak akan bisa di-decrypt")
            print("          sama sekali (gate ini sekarang WAJIB, gak bisa dimatiin dari Settings).")
            print("          Kalau mau otomatis (gak perlu set manual tiap run), pakai menu 2/3")
            print("          yang punya launcher wrapper.")
    except Exception as e:
        print(f"\n[GAGAL] {e}")
    pause()


def menu_full_pipeline():
    clear()
    print(BANNER)
    src = input("Path file .py yang mau diproteksi: ").strip().strip('"')
    if not os.path.isfile(src):
        print("File tidak ditemukan.")
        return pause()
    name = input("Nama binary output (tanpa ekstensi): ").strip()
    if not name:
        name = os.path.splitext(os.path.basename(src))[0]
    outdir = input("Folder output (default: ./dist_protected): ").strip()
    if not outdir:
        outdir = "./dist_protected"

    # require_launcher_gate is now MANDATORY here too - packer.pack()
    # (called by obfuscate_file below to build the intermediate .py
    # loader that PyInstaller/Cython then compiles) raises if it's
    # missing, since without it the AES payload key inside that
    # intermediate loader is fully recoverable by static analysis
    # alone (confirmed happening in practice). This is true regardless
    # of wrap_single_file - the compiled binary itself may get further
    # protection from a native launcher wrapper, but the SOURCE fed
    # into PyInstaller/Cython needs this protection independently.
    use_gate = True
    gate_info = generate_gate_info()

    cfg = ObfuscationConfig(
        encrypt_strings=DEFAULTS["encrypt_strings"],
        min_string_len=DEFAULTS["min_string_len"],
        junk_intensity=DEFAULTS["junk_intensity"],
        anti_debug=DEFAULTS["anti_debug"],
        anti_vpn=DEFAULTS["anti_vpn"],
        rename_identifiers=DEFAULTS["rename_identifiers"],
        inject_decoy_methods=DEFAULTS["inject_decoy_methods"],
        periodic_recheck=DEFAULTS["periodic_recheck"],
        lock_filename=DEFAULTS["lock_filename"],
        require_launcher_gate=use_gate,
        enable_antisandbox=DEFAULTS["enable_antisandbox"],
        bytecode_integrity_check=DEFAULTS["bytecode_integrity_check"],
        antisandbox_threshold=DEFAULTS["antisandbox_threshold"],
        cjk_identifiers=DEFAULTS["cjk_identifiers"],
        ssl_pin_sha256=DEFAULTS["ssl_pin_sha256"],
        hook_detection=DEFAULTS["hook_detection"],
        control_flow_obfuscation=DEFAULTS["control_flow_obfuscation"],
        constant_protection=DEFAULTS["constant_protection"],
        expression_obfuscation=DEFAULTS["expression_obfuscation"],
        import_obfuscation=DEFAULTS["import_obfuscation"],
        attribute_obfuscation=DEFAULTS["attribute_obfuscation"],
        function_transformation=DEFAULTS["function_transformation"],
        data_flow_obfuscation=DEFAULTS["data_flow_obfuscation"],
    )

    tmp_loader = os.path.join(outdir, f"_{name}_loader.py")
    os.makedirs(outdir, exist_ok=True)
    print("\n[1/2] Obfuscating source...")
    try:
        with open(src, "r", encoding="utf-8") as f:
            _src_text = f.read()
        hidden_imports = packer.extract_imported_modules(_src_text)
        vocabulary = leak_scan.extract_sensitive_vocabulary(_src_text)
        with spinner("Obfuscating source", 0, 30):
            _, gate_info = obfuscate_file(src, tmp_loader, cfg, gate_info=gate_info)
    except Exception as e:
        print(f"[GAGAL] Obfuscation error: {e}")
        return pause()
    print("[OK] Source berhasil di-obfuscate.")
    _print_constant_protection_report(cfg)
    _print_expression_obfuscation_report(cfg)
    _print_import_obfuscation_report(cfg)
    _print_attribute_obfuscation_report(cfg)
    _print_function_transformation_report(cfg)
    _print_data_flow_report(cfg)
    _print_native_worker_compat_report(cfg)
    _print_worker_gate_forwarding_report(cfg)

    print("\n[2/2] Building binary via PyInstaller (bisa makan waktu)...")
    try:
        with spinner("Menjalankan PyInstaller", 30, 100):
            final_path = buildmod.build_binary(
                tmp_loader, outdir, name,
                onefile=DEFAULTS["onefile"], console=DEFAULTS["console"],
                hidden_imports=hidden_imports,
            )
        os.remove(tmp_loader)
        if final_path:
            print(f"\n[OK] Binary jadi: {final_path}")
            final_artifact = _maybe_wrap_single_file(final_path, outdir, name, gate_info=gate_info)
            print()
            scan_result = leak_scan.scan_binary_for_leaks(final_artifact, vocabulary)
            print(leak_scan.format_report(scan_result, os.path.basename(final_artifact)))
        else:
            print("\n[WARNING] Build selesai tapi binary tidak ketemu, cek folder output manual.")
    except Exception as e:
        print(f"\n[GAGAL] Build error: {e}")
    pause()


def menu_cython_pipeline():
    clear()
    print(BANNER)
    print("=== Mode Cython (native compile, lebih kuat) ===")
    print("Butuh: Cython (auto-install via pip kalau ada internet) + gcc/clang")
    print("       + python3-config (paket python3-dev).\n")
    src = input("Path file .py yang mau diproteksi: ").strip().strip('"')
    if not os.path.isfile(src):
        print("File tidak ditemukan.")
        return pause()
    name = input("Nama binary output (tanpa ekstensi): ").strip()
    if not name:
        name = os.path.splitext(os.path.basename(src))[0]
    outdir = input("Folder output (default: ./dist_protected): ").strip()
    if not outdir:
        outdir = "./dist_protected"
    os.makedirs(outdir, exist_ok=True)

    # require_launcher_gate is mandatory here too - see menu 2's
    # comment above for the full reasoning (obfuscate_file below
    # builds an intermediate .py loader Cython compiles from, and
    # packer.pack() raises without a real gate token).
    use_gate = True
    gate_info = generate_gate_info()

    cfg = ObfuscationConfig(
        encrypt_strings=DEFAULTS["encrypt_strings"],
        min_string_len=DEFAULTS["min_string_len"],
        junk_intensity=DEFAULTS["junk_intensity"],
        anti_debug=DEFAULTS["anti_debug"],
        anti_vpn=DEFAULTS["anti_vpn"],
        rename_identifiers=DEFAULTS["rename_identifiers"],
        inject_decoy_methods=DEFAULTS["inject_decoy_methods"],
        periodic_recheck=DEFAULTS["periodic_recheck"],
        lock_filename=DEFAULTS["lock_filename"],
        require_launcher_gate=use_gate,
        enable_antisandbox=DEFAULTS["enable_antisandbox"],
        bytecode_integrity_check=DEFAULTS["bytecode_integrity_check"],
        antisandbox_threshold=DEFAULTS["antisandbox_threshold"],
        cjk_identifiers=DEFAULTS["cjk_identifiers"],
        ssl_pin_sha256=DEFAULTS["ssl_pin_sha256"],
        hook_detection=DEFAULTS["hook_detection"],
        control_flow_obfuscation=DEFAULTS["control_flow_obfuscation"],
        constant_protection=DEFAULTS["constant_protection"],
        expression_obfuscation=DEFAULTS["expression_obfuscation"],
        import_obfuscation=DEFAULTS["import_obfuscation"],
        attribute_obfuscation=DEFAULTS["attribute_obfuscation"],
        function_transformation=DEFAULTS["function_transformation"],
        data_flow_obfuscation=DEFAULTS["data_flow_obfuscation"],
    )

    pyx_module_name = _random_module_name()
    pyx_path = os.path.join(outdir, f"{pyx_module_name}.pyx")
    print("\n[1/2] Obfuscating source (string enc + junk + anti-debug)...")
    try:
        with open(src, "r", encoding="utf-8") as f:
            _src_text = f.read()
        vocabulary = leak_scan.extract_sensitive_vocabulary(_src_text)
        with spinner("Obfuscating source", 0, 20):
            _, gate_info = obfuscate_file_for_cython(src, pyx_path, cfg, gate_info=gate_info)
    except Exception as e:
        print(f"[GAGAL] {e}")
        return pause()
    print("[OK] .pyx siap.")
    _print_constant_protection_report(cfg)
    _print_expression_obfuscation_report(cfg)
    _print_import_obfuscation_report(cfg)
    _print_attribute_obfuscation_report(cfg)
    _print_function_transformation_report(cfg)
    _print_data_flow_report(cfg)
    _print_native_worker_compat_report(cfg)
    _print_worker_gate_forwarding_report(cfg)

    bin_path = os.path.join(outdir, name)
    print("\n[2/2] Compiling ke native binary via Cython + gcc (bisa makan waktu)...")
    guard_enabled = DEFAULTS.get("cython_guard", True)
    compile_pct_end = 80 if guard_enabled else 100
    try:
        with spinner("Compiling via Cython + gcc", 20, compile_pct_end):
            cython_build.compile_pyx_to_binary(
                pyx_path, bin_path, auto_install=True,
                inject_anti_ptrace=DEFAULTS.get("cython_anti_ptrace", False),
                inject_disable_coredump=DEFAULTS.get("cython_disable_coredump", True),
            )
        os.remove(pyx_path)
        print(f"\n[OK] Binary native jadi: {bin_path}")

        # Scan the actual Cython payload, before it is wrapped by the
        # optional integrity guard / single-file loader.  Scanning the
        # final wrapper instead also scans generated launcher helpers
        # (e.g. its own ``_state`` / ``_start`` variables), producing
        # false positives unrelated to the obfuscated application.
        scan_result = leak_scan.scan_binary_for_leaks(bin_path, vocabulary)
        print(leak_scan.format_report(scan_result, os.path.basename(bin_path)))

        if guard_enabled:
            print("\n[3/3] Membungkus dengan integrity guard (periodic self-check)...")
            child_path = bin_path + "__cyinner"
            try:
                os.replace(bin_path, child_path)
                with spinner("Membangun guard wrapper", 80, 100):
                    cython_guard.build_guard(
                        child_path, bin_path,
                        enable_memory_check=DEFAULTS.get("cython_guard_memory_check", False),
                    )
                print("[OK] Guard aktif - binary di-check ulang tiap beberapa detik selama jalan.")
            except cython_guard.ToolchainError as e:
                os.replace(child_path, bin_path)
                print(f"[WARNING] Guard gagal dipasang ({e}), binary tetap ada tanpa guard.")
            except Exception as e:
                if os.path.exists(child_path) and not os.path.exists(bin_path):
                    os.replace(child_path, bin_path)
                print(f"[WARNING] Guard gagal dipasang ({e}), binary tetap ada tanpa guard.")

        _lp_version = None
        if DEFAULTS.get("ensure_libpython_fallback", True):
            _lp_version = (sys.version_info.major, sys.version_info.minor)
        final_artifact = _maybe_wrap_single_file(
            bin_path, outdir, name, gate_info=gate_info,
            ensure_libpython_version=_lp_version,
            native_decryptor=True,
        )
        print()
        print(f"[OK] Final wrapper: {final_artifact}")
    except cython_build.ToolchainError as e:
        print(f"\n[GAGAL] Toolchain belum lengkap: {e}")
        print(f"     (.pyx hasil obfuscate masih ada di: {pyx_path}, bisa lu compile manual)")
    except Exception as e:
        print(f"\n[GAGAL] {e}")
    pause()


def menu_embed_pipeline():
    clear()
    print(BANNER)
    print("=== Mode Embed (native compile TANPA Cython) ===")
    print("Butuh: gcc/clang + python3-config (paket python3-dev). TIDAK butuh Cython.")
    print("Catatan: proteksi lebih ringan dari mode Cython (menu 3) - source di-compile")
    print("jadi bytecode Python biasa yang dienkripsi & dibungkus ELF, bukan ditranspile")
    print("jadi C. Cocok kalau install Cython gak memungkinkan di device ini.\n")
    src = input("Path file .py yang mau diproteksi: ").strip().strip('"')
    if not os.path.isfile(src):
        print("File tidak ditemukan.")
        return pause()
    name = input("Nama binary output (tanpa ekstensi): ").strip()
    if not name:
        name = os.path.splitext(os.path.basename(src))[0]
    outdir = input("Folder output (default: ./dist_protected): ").strip()
    if not outdir:
        outdir = "./dist_protected"
    os.makedirs(outdir, exist_ok=True)

    # NOTE: require_launcher_gate is intentionally NOT offered here.
    # This mode's output (embed_build.compile_source_to_binary) is
    # already one standalone ELF with no separate launcher process -
    # there is nothing that would ever set the gate env var before
    # running it, so turning the gate on here would just make this
    # binary permanently refuse to start for everyone, including the
    # legitimate user. The gate only makes sense for modes 2/3 where
    # a launcher (bootstrap.py .py or native_launcher.py ELF) is the
    # thing that actually starts the protected binary.
    cfg = ObfuscationConfig(
        encrypt_strings=DEFAULTS["encrypt_strings"],
        min_string_len=DEFAULTS["min_string_len"],
        junk_intensity=DEFAULTS["junk_intensity"],
        anti_debug=DEFAULTS["anti_debug"],
        anti_vpn=DEFAULTS["anti_vpn"],
        strict_network_check=DEFAULTS.get("strict_network_check", False),
        rename_identifiers=DEFAULTS["rename_identifiers"],
        inject_decoy_methods=DEFAULTS["inject_decoy_methods"],
        periodic_recheck=DEFAULTS["periodic_recheck"],
        lock_filename=DEFAULTS["lock_filename"],
        require_launcher_gate=False,
        enable_antisandbox=DEFAULTS["enable_antisandbox"],
        bytecode_integrity_check=DEFAULTS["bytecode_integrity_check"],
        antisandbox_threshold=DEFAULTS["antisandbox_threshold"],
        cjk_identifiers=DEFAULTS["cjk_identifiers"],
        ssl_pin_sha256=DEFAULTS["ssl_pin_sha256"],
        hook_detection=DEFAULTS["hook_detection"],
        control_flow_obfuscation=DEFAULTS["control_flow_obfuscation"],
        constant_protection=DEFAULTS["constant_protection"],
        expression_obfuscation=DEFAULTS["expression_obfuscation"],
        import_obfuscation=DEFAULTS["import_obfuscation"],
        attribute_obfuscation=DEFAULTS["attribute_obfuscation"],
        function_transformation=DEFAULTS["function_transformation"],
        data_flow_obfuscation=DEFAULTS["data_flow_obfuscation"],
    )

    bin_path = os.path.join(outdir, name)
    print("\n[1/2] Obfuscating source (string enc + junk + anti-debug)...")
    try:
        with open(src, "r", encoding="utf-8") as f:
            _src_text = f.read()
        vocabulary = leak_scan.extract_sensitive_vocabulary(_src_text)
        with spinner("Obfuscating source", 0, 30):
            obf_source, _ = obfuscate_file_for_embed(src, cfg)
    except Exception as e:
        print(f"[GAGAL] {e}")
        return pause()
    print("[OK] Source siap.")
    _print_constant_protection_report(cfg)
    _print_expression_obfuscation_report(cfg)
    _print_import_obfuscation_report(cfg)
    _print_attribute_obfuscation_report(cfg)
    _print_function_transformation_report(cfg)
    _print_data_flow_report(cfg)
    _print_native_worker_compat_report(cfg)
    _print_worker_gate_forwarding_report(cfg)

    print("\n[2/2] Compiling ke native binary via gcc + libpython (bisa makan waktu)...")
    try:
        with spinner("Compiling via gcc", 30, 100):
            embed_build.compile_source_to_binary(
                obf_source, bin_path,
                lock_filename=DEFAULTS["lock_filename"], expected_filename=name,
                self_integrity_check=DEFAULTS.get("self_integrity_check", True),
            )
        print(f"\n[OK] Binary native jadi: {bin_path}")
        print("     (sudah 1 file ELF langsung, gak perlu dibungkus lagi)")
        print()
        scan_result = leak_scan.scan_binary_for_leaks(bin_path, vocabulary)
        print(leak_scan.format_report(scan_result, os.path.basename(bin_path)))
    except embed_build.ToolchainError as e:
        print(f"\n[GAGAL] Toolchain belum lengkap: {e}")
    except Exception as e:
        print(f"\n[GAGAL] {e}")
    pause()


def menu_ssl_pinning_settings():
    """
    Sub-menu for managing the SHA-256 SPKI fingerprints used by
    SSL cert pinning (core/ssl_pinning.py). Lets the user fetch a
    real fingerprint directly from a live server (the common case:
    "I run a server at X, pin it") without needing openssl or any
    external tool, add one manually (e.g. a fingerprint computed
    elsewhere, or a backup key not yet deployed), list current pins,
    or clear them all.
    """
    from core import ssl_pinning
    import ssl as _ssl_mod
    import socket as _socket_mod

    while True:
        print("\n=== SSL Cert Pinning - kelola fingerprint ===")
        pins = DEFAULTS["ssl_pin_sha256"]
        if pins:
            print(f"Fingerprint aktif ({len(pins)}):")
            for i, p in enumerate(pins, 1):
                print(f"  {i}. {p}")
        else:
            print("Belum ada fingerprint (fitur ini OFF sampai minimal 1 fingerprint ditambah).")
        print()
        print("1. Ambil fingerprint dari server langsung (kasih hostname)")
        print("2. Tambah fingerprint manual (paste hash SHA-256, 64 karakter hex)")
        print("3. Hapus satu fingerprint")
        print("4. Hapus semua fingerprint (matiin fitur ini)")
        print("0. Kembali")
        choice = input("\nPilihan: ").strip()

        if choice == "1":
            host = input("Hostname server (contoh: api.example.com): ").strip()
            if not host:
                continue
            port_raw = input("Port (default 443): ").strip()
            port = int(port_raw) if port_raw else 443
            try:
                ctx = _ssl_mod.create_default_context()
                with _socket_mod.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                fingerprint = ssl_pinning.compute_pin_from_der(der_cert)
                print(f"\n[OK] Fingerprint didapat: {fingerprint}")
                confirm = input("Tambahkan ke daftar pin? (y/n): ").strip().lower()
                if confirm == "y":
                    if fingerprint not in DEFAULTS["ssl_pin_sha256"]:
                        DEFAULTS["ssl_pin_sha256"].append(fingerprint)
                        print("[OK] Ditambahkan.")
                    else:
                        print("[INFO] Fingerprint ini udah ada di daftar.")
            except Exception as e:
                print(f"[GAGAL] Gak bisa konek/ambil certificate: {e}")
            pause()
        elif choice == "2":
            raw = input("Paste fingerprint SHA-256 (64 karakter hex): ").strip().lower()
            if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
                print("[GAGAL] Format gak valid - harus 64 karakter hex.")
            elif raw in DEFAULTS["ssl_pin_sha256"]:
                print("[INFO] Fingerprint ini udah ada di daftar.")
            else:
                DEFAULTS["ssl_pin_sha256"].append(raw)
                print("[OK] Ditambahkan.")
            pause()
        elif choice == "3":
            if not pins:
                print("[INFO] Belum ada fingerprint buat dihapus.")
                pause()
                continue
            idx_raw = input("Nomor fingerprint yang mau dihapus: ").strip()
            try:
                idx = int(idx_raw) - 1
                if 0 <= idx < len(pins):
                    removed = DEFAULTS["ssl_pin_sha256"].pop(idx)
                    print(f"[OK] Dihapus: {removed}")
                else:
                    print("[GAGAL] Nomor gak valid.")
            except ValueError:
                print("[GAGAL] Nomor gak valid.")
            pause()
        elif choice == "4":
            if pins:
                confirm = input(f"Yakin hapus semua {len(pins)} fingerprint? (y/n): ").strip().lower()
                if confirm == "y":
                    DEFAULTS["ssl_pin_sha256"] = []
                    print("[OK] Semua fingerprint dihapus, fitur SSL pinning sekarang OFF.")
            else:
                print("[INFO] Sudah kosong.")
            pause()
        elif choice == "0":
            return
        else:
            print("Pilihan tidak valid.")
            pause()


def menu_settings():
    global DEFAULTS
    while True:
        clear()
        print(BANNER)
        print("=== Settings ===")
        print(f"1. Encrypt strings        : {DEFAULTS['encrypt_strings']}")
        print(f"2. Min string length      : {DEFAULTS['min_string_len']}")
        print(f"3. Junk code intensity    : {DEFAULTS['junk_intensity']}")
        print(f"4. Anti-debug/anti-Frida  : {DEFAULTS['anti_debug']}")
        print(f"5. Onefile binary         : {DEFAULTS['onefile']}")
        print(f"6. Console (vs windowed)  : {DEFAULTS['console']}")
        print(f"7. Bungkus jadi 1 file    : {DEFAULTS['wrap_single_file']}")
        print(f"8. Rename identifier      : {DEFAULTS['rename_identifiers']} (variabel lokal + nama fungsi/class/method)")
        print(f"9. Anti-VPN (lokal+network): {DEFAULTS['anti_vpn']}")
        print(f"10. Lock nama file        : {DEFAULTS['lock_filename']}")
        print(f"11. Mode bungkus 1 file   : {DEFAULTS['wrap_mode']} (py = launcher .py, native = C ELF, rust = Rust ELF eksperimen)")
        print(f"12. Cython integrity guard: {DEFAULTS['cython_guard']} (periodic re-check binary saat mode Cython)")
        print(f"13. Wajib lewat launcher  : {DEFAULTS['require_launcher_gate']} (blok jalanin binary mentah langsung,")
        print("                              cuma berlaku kalau opsi 7 'Bungkus jadi 1 file' juga ON)")
        print(f"14. Decoy method di class : {DEFAULTS['inject_decoy_methods']} (sisip 1-3 method palsu ke tiap class asli,")
        print("                              biar campur sama method asli pas nama-nama di-rename)")
        print(f"15. Anti-debug re-check   : {DEFAULTS['periodic_recheck']} (cek ulang TracerPid/debugger/Frida")
        print("                              tiap beberapa detik selama proses jalan, gak cuma di awal)")
        print(f"16. Fallback versi Python : {DEFAULTS['enable_version_fallback']} (CUMA ngaruh di menu 1 'Obfuscate")
        print("                              only' - auto-download Python portable kalau versi beda,")
        print("                              butuh internet sekali per versi/mesin)")
        print(f"17. Fallback libpython.so : {DEFAULTS['ensure_libpython_fallback']} (CUMA ngaruh di menu 3 Cython -")
        print("                              auto-download libpython.so yang cocok kalau device target")
        print("                              gak punya, berlaku di mode wrap 'native' MAUPUN '.py', butuh internet)")
        print(f"18. Anti-sandbox          : {DEFAULTS['enable_antisandbox']} (nolak jalan kalau kedetek analysis")
        print("                              VM/sandbox - PERINGATAN: ada resiko FALSE POSITIVE nyata di")
        print("                              device asli tapi spek kecil/VPS murah/baru fresh-install)")
        print(f"19. Ambang anti-sandbox   : {DEFAULTS['antisandbox_threshold']} (makin kecil makin sensitif/gampang")
        print("                              salah deteksi, makin besar makin longgar/gampang lolos sandbox asli)")
        print(f"20. Self-hash bin         : {DEFAULTS['self_integrity_check']} (mode wrap 'native' & mode 4 embed -")
        print("                              refuse jalan kalau binary-nya sendiri dipatch/di-NOP di disk)")
        print(f"21. Bytecode-integrity    : {DEFAULTS['bytecode_integrity_check']} (deteksi function di-patch SAAT")
        print("                              proses jalan, mis. Frida hook - PERINGATAN: bisa false")
        print("                              positive di beberapa pola dekorator dinamis, lihat README)")
        print(f"22. Identifier CJK (Han)  : {DEFAULTS['cjk_identifiers']} (nama variabel/fungsi/class hasil")
        print("                              rename + nama helper string-decrypt pakai karakter Han acak,")
        print("                              bukan ASCII '_abc123' - beda 'tampilan' dari obfuscator lain.")
        print("                              CATATAN: belum diverifikasi lewat toolchain Cython asli, lihat")
        print("                              core/unicode_names.py; aman dipakai di mode .py/embed)")
        print(f"23. Cython anti-ptrace    : {DEFAULTS['cython_anti_ptrace']} (mode Cython/menu 3 doang - self-trace")
        print("                              via ptrace(PTRACE_TRACEME) SEBELUM payload jalan, biar")
        print("                              gdb/lldb/ptrace-unpacker GAGAL nempel ke binary (bukan cuma")
        print("                              kedetek, tapi structurally diblok kernel).")
        print("                              [PERINGATAN] OFF by default - KONFIRMASI bikin input() gagal")
        print("                              total (EOFError langsung, sebelum sempat ngetik apapun) di")
        print("                              device Android/Termux nyata. Nyalain cuma kalau target build")
        print("                              kamu desktop Linux, dan TETAP test input interaktif binary")
        print("                              hasilnya dulu sebelum dipakai/didistribusikan)")
        print(f"24. Cython no-coredump    : {DEFAULTS['cython_disable_coredump']} (mode Cython/menu 3 doang -")
        print("                              matiin core dump kalau binary crash, biar attacker gak bisa")
        print("                              dump memory (string/key ke-decrypt) lewat crash yang")
        print("                              disengaja. Beda dari opsi 23 di atas - ini gak nyentuh")
        print("                              ptrace/stdin sama sekali, jadi aman dipakai di Termux juga.")
        print("                              ON by default)")
        print(f"25. Guard memory-check    : {DEFAULTS['cython_guard_memory_check']} (mode Cython/menu 3 doang,")
        print("                              butuh opsi 12 'Cython integrity guard' juga ON - guard baca")
        print("                              memory LIVE proses anak (bukan cuma file di disk) tiap")
        print("                              beberapa detik, bandingin sama file aslinya. Nangkep")
        print("                              tampering yang gak nyentuh file sama sekali (misal debugger")
        print("                              nge-patch instruksi langsung di RAM).")
        print("                              [PERINGATAN] OFF by default - belum diverifikasi di device")
        print("                              Android/Termux beneran (butuh akses baca /proc/pid/mem punya")
        print("                              proses lain, bisa dibatasi SELinux/app-sandboxing). Didesain")
        print("                              fail-safe (kalau gak bisa baca, guard tetep jalan normal")
        print("                              tanpa fitur ini, gak block binary), tapi tetep test dulu")
        print("                              binary hasilnya jalan normal sebelum dipakai serius)")
        _pin_count = len(DEFAULTS["ssl_pin_sha256"])
        print(f"26. SSL cert pinning      : {'ON, ' + str(_pin_count) + ' pin(s)' if _pin_count else 'OFF'} (proteksi")
        print("                              koneksi HTTPS dari MITM proxy (Burp/mitmproxy) - koneksi")
        print("                              ditolak kalau public key server gak cocok sama fingerprint")
        print("                              yang kamu masukin, walau cert-nya keliatan valid ke OS.")
        print("                              Nutup: requests, urllib3, http.client/urllib.request,")
        print("                              aiohttp, httpx, raw socket+ssl.")
        print("                              [PERINGATAN] Berlaku GLOBAL ke SEMUA koneksi HTTPS di")
        print("                              proses, gak per-domain - kalau program kamu connect ke")
        print("                              lebih dari satu host (API kamu sendiri + SDK pihak ketiga,")
        print("                              misal python-telegram-bot ke api.telegram.org), pin cuma")
        print("                              buat 1 domain bikin SEMUA domain lain ketolak juga")
        print("                              ('certificate pin mismatch') - konfirmasi kejadian nyata.")
        print("                              Pastikan masukin fingerprint SETIAP host yang dipanggil.")
        print(f"27. Deteksi hook HTTP     : {DEFAULTS['hook_detection']} (deteksi kalau requests.Session.send /")
        print("                              urllib3/http.client/ssl.SSLContext.wrap_socket/wrap_bio")
        print("                              (nutup aiohttp/httpx juga) di-monkey-patch dari luar")
        print("                              (misal tool analisis yang inject via sitecustomize.py buat")
        print("                              baca body request/password/token SEBELUM pinning kepake).")
        print("                              Patch pinning kita sendiri (opsi 26) otomatis dikecualikan,")
        print("                              gak bakal salah kedetek.")
        print("                              BELUM nutup: sys.addaudithook, atau hook yang udah")
        print("                              bersihin jejaknya sebelum kode kamu jalan.")
        print(f"28. Hapus cache abis run  : {DEFAULTS['cleanup_after_run']} (mode bungkus .py/menu 1&2 -")
        print("                              hapus binary+extra file hasil extract dari cache (~) begitu")
        print("                              program selesai, sukses maupun gagal. OFF = cache nempel")
        print("                              terus antar-run (lebih cepat, run berikutnya re-extract)")
        print("                              tapi binary mentah (udah ke-decrypt) nongkrong di disk")
        print("                              tanpa batas waktu sampai dihapus manual. ON = lebih lambat")
        print("                              per-run tapi gak nyisain jejak file mentah abis program")
        print("                              ditutup.")
        print(f"29. Control Flow Obf.     : {DEFAULTS['control_flow_obfuscation']} (flattening konservatif untuk fungsi dengan satu if/elif/else tingkat-atas)")
        print("                              OFF secara default; fungsi kompleks/introspektif otomatis dilewati.")
        print(f"30. Constant Protection   : {DEFAULTS['constant_protection']} (integer/float/complex/bytes/bool/None/tuple literal)")
        print("                              OFF secara default; nilai direkonstruksi saat runtime.")
        print("                              Pattern matching dan operand 'is/is not' dilewati demi kompatibilitas.")
        print("                              Ini obfuscation, bukan enkripsi rahasia yang mustahil dipulihkan.")
        print(f"31. Expression Obf.       : {DEFAULTS['expression_obfuscation']} (De Morgan + double-negation untuk kondisi)")
        print("                              Hanya if/while/ternary/assert/comprehension/match-guard.")
        print("                              Boolean expression yang dipakai sebagai nilai tidak diubah.")
        print("                              OFF secara default; aktifkan dan uji hasil program.")
        print(f"32. Import Obf.           : {DEFAULTS['import_obfuscation']} (dynamic import rewrite)")
        print("                              Absolute import dan from-import yang didukung diubah.")
        print("                              Relative/star import dan dotted alias tertentu dilewati.")
        print("                              OFF secara default; module-name strings ikut String Encryption.")
        print(f"33. Attribute Obf.        : {DEFAULTS['attribute_obfuscation']} (rename field instance lokal yang terbukti aman)")
        print("                              Kelas ber-inheritance/decorator/slots/reflection dan akses ambigu dilewati.")
        print("                              Class dalam __all__ dan pola akses ambigu dilewati.")
        print("                              API lintas-file tidak dapat diinfer otomatis dari satu source.")
        print("                              Reflection/serialisasi eksternal bisa bergantung pada nama field.")
        print(f"34. Function Transform.   : {DEFAULTS['function_transformation']} (split prefix assignment menjadi helper internal)")
        print("                              Hanya fungsi top-level sync dengan prefix assignment sederhana.")
        print("                              Decorator/rekursi/nested/async/generator/introspeksi dilewati.")
        print("                              Helper tambahan bisa mengubah traceback/frame; OFF by default.")
        print(f"35. Data Flow Obf.        : {DEFAULTS['data_flow_obfuscation']} (routing assignment lokal)")
        print("                              Hanya assignment nama sederhana dalam function scope.")
        print("                              Async/generator/introspeksi dilewati; module/class assignment tetap.")
        print("                              OFF secara default.")
        print("0. Kembali")
        choice = input("\nPilih setting yang mau diubah: ").strip()
        if choice == "1":
            DEFAULTS["encrypt_strings"] = not DEFAULTS["encrypt_strings"]
        elif choice == "2":
            v = input("Min string length (int): ").strip()
            if v.isdigit():
                DEFAULTS["min_string_len"] = int(v)
        elif choice == "3":
            v = input("Junk intensity (0-20): ").strip()
            if v.isdigit():
                DEFAULTS["junk_intensity"] = max(0, min(20, int(v)))
        elif choice == "4":
            DEFAULTS["anti_debug"] = not DEFAULTS["anti_debug"]
        elif choice == "5":
            DEFAULTS["onefile"] = not DEFAULTS["onefile"]
        elif choice == "6":
            DEFAULTS["console"] = not DEFAULTS["console"]
        elif choice == "7":
            DEFAULTS["wrap_single_file"] = not DEFAULTS["wrap_single_file"]
        elif choice == "8":
            DEFAULTS["rename_identifiers"] = not DEFAULTS["rename_identifiers"]
        elif choice == "9":
            DEFAULTS["anti_vpn"] = not DEFAULTS["anti_vpn"]
            if DEFAULTS["anti_vpn"]:
                print()
                print("[INFO] Anti-VPN diaktifkan. Catatan penting:")
                print("       - Reliable di Linux desktop.")
                print("       - Di Android/Termux (non-root), /proc/net/dev sering")
                print("         dibatasi OS buat app biasa - jadi walau VPN (mis. WARP)")
                print("         aktif, check ini bisa gak ke-detect. Ini keterbatasan")
                print("         Android, bukan bug tool ini - belum ada API resmi buat")
                print("         cek status VPN dari app non-root di Android.")
                input("       [Enter untuk lanjut]")
        elif choice == "11":
            modes = ("py", "native", "rust")
            current = DEFAULTS.get("wrap_mode", "py")
            DEFAULTS["wrap_mode"] = modes[(modes.index(current) + 1) % len(modes)] if current in modes else "py"
            if DEFAULTS["wrap_mode"] == "rust":
                print("[INFO] Mode Rust memerlukan `pkg install rust clang` di mesin build Termux.")
                print("       Binary hasil hanya kompatibel dengan ABI/arsitektur tempat ia dibangun.")
                input("       [Enter untuk lanjut]")
        elif choice == "12":
            DEFAULTS["cython_guard"] = not DEFAULTS["cython_guard"]
        elif choice == "10":
            DEFAULTS["lock_filename"] = not DEFAULTS["lock_filename"]
        elif choice == "13":
            DEFAULTS["require_launcher_gate"] = not DEFAULTS["require_launcher_gate"]
            if DEFAULTS["require_launcher_gate"] and not DEFAULTS["wrap_single_file"]:
                print()
                print("[INFO] 'Bungkus jadi 1 file' (opsi 7) sedang OFF - gate ini TIDAK akan")
                print("       dipasang sampai opsi 7 di-ON-kan lagi (tanpa launcher, tidak ada")
                print("       apapun yang men-set token-nya, jadi binary akan selalu gagal jalan).")
                input("       [Enter untuk lanjut]")
        elif choice == "14":
            DEFAULTS["inject_decoy_methods"] = not DEFAULTS["inject_decoy_methods"]
        elif choice == "15":
            DEFAULTS["periodic_recheck"] = not DEFAULTS["periodic_recheck"]
            if DEFAULTS["periodic_recheck"] and not DEFAULTS["anti_debug"]:
                print()
                print("[INFO] 'Anti-debug/anti-Frida' (opsi 4) sedang OFF - re-check ini TIDAK")
                print("       akan ada apa-apanya buat di-re-check sampai opsi 4 di-ON-kan lagi.")
                input("       [Enter untuk lanjut]")
        elif choice == "16":
            DEFAULTS["enable_version_fallback"] = not DEFAULTS["enable_version_fallback"]
        elif choice == "17":
            DEFAULTS["ensure_libpython_fallback"] = not DEFAULTS["ensure_libpython_fallback"]
        elif choice == "18":
            DEFAULTS["enable_antisandbox"] = not DEFAULTS["enable_antisandbox"]
            if DEFAULTS["enable_antisandbox"]:
                print()
                print("[PERINGATAN] Anti-sandbox ON. Ini heuristik berbasis skor gabungan")
                print("             (CPU/RAM/uptime/disk kecil, MAC vendor VM, hostname generik,")
                print("             artifact VirtualBox/VMware) - device ASLI tapi spek kecil atau")
                print("             baru fresh-install BISA kena false positive dan nolak jalan.")
                print("             Test dulu di device target sebelum distribusi luas.")
                input("             [Enter untuk lanjut]")
        elif choice == "19":
            try:
                val = int(input("Ambang skor baru (default 6, makin kecil makin sensitif): ").strip())
                if val < 1:
                    print("Ambang minimal 1.")
                else:
                    DEFAULTS["antisandbox_threshold"] = val
            except ValueError:
                print("Input harus angka.")
            pause()
        elif choice == "20":
            DEFAULTS["self_integrity_check"] = not DEFAULTS["self_integrity_check"]
            if DEFAULTS["self_integrity_check"] and DEFAULTS.get("wrap_mode", "py") != "native":
                print()
                print("[INFO] Mode wrap sekarang '" + DEFAULTS.get("wrap_mode", "py") + "', bukan 'native' -")
                print("       self-hash ini cuma berlaku di mode native, gak ngaruh ke mode '.py'.")
                input("       [Enter untuk lanjut]")
        elif choice == "21":
            DEFAULTS["bytecode_integrity_check"] = not DEFAULTS["bytecode_integrity_check"]
            if DEFAULTS["bytecode_integrity_check"]:
                print()
                print("[PERINGATAN] Bytecode-integrity ON. Ini bisa FALSE POSITIVE kalau kode")
                print("             kamu punya pola kayak decorator yang GANTI object function")
                print("             SETELAH definisi awal (function di-reassign, bukan cuma")
                print("             dibungkus). Test dulu script kamu sebelum distribusi luas.")
                input("             [Enter untuk lanjut]")
        elif choice == "22":
            DEFAULTS["cjk_identifiers"] = not DEFAULTS["cjk_identifiers"]
            if DEFAULTS["cjk_identifiers"]:
                print()
                print("[INFO] Identifier CJK ON. Semua nama hasil rename (variabel/fungsi/class)")
                print("       dan nama-nama internal header dekripsi string sekarang pakai karakter")
                print("       Han acak, bukan ASCII. Ini valid Python (PEP 3131) dan sudah dites lewat")
                print("       pipeline .py/embed penuh, TAPI belum pernah dicoba lewat compiler Cython")
                print("       asli (menu 3) - kalau pakai menu 3 sama opsi ini bareng, cek hasilnya")
                print("       manual dulu sebelum distribusi luas.")
                input("       [Enter untuk lanjut]")
        elif choice == "23":
            DEFAULTS["cython_anti_ptrace"] = not DEFAULTS["cython_anti_ptrace"]
            if DEFAULTS["cython_anti_ptrace"]:
                print()
                print("[PERINGATAN] Cython anti-ptrace ON. Fitur ini KONFIRMASI bikin input()")
                print("             gagal total (EOFError) di device Android/Termux nyata - kalau")
                print("             program hasil obfuscate kamu butuh input interaktif (misal minta")
                print("             license key, password, dll) dan target-nya Android/Termux, JANGAN")
                print("             nyalain ini. Kalau target build kamu desktop Linux, boleh dicoba,")
                print("             tapi tetap test binary hasilnya jalan normal dulu sebelum dipakai.")
                input("             [Enter untuk lanjut]")
        elif choice == "24":
            DEFAULTS["cython_disable_coredump"] = not DEFAULTS["cython_disable_coredump"]
        elif choice == "25":
            DEFAULTS["cython_guard_memory_check"] = not DEFAULTS["cython_guard_memory_check"]
            if DEFAULTS["cython_guard_memory_check"]:
                print()
                print("[PERINGATAN] Guard memory-check ON. Fitur ini BELUM diverifikasi di device")
                print("             Android/Termux beneran - didesain fail-safe (kalau gak bisa baca")
                print("             /proc/pid/mem, guard tetep jalan normal tanpa fitur ini), tapi tetap")
                print("             TEST binary hasilnya jalan normal (termasuk kalau butuh input")
                print("             interaktif) sebelum dipakai serius/didistribusikan.")
                input("             [Enter untuk lanjut]")
        elif choice == "26":
            menu_ssl_pinning_settings()
        elif choice == "27":
            DEFAULTS["hook_detection"] = not DEFAULTS["hook_detection"]
            if DEFAULTS["hook_detection"]:
                print()
                print("[INFO] Deteksi hook HTTP ON. Ini nutup jalur monkey-patch ke")
                print("       requests.Session.send/urllib3/http.client connect() dan")
                print("       ssl.SSLContext.wrap_socket/wrap_bio (jadi aiohttp/httpx ikut")
                print("       kecover), TAPI gak nutup sys.addaudithook-based monitoring, dan")
                print("       gak bisa deteksi hook yang udah bersihin jejaknya sebelum kode")
                print("       kamu jalan. Ini mempersulit, bukan jaminan 100% aman.")
                input("       [Enter untuk lanjut]")
        elif choice == "28":
            DEFAULTS["cleanup_after_run"] = not DEFAULTS["cleanup_after_run"]
            if DEFAULTS["cleanup_after_run"]:
                print()
                print("[INFO] Hapus cache abis run ON. Binary + extra file yang diekstrak ke")
                print("       cache (~) akan dihapus begitu program selesai (sukses atau gagal),")
                print("       jadi gak ada lagi salinan binary mentah yang nempel di disk abis")
                print("       program ditutup. Konsekuensinya: setiap kali dijalankan, binary")
                print("       ditulis ulang dari awal (lebih lambat dari sebelumnya, terutama")
                print("       untuk binary besar di storage lambat kayak Termux/Android).")
                input("       [Enter untuk lanjut]")
        elif choice == "29":
            DEFAULTS["control_flow_obfuscation"] = not DEFAULTS["control_flow_obfuscation"]
            if DEFAULTS["control_flow_obfuscation"]:
                print()
                print("[INFO] Control Flow Obfuscation ON.")
                print("       Hanya fungsi dengan tepat satu if/elif/else tingkat-atas yang")
                print("       memenuhi syarat yang akan diubah menjadi state-machine.")
                print("       Fungsi yang memakai locals/vars/eval/exec atau introspeksi frame")
                print("       dilewati untuk menjaga kompatibilitas. Tes hasil build sebelum dipakai.")
                input("       [Enter untuk lanjut]")
        elif choice == "30":
            DEFAULTS["constant_protection"] = not DEFAULTS["constant_protection"]
            if DEFAULTS["constant_protection"]:
                print()
                print("[INFO] Constant Protection ON.")
                print("       Integer, float, complex, bytes, bool, None, dan tuple literal")
                print("       yang memenuhi syarat akan direkonstruksi saat runtime.")
                print("       String tetap ditangani oleh String Encryption yang sudah ada.")
                print("       Operand identity dan pattern matching sengaja dilewati.")
                print("       Nilai tetap dapat dipulihkan saat runtime; ini bukan secret vault.")
                input("       [Enter untuk lanjut]")
        elif choice == "31":
            DEFAULTS["expression_obfuscation"] = not DEFAULTS["expression_obfuscation"]
            if DEFAULTS["expression_obfuscation"]:
                print()
                print("[INFO] Expression Obfuscation ON.")
                print("       Mengubah kondisi truth-test menggunakan De Morgan atau double-negation.")
                print("       Mencakup if/while/ternary/assert/comprehension/match guard.")
                print("       Boolean expression yang dipakai sebagai nilai tetap tidak diubah.")
                print("       Tidak menambah helper runtime atau menggandakan operand.")
                input("       [Enter untuk lanjut]")
        elif choice == "32":
            DEFAULTS["import_obfuscation"] = not DEFAULTS["import_obfuscation"]
            if DEFAULTS["import_obfuscation"]:
                print()
                print("[INFO] Import Obfuscation ON.")
                print("       Absolute import dan from-import yang didukung diubah menjadi dynamic import.")
                print("       Relative imports, star imports, dan dotted aliases tertentu dilewati.")
                print("       Jika source mendefinisikan __import__, pass dilewati seluruhnya.")
                print("       Nama module/member ikut String Encryption bila fitur itu aktif.")
                print("       Uji semua jalur import aplikasi sebelum dipakai.")
                input("       [Enter untuk lanjut]")
        elif choice == "33":
            DEFAULTS["attribute_obfuscation"] = not DEFAULTS["attribute_obfuscation"]
            if DEFAULTS["attribute_obfuscation"]:
                print()
                print("[INFO] Attribute Obfuscation ON.")
                print("       Hanya field instance pada class lokal top-level dengan referensi statis yang diubah.")
                print("       Inheritance, decorator/property, __slots__, __dict__, reflection, dan akses ambigu dilewati.")
                print("       Class yang dideklarasikan di __all__ dilewati sebagai API publik.")
                print("       Akses lintas-file tidak dapat diinfer; serialisasi/reflection eksternal perlu diuji.")
                print("       Class kompleks, dynamic reflection, dan akses ambigu dilewati otomatis.")
                input("       [Enter untuk lanjut]")
        elif choice == "34":
            DEFAULTS["function_transformation"] = not DEFAULTS["function_transformation"]
            if DEFAULTS["function_transformation"]:
                print()
                print("[INFO] Function Transformation ON.")
                print("       Prefix 2-4 simple assignment dari fungsi top-level sync dipindahkan")
                print("       ke helper internal. Function decorated, recursive, nested, async,")
                print("       generator, introspektif, global/nonlocal, atau scope ambigu dilewati.")
                print("       Helper tambahan dapat mengubah traceback/line introspection.")
                input("       [Enter untuk lanjut]")
        elif choice == "35":
            DEFAULTS["data_flow_obfuscation"] = not DEFAULTS["data_flow_obfuscation"]
            if DEFAULTS["data_flow_obfuscation"]:
                print()
                print("[INFO] Data Flow Obfuscation ON.")
                print("       Name-copy memakai tuple route; expression assignment memakai")
                print("       temporary local agar nilai dievaluasi tepat satu kali.")
                print("       Module/class assignment serta async/generator/introspective scope dilewati.")
                input("       [Enter untuk lanjut]")
        elif choice == "0":
            return
        else:
            print("Pilihan tidak valid.")
            pause()


def _initialize_signing_key() -> None:
    """Menyiapkan keypair sekali pada startup tanpa pernah menampilkan isi private key."""
    try:
        key_path, status = ensure_signing_key()
    except SigningKeySetupError as exc:
        raise RuntimeError(f"Signing key setup gagal: {exc}") from exc
    if status == "created":
        print(f"[OK] Signing key baru dibuat: {key_path}")
        print("     Key ini akan dipakai ulang otomatis pada build berikutnya.")
    elif status == "existing":
        print(f"[OK] Signing key siap: {key_path}")
    else:
        print(f"[OK] Signing key override siap: {key_path}")


def _initialize_core_integrity() -> None:
    """Memeriksa (dan bila perlu, auto-resign) integritas source tree
    core/ milik tool ini sendiri di setiap startup CLI - lihat
    core_integrity_autosetup.py's module docstring untuk alasan
    lengkap kenapa ini auto-resign dengan jeda+log, bukan block
    total maupun auto-resign tanpa jejak sama sekali.

    Kegagalan di sini SENGAJA tidak menghentikan CLI (kecuali
    KeyboardInterrupt, yang berarti operator sendiri yang membatalkan
    saat diberi kesempatan) - ini tripwire pelengkap, bukan gerbang
    keamanan utama tool ini (itu perannya gate token/signing key
    launcher yang sudah ada). Status 'clean' dan 'skipped-no-crypto'
    sengaja tidak mencetak apa pun, supaya startup normal (tidak ada
    perubahan) tetap sesenyap sebelum fitur ini ada.
    """
    try:
        status = initialize_core_integrity()
    except KeyboardInterrupt:
        raise
    except CoreIntegrityError as exc:
        print(f"[WARNING] Pemeriksaan integritas core/ gagal (dilanjutkan tanpa proteksi ini): {exc}")
        return
    if status == "created":
        print("[OK] Integritas core/ diinisialisasi (keypair + manifest baru dibuat).")
    elif status == "resigned":
        print("[OK] Manifest integritas core/ diperbarui (lihat core_integrity_history.log untuk riwayat).")


def main_menu():
    while True:
        clear()
        print(BANNER)
        print("1. Obfuscate source saja (.py -> .py terproteksi)")
        print("2. Full pipeline: obfuscate + build binary (PyInstaller)")
        print("3. Full pipeline: obfuscate + build binary NATIVE (Cython, lebih kuat)")
        print("4. Full pipeline: obfuscate + build binary NATIVE (gcc only, TANPA Cython)")
        print("5. Settings (termasuk mode bungkus 1 file: .py launcher / native ELF launcher)")
        print("0. Keluar")
        choice = input("\nPilih menu: ").strip()
        if choice == "1":
            menu_obfuscate_only()
        elif choice == "2":
            menu_full_pipeline()
        elif choice == "3":
            menu_cython_pipeline()
        elif choice == "4":
            menu_embed_pipeline()
        elif choice == "5":
            menu_settings()
        elif choice == "0":
            print("Bye.")
            sys.exit(0)
        else:
            print("Pilihan tidak valid.")
            pause()


if __name__ == "__main__":
    try:
        _initialize_core_integrity()
        _initialize_signing_key()
        main_menu()
    except KeyboardInterrupt:
        print("\nDibatalkan.")
        sys.exit(0)
