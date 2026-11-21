"""
bootstrap.py - wraps an already-built binary (from build.py or
cython_build.py) into a single, self-contained .py "launcher" file.

Why this exists:
  Android shared storage (/sdcard) is usually mounted noexec, so a
  raw binary dropped there can't be chmod'd into something runnable.
  A .py file doesn't have that problem because it's the `python`
  interpreter that's executed, not the file itself.

How it hides its own logic:
  The launcher's actual extract/chmod/run logic (and the embedded
  binary payload itself) is written as ordinary Python source, then
  run through the SAME string-encryption + compile/marshal/XOR-encrypt
  pipeline (packer.pack) used for the main protected script. So the
  final .py file on disk is just a small generic unpack shell around
  one big encrypted blob - reading the file doesn't show "this
  extracts a binary, chmods it, and runs it"; that logic only exists
  as plaintext for the instant it's decrypted in memory at runtime.
  This also means the whole-file self-checksum and optional filename
  lock that packer.pack() already provides come along for free here,
  AND transitively cover the embedded binary too (since the binary's
  bytes are part of what gets hashed as the file's own content).

  On every run it:
    1. verifies its OWN file hasn't been tampered with + optionally
       its filename hasn't changed (via packer.pack's built-in checks)
    2. decodes + decompresses the embedded payload
    3. writes it to a writable, executable location (Termux home,
       or the user's home dir on other platforms - never /sdcard)
    4. skips the rewrite if an identical copy is already there
    5. chmod +x's it automatically - no manual step from the user
    6. executes it, forwarding argv/stdin/stdout/stderr/exit code

  So the end user experience becomes: `python launcher.py` and
  that's it, every time, from anywhere (including /sdcard).
"""
import base64
import hashlib
import os
import random
import string
import zlib

from . import packer
from . import string_enc
from .crypto import xor_encrypt, random_key, split_key_with_junk, build_fragment_chain
from .launch_integrity import build_manifest, load_private_key, sign_manifest, validate_artifact_name
from .native_decryptor_build import NativeDecryptorBuildError, build_native_decryptor


def _rand_name(used: set, n: int = 9) -> str:
    while True:
        cand = "_" + "".join(random.choices(string.ascii_lowercase, k=n))
        if cand not in used:
            used.add(cand)
            return cand


def _read_sibling_source(filename: str) -> str:
    """Reads another module's source from this same core/ directory,
    for embedding as a plain string blob (e.g. runtime_fetch.py's
    fetch/cache logic, embedded so the standalone launcher .py doesn't
    need `core` to be an importable package on the target machine)."""
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _build_manifest_runtime_source(manifest: dict, signed_manifest: dict | None) -> str:
    """Membuat kode verifikasi manifest untuk dimasukkan ke launcher hasil build.

    Public key dan signature boleh ikut didistribusikan. Private key hanya dibaca
    pada build host oleh `launch_integrity.load_private_key`.
    """
    import json

    manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    signature_b64 = (signed_manifest or {}).get("signature_b64", "")
    public_key_pem = (signed_manifest or {}).get("public_key_pem", "")
    return f'''\
def _vh_release_manifest():
    import base64 as _vh_b64
    import json as _vh_json
    _vh_payload = {manifest_json!r}.encode("ascii")
    _vh_signature = {signature_b64!r}
    _vh_public_key = {public_key_pem!r}
    if _vh_signature:
        try:
            from Crypto.PublicKey import ECC as _vh_ecc
            from Crypto.Signature import eddsa as _vh_eddsa
            _vh_key = _vh_ecc.import_key(_vh_public_key)
            _vh_eddsa.new(_vh_key, mode="rfc8032").verify(
                _vh_payload, _vh_b64.b64decode(_vh_signature.encode("ascii"), validate=True)
            )
        except Exception as _vh_exc:
            raise RuntimeError("Launch manifest signature verification failed") from _vh_exc
    _vh_manifest = _vh_json.loads(_vh_payload)
    _vh_canonical = _vh_json.dumps(_vh_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if _vh_canonical != _vh_payload or _vh_manifest.get("format") != 1:
        raise RuntimeError("Launch manifest is malformed")
    return _vh_manifest

_vh_manifest = _vh_release_manifest()
'''


def wrap_binary_as_py(binary_path: str, output_py_path: str, embedded_name: str = None,
                       lock_filename: bool = False, extra_files: dict = None,
                       gate_env_name: str = None, gate_token: str = None,
                       ensure_libpython_version: tuple = None,
                       manifest_private_key_path: str = None,
                       native_decryptor: bool = False,
                       cleanup_after_run: bool = False):
    """
    binary_path: path to an already-built binary (PyInstaller or
                 Cython output).
    output_py_path: where to write the resulting single-file launcher.
    embedded_name: filename to use once extracted (default: basename
                   of binary_path).
    lock_filename: if True, the launcher refuses to run unless its
                   own filename on disk still matches the basename
                   of output_py_path (blocks rename+redistribute).
    extra_files: optional {filename: bytes} for companion files that
                 must be extracted alongside the main binary, in the
                 SAME directory, before the main binary runs - e.g.
                 cython_guard.py's "__cyinner" child binary, which
                 the guard resolves at runtime relative to its own
                 location. Without this, a guard-wrapped binary
                 passed through wrap_binary_as_py would ship without
                 its required companion and fail with something like
                 "execv: No such file or directory" the moment it's
                 extracted somewhere the child never got copied to.
    gate_env_name / gate_token: if the wrapped binary was itself built
                 with ObfuscationConfig(require_launcher_gate=True),
                 pass the SAME env_name/token pair used at that build
                 (from obfuscator.generate_gate_info()) here. This
                 launcher will then set that env var to that token on
                 the child process right before running it - closing
                 the "found the extracted binary's path on disk, ran
                 it directly, skipped this launcher and every check
                 that only lives here" bypass, because the extracted
                 binary now refuses to run at all unless this exact
                 launcher started it. Leave both None if the wrapped
                 binary wasn't built with require_launcher_gate.
    manifest_private_key_path: path private key Ed25519 PEM yang hanya ada di mesin build. Bila diberikan, launcher memverifikasi manifest bertanda tangan sebelum menulis atau menjalankan artefak. Bila None, launcher tetap memeriksa hash/ukuran internal tetapi tidak memiliki jaminan asal rilis berbasis private key.
    native_decryptor: bila True, outer launcher `.py` memakai container native
                   opaque untuk derivasi key, AES-GCM, unmarshal, dan dispatch
                   module CPython. Extension dimuat sementara lalu dibersihkan.
                   Mode ini membutuhkan compiler + header Python di mesin build
                   dan kompatibel hanya dengan target ABI Python/arsitektur yang sama.
    cleanup_after_run: bila True, launcher menghapus binary utama DAN
                 setiap extra_files yang diekstrak ke cache dir, segera
                 setelah proses anak selesai (sukses, gagal, atau
                 OSError saat exec - cleanup tetap jalan di ketiga
                 kasus, sebelum exit code/exception diteruskan).
                 Default False: tanpa ini, cache dir (`_cache_dir()`
                 di bawah ~) menyimpan binary hasil ekstrak SELAMANYA
                 antar-run (itu memang tujuannya - lihat
                 _extract_artifact's skip-if-identical check - supaya
                 run kedua dst tidak perlu menulis ulang binary yang
                 sama, penting untuk binary besar di storage lambat
                 seperti Termux/Android). Trade-off True vs False:
                 True menghapus jejak binary plaintext di disk setelah
                 program selesai (tidak ada lagi yang bisa diambil
                 langsung dari cache dir oleh siapa pun yang punya
                 akses filesystem setelahnya - inilah satu-satunya hal
                 yang seluruh proteksi lain di proyek ini - AES-GCM,
                 fragment chain, strip symbol, gate token - TIDAK
                 pernah lindungi, karena semua itu hanya berlaku
                 selama binary masih terenkripsi di dalam `.py` ini
                 atau selama proses child berjalan, bukan sesudahnya)
                 dengan konsekuensi setiap run menulis ulang binary
                 dari nol (lebih lambat, terutama binary besar di
                 storage lambat). False mempertahankan performa cache
                 tapi binary plaintext tetap ada di disk tanpa batas
                 waktu sampai dihapus manual.
    ensure_libpython_version: pass (major, minor) - e.g. (3, 12) - when
                 binary_path is a Cython/embed build that dynamically
                 links against libpythonX.Y.so at compile time
                 (cython_build.py's normal output). Unlike
                 native_launcher.py's C-side equivalent (which
                 dlopen()-checks BEFORE ever attempting to run the
                 binary), this .py launcher is already running inside
                 a Python process by the time it gets here, so it
                 takes a simpler try-then-fix-on-failure approach
                 instead: try subprocess.run() as normal first; if
                 that fails in a way that looks like a missing shared
                 library (a Linux dynamic linker reports this on
                 stderr, or subprocess.run itself raises OSError if
                 exec failed outright), download the matching
                 libpythonX.Y.so from python-build-standalone (reusing
                 runtime_fetch.py's exact same cache directory,
                 ~/.vh_runtimes/ - so this never re-downloads something
                 mode 1's version-fallback or native_launcher.py's own
                 libpython check already fetched on this machine), set
                 LD_LIBRARY_PATH, and retry ONCE. If a matching
                 libpython is already present (the common case), this
                 costs nothing extra - the first subprocess.run()
                 attempt just succeeds and the retry path never runs.
                 Leave None (default) for PyInstaller-built binaries,
                 which never need this.
    """
    with open(binary_path, "rb") as f:
        raw = f.read()

    extra_files = dict(extra_files or {})
    for _artifact_name in extra_files:
        validate_artifact_name(_artifact_name)

    compressed = zlib.compress(raw, level=9)
    payload_hash = hashlib.sha256(raw).hexdigest()
    payload_b85 = base64.b85encode(compressed).decode()

    name = validate_artifact_name(embedded_name or os.path.basename(binary_path))
    expected_filename = os.path.basename(output_py_path)
    manifest = build_manifest(name, raw, extra_files)
    signed_manifest = None
    if manifest_private_key_path:
        signed_manifest = sign_manifest(manifest, load_private_key(manifest_private_key_path))

    used = set()
    v_payload = _rand_name(used)   # kept OUT of string-encryption (see below):
                                    # it's already opaque base85 data, so a
                                    # second XOR+encode pass over a multi-MB
                                    # string just burns build time for no
                                    # real security gain - it's still fully
                                    # hidden by the outer marshal+XOR layer.
    cache_dir = "." + _rand_name(used, 10).lstrip("_")

    # Build one extract+skip-if-identical block per extra file, using
    # the same pattern as the main binary's own extract logic - each
    # gets its own random variable name and its own embedded payload,
    # written to the SAME cache_dir as the main binary so a relative
    # lookup (like cython_guard's /proc/self/exe-based resolution)
    # finds it right next to the main binary after extraction.
    extra_payload_assignments = []
    extra_extract_blocks = []
    for extra_name, extra_bytes in extra_files.items():
        v_extra = _rand_name(used)
        extra_compressed = zlib.compress(extra_bytes, level=9)
        extra_hash = hashlib.sha256(extra_bytes).hexdigest()
        extra_b85 = base64.b85encode(extra_compressed).decode()
        extra_payload_assignments.append(f"{v_extra} = {extra_b85!r}\n")
        extra_extract_blocks.append(
            f'    _extract_artifact({extra_name!r}, {v_extra})\n'
        )

    extra_extract_source = "".join(extra_extract_blocks)

    # Names only (not bytes) - the actual content is already on disk
    # by the time cleanup runs, this just needs to know WHICH
    # filenames, under the same _cache_dir(), to remove. Built from
    # the same extra_files dict as extra_extract_source above, so the
    # two can never name a different set of files than what was
    # actually extracted.
    if cleanup_after_run:
        cleanup_names_literal = repr([name] + list(extra_files.keys()))
        cleanup_source = f'''
for _vh_cn in {cleanup_names_literal}:
    try:
        os.unlink(os.path.join(_cache_dir(), _vh_cn))
    except OSError:
        pass
try:
    os.rmdir(_cache_dir())
except OSError:
    pass
'''
    else:
        cleanup_source = ""

    if gate_env_name and gate_token is not None:
        # Previously: gate_token went straight into the launcher's
        # source as an f-string literal (`_env[name!r] = token!r`),
        # relying ENTIRELY on the general string_enc.encrypt_strings
        # pass below (every string constant in `logic`, this
        # included) plus packer.pack's outer marshal+XOR envelope for
        # protection - both real, but both SHARED with every other
        # string/the whole file. Breaking either one exposes the gate
        # token as a side effect of exposing everything else, with no
        # extra work targeted at the token specifically. Since this
        # launcher's own gate_token cannot itself be gate-masked (see
        # the allow_no_gate=True comment below for why that would be
        # circular), it gets the same targeted treatment
        # native_launcher.py's C launcher now uses for the exact same
        # problem: XOR-encrypt the token with its own random key, and
        # scatter THAT key into indistinguishable real+decoy
        # fragments selected via a hash chain (split_key_with_junk +
        # build_fragment_chain) - a separate pool from string_enc's
        # own table/key, so reconstructing one doesn't hand over the
        # other. Not a claim this makes the token cryptographically
        # unrecoverable (nothing can, without an external secret -
        # see the circular-dependency note below); it closes the gap
        # where the token specifically had strictly WEAKER protection
        # than the payload key sitting right next to it.
        gt_token_bytes = gate_token.encode("utf-8")
        gt_xor_key = random_key(32)
        gt_enc = xor_encrypt(gt_token_bytes, gt_xor_key)

        gt_frags, gt_real_idx = split_key_with_junk(gt_xor_key)
        gt_seed, gt_tags = build_fragment_chain(gt_frags, gt_real_idx, tag_len=4)

        v_gt_frags, v_gt_seed, v_gt_tags, v_gt_enc, fn_gt_pick = (
            _rand_name(used), _rand_name(used), _rand_name(used),
            _rand_name(used), _rand_name(used),
        )
        gate_setenv_source = (
            f"import hashlib as _vhgh\n"
            f"{v_gt_frags} = {gt_frags!r}\n"
            f"{v_gt_seed} = {gt_seed!r}\n"
            f"{v_gt_tags} = {gt_tags!r}\n"
            f"{v_gt_enc} = {gt_enc!r}\n"
            f"def {fn_gt_pick}():\n"
            f"    _state = {v_gt_seed}\n"
            f"    _used = set()\n"
            f"    _out = b''\n"
            f"    for _tag in {v_gt_tags}:\n"
            f"        _found = None\n"
            f"        for _c, _frag in enumerate({v_gt_frags}):\n"
            f"            if _c in _used:\n"
            f"                continue\n"
            f"            _d = _vhgh.sha256(_state + _frag).digest()\n"
            f"            if _d[:4] == _tag:\n"
            f"                _found = _c\n"
            f"                _digest = _d\n"
            f"                break\n"
            f"        if _found is None:\n"
            f"            return b''\n"
            f"        _used.add(_found)\n"
            f"        _out += {v_gt_frags}[_found]\n"
            f"        _state = _digest\n"
            f"    return _out\n"
            f"def _vhgt_ks(_key, _length):\n"
            f"    _out2 = bytearray()\n"
            f"    _block = _key\n"
            f"    while len(_out2) < _length:\n"
            f"        _block = _vhgh.sha256(_block).digest()\n"
            f"        _out2.extend(_block)\n"
            f"    return bytes(_out2[:_length])\n"
            f"_gt_key = {fn_gt_pick}()\n"
            f"_gt_ks = _vhgt_ks(_gt_key, len({v_gt_enc}))\n"
            f"_gt_raw = bytes(a ^ b for a, b in zip({v_gt_enc}, _gt_ks))\n"
            f"_env = dict(os.environ)\n"
            f"_env[{gate_env_name!r}] = _gt_raw.decode('utf-8')\n"
        )
    else:
        gate_setenv_source = "_env = None\n"

    # libpython fallback: only prepared when the wrapped binary is a
    # Cython/embed build that dynamically links against
    # libpythonX.Y.so - see wrap_binary_as_py's docstring for the
    # full mechanism and why this launcher takes a try-then-fix
    # approach rather than native_launcher.py's pre-check one.
    manifest_runtime_source = _build_manifest_runtime_source(manifest, signed_manifest)

    has_libpython_fallback = ensure_libpython_version is not None
    if has_libpython_fallback:
        lp_major, lp_minor = ensure_libpython_version
        v_rf_module = _rand_name(used)
        # runtime_fetch.py is executed into its own dict namespace
        # (exec(src, ns)) rather than merged into this launcher's own
        # top-level names, so its functions/constants can't collide
        # with or shadow anything else in this generated file.
        _runtime_fetch_src = _read_sibling_source("runtime_fetch.py")
        libpython_fallback_source = f'''
def _vh_try_fix_libpython(major, minor):
    """Downloads a matching libpythonX.Y.so (reusing runtime_fetch's
    ~/.vh_runtimes/ cache - shared with mode 1's version-fallback and
    native_launcher.py's own libpython check, so nothing here ever
    re-downloads something another one of this tool's features
    already fetched on this machine) and points LD_LIBRARY_PATH at
    the directory containing it, for the retry that follows. Returns
    True if a library was found/fetched and the env was updated,
    False if the fetch itself failed (caller should give up and
    surface the ORIGINAL error, not this one, if this returns False)."""
    {v_rf_module} = {{}}
    try:
        exec({_runtime_fetch_src!r}, {v_rf_module})
        _py_bin = {v_rf_module}["ensure_python"](major, minor)
    except Exception:
        return False
    _py_root = os.path.dirname(os.path.dirname(_py_bin))
    _lib_dir = os.path.join(_py_root, "lib")
    if not os.path.isdir(_lib_dir):
        return False
    _existing = os.environ.get("LD_LIBRARY_PATH", "")
    os.environ["LD_LIBRARY_PATH"] = (_lib_dir + ":" + _existing) if _existing else _lib_dir
    return True


def _vh_looks_like_missing_libpython(proc_result, exc):
    """Best-effort detection of "the OS couldn't load a shared library
    this binary depends on" - either subprocess.run() raised OSError
    outright (exec itself failed) or the process ran but printed the
    dynamic linker's characteristic message on stderr. This is a
    heuristic, not a guarantee - stated plainly rather than pretending
    it catches every possible variant of this error across every libc."""
    if exc is not None:
        return True
    if proc_result is not None and proc_result.returncode != 0:
        _stderr = getattr(proc_result, "stderr", None) or b""
        if isinstance(_stderr, bytes):
            _stderr = _stderr.decode("utf-8", "ignore")
        if "error while loading shared libraries" in _stderr or "cannot open shared object file" in _stderr:
            return True
    return False
'''
    else:
        libpython_fallback_source = ""

    logic_template = '''
import base64, zlib, os, sys, hashlib, subprocess, stat, tempfile, signal

def _cache_dir():
    home = os.path.abspath(os.path.expanduser("~"))
    d = os.path.join(home, "{cache_dir}")
    if os.path.lexists(d) and (os.path.islink(d) or not os.path.isdir(d)):
        raise RuntimeError("Launcher cache path is unsafe")
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d

def _manifest_entry(name):
    if not isinstance(name, str) or not name or os.path.basename(name) != name or "/" in name or "\\\\" in name:
        raise RuntimeError("Invalid artifact name")
    entry = _vh_manifest.get("artifacts", {{}}).get(name)
    if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str) or not isinstance(entry.get("size"), int):
        raise RuntimeError("Artifact is absent from launch manifest")
    return entry

def _atomic_write(target, raw):
    directory = os.path.dirname(target)
    fd, temporary = tempfile.mkstemp(prefix=".launch-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, 0o700)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass

def _extract_artifact(name, encoded):
    entry = _manifest_entry(name)
    raw = zlib.decompress(base64.b85decode(encoded))
    if len(raw) != entry["size"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise RuntimeError("Embedded artifact verification failed")
    d = _cache_dir()
    target = os.path.join(d, name)
    if os.path.isfile(target) and not os.path.islink(target):
        with open(target, "rb") as f:
            existing = f.read()
        if len(existing) == entry["size"] and hashlib.sha256(existing).hexdigest() == entry["sha256"]:
            return target
    _atomic_write(target, raw)
    return target

def _extract():
    return _extract_artifact("{name}", {v_payload})

def _extract_extras():
{extra_extract_source}

_extract_extras()
_bin_path = _extract()
{gate_setenv_source}

# SIGTERM has no catchable-exception equivalent by default in Python
# (unlike SIGINT, which the interpreter automatically converts to
# KeyboardInterrupt) - an unhandled SIGTERM just kills the process
# immediately, with zero chance to run any Python code, cleanup
# included. Installing this handler converts it into a SystemExit
# raised at the point the signal arrives, so it unwinds through
# subprocess.run()'s wait() exactly the way KeyboardInterrupt already
# does (same mechanism, same result: cleanup still gets a chance to
# run, see the except clauses right below). 143 = 128 + SIGTERM(15),
# the conventional shell exit code for "killed by SIGTERM" - matches
# what a process killed by an UNHANDLED SIGTERM would normally report,
# so wrapping it this way doesn't change what the exit code LOOKS like
# from outside, only that Python gets a chance to clean up first.
def _vh_sigterm_handler(_signum, _frame):
    raise SystemExit(143)
signal.signal(signal.SIGTERM, _vh_sigterm_handler)

_proc_exc = None
_proc_interrupt = None
try:
    _proc_result = subprocess.run([_bin_path] + sys.argv[1:], env=_env)
except OSError as _e:
    _proc_result = None
    _proc_exc = _e
except (KeyboardInterrupt, SystemExit) as _e:
    # Ctrl+C (SIGINT, auto-converted to KeyboardInterrupt by Python)
    # or an external `kill`/task-manager SIGTERM (converted to
    # SystemExit by the handler installed above) while the wrapped
    # program is still running (the common case for anything long-
    # running - a bot's polling loop, a server, anything that doesn't
    # exit on its own) raises its exception INSIDE subprocess.run()'s
    # own wait() - without this specific catch, that exception unwinds
    # straight past the cleanup block further down and the cache never
    # gets cleaned, confirmed happening in practice for the
    # KeyboardInterrupt case. _proc_result stays unset here - the
    # child's exit status when the parent is being torn down isn't the
    # point; the ONLY job of this except clause is to make sure
    # cleanup still runs before re-raising the SAME exception once it
    # has.
    _proc_result = None
    _proc_interrupt = _e

if {has_lp_fallback_flag}:
    # Only probe for a missing-libpython failure AFTER the normal run
    # has already finished and failed - never speculatively capture
    # output on the primary attempt. capture_output=True buffers ALL
    # of the child's stdout/stderr and (critically) replaces its
    # stdin with a closed pipe, which breaks - or outright HANGS -
    # any program that's interactive, prints progress incrementally,
    # or runs for a long time: the user sees nothing until the child
    # exits, Ctrl+C doesn't cleanly reach the child, and a program
    # waiting on stdin blocks forever since nothing can ever be typed
    # into a pipe the parent never writes to. A normal run's exit code
    # alone is what decides whether it's even worth investigating
    # further - 126/127 are the standard shell/exec-failure codes a
    # missing shared library manifests as, so re-probing is skipped
    # entirely for any other exit code (including a program's own
    # deliberate non-zero exit, which must never be second-guessed
    # here).
    _looks_like_exec_failure = (_proc_exc is not None) or (
        _proc_result is not None and _proc_result.returncode in (126, 127)
    )
    if _looks_like_exec_failure:
        # Re-run ONCE, ONLY NOW, with output captured - purely to read
        # the dynamic linker's error text off stderr and confirm it's
        # actually a missing-libpython situation before attempting any
        # fix. If the program is interactive/long-running, it already
        # would have exited immediately with 126/127 on the FIRST,
        # uncaptured run (a linker failure happens before the program
        # ever starts executing, so there's nothing to hang on here -
        # the process that would hang on stdin never even gets that far).
        # Safe to re-run without double-side-effect concerns: exit
        # codes 126/127 specifically mean the OS refused to exec the
        # binary AT ALL (unlike e.g. exit 1, which the program itself
        # could have chosen after doing real work) - nothing from the
        # program's own logic ever ran on the first attempt, so running
        # it again to inspect the failure reason doesn't repeat any
        # action the program would have taken.
        try:
            _probe_result = subprocess.run([_bin_path] + sys.argv[1:], env=_env, capture_output=True)
        except OSError as _e:
            _probe_result = None
        else:
            _probe_result = _probe_result
        _probe_exc = None if _probe_result is not None else _proc_exc

        if _vh_looks_like_missing_libpython(_probe_result, _probe_exc):
            if _vh_try_fix_libpython({lp_major_lit}, {lp_minor_lit}):
                _env2 = dict(_env if _env else os.environ)
                _env2["LD_LIBRARY_PATH"] = os.environ.get("LD_LIBRARY_PATH", "")
                try:
                    _proc_result = subprocess.run([_bin_path] + sys.argv[1:], env=_env2)
                    _proc_exc = None
                except OSError as _e:
                    _proc_result = None
                    _proc_exc = _e
                except (KeyboardInterrupt, SystemExit) as _e:
                    # Same reasoning as the first subprocess.run()'s
                    # matching catch above - this is the rare
                    # libpython-fallback retry path, but Ctrl+C/SIGTERM
                    # can land here exactly the same way.
                    _proc_result = None
                    _proc_interrupt = _e

{cleanup_source}
# SIGINT / Ctrl+C is an expected user action, not an application error.
# subprocess.run() raises KeyboardInterrupt in this parent process while
# waiting for the wrapped child. Cleanup has already run above; exit with
# the conventional 130 status without re-raising, which would print an
# unnecessary traceback from the generated launcher. Keep SystemExit
# (including the SIGTERM handler's 143) unchanged.
if isinstance(_proc_interrupt, KeyboardInterrupt):
    sys.exit(130)
if _proc_interrupt is not None:
    raise _proc_interrupt
if _proc_exc is not None:
    raise _proc_exc
sys.exit(_proc_result.returncode)
'''
    formatted_extra_extract_source = extra_extract_source or "    return None\n"
    logic = manifest_runtime_source + logic_template.format(
        cache_dir=cache_dir,
        name=name,
        v_payload=v_payload,
        extra_extract_source=formatted_extra_extract_source,
        gate_setenv_source=gate_setenv_source,
        has_lp_fallback_flag=repr(has_libpython_fallback),
        lp_major_lit=(ensure_libpython_version[0] if has_libpython_fallback else 0),
        lp_minor_lit=(ensure_libpython_version[1] if has_libpython_fallback else 0),
        cleanup_source=cleanup_source,
    )

    # String-encrypt the launcher's own small literal strings (cache
    # dir suffix, extracted filename, skip-rewrite hash) - the huge
    # payload blob is injected separately below, untouched by this
    # pass, then everything gets swept up together into one encrypted
    # blob by packer.pack() regardless.
    encrypted_logic, table, key, decrypt_fn_name = string_enc.encrypt_strings(logic)
    header = string_enc.build_runtime_header(table, key, decrypt_fn_name)

    payload_assignment = f"{v_payload} = {payload_b85!r}\n" + "".join(extra_payload_assignments)
    # libpython_fallback_source is injected OUTSIDE the string_enc pass
    # (unlike `logic`) - it's built from repr()/f-string-escaped Python
    # source containing runtime_fetch.py's own full text, and running
    # THAT through a second string-literal-rewriting AST pass would be
    # fragile for no real security benefit (it ends up inside the same
    # outer packer.pack() marshal+XOR envelope regardless, same as
    # everything else in this file).
    combined = payload_assignment + libpython_fallback_source + "\n" + header + "\n" + encrypted_logic

    if native_decryptor:
        # Chosen once per build and threaded through to BOTH the .so's
        # compiled-in digest_concat() call order (build_native_decryptor)
        # and the Python-side build_fragment_chain call for the SAME
        # chain (pack_with_native_decryptor) - these two absolutely
        # must agree, since the .so reconstructs the exact chain the
        # Python side built. See either function's own combine_order
        # docstring for why this exists at all: a real, confirmed-
        # working static-extraction script hardcoded the one shape
        # every prior build used unconditionally for exactly this
        # chain, to walk straight down to the embedded main binary.
        raw_material_combine_order = random.choice(("state_first", "cand_first"))
        native_blob, native_suffix = build_native_decryptor(combine_order=raw_material_combine_order)
        source = packer.pack_with_native_decryptor(
            combined,
            native_module_blob=native_blob,
            native_module_suffix=native_suffix,
            lock_filename=lock_filename,
            expected_filename=expected_filename,
            raw_material_combine_order=raw_material_combine_order,
        )
        with open(output_py_path, "w", encoding="utf-8") as f:
            f.write(source)
        return output_py_path

    # packer.pack() normally REQUIRES a real gate_env_name/gate_token
    # (see its own docstring) - but THIS specific call is exempt via
    # allow_no_gate=True, for a reason specific to this launcher: its
    # own source is entirely generic extract/exec/self-hash/lock-
    # filename logic, identical in shape across every build, with NO
    # user code or secrets of its own - what actually needs gate
    # protection is the EMBEDDED BINARY this launcher wraps (which
    # gets its own, independent gate protection upstream, from
    # require_launcher_gate=True on the ObfuscationConfig that built
    # it - see cli.py). Requiring a gate on the LAUNCHER too would be
    # circular: this launcher is what's SUPPOSED TO set the gate token
    # into the environment before running the wrapped binary (see
    # gate_setenv_source above) - if reading its own source required
    # that same token already be set, it could never run at all
    # without the user manually pre-setting an env var themselves
    # first, defeating the entire point of a self-contained launcher.
    launcher_gate_token_cache_var = _rand_name(set())
    source = packer.pack(
        combined,
        gate_env_name=None,
        gate_token=None,
        gate_token_cache_var=launcher_gate_token_cache_var,
        allow_no_gate=True,
        lock_filename=lock_filename,
        expected_filename=expected_filename,
    )

    with open(output_py_path, "w", encoding="utf-8") as f:
        f.write(source)

    return output_py_path
