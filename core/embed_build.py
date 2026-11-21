"""
embed_build.py - build a native binary from Python source using gcc
+ libpython directly, WITHOUT Cython.

Why this exists (vs cython_build.py):
  cython_build.py transpiles Python source into C - the actual
  control flow becomes C code, which is a structurally stronger
  form of protection but requires the `cython` package to be
  installed on the build machine (an extra pip dependency on top of
  gcc + python3-dev).

  This module skips that step entirely: the obfuscated Python source
  is compiled to ordinary CPython bytecode (marshal.dumps(compile(...))),
  XOR-encrypted, and embedded as a C byte array inside a small C
  program that links against libpython and executes that bytecode
  directly through the CPython C API at runtime (Py_Initialize +
  marshal.loads + PyEval_EvalCode). Only gcc/clang + python3-dev
  headers are needed to build - no Cython package required.

Trade-off (told to the user, not hidden):
  This is WEAKER protection than the Cython path. Cython actually
  transpiles the program's logic into C, so the control flow itself
  is gone from the shipped artifact. Here, the payload is still
  ordinary CPython bytecode - it's encrypted and wrapped in a real
  ELF (so `strings`/`file` won't show a readable .py, and the
  bytecode isn't sitting in the clear anywhere in the binary at
  rest), but if an attacker manages to reconstruct the decrypted
  bytes from a running/dumped process, marshal.loads() + dis.dis()
  or a bytecode decompiler still work on it, same as they would
  against packer.py's .py loader's unpacked payload. This is roughly
  the same protection tier as native_launcher.py (compiled wrapper +
  encrypted payload), applied to the Python source directly instead
  of to an already-built PyInstaller/Cython binary. Use the Cython
  path (menu 3) when the extra `pip install cython` is acceptable
  and you want the stronger structural protection.
"""
import hashlib
import marshal
import os
import random
import shutil
import string
import subprocess
import tempfile

from .crypto import xor_encrypt, random_key, build_fragment_chain
from .cython_build import _python_flags


class ToolchainError(RuntimeError):
    pass


def _find_cc():
    return shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")


def ensure_toolchain():
    cc = _find_cc()
    if cc is None:
        raise ToolchainError(
            "Compiler C (gcc/clang) tidak ketemu. Di Termux: "
            "`pkg install clang`. Di Debian/Ubuntu: `apt install gcc`."
        )
    if shutil.which("python3-config") is None:
        raise ToolchainError(
            "python3-config tidak ketemu (biasanya satu paket sama "
            "python3-dev / python3-devel). Install python3-dev dulu."
        )
    return cc


def _rand_identifier(n: int = 12) -> str:
    first = random.choice(string.ascii_lowercase)
    rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=max(n - 1, 0)))
    return first + rest


def _rand_names(n: int, used: set) -> list:
    out = []
    for _ in range(n):
        while True:
            cand = "_" + _rand_identifier(10)
            if cand not in used:
                used.add(cand)
                out.append(cand)
                break
    return out


def _c_byte_array(data: bytes) -> str:
    return ",".join(f"0x{b:02x}" for b in data)


# Same self-contained SHA-256 as native_launcher.py - no OpenSSL/
# libssl-dev dependency (Termux/Android builds often only have the
# runtime .so, not the dev headers -lcrypto needs).
_SHA256_C = r'''
typedef struct { uint32_t state[8]; uint64_t bitlen; unsigned char buf[64]; size_t buflen; } sha256_ctx;

static const uint32_t sha256_k[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define SHA256_ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))

static void sha256_transform(sha256_ctx *ctx, const unsigned char *data) {
    uint32_t m[64], a, b, c, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; i++)
        m[i] = (data[i*4]<<24)|(data[i*4+1]<<16)|(data[i*4+2]<<8)|(data[i*4+3]);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = SHA256_ROTR(m[i-15],7) ^ SHA256_ROTR(m[i-15],18) ^ (m[i-15] >> 3);
        uint32_t s1 = SHA256_ROTR(m[i-2],17) ^ SHA256_ROTR(m[i-2],19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = SHA256_ROTR(e,6) ^ SHA256_ROTR(e,11) ^ SHA256_ROTR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + sha256_k[i] + m[i];
        uint32_t S0 = SHA256_ROTR(a,2) ^ SHA256_ROTR(a,13) ^ SHA256_ROTR(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(ctx->state, iv, sizeof(iv));
    ctx->bitlen = 0; ctx->buflen = 0;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_transform(ctx, ctx->buf);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char *out) {
    size_t i = ctx->buflen;
    ctx->bitlen += (uint64_t)ctx->buflen * 8;
    ctx->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buf[i++] = 0;
        sha256_transform(ctx, ctx->buf);
        i = 0;
    }
    while (i < 56) ctx->buf[i++] = 0;
    for (int j = 7; j >= 0; j--) ctx->buf[i++] = (unsigned char)(ctx->bitlen >> (j*8));
    sha256_transform(ctx, ctx->buf);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(ctx->state[i] >> 24);
        out[i*4+1] = (unsigned char)(ctx->state[i] >> 16);
        out[i*4+2] = (unsigned char)(ctx->state[i] >> 8);
        out[i*4+3] = (unsigned char)(ctx->state[i]);
    }
}

static void sha256(const unsigned char *data, size_t len, unsigned char *out) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}
'''


def compile_source_to_binary(source: str, output_path: str, lock_filename: bool = False,
                              expected_filename: str = None, keep_c_file: bool = False,
                              self_integrity_check: bool = True):
    """
    source: fully obfuscated python source (anti-debug merged in,
            string-encrypted, junk already inserted, identifiers
            renamed - i.e. what obfuscate_source() produces), ready
            to compile() + marshal.
    output_path: where to write the resulting native binary.
    self_integrity_check: default True. Same file-level tamper
            detection as native_launcher.py's self_integrity_check
            (see that function's docstring for the full mechanism) -
            previously this mode had NO file-integrity check at all,
            unlike native_launcher.py and packer.py's .py loader,
            which both already had one. Two-pass build (compile with
            a placeholder hash, then patch the real hash in after
            strip), checked at every startup via /proc/self/exe.
    Returns output_path on success, raises ToolchainError/RuntimeError.

    Pipeline: source -> compile() -> marshal.dumps() -> XOR-encrypt
    -> embed as C byte array -> gcc links against libpython -> the
    compiled binary decrypts the bytes at startup and runs them via
    marshal.loads() + PyEval_EvalCode inside the CPython C API. No
    Cython/pip dependency, only gcc + python3-dev.

    The XOR key is now stored as junk-key fragments + a hash-chain
    selection (see crypto.split_key_with_junk/build_fragment_chain,
    and native_launcher.py's build_native_launcher for the C
    implementation this mirrors) rather than one single 32-byte C
    array declared right next to the ciphertext it decrypts - the
    previous scheme here (and native_launcher.py's, before it got the
    same fix) was weaker than even packer.py's OLD (pre-junk-key) .py
    loader scheme, since there wasn't even chunk-scattering at all.
    """
    cc = ensure_toolchain()

    code_obj = compile(source, "<vh>", "exec")
    blob = marshal.dumps(code_obj)

    key = random_key(32)
    enc = xor_encrypt(blob, key)
    payload_hash = hashlib.sha256(blob).hexdigest()
    ciphertext_hash = hashlib.sha256(enc).hexdigest()

    lock_name = expected_filename if (lock_filename and expected_filename) else ""

    # Junk-key fragments + hash-chain selection - see this function's
    # docstring and native_launcher.py's build_native_launcher (which
    # this mirrors) for the full rationale.
    FRAG_LEN = 8
    real_key_frags = [key[i:i + FRAG_LEN].ljust(FRAG_LEN, b"\x00") for i in range(0, len(key), FRAG_LEN)]
    n_junk_frags = random.randint(5, 9)
    junk_frags = [os.urandom(FRAG_LEN) for _ in range(n_junk_frags)]

    all_key_frags = real_key_frags + junk_frags
    frag_decl_order = list(range(len(all_key_frags)))
    random.shuffle(frag_decl_order)
    shuffled_key_frags = [all_key_frags[i] for i in frag_decl_order]
    real_key_positions = [frag_decl_order.index(i) for i in range(len(real_key_frags))]

    key_seed, key_tags = build_fragment_chain(shuffled_key_frags, real_key_positions, tag_len=4)

    n_frags_total = len(shuffled_key_frags)
    frag_len = FRAG_LEN
    n_key_tags = len(key_tags)
    key_tag_len = len(key_tags[0]) if key_tags else 4
    keyfrags_c_rows = ",\n".join("    {" + _c_byte_array(f) + "}" for f in shuffled_key_frags)
    keytags_c_rows = ",\n".join("    {" + _c_byte_array(t) + "}" for t in key_tags)

    used = set()
    (v_payload, v_payload_len, v_key, v_hash, v_ct_hash, v_lock_name,
     fn_ks, fn_xor, fn_hex, fn_hash_eq, fn_basename_eq, fn_watchdog) = _rand_names(12, used)
    (v_keyfrags, v_keyseed, v_keytags, fn_pickkey) = _rand_names(4, used)

    # Self-hash placeholder (see native_launcher.py's build_native_launcher
    # for the same two-pass compile-then-patch technique): a 64-char
    # zero placeholder is compiled in first, the final (post-strip)
    # binary is hashed, and the placeholder bytes are found-and-
    # replaced with the real hash - same length in, same length out,
    # so no other file offset shifts.
    self_hash_placeholder = "0" * 64
    (v_self_hash, fn_self_check) = _rand_names(2, used)
    # When explicitly disabled, skip the self-hash gate in main();
    # otherwise an unpatched placeholder would make the binary reject itself.
    self_hash_check_call = (
        f"if (!{fn_self_check}()) {{\n        return 1;\n    }}"
        if self_integrity_check else ""
    )

    c_source = f'''
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

{_SHA256_C}

/* Key material is a pool of {n_frags_total} fixed-length ({frag_len}-byte)
   fragments (real + decoy, format-indistinguishable) - see this
   module's compile_source_to_binary docstring. {fn_pickkey}()
   reconstructs the real key via the hash chain ({v_keyseed} +
   {v_keytags}), same scheme as native_launcher.py's build_native_launcher. */
static const unsigned char {v_keyfrags}[{n_frags_total}][{frag_len}] = {{
{keyfrags_c_rows}
}};
static const unsigned char {v_keyseed}[32] = {{{_c_byte_array(key_seed)}}};
static const unsigned char {v_keytags}[{n_key_tags}][{key_tag_len}] = {{
{keytags_c_rows}
}};
static const unsigned char {v_payload}[] = {{{_c_byte_array(enc)}}};
static const size_t {v_payload_len} = sizeof({v_payload});
static const char {v_hash}[] = "{payload_hash}";
static const char {v_ct_hash}[] = "{ciphertext_hash}";
static const char {v_lock_name}[] = "{lock_name}";
/* NOT const - fn_self_check zeroes these bytes out in its own
   in-memory copy (matching the placeholder that was in this exact
   spot BEFORE this constant was patched with the real hash) rather
   than touching the file on disk. */
static char {v_self_hash}[65] = "{self_hash_placeholder}";

static void {fn_pickkey}(unsigned char *out_key) {{
    unsigned char state[32];
    memcpy(state, {v_keyseed}, 32);
    int used_flag[{n_frags_total}] = {{0}};
    for (int t = 0; t < {n_key_tags}; t++) {{
        int found = -1;
        unsigned char digest[32];
        for (int c = 0; c < {n_frags_total}; c++) {{
            if (used_flag[c]) continue;
            unsigned char buf[32 + {frag_len}];
            memcpy(buf, state, 32);
            memcpy(buf + 32, {v_keyfrags}[c], {frag_len});
            sha256(buf, 32 + {frag_len}, digest);
            if (memcmp(digest, {v_keytags}[t], {key_tag_len}) == 0) {{
                found = c;
                break;
            }}
        }}
        if (found < 0) {{
            memset(out_key, 0, 32);
            return;
        }}
        used_flag[found] = 1;
        memcpy(out_key + (t * {frag_len}), {v_keyfrags}[found], {frag_len});
        memcpy(state, digest, 32);
    }}
}}

static int {fn_self_check}(void) {{
    FILE *f = fopen("/proc/self/exe", "rb");
    if (!f) return 1;  /* can't verify (unsupported OS/sandbox) - fail OPEN, not closed */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {{ fclose(f); return 1; }}
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {{ fclose(f); return 1; }}
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {{ free(buf); return 1; }}
    size_t needle_len = 64;
    long found_at = -1;
    for (long i = 0; i + (long)needle_len <= sz; i++) {{
        if (memcmp(buf + i, {v_self_hash}, needle_len) == 0) {{
            found_at = i;
            break;
        }}
    }}
    if (found_at < 0) {{ free(buf); return 0; }}
    memset(buf + found_at, '0', needle_len);
    unsigned char digest[32];
    sha256(buf, (size_t)sz, digest);
    free(buf);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
    return memcmp(hex, {v_self_hash}, 64) == 0;
}}

static int {fn_basename_eq}(const char *argv0) {{
    if ({v_lock_name}[0] == '\\0') return 1;
    const char *base = argv0;
    for (const char *p = argv0; *p; p++) {{
        if (*p == '/' || *p == '\\\\') base = p + 1;
    }}
    return strcmp(base, {v_lock_name}) == 0;
}}

static void {fn_ks}(const unsigned char *key, size_t key_len, unsigned char *out, size_t out_len) {{
    unsigned char block[32];
    memcpy(block, key, 32);
    size_t filled = 0;
    while (filled < out_len) {{
        unsigned char digest[32];
        sha256(block, 32, digest);
        memcpy(block, digest, 32);
        size_t take = out_len - filled;
        if (take > 32) take = 32;
        memcpy(out + filled, digest, take);
        filled += take;
    }}
}}

static unsigned char *{fn_xor}(const unsigned char *data, size_t len, const unsigned char *key) {{
    unsigned char *ks = malloc(len);
    unsigned char *out = malloc(len);
    if (!ks || !out) {{ exit(1); }}
    {fn_ks}(key, 32, ks, len);
    for (size_t i = 0; i < len; i++) out[i] = data[i] ^ ks[i];
    free(ks);
    return out;
}}

static void {fn_hex}(const unsigned char *digest, char *out_hex) {{
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {{
        out_hex[i * 2] = hexchars[(digest[i] >> 4) & 0xf];
        out_hex[i * 2 + 1] = hexchars[digest[i] & 0xf];
    }}
    out_hex[64] = '\\0';
}}

static int {fn_hash_eq}(const unsigned char *data, size_t len, const char *expected_hex) {{
    unsigned char digest[32];
    sha256(data, len, digest);
    char hex[65];
    {fn_hex}(digest, hex);
    return strcmp(hex, expected_hex) == 0;
}}

/* Periodically re-checks the hash of the still-resident encrypted
   payload array for the life of the process, instead of only once
   at startup before Py_Initialize(). A one-time check only catches
   tampering that happened to the file ON DISK before this process
   started - it says nothing about the array being patched IN MEMORY
   after the process is already running (e.g. a debugger attaching
   and overwriting bytes, or /proc/<pid>/mem writes). The check
   target is the CIPHERTEXT array (v_payload), not the decrypted
   plaintext: the plaintext buffer is freed right after it's handed
   to Python, but the ciphertext stays resident in .rodata for the
   whole process life, so it's the thing a periodic re-check can
   actually keep watching. pthread_detach makes this a fire-and-forget
   background thread that never blocks normal process exit - same
   role as daemon=True for the .py loader's watchdog thread. */
static void *{fn_watchdog}(void *arg) {{
    (void)arg;
    for (;;) {{
        struct timespec ts;
        ts.tv_sec = 3 + (time(NULL) % 4);
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
        if (!{fn_hash_eq}({v_payload}, {v_payload_len}, {v_ct_hash})) {{
            _exit(1);
        }}
    }}
    return NULL;
}}

int main(int argc, char **argv) {{
    if (argc < 1 || !{fn_basename_eq}(argv[0])) {{
        return 1;
    }}
    {self_hash_check_call}

    unsigned char {v_key}[32];
    {fn_pickkey}({v_key});
    unsigned char *dec = {fn_xor}({v_payload}, {v_payload_len}, {v_key});
    if (!{fn_hash_eq}(dec, {v_payload_len}, {v_hash})) {{
        free(dec);
        return 1;
    }}

    pthread_t _watchdog_thread;
    if (pthread_create(&_watchdog_thread, NULL, {fn_watchdog}, NULL) == 0) {{
        pthread_detach(_watchdog_thread);
    }}

    wchar_t *prog_name = Py_DecodeLocale(argv[0], NULL);
    Py_SetProgramName(prog_name);
    Py_Initialize();

    PyObject *code_bytes = PyBytes_FromStringAndSize((const char *)dec, (Py_ssize_t){v_payload_len});
    free(dec);
    if (!code_bytes) {{ PyErr_Print(); Py_Finalize(); return 1; }}

    PyObject *marshal_module = PyImport_ImportModule("marshal");
    PyObject *loads_fn = PyObject_GetAttrString(marshal_module, "loads");
    PyObject *code_obj = PyObject_CallFunctionObjArgs(loads_fn, code_bytes, NULL);
    Py_DECREF(code_bytes);
    Py_DECREF(loads_fn);
    Py_DECREF(marshal_module);

    if (!code_obj) {{ PyErr_Print(); Py_Finalize(); return 1; }}

    PyObject *main_module = PyImport_AddModule("__main__");
    PyObject *main_dict = PyModule_GetDict(main_module);
    PyObject *result = PyEval_EvalCode(code_obj, main_dict, main_dict);
    Py_DECREF(code_obj);

    int rc = 0;
    if (!result) {{
        PyErr_Print();
        rc = 1;
    }} else {{
        Py_DECREF(result);
    }}

    if (Py_FinalizeEx() < 0) rc = 120;
    PyMem_RawFree(prog_name);
    return rc;
}}
'''

    with tempfile.TemporaryDirectory(prefix=f"eb{_rand_identifier(6)}_") as work_dir:
        c_path = os.path.join(work_dir, f"{_rand_identifier(10)}.c")
        with open(c_path, "w", encoding="utf-8") as f:
            f.write(c_source)

        abs_output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)

        includes, ldflags = _python_flags()
        gcc_cmd = (
            [cc, "-Os", "-fvisibility=hidden", "-w", "-o", abs_output_path, c_path]
            + includes + ldflags + ["-lpthread"]
        )
        r = subprocess.run(gcc_cmd, capture_output=True, text=True, cwd=work_dir)
        if r.returncode != 0:
            raise RuntimeError(f"gcc link gagal:\n{r.stdout}\n{r.stderr}\ncmd: {' '.join(gcc_cmd)}")

        if keep_c_file:
            kept_c = os.path.join(os.path.dirname(abs_output_path) or ".", "_vh_embed_build.c")
            shutil.copyfile(c_path, kept_c)

    strip_bin = shutil.which("strip")
    if strip_bin:
        subprocess.run([strip_bin, "--strip-all", output_path], capture_output=True)

    os.chmod(output_path, 0o755)

    if self_integrity_check:
        with open(output_path, "rb") as f:
            final_bytes = f.read()
        real_hash = hashlib.sha256(final_bytes).hexdigest()
        placeholder_bytes = self_hash_placeholder.encode("ascii")
        idx = final_bytes.find(placeholder_bytes)
        if idx == -1:
            raise RuntimeError(
                "self_integrity_check: placeholder gak ketemu di binary hasil compile - "
                "kemungkinan compiler mengoptimasi/reorder data section dengan cara yang "
                "gak terduga. Coba build ulang dengan self_integrity_check=False dulu buat "
                "isolasi masalahnya, atau laporkan sebagai bug."
            )
        patched = bytearray(final_bytes)
        patched[idx:idx + 64] = real_hash.encode("ascii")
        with open(output_path, "wb") as f:
            f.write(patched)
        os.chmod(output_path, 0o755)

    return output_path
