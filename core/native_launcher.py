"""
native_launcher.py - alternative to bootstrap.wrap_binary_as_py that
produces a real compiled ELF/PE launcher instead of a .py file.

Why this exists:
  bootstrap.wrap_binary_as_py's output is still, fundamentally, a
  Python source file - packer.pack() hides the *payload* behind
  encryption, but the extract/chmod/exec LOADER LOGIC ITSELF has to
  exist as plaintext-readable Python for the interpreter to be able
  to start running it at all. An attacker just reads the file.

  This module sidesteps that entirely: the extract/chmod/exec logic
  is written as C, compiled to a real native binary via the same
  gcc toolchain used by cython_build.py, and the embedded payload
  bytes are XOR-encrypted before being baked in as a C byte array -
  so a `strings` dump of the launcher binary shows neither the inner
  ELF's structure nor any Python decrypt routine, only compiled
  machine code. There is no plaintext loader logic on disk at all,
  at any point - which is what the .py-based launcher can never
  achieve as long as it ships as interpreted Python source.

Trade-off (told to the user, not hidden):
  needs a C toolchain on the build machine (same requirement as the
  Cython native-binary mode), and produces a platform-specific
  binary rather than a portable .py file. Doesn't need Cython
  itself though - this path only needs gcc/clang.
"""
import hashlib
import os
import random
import shutil
import string
import subprocess
import tempfile

from .crypto import xor_encrypt, random_key, build_fragment_chain, split_key_with_junk


class ToolchainError(RuntimeError):
    pass


def _read_sibling_source(filename: str) -> str:
    """Reads another module's source from this same core/ directory,
    for embedding as a plain string blob into generated C/Python code
    (e.g. runtime_fetch.py's fetch/cache logic, embedded so a
    standalone launcher binary can use it without `core` needing to
    be an importable package on the target machine)."""
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# Self-contained, public-domain-style SHA-256 in C (no OpenSSL/libssl
# dependency - Termux/Android builds often don't have libssl-dev
# installed, only the runtime .so, so linking -lcrypto would break
# there even though the tool's own Python side never needed it: SHA256
# elsewhere in this project comes from stdlib hashlib, not an external
# lib, and this keeps the native launcher consistent with that).
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


def _find_cc():
    return shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")


def ensure_toolchain():
    cc = _find_cc()
    if cc is None:
        raise ToolchainError(
            "Compiler C (gcc/clang) tidak ketemu. Di Termux: "
            "`pkg install clang`. Di Debian/Ubuntu: `apt install gcc`."
        )
    return cc


def _rand_identifier(n: int = 12) -> str:
    first = random.choice(string.ascii_lowercase)
    rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=max(n - 1, 0)))
    return first + rest


def _c_byte_array(data: bytes) -> str:
    """Render bytes as a C initializer list body, e.g. '0x1a,0x2f,...'."""
    return ",".join(f"0x{b:02x}" for b in data)


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


def build_native_launcher(binary_path: str, output_path: str, embedded_name: str = None,
                           keep_c_file: bool = False, lock_filename: bool = False,
                           expected_filename: str = None, extra_files: dict = None,
                           gate_env_name: str = None, gate_token: str = None,
                           ensure_libpython_version: tuple = None,
                           self_integrity_check: bool = True):
    """
    binary_path: path to an already-built binary (PyInstaller or
                 Cython output) to embed and launch.
    output_path: where to write the resulting native launcher binary.
    embedded_name: filename to use once extracted (default: basename
                   of binary_path).
    lock_filename / expected_filename: if lock_filename is True, the
                 launcher refuses to run unless its own filename on
                 disk (argv[0]'s basename) matches expected_filename
                 exactly - same behavior as packer.py's .py launcher,
                 blocking simple rename + redistribute tampering.
    extra_files: optional {filename: bytes} for companion files that
                 must be extracted alongside the main binary, in the
                 SAME directory, before the main binary runs - e.g.
                 cython_guard.py's "__cyinner" child binary. See
                 bootstrap.wrap_binary_as_py's docstring for the full
                 rationale; this is the native/C equivalent of the
                 same mechanism.
    gate_env_name / gate_token: if the embedded binary was itself
                 built with ObfuscationConfig(require_launcher_gate=True)
                 (via embed_build.py/cython_build.py using the same
                 obfuscator.generate_gate_info() pair), pass that
                 same env_name/token here. This launcher's compiled C
                 will then setenv() that variable to that token in
                 its own process right before execv()'ing the
                 extracted binary - which execv inherits into the
                 child's environment automatically. This closes the
                 "found the extracted binary's cache path, ran it
                 directly, skipped this launcher entirely" bypass:
                 without this launcher setting that env var, the
                 embedded binary's own gate check (baked in at ITS
                 build time, independent of this launcher) refuses to
                 start. Leave both None if the embedded binary wasn't
                 built with require_launcher_gate.
    ensure_libpython_version: pass (major, minor) - e.g. (3, 12) - when
                 the wrapped binary_path is a Cython/embed build that
                 dynamically links against libpythonX.Y.so at compile
                 time (cython_build.py's normal output). Unlike a
                 PyInstaller binary (fully self-contained, needs
                 nothing extra) or a marshal .py loader (version
                 mismatch is fixable at the Python interpreter level -
                 see packer.py/runtime_fetch.py), a Cython binary's
                 libpython dependency is resolved by the OS's dynamic
                 linker BEFORE any Python code - including this
                 project's own version-fallback logic - ever runs. If
                 the target machine doesn't have a matching
                 libpythonX.Y.so installed, the OS refuses to even
                 start the process (a loader-level error, not
                 something Python can catch or recover from).
                 When set, this launcher's compiled C checks (via
                 dlopen(), the standard portable way to test "can this
                 shared library be loaded" without actually needing
                 it linked at compile time of the LAUNCHER itself -
                 only the wrapped Cython binary needs it) whether a
                 matching libpythonX.Y is already loadable on the
                 target machine. If yes: zero extra cost, proceeds
                 straight to execv() as normal. If no: shells out to
                 whatever `python3` is on PATH (ANY version works here
                 - it's only used to run download/extract logic, not
                 to execute the protected payload itself) to download
                 just that one .so file from python-build-standalone
                 (reusing the exact same cache directory,
                 ~/.vh_runtimes/, that packer.py's version-fallback
                 uses - so a machine that already hit a mismatch via
                 mode 1 doesn't need to download it again for mode 3,
                 and vice versa), then sets LD_LIBRARY_PATH to point
                 at it before execv()'ing the real binary. Leave None
                 (default) for PyInstaller-built binaries, which never
                 need this.
    self_integrity_check: default True. Closes a DIFFERENT gap from
                 the existing SHA256 check on the CACHED/extracted
                 binary_path payload (which only ever verifies "the
                 copy sitting in ~/.vh_runtimes/ wasn't corrupted since
                 last extracted" - it says nothing about the LAUNCHER
                 binary itself). When True, this launcher's own
                 compiled bytes are self-hashed at build time (via the
                 same placeholder-then-patch technique packer.py uses
                 for its .py loader's self-hash - see the
                 build_native_launcher implementation for the two-pass
                 compile), and at every startup the launcher re-reads
                 its own file from /proc/self/exe, re-hashes it (with
                 the stored-hash bytes themselves zeroed out first, so
                 the check doesn't have to hash itself INCLUDING its
                 own answer), and refuses to run if that doesn't match
                 what was baked in at build time. This is what actually
                 detects "someone opened this ELF in a hex editor/
                 radare2/Ghidra and patched a byte atau dua" (misalnya
                 mengubah pemeriksaan integritas) - static-file tamper
                 sebelum launcher melakukan ekstraksi. Pemeriksaan ini
                 hanya memvalidasi artefak on-disk sebelum eksekusi;
                 integritas memori setelah program berjalan berada di
                 luar kontraknya.

    Returns output_path on success, raises ToolchainError/RuntimeError.

    Behavior mirrors bootstrap.wrap_binary_as_py: extracts the
    embedded payload to a writable+executable location (never
    /sdcard on Android/Termux), skips rewriting if an identical copy
    is already there (checked via SHA256), chmods it executable, and
    execs it with argv/exit-code forwarded.
    """
    cc = ensure_toolchain()

    with open(binary_path, "rb") as f:
        raw = f.read()

    key = random_key(32)
    enc = xor_encrypt(raw, key)
    payload_hash = hashlib.sha256(raw).hexdigest()
    name = embedded_name or os.path.basename(binary_path)
    lock_name = expected_filename if (lock_filename and expected_filename) else ""

    # Junk-key fragments + hash-chain selection (C port of the same
    # scheme packer.py uses for the .py loader's AES key - see
    # crypto.split_key_with_junk/build_fragment_chain's docstrings for
    # the full rationale). Previously this XOR key was stored as ONE
    # single 32-byte C array declared right next to the ciphertext it
    # decrypts - format-wise weaker than even the .py loader's OLD
    # (pre-junk-key) scheme, since there wasn't even chunk-scattering
    # here at all. Fixed 8-byte fragments (rather than
    # variable-length like the Python version) keep the C array
    # declarations simple and uniform - real and decoy fragments are
    # then completely indistinguishable by shape.
    FRAG_LEN = 8
    n_real_frags = (len(key) + FRAG_LEN - 1) // FRAG_LEN  # ceil division
    real_key_frags = [key[i:i + FRAG_LEN].ljust(FRAG_LEN, b"\x00") for i in range(0, len(key), FRAG_LEN)]
    # (key is 32 bytes, FRAG_LEN=8 -> exactly 4 fragments, no padding
    # needed in practice, but the ljust above is defensive if this
    # constant ever changes)
    n_junk_frags = random.randint(5, 9)
    junk_frags = [os.urandom(FRAG_LEN) for _ in range(n_junk_frags)]

    all_key_frags = real_key_frags + junk_frags
    frag_decl_order = list(range(len(all_key_frags)))
    random.shuffle(frag_decl_order)
    shuffled_key_frags = [all_key_frags[i] for i in frag_decl_order]
    # real_key_positions: for each real fragment (in ORIGINAL key
    # order), its position in shuffled_key_frags.
    real_key_positions = [frag_decl_order.index(i) for i in range(len(real_key_frags))]

    key_seed, key_tags = build_fragment_chain(shuffled_key_frags, real_key_positions, tag_len=4)

    n_frags_total = len(shuffled_key_frags)
    frag_len = FRAG_LEN
    n_key_tags = len(key_tags)
    key_tag_len = len(key_tags[0]) if key_tags else 4
    keyfrags_c_rows = ",\n".join(
        "    {" + _c_byte_array(f) + "}" for f in shuffled_key_frags
    )
    keytags_c_rows = ",\n".join(
        "    {" + _c_byte_array(t) + "}" for t in key_tags
    )

    used = set()
    (v_payload, v_payload_len, v_key, v_hash, v_cachedir, v_name,
     fn_ks, fn_xor, fn_hex, fn_extract, fn_hash_eq) = _rand_names(11, used)
    (v_lock_name, fn_basename_eq) = _rand_names(2, used)
    (v_gate_env,) = _rand_names(1, used)
    (v_self_hash, fn_self_check) = _rand_names(2, used)
    (v_keyfrags, v_keyseed, v_keytags, fn_pickkey) = _rand_names(4, used)
    (v_gt_enc, v_gt_enc_len, v_gt_keyfrags, v_gt_keyseed, v_gt_keytags,
     fn_gt_pickkey, v_gt_buf) = _rand_names(7, used)

    cache_dir_name = "." + _rand_identifier(10)

    # Same placeholder-then-patch technique packer.py uses for its .py
    # loader's self-hash: a fixed-length (64 hex chars = SHA256 digest
    # length) dummy string is compiled in first, the resulting binary
    # is hashed, and the placeholder bytes are found-and-replaced with
    # the real hash - since the replacement is byte-for-byte the same
    # LENGTH as the placeholder, this never shifts any other offset in
    # the file, which is what makes patching a pre-linked binary safe.
    self_hash_placeholder = "0" * 64

    has_gate = bool(gate_env_name and gate_token is not None)
    # C string literals can't contain a raw '"' or '\' unescaped -
    # env var names and hex tokens generated by this project's own
    # _rand_env_name()/secrets.token_hex() never contain either, but
    # escape defensively anyway in case a caller passes something
    # unexpected through these params.
    def _c_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def _c_escape_multiline(s: str) -> str:
        """
        Like _c_escape, but also escapes newlines/tabs/carriage returns
        - needed for embedding a whole multi-line Python script as one
        C string literal (fputs("...")). A raw, un-escaped newline
        inside a C string literal is a syntax error (C string literals
        can't span lines without an escape) - this is what broke the
        first attempt at embedding runtime_fetch.py/libpython_fetch.py
        wholesale via the short-string-only _c_escape.
        """
        return (
            s.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\n", "\\n")
             .replace("\r", "\\r")
             .replace("\t", "\\t")
        )
    gate_env_c = _c_escape(gate_env_name) if has_gate else ""

    # gate_token protection: previously stored as a plain
    # `static const char [] = "..."` C string literal - a `strings
    # <launcher_binary>` dump showed the token in cleartext with zero
    # effort, no reversing needed at all. That defeats this whole
    # launcher's purpose (see module docstring: "no plaintext loader
    # logic on disk at all"), and specifically defeats the gate
    # mechanism this exact parameter exists for - the WHOLE POINT of
    # gate_env_name/gate_token is that an attacker who skips this
    # launcher and runs the extracted binary directly shouldn't have
    # the token; a plaintext copy sitting right here in the launcher
    # handed it over anyway. Fixed by reusing the same junk-key +
    # hash-chain fragment scheme already used for the embedded
    # payload's XOR key (see split_key_with_junk/build_fragment_chain
    # above): the token's bytes are XOR-encrypted with a random
    # 32-byte key, and THAT key - not the token - is what gets
    # scattered into indistinguishable real+decoy fragments selected
    # via a hash chain. Reconstruction happens in C at runtime, right
    # before the token is needed for setenv(), the same way
    # {fn_pickkey} reconstructs the payload key.
    if has_gate:
        gate_token_bytes = gate_token.encode("utf-8")
        gate_token_xor_key = random_key(32)
        gate_token_enc = xor_encrypt(gate_token_bytes, gate_token_xor_key)

        GT_FRAG_LEN = 8
        gt_real_frags = [gate_token_xor_key[i:i + GT_FRAG_LEN].ljust(GT_FRAG_LEN, b"\x00")
                          for i in range(0, len(gate_token_xor_key), GT_FRAG_LEN)]
        gt_n_junk = random.randint(5, 9)
        gt_junk_frags = [os.urandom(GT_FRAG_LEN) for _ in range(gt_n_junk)]
        gt_all_frags = gt_real_frags + gt_junk_frags
        gt_decl_order = list(range(len(gt_all_frags)))
        random.shuffle(gt_decl_order)
        gt_shuffled_frags = [gt_all_frags[i] for i in gt_decl_order]
        gt_real_positions = [gt_decl_order.index(i) for i in range(len(gt_real_frags))]
        gt_key_seed, gt_key_tags = build_fragment_chain(gt_shuffled_frags, gt_real_positions, tag_len=4)

        gt_n_frags_total = len(gt_shuffled_frags)
        gt_n_key_tags = len(gt_key_tags)
        gt_key_tag_len = len(gt_key_tags[0]) if gt_key_tags else 4
        gt_keyfrags_c_rows = ",\n".join(
            "    {" + _c_byte_array(f) + "}" for f in gt_shuffled_frags
        )
        gt_keytags_c_rows = ",\n".join(
            "    {" + _c_byte_array(t) + "}" for t in gt_key_tags
        )
        gt_token_len = len(gate_token_enc)

        gate_token_consts_src = (
            f"static const unsigned char {v_gt_keyfrags}[{gt_n_frags_total}][{GT_FRAG_LEN}] = {{\n"
            f"{gt_keyfrags_c_rows}\n"
            f"}};\n"
            f"static const unsigned char {v_gt_keyseed}[32] = {{{_c_byte_array(gt_key_seed)}}};\n"
            f"static const unsigned char {v_gt_keytags}[{gt_n_key_tags}][{gt_key_tag_len}] = {{\n"
            f"{gt_keytags_c_rows}\n"
            f"}};\n"
            f"static const unsigned char {v_gt_enc}[] = {{{_c_byte_array(gate_token_enc)}}};\n"
            f"static const size_t {v_gt_enc_len} = sizeof({v_gt_enc});"
        )
        # Reconstructs the 32-byte XOR key that decrypts the gate
        # token, via the exact same hash-chain walk as {fn_pickkey}
        # above (kept as a separate function/array set so the two
        # fragment pools - payload key vs gate-token key - can't be
        # cross-mixed by a reader trying candidates from the wrong
        # pool). {v_gt_buf} is written by the caller directly into
        # a stack buffer sized for the token plus a NUL terminator.
        gate_token_pickkey_src = f'''
static void {fn_gt_pickkey}(unsigned char *out_key) {{
    unsigned char state[32];
    memcpy(state, {v_gt_keyseed}, 32);
    int used_flag[{gt_n_frags_total}] = {{0}};
    for (int t = 0; t < {gt_n_key_tags}; t++) {{
        int found = -1;
        unsigned char digest[32];
        for (int c = 0; c < {gt_n_frags_total}; c++) {{
            if (used_flag[c]) continue;
            unsigned char buf[32 + {GT_FRAG_LEN}];
            memcpy(buf, state, 32);
            memcpy(buf + 32, {v_gt_keyfrags}[c], {GT_FRAG_LEN});
            sha256(buf, 32 + {GT_FRAG_LEN}, digest);
            if (memcmp(digest, {v_gt_keytags}[t], {gt_key_tag_len}) == 0) {{
                found = c;
                break;
            }}
        }}
        if (found < 0) {{
            memset(out_key, 0, 32);
            return;
        }}
        used_flag[found] = 1;
        memcpy(out_key + (t * {GT_FRAG_LEN}), {v_gt_keyfrags}[found], {GT_FRAG_LEN});
        memcpy(state, digest, 32);
    }}
}}'''
    else:
        gate_token_consts_src = ""
        gate_token_pickkey_src = ""

    if has_gate:
        gate_setenv_block = f'''    if ({v_gate_env}[0] != '\\0') {{
        /* setenv() affects OUR process's environment; execv() passes
           the calling process's environment through to the new
           program image unchanged, so the extracted binary inherits
           it automatically - letting that binary's own gate check
           (baked in at ITS build time) see the token and pass, while
           anyone running the extracted binary directly - skipping
           this launcher - never gets this variable set and fails.
           The token itself is reconstructed here, right before use,
           from the junk-key + hash-chain fragments above ({fn_gt_pickkey})
           rather than sitting as a static plaintext string anywhere
           in this binary - a `strings` dump of this launcher no
           longer hands the gate token over for free. */
        unsigned char {v_gt_buf}_key[32];
        {fn_gt_pickkey}({v_gt_buf}_key);
        unsigned char *{v_gt_buf}_dec = {fn_xor}({v_gt_enc}, {v_gt_enc_len}, {v_gt_buf}_key);
        char {v_gt_buf}[{gt_token_len} + 1];
        memcpy({v_gt_buf}, {v_gt_buf}_dec, {gt_token_len});
        {v_gt_buf}[{gt_token_len}] = '\\0';
        free({v_gt_buf}_dec);
        setenv({v_gate_env}, {v_gt_buf}, 1);
        memset({v_gt_buf}, 0, sizeof({v_gt_buf}));
        memset({v_gt_buf}_key, 0, sizeof({v_gt_buf}_key));
    }}'''
    else:
        gate_setenv_block = ""

    # One embedded array + hash + tiny extract-if-needed block per
    # extra file, written into the SAME cache dir as the main binary
    # (so a relative lookup like cython_guard's /proc/self/exe-based
    # resolution finds it right next to the main binary afterward).
    extra_files = extra_files or {}
    extra_consts = []
    extra_extract_calls = []
    extra_fn_blocks = []
    for extra_name, extra_bytes in extra_files.items():
        extra_key = random_key(32)
        extra_enc = xor_encrypt(extra_bytes, extra_key)
        extra_hash = hashlib.sha256(extra_bytes).hexdigest()
        (v_ekey, v_epayload, v_epayload_len, v_ehash, v_ename, fn_eextract) = _rand_names(6, used)
        extra_consts.append(
            f"static const unsigned char {v_ekey}[32] = {{{_c_byte_array(extra_key)}}};\n"
            f"static const unsigned char {v_epayload}[] = {{{_c_byte_array(extra_enc)}}};\n"
            f"static const size_t {v_epayload_len} = sizeof({v_epayload});\n"
            f'static const char {v_ehash}[] = "{extra_hash}";\n'
            f'static const char {v_ename}[] = "{extra_name}";'
        )
        extra_fn_blocks.append(f'''
static void {fn_eextract}(const char *dir) {{
    static char target[4096];
    snprintf(target, sizeof(target), "%s/%s", dir, {v_ename});
    FILE *existing = fopen(target, "rb");
    if (existing) {{
        fseek(existing, 0, SEEK_END);
        long sz = ftell(existing);
        fseek(existing, 0, SEEK_SET);
        if (sz > 0) {{
            unsigned char *buf = malloc((size_t)sz);
            if (buf && fread(buf, 1, (size_t)sz, existing) == (size_t)sz) {{
                if ({fn_hash_eq}(buf, (size_t)sz, {v_ehash})) {{
                    free(buf);
                    fclose(existing);
                    return;
                }}
            }}
            free(buf);
        }}
        fclose(existing);
    }}
    unsigned char *dec = {fn_xor}({v_epayload}, {v_epayload_len}, {v_ekey});
    FILE *out = fopen(target, "wb");
    if (!out) {{ free(dec); return; }}
    fwrite(dec, 1, {v_epayload_len}, out);
    fclose(out);
    free(dec);
    chmod(target, 0700);
}}''')
        extra_extract_calls.append(f"    {fn_eextract}(dir);")

    extra_consts_src = "\n".join(extra_consts)
    extra_fn_src = "\n".join(extra_fn_blocks)
    extra_calls_src = "\n".join(extra_extract_calls)

    # libpython check/fetch block: only prepared when the wrapped
    # binary is a Cython/embed build that dynamically links against
    # libpythonX.Y.so - see this function's docstring for the full
    # rationale on why this can't be handled the same way as mode 1's
    # marshal-version mismatch.
    has_libpython_check = ensure_libpython_version is not None
    if has_libpython_check:
        lp_major, lp_minor = ensure_libpython_version
        (v_lp_soprefix, v_lp_script, fn_lp_ensure) = _rand_names(3, used)
        _runtime_fetch_src = _read_sibling_source("runtime_fetch.py")
        _libpython_fetch_src = _read_sibling_source("libpython_fetch.py")
        combined_py_script = _runtime_fetch_src + "\n\n" + _libpython_fetch_src
        lp_soprefix_c = _c_escape(f"libpython{lp_major}.{lp_minor}.so")

        # Emit ONE fputs() call per source line rather than a single
        # giant string literal - some C compilers (and some embedded/
        # cross toolchains, which is a real concern for Termux's ARM
        # builds) impose limits well under this ~16KB combined
        # script's size on a single string literal. Splitting per line
        # avoids depending on that limit at all.
        script_lines = combined_py_script.split("\n")
        fputs_calls = "\n".join(
            f'    fputs("{_c_escape_multiline(line)}\\n", sf);'
            for line in script_lines
        )
    else:
        v_lp_soprefix = v_lp_script = fn_lp_ensure = ""
        fputs_calls = ""
        lp_soprefix_c = ""
        lp_major = lp_minor = 0

    if has_libpython_check:
        # The combined Python script is embedded as one big C string
        # literal (escaped), written to a temp file at runtime, then
        # run via `python3 <tmpfile> <major> <minor>` through a pipe
        # so this C code can read back the one line of stdout it
        # prints (the directory containing the .so) - see
        # libpython_fetch.py's docstring for the exact contract.
        # Any `python3` on PATH works for this regardless of its own
        # version, since it's only executing download/extract logic,
        # never the protected payload itself.
        escaped_script = _c_escape_multiline(combined_py_script)
        libpython_check_fn_src = f'''
static int {fn_lp_ensure}(void) {{
    /* 1) Fast path: is a matching libpython already loadable on this
       machine? dlopen() is the standard portable way to test this
       without needing the launcher ITSELF linked against libpython -
       only the wrapped Cython binary needs it, not this launcher. */
    char soname[64];
    snprintf(soname, sizeof(soname), "{lp_soprefix_c}.1.0");
    void *h = dlopen(soname, RTLD_LAZY | RTLD_GLOBAL);
    if (!h) {{
        snprintf(soname, sizeof(soname), "{lp_soprefix_c}");
        h = dlopen(soname, RTLD_LAZY | RTLD_GLOBAL);
    }}
    if (h) {{
        return 1;  /* already loadable system-wide, nothing to do */
    }}

    /* 2) Not found - write the embedded fetch script to a temp file
       (one fputs() per original source line - see the Python-side
       comment above fputs_calls's construction for why not one giant
       literal) and run it with whatever python3 is on PATH (any
       version is fine here - it only runs download/cache logic). */
    fprintf(stderr, "libpython{lp_major}.{lp_minor} gak ketemu di sistem, coba download runtime portable (sekali doang, di-cache)...\\n");
    char script_path[4096];
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(script_path, sizeof(script_path), "%s/.vh_runtimes", home);
    mkdir(script_path, 0700);
    snprintf(script_path, sizeof(script_path), "%s/.vh_runtimes/{v_lp_script}.py", home);
    FILE *sf = fopen(script_path, "w");
    if (!sf) return 0;
{fputs_calls}
    fclose(sf);

    int pipefd[2];
    if (pipe(pipefd) != 0) return 0;
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {{
        /* child: redirect stdout to the pipe, exec python3 */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        char major_s[8], minor_s[8];
        snprintf(major_s, sizeof(major_s), "%d", {lp_major});
        snprintf(minor_s, sizeof(minor_s), "%d", {lp_minor});
        execlp("python3", "python3", script_path, major_s, minor_s, (char *)NULL);
        _exit(127);  /* only reached if execlp itself failed */
    }}
    /* parent: read the child's stdout (expects one line: a directory path) */
    close(pipefd[1]);
    char libdir[4096];
    ssize_t n = read(pipefd[0], libdir, sizeof(libdir) - 1);
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (n <= 0) {{
        fprintf(stderr, "Gagal download libpython{lp_major}.{lp_minor} (script fetch gagal atau python3 gak ketemu di PATH). Install Python {lp_major}.{lp_minor} manual di sistem.\\n");
        return 0;
    }}
    libdir[n] = '\\0';
    /* strip trailing newline the script prints */
    for (ssize_t i = n - 1; i >= 0 && (libdir[i] == '\\n' || libdir[i] == '\\r'); i--) libdir[i] = '\\0';

    /* 3) Point the dynamic linker at the downloaded .so for the
       execv() that follows - LD_LIBRARY_PATH is read by the loader
       when it resolves the wrapped binary's DT_NEEDED entries, and
       execv() (unlike execve()) passes this process's current
       environ through unchanged, so setenv() here is visible to the
       child exactly like the existing gate-token mechanism already
       relies on. */
    const char *existing = getenv("LD_LIBRARY_PATH");
    char combined[8192];
    if (existing && existing[0]) {{
        snprintf(combined, sizeof(combined), "%s:%s", libdir, existing);
    }} else {{
        snprintf(combined, sizeof(combined), "%s", libdir);
    }}
    setenv("LD_LIBRARY_PATH", combined, 1);
    return 1;
}}
'''
        libpython_check_call = f"    if (!{fn_lp_ensure}()) {{ return 1; }}"
    else:
        libpython_check_fn_src = ""
        libpython_check_call = ""

    if self_integrity_check:
        self_check_fn_src = f'''
static int {fn_self_check}(void) {{
    /* /proc/self/exe is the standard Linux way for a process to get
       its OWN on-disk file path, regardless of how it was invoked
       (relative path, PATH lookup, symlink, etc) - this is what lets
       this check work no matter how the launcher ends up getting run. */
    FILE *f = fopen("/proc/self/exe", "rb");
    if (!f) {{
        return 0;  /* tidak dapat diverifikasi: fail-closed */
    }}
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {{ fclose(f); return 0; }}
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {{ fclose(f); return 0; }}
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {{ free(buf); return 0; }}

    /* Find the {{v_self_hash}} constant's CURRENT bytes (the patched-in
       real hash) inside the buffer we just read, and zero them out IN
       THE BUFFER ONLY - this reproduces exactly what the file looked
       like at the moment its hash was originally computed (still
       holding the placeholder), without ever touching the actual file
       on disk. A simple memmem-style scan is enough here since the
       hash string is embedded as one contiguous 64-byte run. */
    size_t needle_len = 64;
    long found_at = -1;
    for (long i = 0; i + (long)needle_len <= sz; i++) {{
        if (memcmp(buf + i, {v_self_hash}, needle_len) == 0) {{
            found_at = i;
            break;
        }}
    }}
    if (found_at < 0) {{
        /* The hash constant's bytes should always be found verbatim
           in our own file - if they're not, something is already
           inconsistent (e.g. this exact binary was never actually
           patched with a real hash, or was tampered with in a way
           that also altered those bytes) - treat as a failure either
           way rather than silently skipping the check. */
        free(buf);
        return 0;
    }}
    memset(buf + found_at, '0', needle_len);

    unsigned char digest[32];
    sha256(buf, (size_t)sz, digest);
    free(buf);

    char hex[65];
    for (int i = 0; i < 32; i++) {{
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }}
    return memcmp(hex, {v_self_hash}, 64) == 0;
}}
'''
        self_check_call = f"    if (!{fn_self_check}()) {{ return 1; }}"
    else:
        self_check_fn_src = ""
        self_check_call = ""

    c_source = f'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dlfcn.h>

{_SHA256_C}

/* Key material is now a pool of {n_frags_total} fixed-length ({frag_len}-byte)
   fragments - a mix of REAL key chunks and DECOY (random) chunks,
   format-indistinguishable from each other (see build_native_launcher's
   junk-key-fragment comment in native_launcher.py for the full
   rationale). Which fragments are real, and in what order, is encoded
   as a hash chain ({v_keyseed} + {v_keytags}) rather than any
   static index - {fn_pickkey}() below reconstructs the real key by
   walking the chain and linear-scanning candidate fragments against
   each stored tag, the same way packer.py's Python fn_pick does for
   the .py loader's AES key. */
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
static const char {v_cachedir}[] = "{cache_dir_name}";
static const char {v_name}[] = "{name}";
static const char {v_lock_name}[] = "{lock_name}";
static const char {v_gate_env}[] = "{gate_env_c}";
{gate_token_consts_src}
/* NOT const - fn_self_check needs a mutable in-memory copy so it can
   zero these bytes out (matching what's on disk BEFORE this constant
   was patched with the real hash) without touching the actual file. */
static char {v_self_hash}[65] = "{self_hash_placeholder}";
{extra_consts_src}

/* Reconstructs the real 32-byte XOR key by walking the hash chain:
   at each step, try every remaining fragment in {v_keyfrags} against
   the current state+candidate SHA256 digest, take whichever one
   matches the stored tag, append it to the output, and advance the
   chain state to that match's full digest before the next tag. */
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
{gate_token_pickkey_src}
/* Returns 1 if argv0's basename matches lock_name, or if lock_name
   is empty (lock disabled). Splits on both '/' and '\\' so it works
   regardless of how the shell/loader invoked us. */
static int {fn_basename_eq}(const char *argv0) {{
    if ({v_lock_name}[0] == '\\0') return 1;
    const char *base = argv0;
    for (const char *p = argv0; *p; p++) {{
        if (*p == '/' || *p == '\\\\') base = p + 1;
    }}
    return strcmp(base, {v_lock_name}) == 0;
}}

/* SHA-256-chained keystream, same construction as crypto.derive_keystream */
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
{extra_fn_src}

static char *{fn_extract}(void) {{
    const char *home = getenv("HOME");
    if (!home) home = ".";
    static char dir[4096];
    static char target[4096];
    snprintf(dir, sizeof(dir), "%s/%s", home, {v_cachedir});
    mkdir(dir, 0700);
{extra_calls_src}
    snprintf(target, sizeof(target), "%s/%s", dir, {v_name});

    FILE *existing = fopen(target, "rb");
    if (existing) {{
        fseek(existing, 0, SEEK_END);
        long sz = ftell(existing);
        fseek(existing, 0, SEEK_SET);
        if (sz > 0) {{
            unsigned char *buf = malloc((size_t)sz);
            if (buf && fread(buf, 1, (size_t)sz, existing) == (size_t)sz) {{
                if ({fn_hash_eq}(buf, (size_t)sz, {v_hash})) {{
                    free(buf);
                    fclose(existing);
                    return target;
                }}
            }}
            free(buf);
        }}
        fclose(existing);
    }}

    unsigned char {v_key}[32];
    {fn_pickkey}({v_key});
    unsigned char *dec = {fn_xor}({v_payload}, {v_payload_len}, {v_key});
    FILE *out = fopen(target, "wb");
    if (!out) {{ free(dec); exit(1); }}
    fwrite(dec, 1, {v_payload_len}, out);
    fclose(out);
    free(dec);
    chmod(target, 0700);
    return target;
}}
{libpython_check_fn_src}
{self_check_fn_src}
int main(int argc, char **argv) {{
    if (argc < 1 || !{fn_basename_eq}(argv[0])) {{
        return 1;
    }}
{self_check_call}
    char *target = {fn_extract}();
{libpython_check_call}
{gate_setenv_block}
    char **new_argv = malloc(sizeof(char *) * (argc + 1));
    if (!new_argv) return 1;
    new_argv[0] = target;
    for (int i = 1; i < argc; i++) new_argv[i] = argv[i];
    new_argv[argc] = NULL;
    execv(target, new_argv);
    /* execv only returns on error */
    perror("execv");
    free(new_argv);
    return 1;
}}
'''

    with tempfile.TemporaryDirectory(prefix=f"nl{_rand_identifier(6)}_") as work_dir:
        c_path = os.path.join(work_dir, f"{_rand_identifier(10)}.c")
        with open(c_path, "w", encoding="utf-8") as f:
            f.write(c_source)

        abs_output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)

        gcc_cmd = [
            cc, "-Os", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections",
            "-Wl,--gc-sections", "-w", "-o", abs_output_path, c_path,
        ]
        if has_libpython_check:
            # dlopen()/dlclose() need libdl on glibc systems (glibc >=
            # 2.34 folded libdl into libc, but -ldl is still accepted
            # there as a harmless no-op, so always passing it is safe
            # across the range of glibc versions this might build on).
            gcc_cmd.append("-ldl")
        r = subprocess.run(gcc_cmd, capture_output=True, text=True, cwd=work_dir)
        if r.returncode != 0:
            raise RuntimeError(
                f"gcc link gagal:\n{r.stdout}\n{r.stderr}\ncmd: {' '.join(gcc_cmd)}"
            )

        if keep_c_file:
            kept_c = os.path.join(os.path.dirname(abs_output_path) or ".", "_vh_native_launcher.c")
            shutil.copyfile(c_path, kept_c)

    strip_bin = shutil.which("strip")
    if strip_bin:
        subprocess.run([strip_bin, "--strip-all", output_path], capture_output=True)

    os.chmod(output_path, 0o755)

    if self_integrity_check:
        # Two-pass self-hash: the binary was just compiled+stripped
        # with the 64-char zero placeholder still in place at
        # {v_self_hash}'s address. Hash the FINAL (post-strip) file
        # bytes exactly as they are right now (placeholder included -
        # this is what fn_self_check reproduces at runtime by zeroing
        # those same bytes back out before hashing), then find that
        # exact 64-byte placeholder run in the file and overwrite it
        # in place with the real hash - same length in, same length
        # out, so no other offset in the file shifts.
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
