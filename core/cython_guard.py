"""
cython_guard.py - adds periodic self-integrity checking to the
Cython native-binary pipeline (cython_build.py), which otherwise has
no runtime tamper detection at all once compiled.

Why this is a separate wrapper process instead of an embedded check
(the way embed_build.py's own main() carries its own watchdog):
cython_build.py's binary is generated FROM the .pyx by `cython
--embed` itself - we hand Cython a .pyx file and it produces the C
source and therefore the compiled main(), so there's no place in
that generated code for us to inject a watchdog thread the way
embed_build.py can (embed_build.py writes 100% of its own C, so its
main() is ours to add a pthread into). The only thing we control
from outside Cython's generated code is what happens BEFORE and
AROUND running that binary.

So: this module builds a small, separate C program (the "guard")
that:
  1. embeds the SHA256 of the already-built Cython child binary
     (computed once, after cython_build.py finishes) as a constant
  2. forks, and the child execs the real Cython binary
  3. the parent re-hashes the child binary FILE on disk periodically
     from a background thread and kills the child (SIGKILL) the
     moment the hash no longer matches, then exits non-zero itself
  4. otherwise waits for the child and forwards its exit code

This catches the child binary being modified ON DISK while the
guard+child are running (e.g. another process patching the file via
a debugger's "detach, patch binary, re-attach" workflow, or any
tool that rewrites the executable while it's memory-mapped). It does
NOT catch in-memory-only patches to the child's own address space
after it's already running (unlike embed_build.py's watchdog, which
re-hashes a byte array that's resident in the SAME process, the
guard here is a separate process watching the child's file on disk -
patching the child's live memory without touching the file it was
loaded from is invisible to this). This is a real, but different and
narrower, protection than embed_build.py's - told plainly rather than
implied to be equivalent.
"""
import hashlib
import os
import random
import shutil
import string
import subprocess
import tempfile


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


# Same self-contained SHA-256 as native_launcher.py/embed_build.py -
# no OpenSSL/libssl-dev dependency.
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

static void sha256_file(const char *path, unsigned char *out) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    FILE *f = fopen(path, "rb");
    if (!f) { memset(out, 0, 32); return; }
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha256_update(&ctx, buf, n);
    }
    fclose(f);
    sha256_final(&ctx, out);
}

static void sha256_to_hex(const unsigned char *digest, char *out_hex) {
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out_hex[i * 2] = hexchars[(digest[i] >> 4) & 0xf];
        out_hex[i * 2 + 1] = hexchars[digest[i] & 0xf];
    }
    out_hex[64] = '\0';
}
'''


# Adds a second, independent check to the watchdog thread: reading the
# CHILD PROCESS'S OWN LIVE MEMORY (not the file on disk - see
# build_guard's enable_memory_check docstring for what gap this
# closes) and comparing its executable segment byte-for-byte against
# the same range read from the file. Only compiled in when
# enable_memory_check=True, so the disk-hash-only guard's C source
# (and therefore its behavior) is completely unchanged when this
# stays off - no new code path exists to accidentally affect the
# default configuration.
#
# Design choices worth calling out:
#   - /proc/<pid>/maps parsing looks for the FIRST mapping whose
#     pathname matches the child's own basename (via strstr, not an
#     exact match, since maps entries can have trailing annotations
#     like " (deleted)") AND whose permissions include 'x' - Cython
#     binaries are typically single-PT_LOAD-per-permission-class, so
#     the first executable+matching-path entry is reliably the main
#     code segment for this project's build (not a multi-.so
#     application with several distinct executable regions to
#     disambiguate between).
#   - The comparison is FILE-OFFSET-based (each maps line's own
#     "offset" field, read directly from the mapping - not
#     recomputed or assumed), matching how ELF loaders actually work:
#     a PT_LOAD segment's file offset and its runtime vaddr can differ
#     (see cython_build.py's own hard-learned lesson on this exact
#     point from the vaddr-vs-file-offset relocation bug), but the
#     kernel's own /proc/pid/maps entry always reports the correct
#     file offset for whatever it mapped - reading that value directly
#     sidesteps needing to re-derive it, which is exactly the kind of
#     re-derivation that went wrong before.
#   - Every syscall that can fail (fopen maps, open mem, pread either
#     side, mismatched read lengths) sets a `disabled` flag and
#     returns/continues rather than treating the failure itself as a
#     tamper signal - see build_guard's docstring for why fail-open
#     here is deliberate, not an oversight.
_MEMORY_CHECK_C = r'''
static volatile int g_memcheck_disabled = 0;

static int {fn_find_child_segment}(pid_t pid, const char *basename_needle,
                                     unsigned long *out_start, unsigned long *out_end,
                                     unsigned long *out_file_offset) {{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) return 0;

    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {{
        unsigned long start, end, offset;
        char perms[8] = {{0}};
        char pathname[4096] = {{0}};
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095[^\n]", &start, &end, perms, &offset, pathname);
        if (n >= 4 && strchr(perms, 'x') && strstr(pathname, basename_needle)) {{
            *out_start = start;
            *out_end = end;
            *out_file_offset = offset;
            found = 1;
            break;
        }}
    }}
    fclose(maps);
    return found;
}}

/* Returns 1 if memory and file segments match (or the check could not
   run and was safely skipped), 0 ONLY if both were successfully read
   and they genuinely differ - i.e. the only "tamper detected" return
   path requires two successful reads that disagree, never a failed
   read standing in for a mismatch. */
static int {fn_check_memory}(pid_t pid, const char *child_path, const char *basename_needle) {{
    if (g_memcheck_disabled) return 1;

    unsigned long mstart, mend, moffset;
    if (!{fn_find_child_segment}(pid, basename_needle, &mstart, &mend, &moffset)) {{
        g_memcheck_disabled = 1;
        return 1;
    }}

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pid);
    int memfd = open(mem_path, O_RDONLY);
    if (memfd < 0) {{
        g_memcheck_disabled = 1;
        return 1;
    }}

    size_t seg_size = (size_t)(mend - mstart);
    /* Cap the comparison size - this is a tamper SAMPLE, not a full
       binary re-verification (the disk-hash check already covers the
       whole file); an unbounded read here would cost real time on
       every watchdog tick for no meaningful extra protection, since a
       patch small enough to matter (a few bytes flipping a branch or
       NOPing a call) is caught just as well by sampling the first
       chunk of the executable segment as by reading all of it. */
    if (seg_size > 262144) seg_size = 262144;

    unsigned char *mem_buf = malloc(seg_size);
    unsigned char *file_buf = malloc(seg_size);
    if (!mem_buf || !file_buf) {{
        free(mem_buf); free(file_buf);
        g_memcheck_disabled = 1;
        return 1;
    }}

    ssize_t mn = pread(memfd, mem_buf, seg_size, (off_t)mstart);
    close(memfd);

    int fatal_and_disable = 0;
    if (mn != (ssize_t)seg_size) {{
        fatal_and_disable = 1;
    }}

    int result = 1;
    if (!fatal_and_disable) {{
        int filefd = open(child_path, O_RDONLY);
        if (filefd < 0) {{
            fatal_and_disable = 1;
        }} else {{
            ssize_t fn = pread(filefd, file_buf, seg_size, (off_t)moffset);
            close(filefd);
            if (fn != (ssize_t)seg_size) {{
                fatal_and_disable = 1;
            }} else {{
                result = (memcmp(mem_buf, file_buf, seg_size) == 0) ? 1 : 0;
            }}
        }}
    }}

    free(mem_buf);
    free(file_buf);
    if (fatal_and_disable) {{
        g_memcheck_disabled = 1;
        return 1;
    }}
    return result;
}}
'''


def build_guard(child_binary_path: str, output_path: str, keep_c_file: bool = False,
                 enable_memory_check: bool = False):
    """
    child_binary_path: path to the already-built Cython native binary
                        (cython_build.compile_pyx_to_binary's output).
    output_path: where to write the guard wrapper binary. The child
                 binary is renamed alongside it (see cli.py's
                 integration) - the guard execs it by its own path,
                 so the child file must exist at a known path at
                 guard-build time and stay there at runtime.

    enable_memory_check: OFF by default (opt-in, unverified on
    Android/Termux - see the long comment block right before
    _MEMORY_CHECK_C below for the full rationale). When True, the
    watchdog thread ALSO periodically reads the child process's own
    LIVE memory (via /proc/<child_pid>/mem) for its executable text
    segment and compares it byte-for-byte against the same range read
    from the binary FILE on disk. This catches a class of tampering
    the disk-hash check alone cannot: a debugger or ptrace-based tool
    patching the child's in-memory code directly (e.g. NOPing out a
    license check or an anti-debug branch) WITHOUT ever touching the
    file on disk - which the existing disk-hash re-check (this
    function's main docstring, point 3) is structurally blind to,
    since it only ever re-reads the file.

    This is designed to fail SAFE, not fail CLOSED: if
    /proc/<pid>/mem can't be opened (permission denied - plausible on
    Android given SELinux/app-sandboxing and yama.ptrace_scope
    restrictions this project has NOT been able to verify the exact
    behavior of on a real device) or the child's own text segment
    can't be located in /proc/<pid>/maps, the memory-check simply
    stops trying for the rest of that run and the guard falls back to
    disk-hash-only protection - it does NOT treat "can't check memory"
    as itself suspicious and kill the child. Getting that fail-mode
    wrong the same way a past change here (unrelated feature, see git
    history / prior session notes on cython_build.py's ptrace toggle)
    broke stdin entirely on a real Android device is exactly the risk
    this flag defaulting to False, and failing open rather than
    closed, is meant to avoid repeating.
    Returns output_path on success, raises ToolchainError/RuntimeError.
    """
    cc = ensure_toolchain()

    with open(child_binary_path, "rb") as f:
        child_hash = hashlib.sha256(f.read()).hexdigest()

    # Store only the child's BASENAME, not its absolute build-time
    # path - the guard resolves the actual path at runtime relative
    # to its own location (via /proc/self/exe), so guard+child can be
    # moved/extracted anywhere together (e.g. by a .py or native
    # launcher wrap step copying both into $HOME) and execv() still
    # finds the right file. A hardcoded absolute path would silently
    # break the moment either file moves from where it was at build
    # time, which is exactly what happened when this was wrapped into
    # a single-file .py launcher that extracts to a different directory.
    child_basename = os.path.basename(child_binary_path)

    used = set()
    (v_child_name, v_child_hash, fn_watchdog, fn_resolve_path) = _rand_names(4, used)

    memcheck_includes = ""
    memcheck_block = ""
    memcheck_call = ""
    if enable_memory_check:
        (fn_find_child_segment, fn_check_memory) = _rand_names(2, used)
        memcheck_includes = "#include <fcntl.h>\n#include <errno.h>\n#include <sys/stat.h>"
        memcheck_block = _MEMORY_CHECK_C.format(
            fn_find_child_segment=fn_find_child_segment,
            fn_check_memory=fn_check_memory,
        )
        # child_basename (v_child_name) doubles as the /proc/pid/maps
        # pathname needle - it's the same basename the child binary
        # was execv'd with, so it's exactly what shows up in the
        # child's own maps entries.
        memcheck_call = f'''
        if (!{fn_check_memory}(g_child_pid, g_child_path, {v_child_name})) {{
            if (g_child_pid > 0) kill(g_child_pid, SIGKILL);
            _exit(1);
        }}'''

    c_source = f'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <limits.h>
{memcheck_includes}

{_SHA256_C}

{memcheck_block}

static const char {v_child_name}[] = "{child_basename}";
static const char {v_child_hash}[] = "{child_hash}";

static pid_t g_child_pid = -1;
static char g_child_path[PATH_MAX];

/* Resolves the child's path at RUNTIME as "directory containing this
   guard binary" + "/" + child's basename - NOT a path baked in at
   build time. /proc/self/exe (Linux/Android) always points at the
   currently-running binary's real, resolved path regardless of how
   it was invoked (relative, PATH lookup, symlink, etc), which is
   what makes this work even if the guard was copied/extracted
   somewhere else after being built. */
static void {fn_resolve_path}(void) {{
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len <= 0) {{
        /* Fallback: assume child is in the current working directory. */
        snprintf(g_child_path, sizeof(g_child_path), "./%s", {v_child_name});
        return;
    }}
    self_path[len] = '\\0';
    char *last_slash = strrchr(self_path, '/');
    if (last_slash) {{
        *last_slash = '\\0';
        snprintf(g_child_path, sizeof(g_child_path), "%s/%s", self_path, {v_child_name});
    }} else {{
        snprintf(g_child_path, sizeof(g_child_path), "./%s", {v_child_name});
    }}
}}

static void *{fn_watchdog}(void *arg) {{
    (void)arg;
    for (;;) {{
        struct timespec ts;
        ts.tv_sec = 3 + (time(NULL) % 4);
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
        unsigned char digest[32];
        char hex[65];
        sha256_file(g_child_path, digest);
        sha256_to_hex(digest, hex);
        if (strcmp(hex, {v_child_hash}) != 0) {{
            if (g_child_pid > 0) kill(g_child_pid, SIGKILL);
            _exit(1);
        }}
{memcheck_call}
    }}
    return NULL;
}}

int main(int argc, char **argv) {{
    {fn_resolve_path}();

    unsigned char digest[32];
    char hex[65];
    sha256_file(g_child_path, digest);
    sha256_to_hex(digest, hex);
    if (strcmp(hex, {v_child_hash}) != 0) {{
        return 1;
    }}

    pid_t pid = fork();
    if (pid < 0) {{
        perror("fork");
        return 1;
    }}
    if (pid == 0) {{
        execv(g_child_path, argv);
        perror("execv");
        _exit(1);
    }}

    g_child_pid = pid;
    pthread_t _watchdog_thread;
    if (pthread_create(&_watchdog_thread, NULL, {fn_watchdog}, NULL) == 0) {{
        pthread_detach(_watchdog_thread);
    }}

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}}
'''

    with tempfile.TemporaryDirectory(prefix=f"cg{_rand_identifier(6)}_") as work_dir:
        c_path = os.path.join(work_dir, f"{_rand_identifier(10)}.c")
        with open(c_path, "w", encoding="utf-8") as f:
            f.write(c_source)

        abs_output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)

        gcc_cmd = [
            cc, "-Os", "-fvisibility=hidden", "-w", "-o", abs_output_path, c_path, "-lpthread",
        ]
        r = subprocess.run(gcc_cmd, capture_output=True, text=True, cwd=work_dir)
        if r.returncode != 0:
            raise RuntimeError(f"gcc link gagal:\n{r.stdout}\n{r.stderr}\ncmd: {' '.join(gcc_cmd)}")

        if keep_c_file:
            kept_c = os.path.join(os.path.dirname(abs_output_path) or ".", "_vh_cython_guard.c")
            shutil.copyfile(c_path, kept_c)

    strip_bin = shutil.which("strip")
    if strip_bin:
        subprocess.run([strip_bin, "--strip-all", output_path], capture_output=True)

    os.chmod(output_path, 0o755)

    return output_path
