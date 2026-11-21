"""
cython_build.py - alternative protection mode that compiles the
obfuscated source to a real standalone native binary via Cython,
instead of bundling interpreted bytecode (as the marshal/PyInstaller
mode does).

Pipeline:
  obfuscated_source.py (string-encrypted + junk, from core.obfuscator,
                         WITHOUT the marshal packer step)
    -> written as a .pyx file
    -> `cython --embed` compiles it to a single C file containing a
       real main() (Py_Main under the hood)
    -> gcc links that C file against libpython using the flags
       `python3-config` reports, producing a standalone ELF/PE binary

Why this is stronger than the marshal mode:
  the marshal mode still ships a `code` object that, once the runtime
  XOR key is recovered (e.g. by dumping process memory after the
  anti-debug checks pass), can be marshal.loads()'d straight back into
  inspectable Python bytecode. The Cython mode instead compiles logic
  to actual C -> machine code, so there's no Python bytecode object to
  dump; an attacker has to reverse compiled machine code instead.

Trade-offs (told to the user, not hidden):
  - needs a real C toolchain (gcc/clang) and Cython installed on the
    BUILD machine. The output binary itself is standalone.
  - some dynamic Python features (heavy use of exec/eval on fully
    runtime-generated code, some metaclass tricks, etc.) can be
    slower or need small rewrites under Cython. Typical scripts
    compile fine as-is.
  - the produced binary still dynamically links against libpythonX.Y,
    so it needs a matching Python runtime library present on the
    target machine (same as running any Cython --embed binary would).
    Fully static-linked binaries are possible but need a static
    libpython build, which is a separate, more involved setup.
"""
import ast
import os
import random
import re
import shutil
import string
import subprocess
import tempfile


class ToolchainError(RuntimeError):
    pass


def _rand_token(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


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


def _rand_identifier(n: int = 12) -> str:
    """
    Same idea as _rand_token, but guaranteed to be a valid Python/C
    identifier (first character is always a letter). Cython derives
    the compiled module's name from the .pyx filename, and a module
    name can't start with a digit - a plain _rand_token() result
    starting with a digit (about 1 in 3.6 odds, since digits are 10
    of the 36 possible characters) makes Cython reject the file with
    "<name> is not a valid module name" before compilation even
    starts. Used anywhere the random string ends up as a filename
    stem that becomes an identifier (the .pyx/.c stub name).
    """
    first = random.choice(string.ascii_lowercase)
    rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=max(n - 1, 0)))
    return first + rest


def _extract_future_imports(source: str) -> tuple[str, str]:
    """Extract module-level future imports and encryptable docstring setup.

    Future imports must precede generated prelude code. A module docstring is
    converted to an explicit ``__doc__ = <literal>`` assignment in the body;
    the normal string-encryption pass then encrypts that literal. This keeps
    runtime ``__doc__`` behavior without leaving documentation text in clear
    text in the generated source.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "", source

    raw = source.encode("utf-8")
    raw_lines = raw.splitlines(keepends=True)
    line_starts = []
    offset = 0
    for line in raw_lines:
        line_starts.append(offset)
        offset += len(line)

    def absolute_position(lineno: int, column: int) -> int:
        return line_starts[lineno - 1] + column

    def node_span(node):
        start = absolute_position(node.lineno, node.col_offset)
        end_lineno = node.end_lineno or node.lineno
        end_column = node.end_col_offset if node.end_col_offset is not None else node.col_offset
        end = absolute_position(end_lineno, end_column)
        return start, end

    future_nodes = [
        node for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "__future__"
    ]
    preamble_parts = [
        ast.get_source_segment(source, node)
        for node in future_nodes
    ]

    # Keep module documentation as a runtime assignment. It is deliberately
    # left in the body so StringEncryptor can encrypt its value.
    replacements = []
    if tree.body:
        first = tree.body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            start, end = node_span(first)
            replacement = "__doc__ = " + repr(first.value.value)
            replacements.append((start, end, replacement.encode("utf-8")))

    removals = []
    for node in future_nodes:
        start, end = node_span(node)

        # Remove a trailing semicolon separator when another statement
        # follows on the same physical line, preserving the other statement.
        line_end = raw.find(b"\n", end)
        if line_end < 0:
            line_end = len(raw)
        cursor = end
        while cursor < line_end and raw[cursor:cursor + 1] in (b" ", b"\t"):
            cursor += 1
        if cursor < line_end and raw[cursor:cursor + 1] == b";":
            cursor += 1
            while cursor < line_end and raw[cursor:cursor + 1] in (b" ", b"\t"):
                cursor += 1
            end = cursor
        removals.append((start, end))

    edits = [(start, end, replacement) for start, end, replacement in replacements]
    edits.extend((start, end, b"") for start, end in removals)
    body_bytes = raw
    for start, end, replacement in sorted(edits, key=lambda item: item[0], reverse=True):
        body_bytes = body_bytes[:start] + replacement + body_bytes[end:]

    preamble = "\n".join(part for part in preamble_parts if part)
    if preamble:
        preamble += "\n"
    return preamble, body_bytes.decode("utf-8")
_ANTI_PTRACE_PYX_PRELUDE = '''# --- injected by cython_build.py (inject_anti_ptrace) ---
cdef extern from *:
    """
    #include <unistd.h>

    #ifdef __linux__
    extern long ptrace(int __request, ...);
    #define VH_PTRACE_TRACEME 0
    #endif

    static void {fn_init}(void) {{
        #ifdef __linux__
        ptrace(VH_PTRACE_TRACEME, 0, (void*)0, (void*)0);
        #endif
    }}
    """
    void {fn_init}()

{fn_init}()
# --- end injected block ---

'''

_DISABLE_COREDUMP_PYX_PRELUDE = '''# --- injected by cython_build.py (inject_disable_coredump) ---
cdef extern from *:
    """
    #include <sys/resource.h>

    static void {fn_init}(void) {{
        struct rlimit {rl_var};
        {rl_var}.rlim_cur = 0;
        {rl_var}.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &{rl_var});
    }}
    """
    void {fn_init}()

{fn_init}()
# --- end injected block ---

'''

def _build_anti_ptrace_prelude() -> str:
    used = set()
    (fn_init,) = _rand_names(1, used)
    # fn_init is a valid C identifier already (see _rand_names /
    # _rand_identifier) - .format() is safe here since none of the
    # C source's own braces are left unescaped except through the
    # {fn_init} placeholder itself (the literal C code's braces are
    # doubled as {{ }} above specifically so .format() passes them
    # through unchanged).
    return _ANTI_PTRACE_PYX_PRELUDE.format(fn_init=fn_init[1:])
    # [1:] strips the leading underscore _rand_names gives every name -
    # a leading-underscore identifier is valid C too, but keeping the
    # injected C symbols visually distinct from the Python-side "_xxx"
    # convention makes this block easier to spot if anyone greps the
    # generated .pyx while debugging a future build issue.


def _build_disable_coredump_prelude() -> str:
    used = set()
    fn_init, rl_var = _rand_names(2, used)
    return _DISABLE_COREDUMP_PYX_PRELUDE.format(fn_init=fn_init[1:], rl_var=rl_var[1:])


def _find_cython_cmd():
    """Return the command list to invoke cython, or None if unavailable."""
    exe = shutil.which("cython") or shutil.which("cython3")
    if exe:
        return [exe]
    try:
        import Cython  # noqa
        import sys
        return [sys.executable, "-m", "cython"]
    except ImportError:
        return None


def _find_cc():
    return shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")


def ensure_toolchain(auto_install: bool = False):
    """
    Raises ToolchainError with a clear message if something required
    is missing. Tries `pip install cython` first if it's absent and
    auto_install is True (needs internet on the build machine).
    """
    if _find_cython_cmd() is None and auto_install:
        try:
            import sys
            subprocess.run(
                ["/bin/false", "offline-mode-pip-disabled",
                 "--break-system-packages", "cython"],
                check=True,
            )
        except Exception:
            pass

    cython_cmd = _find_cython_cmd()
    if cython_cmd is None:
        raise ToolchainError(
            "Cython tidak ketemu dan gagal auto-install (butuh internet). "
            "Install manual: pip install --break-system-packages cython"
        )

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

    return cython_cmd, cc


def _python_flags():
    """Return (include_flags, link_flags) using python3-config."""
    def run(args):
        r = subprocess.run(["python3-config"] + args, capture_output=True, text=True)
        return r.stdout.split()

    includes = run(["--includes"])
    ldflags = run(["--ldflags", "--embed"])
    if not ldflags:
        ldflags = run(["--ldflags"])
    return includes, ldflags


def _scrub_embedded_paths(binary_path: str, needles: list):
    """
    Overwrite any leftover occurrence of the given byte strings
    (original .pyx path, module name, .c path) still sitting in the
    compiled binary's data sections with random filler of the SAME
    LENGTH, in place. `strip` only removes debug/symbol-table
    entries; it does NOT touch string literals the program actually
    references at runtime (e.g. the module's __file__/docstring, or
    a filename baked into an error-format string), so those can
    survive strip and show up in a `strings` dump. Same-length
    in-place overwriting keeps every existing offset/pointer in the
    binary valid (no size shift = no lengths, offsets or relocation
    tables to fix up).
    """
    if not needles:
        return
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    for needle in needles:
        if not needle:
            continue
        nb = needle.encode("utf-8", errors="ignore")
        if not nb:
            continue
        start = 0
        while True:
            idx = data.find(nb, start)
            if idx == -1:
                break
            filler = "".join(random.choices(string.ascii_lowercase, k=len(nb))).encode()
            data[idx:idx + len(nb)] = filler
            start = idx + len(nb)

    with open(binary_path, "wb") as f:
        f.write(data)


# Matches the "known module-level declarations" string table Cython
# --embed emits into .rodata for each function it compiles - e.g.
# b"PyObject *__pyx_Upf_12j3by2f5tus8g_61__1r76bbyar8io8k7pdfrn(PyObject *)"
# or b"int __pyx_pymod_exec_j3by2f5tus8g(PyObject *)" (Cython uses two
# different C return types across this table - "PyObject *" for
# regular/generator functions, "int" for the module-init function
# specifically - both are matched below; a real compiled binary was
# checked byte-for-byte for every distinct prefix Cython emits here
# and only these two occur).
# This is normally used for cross-module cimport signature-checking
# in a multi-.pyx Cython project; a single-.pyx build (which is all
# this project ever produces) never triggers the code path that reads
# these strings back, but Cython's codegen still emits the full table
# regardless. Left in place, `strings <binary>` reveals: (1) the exact
# COUNT of top-level functions/methods/generators in the obfuscated
# program, (2) each one's exact PARAMETER COUNT (arity) from the
# PyObject* count, and (3) the module hash prefix - none of which
# requires disassembly to read, undermining a good chunk of what
# identifier_rename.py and junk.py are for in the first place.
# Confirmed via a real compiled binary that these strings carry no
# relocation entries pointing AT them (readelf -r shows nothing
# landing inside either string's own byte range - a relocation was
# found pointing at the END of the PRECEDING string's null terminator,
# immediately adjacent to but not overlapping one of these, which is
# how thoroughly this was checked) and the module name is entirely
# absent from the dynamic symbol table (nm -D/readelf -sW both empty
# for it) - i.e. these are plain, never-read-back-by-pointer data,
# safe to overwrite in place PROVIDED the match boundaries are exact
# (see the adjacency note above for why sloppy boundaries here would
# be dangerous, not just cosmetically imprecise).
#
# The [^)]* at the end (rather than something like [\w, ]*) is
# deliberate: it has to also swallow "__pyx_CoroutineObject *",
# "PyThreadState *" and similar multi-word, space-and-star-containing
# parameter types that appear in generator/coroutine function
# prototypes, and using a maximally-permissive "not a closing paren"
# class is simpler and more robust to future Cython parameter-type
# changes than trying to enumerate every C type keyword Cython might
# use. \x80-\xff in the identifier char class accounts for renamed
# Python-level names that contain non-ASCII (CJK) identifier
# characters, per core/unicode_names.py's cjk_identifiers feature -
# `strings`' default ASCII-only scan visibly truncates those at the
# first multibyte character, which is a red herring for a human
# reading raw `strings` output but NOT a safe place for this regex to
# stop matching, since the underlying bytes (and thus what needs
# scrubbing) continue past that point in the actual file.
_PYX_PROTOTYPE_STRING_RE = re.compile(
    rb"(?:PyObject \*|int )__pyx_[A-Za-z0-9_\x80-\xff]+\([^)]*\)"
)


def _scrub_pyx_prototype_strings(binary_path: str):
    """
    Same in-place, same-length overwrite strategy as
    _scrub_embedded_paths, but pattern-based (regex) instead of exact
    substring matches, since the module hash and per-function suffix
    in each prototype string are different every build and can't be
    listed as fixed needles ahead of time. See _PYX_PROTOTYPE_STRING_RE
    above for exactly what's targeted and why it's safe to blank.
    """
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    for m in _PYX_PROTOTYPE_STRING_RE.finditer(bytes(data)):
        start, end = m.start(), m.end()
        filler = "".join(random.choices(string.ascii_lowercase, k=end - start)).encode()
        data[start:end] = filler

    with open(binary_path, "wb") as f:
        f.write(data)


def compile_pyx_to_binary(pyx_path: str, output_path: str, auto_install: bool = True,
                           keep_c_file: bool = False, inject_anti_ptrace: bool = False,
                           inject_disable_coredump: bool = True):
    """
    pyx_path: path to the .pyx source (obfuscated, string-encrypted).
    output_path: where to put the final standalone binary.
    Returns output_path on success, raises ToolchainError/RuntimeError on failure.

    inject_anti_ptrace and inject_disable_coredump are two INDEPENDENT
    C-level hardening toggles (see the module-level docstring above
    _ANTI_PTRACE_PYX_PRELUDE for the full technical rationale of each).
    Both only affect this Cython native-binary pipeline - the
    marshal/PyInstaller and embed pipelines are unaffected and keep
    relying on core/antidebug.py's Python-level TracerPid check
    instead, since they don't produce a real standalone C binary
    these techniques need.

    inject_anti_ptrace: OFF by default. Self-traces via
    ptrace(PTRACE_TRACEME) so a debugger's later PTRACE_ATTACH fails
    outright.
    WARNING - confirmed broken on at least one real Android/Termux
    device: PTRACE_TRACEME there causes the compiled binary's very
    first input() call to raise EOFError immediately, before the user
    can type anything at all - not a debugger-detection false
    positive, a complete loss of interactive stdin. The exact
    mechanism isn't nailed down (Android's zygote/process sandboxing
    likely does something with self-traced processes that doesn't
    happen on desktop Linux, but this hasn't been root-caused at the
    kernel/Bionic level), so this stays disabled by default until it's
    verified safe across more Android versions/devices. It has NOT
    shown this problem in desktop Linux testing, so it may be safe to
    enable there - but given how severe the failure is when it does
    happen (breaks the built program outright, not just the
    anti-debug layer), treat it as experimental and test the actual
    output binary's interactive input before shipping it with this on.

    inject_disable_coredump: ON by default. Calls
    setrlimit(RLIMIT_CORE, 0) so a crash (natural or deliberately
    triggered to probe memory) never leaves a core-dump file behind
    for later inspection. This is a plain rlimit call with no
    interaction with the process's stdin, ptrace state, or terminal
    control - nothing in testing suggests it shares
    inject_anti_ptrace's failure mode, which is why it defaults ON
    even while inject_anti_ptrace defaults OFF. If a future report
    ever shows this one causing problems too, split it off the same
    way this one was just split from inject_anti_ptrace.

    The whole cython/gcc pass now runs inside a randomly-named temp
    directory, and the .pyx itself is copied there under a fresh
    random name too. This matters because `cython --embed` bakes
    BOTH the module name and the full path it was given for the .pyx
    (used for __file__, the module docstring, and traceback/error
    formatting) into the compiled C source as plain string literals
    - which end up as live, `strip`-proof data in the final binary's
    .rodata section. Building from a random temp path means there's
    no project directory name, original filename, or predictable
    "vh_..." pattern for a `strings` scan to key on. As a final
    safety net (temp-dir randomization only helps if it's actually
    the string that got embedded - Cython's exact behavior here can
    vary by version), every path/name string we know we handed to
    the toolchain gets scrubbed from the finished binary too.

    KNOWN LIMITATION - the bare random module name itself (rand_stub,
    e.g. "j3by2f5tus8g") is NOT scrubbed anywhere it appears
    standalone or as a "<rand_stub>.<qualifier>" qualified name (e.g.
    Cython's per-scope "<modname>.__pyx_scope_struct_N_genexpr"
    qualname strings, or the "Module '<modname>' has already been
    imported" re-init guard message). A real compiled binary showed
    SOME of these qualified-name strings genuinely referenced by a
    relocation entry (most likely for __qualname__ support at
    runtime) - unlike the prototype-string table
    (_PYX_PROTOTYPE_STRING_RE), which was verified to have NO such
    references anywhere. An attempt to selectively scrub only the
    non-referenced ones (by checking each string's file offset against
    the relocation table) was tried and reverted - the check compared
    relocation target virtual addresses directly against file offsets
    without correcting for the different base address each ELF
    load segment uses (the two only coincide for the first segment;
    .bss in particular has no file offset at all), which risked
    treating a genuinely-referenced string as safe to scrub if its
    offset happened to numerically collide with an unrelated,
    uncorrected relocation target - suspected to be the cause of a
    real compiled binary crashing silently after that scrub ran. A
    correct version of this would need proper vaddr-to-file-offset
    translation via the program headers, verified against a working
    Cython/gcc build-and-run cycle - not available in this development
    environment, so it's left as a known gap rather than shipped
    half-verified. The bare module name and its qualified-name
    derivatives survive in a `strings` dump (leaking nesting structure
    - how many classes/methods/genexprs exist and their random names,
    not program logic); the per-function prototype table, original
    file paths, and temp-build paths do not.
    """
    cython_cmd, cc = ensure_toolchain(auto_install=auto_install)

    with tempfile.TemporaryDirectory(prefix=f"b{_rand_token(6)}_") as work_dir:
        rand_stub = _rand_identifier(12)
        tmp_pyx = os.path.join(work_dir, f"{rand_stub}.pyx")
        with open(pyx_path, "r", encoding="utf-8") as f:
            pyx_source = f.read()
        module_preamble, pyx_body = _extract_future_imports(pyx_source)
        prelude = ""
        if inject_anti_ptrace:
            prelude += _build_anti_ptrace_prelude()
        if inject_disable_coredump:
            prelude += _build_disable_coredump_prelude()
        # A Cython prelude is executable module-level code.  Keep every
        # __future__ directive at the beginning, before this prelude, or
        # Cython fails with: "from __future__ imports must occur at the
        # beginning of the file".
        pyx_source = module_preamble + prelude + pyx_body
        with open(tmp_pyx, "w", encoding="utf-8") as f:
            f.write(pyx_source)
        c_path = os.path.join(work_dir, f"{rand_stub}.c")

        # 1. cython --embed: python source -> C source with a real main()
        cmd = cython_cmd + ["--embed", "-3", "-o", c_path, tmp_pyx]
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=work_dir)
        if r.returncode != 0:
            raise RuntimeError(f"Cython compile gagal:\n{r.stdout}\n{r.stderr}")

        # 2. gcc: C source -> standalone binary linked against libpython.
        #    -fvisibility=hidden + -ffunction-sections/-fdata-sections
        #    (paired with --gc-sections at link time) shrink the export/
        #    symbol surface beyond what `strip` alone removes; -w quiets
        #    Cython's generated-code warnings so they don't clutter output.
        includes, ldflags = _python_flags()
        abs_output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)
        gcc_cmd = (
            [cc, "-Os", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections",
             "-Wl,--gc-sections", "-w", "-o", abs_output_path, c_path]
            + includes + ldflags
        )
        r = subprocess.run(gcc_cmd, capture_output=True, text=True, cwd=work_dir)
        if r.returncode != 0:
            raise RuntimeError(f"gcc link gagal:\n{r.stdout}\n{r.stderr}\ncmd: {' '.join(gcc_cmd)}")

        if keep_c_file:
            kept_c = os.path.join(os.path.dirname(abs_output_path) or ".", "_vh_cy_embed.c")
            shutil.copyfile(c_path, kept_c)

    # 3. strip symbols to make static analysis a little harder / smaller binary
    strip_bin = shutil.which("strip")
    if strip_bin:
        subprocess.run([strip_bin, "--strip-all", output_path], capture_output=True)

    # 4. scrub any surviving plaintext trace of the source/module names
    #    that strip doesn't touch (see docstring above).
    #
    # IMPORTANT: what actually ends up embedded in the compiled binary
    # is the RANDOM temp-dir name/module name this function generated
    # for the compile (rand_stub, work_dir) - NOT the caller's original
    # pyx_path/module name, because pyx_source is written out to
    # tmp_pyx (a fresh random path) and THAT is what gets handed to
    # `cython --embed`. A previous version of this scrub list passed
    # the original pyx_path/module name instead, which searched the
    # binary for strings that were never actually written into it -
    # the real random module name (e.g. Cython's __pyx_pymod_exec_<name>
    # convention, and every "<name>.pyx"/"<name>.<qualname>" traceback
    # string) was left completely unscrubbed. Confirmed via a real
    # compiled binary: `nm -D`/`readelf -sW` show the module name never
    # appears in the dynamic symbol table (Cython's per-function C names
    # embed the module name as a substring of a *local*, non-exported C
    # identifier - the linker resolves those internally and `strip`
    # already removes the symbol *table* entries; only the leftover
    # plain-string literals purely written for docstrings/tracebacks
    # are what `strings` picks up and what this scrub targets), so
    # overwriting these specific strings in place cannot break any
    # relocation/pointer the running binary depends on.
    #
    # rand_stub itself (the bare module name, e.g. "j3by2f5tus8g") is
    # NOT scrubbed - Cython's generated C function names embed it as
    # part of a single fused identifier (__pyx_pymod_exec_j3by2f5tus8g,
    # __pyx_Upf_12j3by2f5tus8g_61__..., etc.), and blanking a substring
    # out of the middle of an otherwise-still-present string (the
    # surrounding "__pyx_Upf_12" + "_61__..." parts) would leave an
    # obviously-mutilated fragment behind - worse for both binary
    # correctness *and* stealth than leaving the coherent original
    # string alone. What IS scrubbed below (rand_stub + ".pyx", and the
    # temp work_dir path) are strings that appear as their OWN complete
    # literal, not as a substring fused into a longer identifier, so
    # blanking them leaves no partial fragment.
    _scrub_embedded_paths(output_path, [
        tmp_pyx,
        f"{rand_stub}.pyx",
        os.path.abspath(work_dir),
        work_dir,
    ])

    # 5. blank out the per-function C prototype string table Cython
    #    embeds regardless of whether this single-.pyx build ever
    #    reads it back - see _PYX_PROTOTYPE_STRING_RE's docstring for
    #    what this leaks (function count + exact arity of each) and
    #    why overwriting it in place is safe.
    _scrub_pyx_prototype_strings(output_path)

    # NOTE: an earlier version of this function also attempted to
    # selectively scrub "<module>.<qualifier>" qualified-name strings
    # (e.g. "<module>.SomeClass.some_method"), gated on a
    # relocation-table check meant to only touch strings confirmed to
    # have no live pointer referencing them. That check was WRONG: it
    # compared each relocation's target VALUE directly against file
    # offsets, but a relocation's target is a virtual (runtime-load)
    # address, which only equals its file offset for data in the
    # FIRST PT_LOAD segment - later segments (anything landing in
    # .data/.bss) have a different base, and some relocations in a
    # real compiled binary pointed into .bss (which has no file
    # representation at all - not even a valid offset to check). This
    # meant the "is this string safe to scrub" check could give a
    # false negative for a string that WAS actually safe (harmless -
    # just less thorough) but, worse, had no principled guarantee
    # against a false POSITIVE (declaring a string safe when it
    # wasn't) if a genuinely-referenced .rodata string's file offset
    # happened to collide numerically with an unrelated .bss/.data
    # virtual address from the (uncorrected) target set - this is
    # suspected to be the cause of a real binary crashing (silently,
    # no output at all) after this scrub ran. Removed entirely rather
    # than patched, since a correct fix needs proper vaddr-to-
    # file-offset translation via the program headers (readelf -l),
    # verified against a real compile+run cycle - which requires a
    # working Cython/gcc toolchain to iterate against safely, not
    # available in this development environment. The bare module name
    # and its qualified-name derivatives remain unscrubbed for now;
    # see this function's own docstring for what that leaks (nesting
    # structure, not program logic).

    os.chmod(output_path, 0o755)

    return output_path
