"""
packer.py - takes the fully obfuscated (string-encrypted + junk
padded, anti-debug source already merged in) source, compiles it to
a code object, marshals it, encrypts the marshal blob with AES-256-GCM
and stitches together the final loader .py that:
  1. verifies a whole-file self-checksum (and optional filename lock)
  2. memerlukan dependency pycryptodome yang sudah dipasang pada target
     (launcher tidak mengunduh atau memasang paket dari jaringan saat runtime)
  3. reassembles the AES key from several separately-stored, randomly
     placed chunks, then runs it through HKDF to get the actual key
     used for decryption (recovering the raw chunks isn't enough on
     its own - the derivation step has to be replicated too)
  4. decrypts (AES-GCM auth tag verifies integrity - no separate
     hash check needed) + marshal.loads + exec's the real payload
     (which includes the anti-debug/anti-Frida/anti-VPN checks as
     the very first thing it does, since those got merged into the
     source before it ever reached this module)

This means the shipped .py (and the binary built from it) never
contains the original source - OR the anti-debug logic, OR its own
tamper-check machinery - in any recoverable plaintext form. Every
identifier name used in the generated loader boilerplate is randomly
generated PER BUILD too, so there's no fixed name (like a hardcoded
"_vh_payload_key") that would work as a static signature across every
output this tool has ever produced.

Payload/key-chunk representation: raw bytes literals (b"\\x.."), not
base85-encoded text assigned to a string then base85-decoded at
runtime. The .py loader file itself is always plaintext-readable
source either way (that's inherent to being a .py file at all - this
only matters once this same source flows into a COMPILED binary, via
build.py/PyInstaller or cython_build.py/Cython), but a raw bytes
literal is still the more honest/consistent representation to emit,
since it drops a needless base85 round-trip and keeps this module in
line with string_enc.py's ciphertext representation.

Why AES-GCM over the plain XOR+SHA256 cipher (still used by
native_launcher.py/embed_build.py's C side, and by
obfuscate_source_for_cython, since a C program can't easily pull in
pycryptodome, and Cython needs plain compilable source, not a
pre-encrypted blob): XOR-with-a-keystream is simple obfuscation, not
real cryptographic confidentiality - the keystream is fully
determined by the key, so if a chunk of known/guessable plaintext
ever lines up with ciphertext, the keystream (and with it, every
other byte encrypted under that reused stream) is recoverable. AES
here delegates the actual cipher work to pycryptodome, a real, this
is a genuine confidentiality upgrade for the .py loader path
specifically, not just cosmetic.
"""
import marshal
import base64
import hashlib
import ast
import os
import random
import zlib
import string
import sys
from .crypto import random_key, split_key_with_junk, build_fragment_chain, hkdf_sha256
from . import runtime_fetch as _runtime_fetch_module

with open(_runtime_fetch_module.__file__, "r", encoding="utf-8") as _f:
    _RUNTIME_FETCH_SOURCE = _f.read()


def _rand_name(used: set, n: int = 9) -> str:
    while True:
        cand = "_" + "".join(random.choices(string.ascii_lowercase, k=n))
        if cand not in used:
            used.add(cand)
            return cand


def _build_die_helper(used: set) -> tuple:
    """
    Generates a random-named "die" function definition (its own
    source text, as a string) plus a randomized xor key used inside
    it, and returns (fn_name, source_block). Every integrity-
    enforcement call site in this module (self-hash mismatch,
    filename-lock mismatch, the periodic re-check thread, and every
    equivalent spot in pack_with_native_decryptor's three stages)
    calls `{fn_name}()` instead of writing `os._exit(1)` (or
    `sys.exit(1)`) directly.

    WHY THIS EXISTS: a literal `os._exit(1)` or `sys.exit(1)` sitting
    in the launcher's own plaintext .py source is trivially findable
    and neutralizable by a blanket, no-skill regex substitution run
    against the file BEFORE it's ever executed - e.g.
    `re.sub(r'os\\._exit\\(\\s*[01]\\s*\\)', 'pass', source)` turns
    every enforcement point into a no-op in one shot, regardless of
    which specific check it belonged to. This was confirmed working
    against a real build. No self-verifying mechanism that lives as
    editable plaintext in the same file it's meant to protect can be
    made fully immune to a sufficiently determined manual read-and-
    patch (that limitation is fundamental, not a bug to fix - see
    this function's own callers' docstrings for the honest framing),
    but a BLANKET, non-targeted regex like the one above is a much
    lower bar than "read and understand this code" - defeating it
    doesn't require any Python or reverse-engineering skill, just a
    generic pattern that happens to match common exit idioms. This
    function's job is narrowly to make THAT specific class of
    zero-effort, copy-pasted bypass script stop working, by making
    sure no build ever contains the literal substrings a generic
    regex would key on.

    Achieves that three ways, each independently defeating a
    different generic pattern an attacker's regex might target:
      1. The exit call itself is never written as `os._exit(` or
         `sys.exit(` in the source - it's reached via getattr() with
         the attribute name reconstructed from an XOR-obfuscated
         byte string at call time, so grepping for those substrings
         finds nothing.
      2. The die function's OWN internal pattern is chosen randomly
         per build from three genuinely different mechanisms (see
         the three branches below) - a bypass script would need to
         separately detect and defeat all three to be reliable
         across builds, not just pattern-match one.
      3. (Handled by callers, not here): the call sites themselves
         are plain `{fn_name}()` calls with a random name - nothing
         about the call site text says "this is the integrity
         enforcement", unlike a bare `os._exit(1)` which announces
         its own purpose contextually to anyone scanning for exit
         calls near a hash comparison.
    """
    fn_name = _rand_name(used)
    xor_key = random.randint(1, 255)

    variant = random.choice(("os_exit", "raise_systemexit", "infinite_wait"))

    if variant == "os_exit":
        # Reconstructs "_exit" via XOR against xor_key at call time,
        # then getattr(os, that_string)(1) - equivalent to os._exit(1)
        # but with no literal "_exit" substring anywhere in this
        # build's source.
        encoded = bytes(b ^ xor_key for b in b"_exit")
        block = f'''def {fn_name}():
    _k = {xor_key}
    _enc = {encoded!r}
    _name = "".join(chr(b ^ _k) for b in _enc)
    getattr(os, _name)(1)'''
    elif variant == "raise_systemexit":
        # SystemExit(1) is functionally equivalent to sys.exit(1) (sys.exit
        # just raises SystemExit under the hood) but contains neither
        # the substring "os._exit" nor "sys.exit" - a regex targeting
        # either literal call form misses this entirely, while still
        # reliably terminating the process (uncaught SystemExit
        # propagates out of any surrounding try/except that doesn't
        # specifically catch BaseException, and every enforcement call
        # site in this module already re-raises SystemExit explicitly
        # rather than swallowing it - see fn_check_block's own
        # `except SystemExit: raise` line).
        block = f'''def {fn_name}():
    raise SystemExit(1)'''
    else:
        # Never returns at all, rather than exiting - a script that
        # patches out "the exit call" gains nothing here, because
        # there IS no exit call to find: tampering just hangs the
        # process indefinitely instead of letting it proceed. A
        # bounded sleep loop (rather than a tight busy-loop) keeps CPU
        # usage negligible while stuck.
        block = f'''def {fn_name}():
    while True:
        time.sleep(3600)'''

    return fn_name, block


def extract_imported_modules(source: str) -> list:
    """
    Walks the ORIGINAL (pre-encryption) source's AST and collects
    every top-level module name it imports. PyInstaller determines
    what to bundle by statically scanning .py source text for
    `import` statements - but our loader stub's own source doesn't
    contain the real script's imports as visible text (they're
    compiled + marshal + encrypted into an opaque blob), so
    PyInstaller can't see them and silently omits them from the
    build, causing ModuleNotFoundError at runtime. This function lets
    the build step pass them explicitly as --hidden-import flags.
    """
    tree = ast.parse(source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module)
                modules.add(node.module.split(".")[0])
    return sorted(modules)


def _decoy_body(style: int, used: set) -> str:
    """
    Generates one small, syntactically-real but functionally inert
    function body, styled to look like it could plausibly be part of
    the decrypt/verify pipeline (hashing, byte-juggling, base85,
    comparisons) - without doing anything that affects the real
    payload. Mixed in among the real loader functions so a human (or
    an AI) skimming the file top-to-bottom can't just visually pick
    out "the functions that matter" from "the rest" - every function
    has to actually be traced to know if it's load-bearing.
    """
    a, b, c = (_rand_name(used) for _ in range(3))
    if style == 0:
        return (
            f"def {a}({b}):\n"
            f"    {c} = hashlib.sha256({b} if isinstance({b}, bytes) else str({b}).encode()).digest()\n"
            f"    return {c}[0] ^ {c}[-1]\n"
        )
    if style == 1:
        return (
            f"def {a}({b}, {c}):\n"
            f"    return bytes((x + {c}) % 256 for x in {b})\n"
        )
    if style == 2:
        return (
            f"def {a}({b}):\n"
            f"    return base64.b85encode(hashlib.sha256(repr({b}).encode()).digest())\n"
        )
    return (
        f"def {a}({b}):\n"
        f"    return sum({b}) % 97 if {b} else 0\n"
    )


def pack(source: str, gate_env_name: str = None, gate_token: str = None,
          gate_token_cache_var: str = None, allow_no_gate: bool = False,
          lock_filename: bool = False, expected_filename: str = None,
          enable_version_fallback: bool = False) -> str:
    """
    source: fully obfuscated python source (anti-debug merged in,
            string-encrypted, junk already inserted) ready to compile.

    gate_env_name / gate_token: REQUIRED, NOT optional (no default -
            calling pack() without a real gate token is a TypeError,
            by design). This closes a real gap found in production
            use: previously, packer.py's AES key for the marshal
            payload was NEVER tied to the launcher gate at all - the
            gate-check function lived INSIDE the encrypted payload
            (merged in by antidebug.py before this function ever sees
            `source`), which only runs AFTER the payload is already
            successfully decrypted and exec'd. That meant recovering
            the AES key (and therefore the entire payload) never
            required the gate token in the first place - an attacker
            (human or AI) who statically read this module's junk-key +
            hash-chain fragment-selection logic (see split_key_with_
            junk/build_fragment_chain in crypto.py) could correctly
            reconstruct the real key and successfully AES-GCM-decrypt
            the payload with ZERO knowledge of the gate token,
            entirely independent of whether require_launcher_gate was
            even enabled for that build. This was confirmed happening
            in practice against a real build.
            Now: `raw_material` (the 32 bytes that get HKDF-derived
            into the actual AES key) is XORed with SHA256(gate_token)
            BEFORE being split into junk-key fragments - so even a
            perfect reconstruction of every fragment via the hash
            chain only yields the MASKED raw_material, not the real
            one. Unmasking needs the same gate_token, which - same as
            string_enc.py's gate-token-mixed key masking - never
            touches disk and only exists in the launched process's
            environment for that one run. This is what makes gate
            protection ACTUALLY extend to payload decryption itself,
            not just to what happens after decryption succeeds.
    lock_filename / expected_filename: if lock_filename is True, the
            loader refuses to run unless its own filename on disk
            matches expected_filename exactly (blocks simple rename
            + redistribute tampering). Content changes are already
            caught by the self-hash check regardless of this flag.
    enable_version_fallback: marshal's bytecode format is tied to the
            exact Python MINOR version used to compile() it - a loader
            built under 3.12 raises a version-mismatch error (or worse,
            silently misbehaves) if later run under 3.13/3.14/etc. When
            this is True, the loader's very first action (before even
            the self-hash/anti-debug checks) is comparing its own
            build-time sys.version_info against the CURRENT
            interpreter's. On exact match, nothing changes - runs
            normally, zero extra cost. On mismatch, it downloads (via
            an embedded copy of runtime_fetch.py's logic - see that
            module for the full mechanism and its own documented
            limitations) a portable CPython build matching the needed
            version from python-build-standalone, CACHES it locally
            (so this download only ever happens once per machine per
            needed version), and re-execs itself under that portable
            interpreter via os.execv - which then re-enters this exact
            same check, finds a match the second time, and proceeds
            normally. Requires internet on first use per (version,
            machine) combination; fails with a clear stderr message
            (not a silent hang) if no internet and nothing cached yet.
            Off by default since it changes the loader's behavior
            (network access, disk writes to ~/.vh_runtimes) in a way
            that should be an explicit opt-in, not implicit.
    gate_token_cache_var: REQUIRED whenever gate_env_name/gate_token are
            provided. Names the same sys-module attribute antidebug.py's
            gate check (get_antidebug_source's gate_token_cache_var
            param) stashes the verified token onto - MUST be the exact
            same name passed there, since that's how this module's
            generated fn_derive() code reads the token back at runtime
            without either module needing to import the other. See
            string_enc.py's docstring for the fuller rationale on why a
            sys-module ATTRIBUTE (not a plain variable) is used
            specifically: it's the one kind of reference that survives
            identifier_rename.py's pass unchanged on both the
            antidebug.py-generated side and this module's independently-
            generated side.
    allow_no_gate: default False - explicit opt-OUT of the mandatory
            gate requirement below, for callers packing source that is
            KNOWN to contain no user code or secrets of its own (the
            only current caller is bootstrap.py's wrap_binary_as_py,
            for its own generic extract/exec launcher logic - see that
            function's comment for why gating the LAUNCHER itself would
            be circular). This is NOT a general escape hatch for "I
            don't want to deal with gate tokens" - obfuscator.py's
            obfuscate_source (the actual user-code pipeline) never
            passes this, and enforces its OWN mandatory-gate check
            before ever calling this function, independent of this
            parameter's default.
    Returns: final loader .py source as a string.
    """
    if not allow_no_gate and (not gate_env_name or not gate_token):
        raise ValueError(
            "packer.pack() requires a real gate_env_name/gate_token - the .py launcher "
            "mode no longer supports building without launcher-gate protection, since "
            "without it the AES payload key is fully recoverable by anyone who reads "
            "this module's fragment-reconstruction scheme (confirmed happening in "
            "practice). Generate one with obfuscator.generate_gate_info() first, or pass "
            "allow_no_gate=True only if you specifically know this source has no user "
            "code/secrets of its own (see that parameter's docs)."
        )
    if gate_env_name and gate_token and not gate_token_cache_var:
        raise ValueError(
            "packer.pack() requires gate_token_cache_var whenever gate_env_name/gate_token "
            "are provided - must match the same name passed to "
            "antidebug.get_antidebug_source's gate_token_cache_var param."
        )
    has_gate = bool(gate_env_name and gate_token)

    code_obj = compile(source, "<vh>", "exec")
    blob = marshal.dumps(code_obj)

    # --- AES-256-GCM encryption of the payload ---
    raw_material = random_key(32)   # split into chunks below, never stored whole
    nonce = random_key(12)          # GCM standard nonce size
    # Mask raw_material with the gate token BEFORE any splitting - see
    # this function's gate_env_name/gate_token docs above for why this
    # (not just the split_key_with_junk/build_fragment_chain scattering
    # below) is what actually ties payload decryption to the launcher
    # gate. Only happens when has_gate is True; in allow_no_gate mode
    # there's no token to mask with, so raw_material_masked is just
    # raw_material itself (still goes through the same junk-key +
    # hash-chain scattering below either way).
    if has_gate:
        gate_mask = hashlib.sha256(gate_token.encode("utf-8")).digest()
        raw_material_masked = bytes(a ^ b for a, b in zip(raw_material, gate_mask))
    else:
        raw_material_masked = raw_material
    # hkdf_info is randomized PER BUILD (was previously a fixed
    # b"vh-payload-key" constant shared by every build this tool ever
    # produced - a real, working generic decoder for this tool's .py
    # output only had to hardcode that one known value once, and it

    # would keep working against every future build too). Random per
    # build closes that: a decoder that worked against one build's
    # output has no reason to keep working against the next one.
    hkdf_info = os.urandom(random.randint(12, 20))
    aes_key = hkdf_sha256(raw_material, length=32, info=hkdf_info)

    from Crypto.Cipher import AES
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(blob)

    # Tidak menyimpan nama launcher mentah pada outer bootstrap. Untuk
    # filename-lock, bootstrap cukup membandingkan digest SHA-256 nama
    # file saat runtime terhadap digest yang dibuat di mesin build.
    lock_name_digest = (
        hashlib.sha256(expected_filename.encode("utf-8")).digest()
        if (lock_filename and expected_filename)
        else b""
    )
    placeholder = "0" * 64

    used = set()
    v_self_hash = _rand_name(used)
    v_lock_name_digest = _rand_name(used)
    v_nonce = _rand_name(used)
    v_tag = _rand_name(used)
    v_ct = _rand_name(used)
    v_marker = _rand_name(used)
    fn_check = _rand_name(used)
    fn_ensure_pkg = _rand_name(used)
    fn_derive = _rand_name(used)
    fn_unpack = _rand_name(used)
    fn_watchdog = _rand_name(used)
    fn_verfallback = _rand_name(used)
    v_code = _rand_name(used)
    fn_die, die_block = _build_die_helper(used)
    v_verified = _rand_name(used)

    # Split the raw key material into several chunks INTERLEAVED WITH
    # DECOY FRAGMENTS that are format-indistinguishable from the real
    # ones (same length range, same "random bytes" appearance, no
    # structural marker). This closes a real gap the previous
    # split_key-only scheme had: even with chunks scattered and
    # declared in shuffled order, the RECOMBINATION EXPRESSION used to
    # be written out verbatim as literal code (e.g.
    # `raw = _a + _b + _c + _d + _e`) - a plain top-to-bottom
    # AST read of that one line handed over the exact correct order
    # with zero guessing required. Now, every top-level bytes-literal
    # assignment in this section could be real key material OR could
    # be a decoy - and which ones are real, and in what order, is
    # never written anywhere as a literal, human/AST-readable
    # list - see fn_derive_block below for how the selection is
    # instead baked into which specific list-index positions get
    # summed, computed from data that has no comment or name pointing
    # out what it means.
    n_real = random.randint(5, 8)
    n_junk = random.randint(4, 7)
    fragments, real_indices = split_key_with_junk(raw_material_masked, n_real_chunks=n_real, n_junk_chunks=n_junk)
    n_total = len(fragments)

    # hkdf_info (see above - now random per build) is folded in as ONE
    # MORE same-shaped fragment in this same pool, rather than a
    # separately-named, obviously-labeled variable - "which fragment
    # is the HKDF info string" is exactly as hidden as "which
    # fragments are the real key chunks".
    info_fragment_index = len(fragments)
    fragments = fragments + [hkdf_info]
    n_total = len(fragments)

    frag_names = [_rand_name(used) for _ in range(n_total)]
    decl_order = list(range(n_total))
    random.shuffle(decl_order)  # order fragments are DECLARED in the file

    # 3-6 decoy functions, randomly interleaved with the real chunk
    # declarations and functions below.
    decoys = [_decoy_body(random.randint(0, 3), used) for _ in range(random.randint(3, 6))]

    chunk_decl_lines = []
    for i, idx in enumerate(decl_order):
        if i < len(decoys):
            chunk_decl_lines.append(decoys[i])
        chunk_decl_lines.append(f"{frag_names[idx]} = {bytes(fragments[idx])!r}")
    remaining_decoys = "\n\n".join(decoys[len(decl_order):])
    chunk_decls = "\n".join(chunk_decl_lines)

    # --- Encoding real_indices + info_fragment_index without ever
    # writing them as a literal, labeled, human-readable list, AND
    # without any STATIC ARITHMETIC (like "index = offset - base")
    # that a file-only reader could evaluate without ever touching
    # the actual fragment bytes ---
    #
    # v_idxmap holds ALL n_total fragment-name references, in a FIXED
    # but arbitrary (per-build random) order - looks exactly like "an
    # array of all our byte chunks", the same way a real program might
    # legitimately keep a list of buffers around, with NOTHING marking
    # which positions matter.
    #
    # Which positions ARE the real chunks (in the right order, plus
    # the info fragment as the final link) is instead encoded as a
    # forward HASH CHAIN (crypto.build_fragment_chain): a root seed
    # plus one short verification tag per real fragment. Recovering
    # the mapping means walking the chain step by step, and at EACH
    # step trying every remaining candidate fragment's bytes against
    # the stored tag until one matches - genuinely content-dependent
    # (the fragment BYTES are part of what's hashed), not a lookup
    # table or arithmetic shortcut sitting in the file. See
    # crypto.build_fragment_chain's docstring for the full mechanism,
    # what it does and doesn't guarantee, and why a linear scan (not
    # cryptographic hardness) is the deliberate design here.
    v_idxmap = _rand_name(used)
    v_seed = _rand_name(used)
    v_tags = _rand_name(used)
    fn_pick = _rand_name(used)

    # Per-build variation of the chain's hash-combine order and tag
    # length - see crypto.build_fragment_chain's combine_order/tag_len
    # docstring for why this exists: a real static-extraction script
    # (confirmed working) hardcoded ONE specific shape (state+candidate,
    # truncated to 4 bytes) that every build before this used
    # unconditionally, so it worked unmodified against any build ever
    # produced. Randomizing which shape THIS build uses, and generating
    # fn_pick_block below to match whichever was chosen, means that
    # same hardcoded script now only works by chance (roughly 1-in-2
    # for combine_order alone) against any single given build, and
    # fails LOUDLY (AES-GCM auth tag rejects the wrong key outright)
    # rather than silently on a mismatch.
    chain_combine_order = random.choice(("state_first", "cand_first"))
    chain_tag_len = random.randint(4, 6)

    chain_order = real_indices + [info_fragment_index]
    root_seed, chain_tags = build_fragment_chain(
        fragments, chain_order, tag_len=chain_tag_len, combine_order=chain_combine_order,
    )

    idxmap_literal = "[" + ", ".join(frag_names[i] for i in range(n_total)) + "]"
    seed_literal = repr(root_seed)
    tags_literal = "[" + ", ".join(repr(t) for t in chain_tags) + "]"

    _digest_expr = (
        "_vhhl2.sha256(_state + _cand).digest()" if chain_combine_order == "state_first"
        else "_vhhl2.sha256(_cand + _state).digest()"
    )
    fn_pick_block = f'''def {fn_pick}():
    import hashlib as _vhhl2
    _state = {v_seed}
    _pool = list({v_idxmap})
    _picked = []
    for _tag in {v_tags}:
        _match = None
        for _cand in _pool:
            _digest = {_digest_expr}
            if _digest[:{len(chain_tags[0]) if chain_tags else 4}] == _tag:
                _match = (_cand, _digest)
                break
        if _match is None:
            return b"", b""
        _picked.append(_match[0])
        _state = _match[1]
    _info_frag = _picked[-1]
    _real_frags = _picked[:-1]
    return b"".join(_real_frags), _info_frag'''
    # --- Everything below is an independently-orderable BLOCK: each
    # one is either a function def (callable from anywhere below its
    # own definition - Python resolves the name at call time, not at
    # def time, so these don't have to stay in "logical" order) or a
    # value declaration used only inside a later function body (same
    # reasoning). Only two things are pinned: fn_check must run right
    # after the self-hash/lock constants are declared (checked before
    # ANYTHING else executes), and the final unpack+exec must be last.
    # Shuffling every block's position - not just the key chunks -
    # means the file no longer reads top-to-bottom as "check, then
    # install, then decrypt" in an obvious line; the six or so
    # movable blocks (fn_check def, fn_ensure_pkg def, the scattered
    # key-chunk declarations, nonce/tag/ct assignment, fn_derive def,
    # fn_unpack def) come out in a different order every build.
    fn_check_block = f'''def {fn_check}():
    global {v_verified}
    try:
        with open(__file__, "r", encoding="utf-8") as _f:
            _c = _f.read()
        _marker = {v_marker}.decode()
        _i = _c.find(_marker)
        if _i != -1:
            _s = _i + len(_marker)
            _e = _c.find('"', _s)
            _stored = _c[_s:_e]
            _rebuilt = _c[:_s] + "0" * 64 + _c[_e:]
            _computed = hashlib.sha256(_rebuilt.encode("utf-8")).hexdigest()
            if _computed != _stored:
                {fn_die}()
        if {v_lock_name_digest}:
            _name_digest = hashlib.sha256(os.path.basename(__file__).encode("utf-8")).digest()
            if not hmac.compare_digest(_name_digest, {v_lock_name_digest}):
                {fn_die}()
    except SystemExit:
        raise
    except Exception:
        # Verifikasi integritas harus gagal-tertutup. Bila launcher
        # sendiri tidak dapat dibaca atau diverifikasi, jangan lanjut
        # mendekripsi payload.
        {fn_die}()
    {v_verified} = True'''

    # Re-runs the SAME fn_check() (self-hash + lock-filename check)
    # periodically from a background daemon thread for the life of
    # the process, instead of only once at the very start. A
    # one-time check at startup only catches tampering that happened
    # BEFORE the process launched - it says nothing about the file
    # being patched on disk while the process is still running (e.g.
    # a long-lived script, or a debugger pausing execution to modify
    # things mid-run). daemon=True so this thread never blocks normal
    # program exit; the random 3-6s jitter avoids a perfectly regular
    # interval an attacker could time around.
    #
    # Honest limitation: __file__ is resolved once by Python at
    # process start and stays a fixed path string for the process's
    # whole life. On Linux, open(__file__) still reads by that path,
    # and renaming a file doesn't change what a fixed path resolves
    # to referencing the same inode - so a rename that happens AFTER
    # the process has already started is NOT caught by this, same as
    # it wasn't caught by the original one-time check either (no
    # regression - this was never something either version could
    # catch). What genuinely benefits from being periodic instead of
    # one-shot is the CONTENT check: if the file's bytes on disk
    # change while the process is running, this catches it within
    # one interval, not just at startup.
    watchdog_interval = random.uniform(3.0, 6.0)
    fn_watchdog_block = f'''def {fn_watchdog}():
    import threading, time as _vhtime
    def _loop():
        while True:
            _vhtime.sleep({watchdog_interval!r} + _vhtime.time() % 1.0)
            {fn_check}()
    _t = threading.Thread(target=_loop, daemon=True)
    _t.start()'''

    # Tidak ada auto-install runtime. Menjalankan pip dari launcher
    # memperluas permukaan serangan, menambah impor yang terlihat, dan
    # membuat hasil build bergantung pada jaringan. Dependency dicek
    # tepat sebelum dekripsi di fn_unpack_block.

    payload_block = (
        f"{v_nonce} = {bytes(nonce)!r}\n"
        f"{v_tag} = {bytes(tag)!r}\n"
        f"{v_ct} = {bytes(ciphertext)!r}"
    )

    if has_gate:
        unmask_line = (
            f'    _tok = getattr(_vhsys5, {gate_token_cache_var!r}, None) or os.environ.get({gate_env_name!r}, "")\n'
            f'    _gate_mask = hashlib.sha256(_tok.encode("utf-8")).digest()\n'
            f'    _raw = bytes(a ^ b for a, b in zip(_raw_masked, _gate_mask))'
        )
    else:
        # allow_no_gate mode: raw_material was never masked at build
        # time (nothing to mask with), so the reconstructed value
        # from fn_pick() IS the real raw_material already.
        unmask_line = '    _raw = _raw_masked'

    fn_derive_block = f'''def {fn_derive}():
    import sys as _vhsys5
    _raw_masked, _info = {fn_pick}()
{unmask_line}
    _prk = hmac.new(b"\\x00" * 32, _raw, hashlib.sha256).digest()
    _out = b""
    _prev = b""
    _counter = 1
    while len(_out) < 32:
        _prev = hmac.new(_prk, _prev + _info + bytes([_counter]), hashlib.sha256).digest()
        _out += _prev
        _counter += 1
    return _out[:32]'''

    fn_unpack_block = f'''def {fn_unpack}():
    try:
        from Crypto.Cipher import AES
    except ImportError:
        sys.stderr.write("Dependency kriptografi launcher belum tersedia.\\n")
        {fn_die}()
    _key = {fn_derive}()
    _cipher = AES.new(_key, AES.MODE_GCM, nonce={v_nonce})
    try:
        _pt = _cipher.decrypt_and_verify({v_ct}, {v_tag})
    except Exception:
        {fn_die}()
    return marshal.loads(_pt)'''

    # Version-fallback block: baked-in build-time (major, minor), plus
    # an embedded copy of runtime_fetch.py's full source (executed in
    # its own namespace via exec(), so its top-level names don't leak
    # into/collide with this loader's own names). Deliberately runs
    # BEFORE fn_check()/fn_watchdog() - if the marshal blob genuinely
    # can't be read under this interpreter, there's no point checking
    # file integrity first; get onto a working interpreter ASAP.
    build_major, build_minor = sys.version_info[0], sys.version_info[1]
    if enable_version_fallback:
        fn_verfallback_block = f'''def {fn_verfallback}():
    if sys.version_info[0] == {build_major} and sys.version_info[1] == {build_minor}:
        return
    _rfmod = {{}}
    try:
        exec({_RUNTIME_FETCH_SOURCE!r}, _rfmod)
        _sys.stderr.write(
            "Versi Python kamu (%d.%d) beda sama yang dipakai buat build script ini (%d.%d).\\n"
            "Lagi download runtime Python portable yang cocok (sekali doang, bakal di-cache)...\\n"
            % (sys.version_info[0], sys.version_info[1], {build_major}, {build_minor})
        )
        _py_path = _rfmod["ensure_python"]({build_major}, {build_minor})
    except Exception as _e:
        _sys.stderr.write(
            "Versi Python kamu (%d.%d) gak kompatibel sama script ini (butuh %d.%d) "
            "dan auto-download runtime portable gagal: %s\\n"
            "Install Python %d.%d manual, atau jalanin script ini dari situ.\\n"
            % (sys.version_info[0], sys.version_info[1], {build_major}, {build_minor}, _e,
               {build_major}, {build_minor})
        )
        {fn_die}()
    try:
        os.execv(_py_path, [_py_path, __file__] + sys.argv[1:])
    except Exception as _e:
        _sys.stderr.write("Gagal jalanin runtime portable %s: %s\\n" % (_py_path, _e))
        {fn_die}()'''
        fn_verfallback_call = f"{fn_verfallback}()"
        verfallback_import = "import sys as _sys\n"
    else:
        fn_verfallback_block = ""
        fn_verfallback_call = "pass"
        verfallback_import = ""

    idxmap_decl_block = (
        f"{v_idxmap} = {idxmap_literal}\n"
        f"{v_seed} = {seed_literal}\n"
        f"{v_tags} = {tags_literal}"
    )
    # chunk_decls defines every frag_names[i] variable; idxmap_decl_block's
    # idxmap_literal REFERENCES all of those names. They must stay in
    # this relative order (chunk_decls first) wherever they end up in
    # the shuffled output - so they're combined into one indivisible
    # unit here, rather than being two independently-shufflable
    # entries in movable_blocks (which could otherwise land in either
    # order, and half the time raise NameError at import time exactly
    # like this bug did before the fix).
    chunk_and_idxmap_block = chunk_decls + "\n\n" + idxmap_decl_block

    movable_blocks = [chunk_and_idxmap_block, remaining_decoys, payload_block,
                       fn_pick_block, fn_derive_block, fn_unpack_block]
    movable_blocks = [b for b in movable_blocks if b.strip()]
    random.shuffle(movable_blocks)
    movable_source = "\n\n".join(movable_blocks)

    marker_literal = f'{v_self_hash} = "'
    marker_bytes = marker_literal.encode("utf-8")

    header = (
        "#!/usr/bin/env python3\n"
        "import marshal,base64,hashlib,os,sys,hmac,time\n"
        f"{verfallback_import}\n"
        f'{v_self_hash} = "{placeholder}"\n'
        f"{v_lock_name_digest} = {lock_name_digest!r}\n"
        f"{v_marker} = {marker_bytes!r}\n\n"
        f"{die_block}\n\n"
        f"{v_verified} = False\n\n"
        # fn_verfallback dan fn_check dipanggil
        # immediately below, at top level (not from inside another
        # function) - so unlike the movable blocks, their def MUST
        # come before the call and can't be shuffled to an arbitrary
        # later position. fn_verfallback runs FIRST, ahead of even
        # the self-hash check - see its own comment above for why.
        f"{fn_verfallback_block}\n\n"
        f"{fn_verfallback_call}\n\n"
        f"{fn_check_block}\n\n"
        f"{fn_check}()\n\n"
        f"{fn_watchdog_block}\n\n"
        f"{fn_watchdog}()\n\n"
    )
    footer = (
        # Redundant, independent re-check right before the payload is
        # actually decrypted and exec'd - deliberately separate from
        # fn_check()'s own internal enforcement (see _build_die_helper's
        # docstring: this is the "check the SUCCESS flag in multiple,
        # separate places" leg of that mitigation). A patch script that
        # successfully neutralizes every exit call inside fn_check
        # itself still has to ALSO separately neutralize this check,
        # because {v_verified} starts False and is set True only
        # inside fn_check's own success path - if fn_check's body is
        # gutted rather than merely having its exit calls patched, it
        # never reaches the line that sets {v_verified}, and this
        # still blocks. This is not the same failure mode as the
        # exit-call patch it's meant to catch: that patch left
        # fn_check's logic (the hash comparison) running but defanged
        # its consequence; gutting fn_check's body avoids the
        # comparison entirely but trips this instead.
        f"\n\nif not {v_verified}:\n"
        f"    {fn_die}()\n"
        f"{v_code} = {fn_unpack}()\n"
        f'exec({v_code}, {{"__name__": "__main__"}})\n'
    )

    rendered = header + movable_source + footer

    # --- Minify: strip blank lines and comments the generator itself
    # didn't add, without collapsing everything to one line (that
    # would break tracebacks and isn't even possible for def/try/while
    # blocks without a real statement-level rewrite). This keeps each
    # logical line but removes the empty-line "paragraph" separation
    # a human skim relies on to visually chunk the file into sections.
    minified_lines = [ln for ln in rendered.split("\n") if ln.strip() != ""]
    rendered = "\n".join(minified_lines)

    self_hash = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    placeholder_line = f'{v_self_hash} = "{placeholder}"'
    final_line = f'{v_self_hash} = "{self_hash}"'
    loader = rendered.replace(placeholder_line, final_line, 1)

    return loader


def pack_with_native_decryptor(source: str, native_module_blob: bytes, native_module_suffix: str,
                               lock_filename: bool = False, expected_filename: str = None,
                               raw_material_combine_order: str = "state_first") -> str:
    """Membuat launcher Python dengan dekripsi payload di modul native.

    Fungsi ini khusus untuk bootstrap launcher generik. Tidak ada user source atau
    key build yang disimpan dalam ekstensi; ekstensi hanya menyediakan algoritme
    runtime untuk merekonstruksi fragmen key, membuka AES-GCM, unmarshal, lalu
    menjalankan code object. Dengan demikian outer `.py` tidak memuat
    `marshal.loads`, `Crypto.Cipher.AES`, atau fungsi derivasi key plaintext.

    raw_material_combine_order: MUST match exactly the combine_order
    the caller compiled native_module_blob's .so with (see
    native_decryptor_build.build_native_decryptor's own
    combine_order param) - this value picks which argument order
    build_fragment_chain uses for raw_material's chain below, and
    that chain is reconstructed at runtime INSIDE the .so (via its
    compiled-in digest_concat() call - see run_payload in
    native_decryptor_build.py's C source), not in the Python emitted
    here. A mismatch between the two doesn't fail loudly at build
    time - it silently produces a .so that can never verify its own
    chain, breaking every real run of the resulting launcher, not
    just an attacker's script. See crypto.build_fragment_chain's
    combine_order docstring for why this varies per build at all: a
    real, confirmed-working static-extraction script hardcoded the
    ONE shape every build before this used unconditionally to walk
    exactly this chain (the one directly protecting the embedded main
    binary) down to the plaintext payload.
    """
    if not isinstance(native_module_blob, bytes) or not native_module_blob:
        raise ValueError("native_module_blob harus berupa shared object non-kosong")
    if not native_module_suffix.startswith("."):
        raise ValueError("native_module_suffix tidak valid")
    if raw_material_combine_order not in ("state_first", "cand_first"):
        raise ValueError(
            f"raw_material_combine_order must be 'state_first' or 'cand_first', "
            f"got {raw_material_combine_order!r}"
        )

    # Simpan extension sebagai container opaque, bukan raw ELF pada source .py.
    native_key = random_key(32)
    native_magic = random_key(4)
    native_nonce = random_key(12)
    from Crypto.Cipher import AES
    native_cipher = AES.new(native_key, AES.MODE_GCM, nonce=native_nonce)
    native_ct, native_tag = native_cipher.encrypt_and_digest(zlib.compress(native_module_blob, level=9))
    native_container = native_magic + native_nonce + native_tag + native_ct
    native_parts, native_real_indices = split_key_with_junk(native_key, n_real_chunks=5, n_junk_chunks=5)
    # Per-build variation - see the matching comment at pack()'s own
    # build_fragment_chain call site above for the full rationale
    # (a real hardcoded static-extraction script only knew the one
    # shape every build used before this). This chain is reconstructed
    # by fn_run_source below (plain Python, not the .so's C code - see
    # that block's own comment for why this one CAN vary per build
    # while the raw_material chain a few lines down, reconstructed
    # inside the compiled .so, currently cannot without also
    # regenerating matching C source per build).
    native_combine_order = random.choice(("state_first", "cand_first"))
    native_tag_len = random.randint(4, 6)
    native_seed, native_chain_tags = build_fragment_chain(
        native_parts, native_real_indices, tag_len=native_tag_len, combine_order=native_combine_order,
    )

    code_obj = compile(source, "<pyobf-native-launcher>", "exec")
    blob = marshal.dumps(code_obj)
    raw_material = random_key(32)
    nonce = random_key(12)
    hkdf_info = os.urandom(random.randint(12, 20))
    aes_key = hkdf_sha256(raw_material, length=32, info=hkdf_info)

    from Crypto.Cipher import AES
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(blob)

    # Material key tetap disebar bersama ciphertext (sebagaimana setiap launcher
    # offline), tetapi algoritme pemilihan dan dekripsi berpindah ke modul native.
    n_real = random.randint(5, 8)
    n_junk = random.randint(4, 7)
    fragments, real_indices = split_key_with_junk(raw_material, n_real_chunks=n_real, n_junk_chunks=n_junk)
    info_fragment_index = len(fragments)
    fragments.append(hkdf_info)
    chain_order = real_indices + [info_fragment_index]
    raw_material_tag_len = random.randint(4, 6)
    root_seed, chain_tags = build_fragment_chain(
        fragments, chain_order, tag_len=raw_material_tag_len, combine_order=raw_material_combine_order,
    )

    lock_name_digest = (
        hashlib.sha256(expected_filename.encode("utf-8")).digest()
        if (lock_filename and expected_filename)
        else b""
    )
    placeholder = "0" * 64
    used: set[str] = set()
    v_self_hash = _rand_name(used)
    v_lock_digest = _rand_name(used)
    v_marker = _rand_name(used)
    v_pool = _rand_name(used)
    v_seed = _rand_name(used)
    v_tags = _rand_name(used)
    v_nonce = _rand_name(used)
    v_ct = _rand_name(used)
    v_tag = _rand_name(used)
    v_native_container = _rand_name(used)
    v_native_magic = _rand_name(used)
    v_native_suffix = _rand_name(used)
    v_native_pool = _rand_name(used)
    v_native_seed = _rand_name(used)
    v_native_tags = _rand_name(used)
    fn_check = _rand_name(used)
    fn_run = _rand_name(used)
    fn_die, die_block = _build_die_helper(used)
    v_verified = _rand_name(used)

    fragment_names = [_rand_name(used) for _ in fragments]
    declaration_order = list(range(len(fragments)))
    random.shuffle(declaration_order)
    fragment_declarations = "\n".join(
        f"{fragment_names[index]} = {bytes(fragments[index])!r}"
        for index in declaration_order
    )
    pool_literal = "[" + ", ".join(fragment_names) + "]"
    tag_literal = "[" + ", ".join(repr(item) for item in chain_tags) + "]"
    native_fragment_names = [_rand_name(used) for _ in native_parts]
    native_declarations = "\n".join(
        f"{native_fragment_names[index]} = {bytes(native_parts[index])!r}"
        for index in range(len(native_parts))
    )
    native_pool_literal = "[" + ", ".join(native_fragment_names) + "]"
    native_tag_literal = "[" + ", ".join(repr(item) for item in native_chain_tags) + "]"
    native_container_b85 = base64.b85encode(native_container).decode("ascii")
    fn_check_source = f'''def {fn_check}():
    global {v_verified}
    try:
        with open(__file__, "r", encoding="utf-8") as _f:
            _content = _f.read()
        _marker = {v_marker}.decode()
        _start = _content.find(_marker)
        if _start == -1:
            {fn_die}()
        _start += len(_marker)
        _end = _content.find('"', _start)
        if _end == -1:
            {fn_die}()
        _stored = _content[_start:_end]
        _rebuilt = _content[:_start] + "0" * 64 + _content[_end:]
        if not hmac.compare_digest(hashlib.sha256(_rebuilt.encode("utf-8")).hexdigest(), _stored):
            {fn_die}()
        if {v_lock_digest}:
            _name = hashlib.sha256(os.path.basename(__file__).encode("utf-8")).digest()
            if not hmac.compare_digest(_name, {v_lock_digest}):
                {fn_die}()
    except SystemExit:
        raise
    except Exception:
        {fn_die}()
    {v_verified} = True'''

    fn_run_source = f'''def {fn_run}():
    import base64 as _ib
    import importlib.util as _iu
    import tempfile as _it
    import zlib as _iz
    import sys as _isys
    _stage = "container-open"
    _path = None
    _plain = None
    try:
        _state = {v_native_seed}
        _candidates = list({v_native_pool})
        _picked = []
        for _want in {v_native_tags}:
            _found = None
            for _index, _candidate in enumerate(_candidates):
                _digest = {"hashlib.sha256(_state + _candidate).digest()" if native_combine_order == "state_first" else "hashlib.sha256(_candidate + _state).digest()"}
                if hmac.compare_digest(_digest[:len(_want)], _want):
                    _found = _index
                    _state = _digest
                    _picked.append(_candidate)
                    break
            if _found is None:
                raise RuntimeError("container key chain invalid")
            _candidates.pop(_found)
        _key = b"".join(_picked)
        if len(_key) != 32:
            raise RuntimeError("container key invalid")
        _sealed = _ib.b85decode({v_native_container}.encode("ascii"))
        if len(_sealed) < 33 or _sealed[:4] != {v_native_magic}:
            raise RuntimeError("container format invalid")
        from Crypto.Cipher import AES as _ia
        _opened = _ia.new(_key, _ia.MODE_GCM, nonce=_sealed[4:16]).decrypt_and_verify(_sealed[32:], _sealed[16:32])
        _plain = bytearray(_iz.decompress(_opened))
        _opened = None
        _stage = "module-load"
        _fd, _path = _it.mkstemp(prefix=".rt-", suffix={v_native_suffix})
        with os.fdopen(_fd, "wb") as _out:
            _out.write(_plain)
            _out.flush()
            os.fsync(_out.fileno())
        _plain[:] = b"\\x00" * len(_plain)
        _spec = _iu.spec_from_file_location("_pyobf_native", _path)
        if _spec is None or _spec.loader is None:
            raise RuntimeError("native module spec unavailable")
        _module = _iu.module_from_spec(_spec)
        _spec.loader.exec_module(_module)
        _stage = "payload-dispatch"
        return _module.run({v_pool}, {v_seed}, {v_tags}, {v_nonce}, {v_ct}, {v_tag})
    except SystemExit:
        raise
    except Exception as _exc:
        if os.environ.get("PYOBF_LAUNCHER_DIAGNOSTIC") == "1":
            try:
                _detail = str(_exc).replace("\\n", " ").strip()[:180]
                _line = "[pyobf] launcher stage failed: " + _stage + " (" + type(_exc).__name__ + ")"
                if _detail:
                    _line += ": " + _detail
                _isys.stderr.write(_line + "\\n")
            except Exception:
                pass
        {fn_die}()
    finally:
        if _plain is not None:
            try:
                _plain[:] = b"\\x00" * len(_plain)
            except Exception:
                pass
        if _path:
            try:
                os.unlink(_path)
            except OSError:
                pass'''

    marker_literal = f'{v_self_hash} = "'
    header = (
        "#!/usr/bin/env python3\n"
        "import hashlib,os,hmac,time\n"
        f'{v_self_hash} = "{placeholder}"\n'
        f"{v_lock_digest} = {lock_name_digest!r}\n"
        f"{v_marker} = {marker_literal.encode('utf-8')!r}\n"
        f"{v_native_container} = {native_container_b85!r}\n"
        f"{v_native_magic} = {native_magic!r}\n"
        f"{v_native_suffix} = {native_module_suffix!r}\n"
        f"{die_block}\n"
        f"{v_verified} = False\n"
        f"{fn_check_source}\n"
        f"{fn_check}()\n"
    )
    payload = (
        f"{fragment_declarations}\n"
        f"{native_declarations}\n"
        f"{v_native_pool} = {native_pool_literal}\n"
        f"{v_native_seed} = {native_seed!r}\n"
        f"{v_native_tags} = {native_tag_literal}\n"
        f"{v_pool} = {pool_literal}\n"
        f"{v_seed} = {root_seed!r}\n"
        f"{v_tags} = {tag_literal}\n"
        f"{v_nonce} = {bytes(nonce)!r}\n"
        f"{v_ct} = {bytes(ciphertext)!r}\n"
        f"{v_tag} = {bytes(tag)!r}\n"
        f"{fn_run_source}\n"
        # Same redundant, independent re-check as pack()'s footer - see
        # that function's own comment (right before its footer's
        # `if not {v_verified}` line) for the full rationale. A patch
        # that guts fn_check's body (rather than merely patching its
        # exit calls) never reaches the line setting {v_verified},
        # and this still blocks - a genuinely separate failure mode
        # from the one the exit-call obfuscation above defends
        # against.
        f"if not {v_verified}:\n"
        f"    {fn_die}()\n"
        f"{fn_run}()\n"
    )
    rendered = "\n".join(line for line in (header + payload).split("\n") if line.strip())
    self_hash = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    loader = rendered.replace(
        f'{v_self_hash} = "{placeholder}"',
        f'{v_self_hash} = "{self_hash}"',
        1,
    )
    return loader
