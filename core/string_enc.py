"""
string_enc.py - walks the target source's AST and replaces string
constant literals with calls to a runtime decrypt function, so the
original strings never appear as plaintext in the shipped bytecode.

Ciphertext representation: raw bytes literals (b"\\x.."), NOT
base85-encoded text. Storing ciphertext as base85 ASCII text (the
previous approach) is still cryptographically opaque - you can't
recover the original string without the key - but base85 encoding by
definition only uses printable ASCII characters, so a long base85
blob still shows up as one long, contiguous, readable-looking chunk
in a `strings <binary>` dump. It doesn't reveal the *content*, but it
visibly marks "there is an encrypted payload sitting right here",
which is exactly what the "kek gini masih kebaca sbg teks" complaint
is about. A Python bytes literal, by contrast, is emitted as an
actual PyBytesObject with raw ciphertext bytes - which are uniformly
distributed pseudorandom bytes (that's what XOR-with-keystream output
looks like) and so almost never form runs of 4+ printable ASCII bytes
in a row, which is the threshold tools like `strings` use to report
a "string" at all. Net effect: encrypted literals stop showing up as
any kind of contiguous readable blob in a binary dump, not just an
unreadable one.

Key storage - WEAKNESS THIS MODULE USED TO HAVE, AND HOW IT'S ADDRESSED
NOW: previously, the decryption key was stored in the SAME file as the
ciphertext it decrypts, in plaintext (a bytes literal), with nothing
else needed to recover it. Anyone who could read the file at all -
whether by opening the .py source directly, or by dumping strings/
disassembling a compiled binary and finding the key's bytes literal -
had everything needed to decrypt every string, with zero additional
effort, regardless of whether they understood anything else about the
program. This is fundamentally different from how real software
protection usually stores secrets: never alongside the ciphertext they
protect.

Two modes now, chosen by whether a gate token is available (i.e.
whether require_launcher_gate is enabled for this build - see
obfuscator.py):

  1. GATE-TOKEN-MIXED (when a gate token is available): the key stored
     in the file is NOT the real decryption key - it's the real key
     XORed with a value derived (via SHA-256) from the SAME per-build,
     per-launch gate token that require_launcher_gate already uses
     (see obfuscator.generate_gate_info() and antidebug.py's gate
     check). That token is never written to disk anywhere and only
     ever exists in the launched process's environment for that one
     run - so reading the extracted/compiled file alone (without ever
     having gone through the launcher, which is exactly the scenario
     require_launcher_gate already exists to block) is not enough to
     recover the real key: the stored bytes are only ever a MASKED
     key, unmaskable only by whoever also has the token. This reuses
     an existing, already-necessary secret rather than inventing a
     new distribution problem - the token already has to reach the
     process through the launcher for the unrelated gate-check to
     work at all, so piggy-backing the string-encryption key on it
     costs nothing extra to distribute correctly.
  2. SPLIT-KEY FALLBACK (when no gate token is available, i.e.
     require_launcher_gate is off): there's no external secret to mix
     in, so the key is instead stored as several separate fragments,
     scattered at different points in the generated header (interleaved
     with other declarations, not as consecutive lines) and
     concatenated back together at runtime - not a cryptographic
     strengthening (the fragments are still all present in the same
     file, so a determined static read still recovers the full key
     eventually), but it does mean "grep for one obvious KEY_NAME
     assignment" no longer works, raising the floor above the previous
     single-line-plaintext-key baseline.

Either way, the STORED value is never the literal key that gets fed
into the XOR keystream - some reconstruction step (unmask via gate
token, or reassemble fragments) always happens first, at runtime.
"""
import ast
import hashlib
import os
import random
import string
from .crypto import xor_encrypt, random_key
from . import unicode_names


def _rand_py_identifier(n: int = 10) -> str:
    return "_" + "".join(random.choices(string.ascii_lowercase, k=n))


def _rand_py_identifier_cjk(n: int = 6) -> str:
    """CJK counterpart to _rand_py_identifier - no collision tracking
    (same as _rand_py_identifier itself: every call site here already
    tolerates independent random names without needing global
    uniqueness, since they're each scoped to their own generated
    header/table). See unicode_names.py for rationale."""
    return unicode_names.rand_cjk_identifier(n)


class StringEncryptor(ast.NodeTransformer):
    def __init__(self, min_len=1, decrypt_fn_name=None, use_cjk=False):
        self.min_len = min_len
        self.table = []  # list of raw ciphertext bytes objects
        self.key = random_key(32)
        # Generated fresh per call unless the caller passes one in -
        # this is what call sites in the rewritten source (__vh_ds__(0)
        # etc, in the OLD fixed-name scheme) actually look like now:
        # a random name that changes every build, so it's no longer
        # possible to fingerprint "this file came from this tool" by
        # grepping for a name that used to be identical everywhere.
        # use_cjk switches the generator to unicode_names' CJK-character
        # identifiers instead of ASCII - see that module's docstring.
        name_fn = _rand_py_identifier_cjk if use_cjk else _rand_py_identifier
        self.decrypt_fn_name = decrypt_fn_name or name_fn()
        self.use_cjk = use_cjk

    @staticmethod
    def _is_docstring_statement(node):
        return (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )

    def _encrypt_string_value(self, value, location=None):
        """Replace one string value with a call into the runtime decryptor."""
        if len(value) < self.min_len:
            return ast.copy_location(ast.Constant(value=value), location) if location else ast.Constant(value=value)
        idx = len(self.table)
        self.table.append(xor_encrypt(value.encode("utf-8"), self.key))
        call = ast.Call(
            func=ast.Name(id=self.decrypt_fn_name, ctx=ast.Load()),
            args=[ast.Constant(value=idx)],
            keywords=[],
        )
        return ast.copy_location(call, location) if location else call

    def _docstring_decorator(self, docstring_expr):
        """Build an identity decorator that restores an encrypted docstring."""
        name_fn = _rand_py_identifier_cjk if self.use_cjk else _rand_py_identifier
        target_name = name_fn(8)
        target = ast.Name(id=target_name, ctx=ast.Load())
        set_doc = ast.Call(
            func=ast.Name(id="setattr", ctx=ast.Load()),
            args=[target, ast.Constant(value="__doc__"), docstring_expr],
            keywords=[],
        )
        body = ast.BoolOp(op=ast.Or(), values=[set_doc, target])
        args = ast.arguments(
            posonlyargs=[], args=[ast.arg(arg=target_name)], vararg=None,
            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[],
        )
        return ast.Lambda(args=args, body=body)

    def _visit_definition_with_docstring(self, node):
        if node.body and self._is_docstring_statement(node.body[0]):
            doc_node = node.body.pop(0)
            encrypted_doc = self._encrypt_string_value(doc_node.value.value, doc_node)
            # The injected decorator is innermost, so it restores the docstring
            # before any user-supplied decorators are applied.
            node.decorator_list.append(self._docstring_decorator(encrypted_doc))
            if not node.body:
                node.body.append(ast.copy_location(ast.Pass(), doc_node))
        return self.generic_visit(node)

    def visit_Module(self, node):
        if node.body and self._is_docstring_statement(node.body[0]):
            doc_node = node.body[0]
            value = self._encrypt_string_value(doc_node.value.value, doc_node)
            assignment = ast.Assign(
                targets=[ast.Name(id="__doc__", ctx=ast.Store())], value=value
            )
            node.body[0] = ast.copy_location(assignment, doc_node)
        return self.generic_visit(node)

    def visit_ClassDef(self, node):
        return self._visit_definition_with_docstring(node)

    def visit_FunctionDef(self, node):
        return self._visit_definition_with_docstring(node)

    def visit_AsyncFunctionDef(self, node):
        return self._visit_definition_with_docstring(node)

    def visit_JoinedStr(self, node):
        # f-strings: literal text segments AND the expression parts
        # both get encrypted. Literal segments (plain ast.Constant str)
        # can't be swapped for a Call node directly inside JoinedStr.values
        # (ast.unparse requires Constant/FormattedValue there), so we
        # convert the WHOLE f-string into string concatenation instead:
        #   f"Halo, {name}!"  ->  (__vh_ds__(0) + str(name) + __vh_ds__(1))
        # This fully removes the plaintext literal chunks.
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                idx = len(self.table)
                enc = xor_encrypt(v.value.encode("utf-8"), self.key)
                self.table.append(enc)
                call = ast.Call(
                    func=ast.Name(id=self.decrypt_fn_name, ctx=ast.Load()),
                    args=[ast.Constant(value=idx)],
                    keywords=[],
                )
                parts.append(ast.copy_location(call, v))
            elif isinstance(v, ast.FormattedValue):
                v.value = self.visit(v.value)
                inner = v.value
                if v.conversion == 114:  # !r
                    inner = ast.Call(func=ast.Name(id="repr", ctx=ast.Load()), args=[inner], keywords=[])
                elif v.conversion == 115:  # !s
                    inner = ast.Call(func=ast.Name(id="str", ctx=ast.Load()), args=[inner], keywords=[])
                elif v.conversion == 97:  # !a
                    inner = ast.Call(func=ast.Name(id="ascii", ctx=ast.Load()), args=[inner], keywords=[])
                fmt_spec = self.visit(v.format_spec) if v.format_spec is not None else ast.Constant(value="")
                fmt_call = ast.Call(
                    func=ast.Name(id="format", ctx=ast.Load()),
                    args=[inner, fmt_spec],
                    keywords=[],
                )
                parts.append(ast.copy_location(fmt_call, v))
            else:
                parts.append(self.visit(v))

        if not parts:
            return ast.copy_location(ast.Constant(value=""), node)
        expr = parts[0]
        for p in parts[1:]:
            expr = ast.BinOp(left=expr, op=ast.Add(), right=p)
        return ast.copy_location(expr, node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) >= self.min_len:
            return self._encrypt_string_value(node.value, node)
        if isinstance(node.value, bytes) and len(node.value) >= self.min_len:
            # bytes literals (b"...") are a SEPARATE constant kind from
            # str in Python's AST - isinstance(x, str) is False for a
            # bytes object, so without this branch every b"..." literal
            # in the source sails straight through untouched. This was
            # a real, confirmed leak: a build embedding protobuf-style
            # binary config data as bytes literals (device/version
            # strings inside a serialized blob) had that data survive
            # in full, human-readable plaintext in the compiled
            # binary's data section, because only the str branch above
            # existed. The second positional arg (`True`) tells the
            # generated decrypt function to return raw bytes instead of
            # decoding as UTF-8 - see build_runtime_header's decrypt_fn
            # for the corresponding branch. Ciphertext bytes themselves
            # are identical either way (XOR against the raw byte
            # values, no UTF-8 involved on the encrypt side either) -
            # only the RUNTIME return type differs.
            idx = len(self.table)
            enc = xor_encrypt(node.value, self.key)
            self.table.append(enc)
            call = ast.Call(
                func=ast.Name(id=self.decrypt_fn_name, ctx=ast.Load()),
                args=[ast.Constant(value=idx), ast.Constant(value=True)],
                keywords=[],
            )
            return ast.copy_location(call, node)
        return node


def encrypt_strings(source: str, min_len: int = 1, decrypt_fn_name: str = None, use_cjk: bool = False):
    """
    Returns (new_source_code, encrypted_table, key_bytes, decrypt_fn_name)
    encrypted_table is a list of raw `bytes` ciphertext objects (NOT
    base85 text) - see module docstring for why. decrypt_fn_name is
    the (randomly generated, unless one was passed in) name used for
    every __vh_ds__-style call site in new_source_code - the caller
    MUST pass this exact same value to build_runtime_header() so the
    function it defines matches the name actually being called.

    use_cjk: when True (and decrypt_fn_name wasn't explicitly passed),
    the generated decrypt_fn_name is a CJK identifier instead of
    ASCII - see unicode_names.py. Callers MUST pass the same use_cjk
    value to build_runtime_header() too, so every OTHER name that
    function generates (table/key vars, its helper functions, import
    aliases) matches in style rather than mixing CJK and ASCII names
    in the same header.
    """
    tree = ast.parse(source)
    enc = StringEncryptor(min_len=min_len, decrypt_fn_name=decrypt_fn_name, use_cjk=use_cjk)
    new_tree = enc.visit(tree)
    ast.fix_missing_locations(new_tree)
    new_source = ast.unparse(new_tree)
    return new_source, enc.table, enc.key, enc.decrypt_fn_name


def build_runtime_header(table, key: bytes, decrypt_fn_name: str, gate_env_name: str = None,
                          gate_token: str = None, gate_token_cache_var: str = None,
                          use_cjk: bool = False) -> str:
    """
    Produces the python source prefix that defines the decrypt table,
    (masked or split) key, and the decrypt function. This is injected
    before the (now string-free) transformed source.

    decrypt_fn_name: REQUIRED - must be the exact same value that was
    passed to (or returned by) encrypt_strings() for this same build,
    since that's the name every __vh_ds__-style call site in the
    transformed source actually calls. Every other name this function
    needs (the table variable, the key variable, its own helper
    functions, its import aliases) is generated fresh right here on
    every call - none of it is a fixed constant anymore, so there's
    no single name left in this whole header that's identical across
    two different builds.

    gate_env_name / gate_token: if BOTH are provided (i.e.
    require_launcher_gate is enabled for this build - see
    obfuscator.generate_gate_info(), which creates the actual token
    value BEFORE packer.pack() ever runs, so the real token - not a
    placeholder - is available here at build time), switches to the
    GATE-TOKEN-MIXED key storage mode described in the module
    docstring: the value stored in the file is
    `key XOR SHA256(gate_token)`, computed once, right now, using the
    real token. At runtime, the generated code needs that same token
    back to re-derive the same mask - see gate_token_cache_var below
    for exactly where it reads that from, since os.environ alone
    isn't reliable for this (antidebug.py's gate check deliberately
    clears the env var after its own one-time verification - see that
    module's gate check comment for why). XOR being its own inverse is
    what makes the mask-then-unmask round trip work without ever
    needing to store the real key anywhere.
    If gate_env_name/gate_token are None/empty (no gate token available
    for this build, i.e. require_launcher_gate is off), falls back to
    the SPLIT-KEY mode instead - see module docstring for both.

    gate_token_cache_var: REQUIRED whenever gate_env_name/gate_token
    are provided (raises ValueError otherwise). Names the SAME custom
    attribute antidebug.py's gate check (see that module's
    get_antidebug_source, `gate_token_cache_var` param) stashes the
    verified token onto the `sys` module object with, right before
    deleting the token from os.environ. The generated real-key-recovery
    function reads the token via getattr(sys, that_name) (falling
    back to os.environ only as a defensive secondary path, in case
    gate order or config ever changes such that the cached attribute
    isn't set yet) rather than only os.environ, which is what makes
    key-unmasking keep working for every decrypt call for the rest of
    the process's life, not just the first one before the gate check's
    own cleanup runs. A module ATTRIBUTE (not a plain variable) is
    used specifically because this header and antidebug.py's gate
    check are two separate source fragments assembled at different
    pipeline stages, only one of which goes through
    identifier_rename.py's renaming pass - a plain variable name
    agreed on between them would desync the moment one side's copy
    got renamed and the other didn't, whereas an attribute name
    string is never a rename candidate on either side.

    Every table entry (the ciphertext itself) is still always emitted
    as a Python BYTES LITERAL (b"\\x.."), same as before - see module
    docstring for why that specifically matters for `strings` output
    on a compiled binary. This function only changes how the KEY
    itself is stored/reconstructed, not the ciphertext table.

    use_cjk: generates every OTHER name this function creates (table/
    key vars, helper function names, import aliases) as CJK
    identifiers instead of ASCII - see unicode_names.py. Pass the
    SAME value used for the encrypt_strings() call that produced
    decrypt_fn_name, so this header's names match that style too
    (decrypt_fn_name itself is a parameter here, not regenerated -
    its style was already decided by encrypt_strings()).
    """
    if not decrypt_fn_name:
        raise ValueError(
            "build_runtime_header: decrypt_fn_name is required - pass the exact "
            "value encrypt_strings() returned, or every __vh_ds__-style call site "
            "in the transformed source will reference an undefined function."
        )

    name_fn = _rand_py_identifier_cjk if use_cjk else _rand_py_identifier
    table_literal = "[" + ", ".join(repr(bytes(entry)) for entry in table) + "]"

    if gate_env_name and gate_token:
        if not gate_token_cache_var:
            raise ValueError(
                "build_runtime_header: gate_token_cache_var is required when "
                "gate_env_name/gate_token are provided - it must match the same "
                "name passed to antidebug.get_antidebug_source's gate_token_cache_var, "
                "or key-unmasking will only work until the gate check clears os.environ."
            )
        table_name, key_name, fn_ks, fn_real_key = (name_fn() for _ in range(4))
        alias_hl, alias_os, alias_sys = (name_fn(6) for _ in range(3))

        token_mask = hashlib.sha256(gate_token.encode("utf-8")).digest()
        # key and token_mask may have different lengths (key is 32
        # bytes from random_key(32); a SHA-256 digest is also 32 bytes,
        # so in practice they always match here - but repeat/truncate
        # defensively rather than assume, in case either changes size
        # independently in the future).
        repeated_mask = (token_mask * ((len(key) // len(token_mask)) + 1))[:len(key)]
        masked_key = bytes(a ^ b for a, b in zip(key, repeated_mask))
        masked_key_literal = repr(masked_key)
        header = f'''
import hashlib as {alias_hl}
import os as {alias_os}
{table_name} = {table_literal}
{key_name} = {masked_key_literal}
def {fn_ks}(key, length):
    out = bytearray()
    block = key
    while len(out) < length:
        block = {alias_hl}.sha256(block).digest()
        out.extend(block)
    return bytes(out[:length])
def {fn_real_key}():
    # Prefer the value antidebug.py's gate check cached on the sys
    # module (see this function's docstring) - it remains populated
    # for the rest of the process's life. Falling back to os.environ
    # directly covers the (should-never-normally-happen) case where
    # this runs before the gate check has, in which case the env var
    # the launcher set is still there too.
    import sys as {alias_sys}
    _tok = getattr({alias_sys}, {gate_token_cache_var!r}, None) or {alias_os}.environ.get({gate_env_name!r}, "")
    _mask = {alias_hl}.sha256(_tok.encode("utf-8")).digest()
    _mask = (_mask * ((len({key_name}) // len(_mask)) + 1))[:len({key_name})]
    return bytes(a ^ b for a, b in zip({key_name}, _mask))
def {decrypt_fn_name}(idx, is_bytes=False):
    raw = {table_name}[idx]
    ks = {fn_ks}({fn_real_key}(), len(raw))
    plain = bytes(a ^ b for a, b in zip(raw, ks))
    return plain if is_bytes else plain.decode("utf-8")
'''
        return header
    else:
        return _build_split_key_header(table, key, decrypt_fn_name, use_cjk=use_cjk)


def _build_split_key_header(table, key: bytes, decrypt_fn_name: str, use_cjk: bool = False) -> str:
    """
    SPLIT-KEY fallback mode (used when no gate token is available for
    this build - see build_runtime_header's docstring). Splits `key`
    into 3-5 fragments of random (but summing-to-total) length,
    assigns each to its own separately-named variable, and scatters
    those assignments among a few harmless-looking decoy variable
    assignments so they don't visually stand out as a contiguous key
    declaration block. Reassembly happens in the declared ORIGINAL
    order at runtime (fragment order itself isn't randomized, since
    the variable NAMES are already randomized per-build and the
    fragments are scattered among decoys - reordering the fragments
    too would need the reassembly code to also know that order, which
    just moves the same information elsewhere rather than removing it).
    """
    name_fn = _rand_py_identifier_cjk if use_cjk else _rand_py_identifier
    table_name, key_name, fn_ks = (name_fn() for _ in range(3))
    alias_hl = name_fn(6)

    n_fragments = random.randint(3, 5)
    # split key into n_fragments pieces of near-equal (but not
    # perfectly uniform - avoids an obvious "always exactly len/n"
    # pattern) length
    cut_points = sorted(random.sample(range(1, len(key)), n_fragments - 1))
    bounds = [0] + cut_points + [len(key)]
    fragments = [key[bounds[i]:bounds[i + 1]] for i in range(len(bounds) - 1)]

    frag_names = [name_fn() for _ in fragments]
    decoy_names = [name_fn() for _ in range(random.randint(2, 4))]

    # Interleave fragment declarations with decoy declarations, in a
    # shuffled order, so a plain top-to-bottom read of the header
    # doesn't show "N key-shaped lines in a row" as a visual tell.
    decl_lines = []
    for name, frag in zip(frag_names, fragments):
        decl_lines.append(f"{name} = {frag!r}")
    for name in decoy_names:
        decl_lines.append(f"{name} = {_random_key_shaped_decoy()!r}")
    random.shuffle(decl_lines)

    table_literal = "[" + ", ".join(repr(bytes(entry)) for entry in table) + "]"
    reassemble_expr = " + ".join(frag_names)
    decls_src = "\n".join(decl_lines)

    header = f'''
import hashlib as {alias_hl}
{table_name} = {table_literal}
{decls_src}
{key_name} = {reassemble_expr}
def {fn_ks}(key, length):
    out = bytearray()
    block = key
    while len(out) < length:
        block = {alias_hl}.sha256(block).digest()
        out.extend(block)
    return bytes(out[:length])
def {decrypt_fn_name}(idx, is_bytes=False):
    raw = {table_name}[idx]
    ks = {fn_ks}({key_name}, len(raw))
    plain = bytes(a ^ b for a, b in zip(raw, ks))
    return plain if is_bytes else plain.decode("utf-8")
'''
    return header


def _random_key_shaped_decoy() -> bytes:
    return bytes(random.randint(0, 255) for _ in range(random.randint(4, 12)))
