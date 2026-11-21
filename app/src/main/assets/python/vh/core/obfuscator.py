"""
obfuscator.py - orchestrates the full pipeline:
  source.py
    -> AST string literal encryption
    -> junk code injection
    -> compile + marshal + XOR encrypt (packer)
    -> loader stub .py  (this is what you ship / feed to PyInstaller)
"""
import ast
import hashlib
import os
import random
import secrets
import string
from . import string_enc
from . import junk
from . import packer
from . import antidebug
from . import antisandbox
from . import identifier_rename
from . import unicode_names
from . import ssl_pinning
from . import hook_detection
from . import control_flow
from . import ast_integrity
from . import constant_protection
from . import expression_obfuscation
from . import import_obfuscation
from . import attribute_obfuscation
from . import function_transformation
from . import data_flow_obfuscation
from . import native_worker_compat
from . import worker_gate_compat


def _rand_env_name(n: int = 14) -> str:
    # Uppercase so it looks like an ordinary env var to a casual
    # `env`/`printenv` glance, but random per build so it can't be
    # grepped for across every output this tool produces.
    first = random.choice(string.ascii_uppercase)
    rest = "".join(random.choices(string.ascii_uppercase + string.digits, k=max(n - 1, 0)))
    return "VH_" + first + rest


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
def _rand_py_identifier(n: int = 10) -> str:
    return "_" + "".join(random.choices(string.ascii_lowercase, k=n))


def _rand_gate_cache_var(cjk: bool = False) -> str:
    # gate_token_cache_var names a `sys` module ATTRIBUTE (see
    # string_enc.py's build_runtime_header docstring) - it's read/set
    # via getattr/setattr with a plain string, never appears as a
    # Python Name/Store node, so it's never touched by
    # identifier_rename.py's renaming pass either way. Safe to draw
    # from either generator; kept consistent with cjk_identifiers
    # purely so a CJK-mode build doesn't have one stray ASCII name
    # sitting next to everything else.
    return unicode_names.rand_cjk_identifier(6) if cjk else _rand_py_identifier()


def _build_hook_marker():
    # Shared (attribute_name, attribute_value) pair passed to BOTH
    # ssl_pinning.get_ssl_pinning_source's hook_marker param and
    # hook_detection.get_hook_detection_source's known_patch_marker
    # param - see hook_detection.py's module docstring ("TELLING OUR
    # OWN PATCH APART FROM AN ATTACKER'S") for why this needs to be
    # shared and fresh per build rather than a fixed constant: a
    # constant value could be spoofed by an attacker's hook setting
    # the same attribute/value on their own patched function, but a
    # value regenerated randomly every build can't be predicted in
    # advance.
    attr_name = _rand_py_identifier(12)
    attr_value = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
    return (attr_name, attr_value)


class ObfuscationConfig:
    def __init__(
        self,
        encrypt_strings: bool = True,
        min_string_len: int = 1,
        junk_intensity: int = 6,
        anti_debug: bool = True,
        anti_vpn: bool = False,
        strict_network_check: bool = False,
        rename_identifiers: bool = True,
        lock_filename: bool = False,
        require_launcher_gate: bool = True,
        inject_decoy_methods: bool = True,
        periodic_recheck: bool = False,
        enable_version_fallback: bool = False,
        enable_antisandbox: bool = False,
        antisandbox_threshold: int = 6,
        bytecode_integrity_check: bool = False,
        recheck_interval_range: tuple = (4, 9),
        cjk_identifiers: bool = False,
        ssl_pin_sha256: list = None,
        hook_detection: bool = False,
        control_flow_obfuscation: bool = False,
        constant_protection: bool = False,
        expression_obfuscation: bool = False,
        import_obfuscation: bool = False,
        attribute_obfuscation: bool = False,
        function_transformation: bool = False,
        data_flow_obfuscation: bool = False,
    ):
        self.encrypt_strings = encrypt_strings
        self.min_string_len = min_string_len
        self.junk_intensity = junk_intensity
        self.anti_debug = anti_debug
        self.anti_vpn = anti_vpn
        self.strict_network_check = strict_network_check
        self.rename_identifiers = rename_identifiers
        self.lock_filename = lock_filename
        # inject_decoy_methods: splices 1-3 fake methods (that touch a
        # fake self.attribute, so they superficially look like real
        # methods rather than obviously-dead code) into every class
        # found in the user's source. Combined with rename_identifiers
        # covering function/class/method names too, a decoy method and
        # a real-but-renamed method end up sharing the exact same name
        # format and are visually indistinguishable in co_names/a
        # `strings` dump of the compiled binary - there's no
        # "real methods got renamed to a distinctive pattern, junk
        # didn't" tell to filter decoys out by.
        self.inject_decoy_methods = inject_decoy_methods
        # periodic_recheck: re-runs the TracerPid/Windows-debugger-API/
        # process-name/Frida checks from a background daemon thread
        # every few seconds for the process's whole lifetime, closing
        # (not eliminating - see antidebug.py's docstring) the window
        # where a debugger/Frida attaches AFTER the one-time startup
        # check already passed. Only meaningful when anti_debug is
        # also True - see antidebug.get_antidebug_source's docs.
        self.periodic_recheck = periodic_recheck
        # enable_version_fallback: ONLY meaningful for the .py launcher
        # path (packer.py) - Cython/embed builds don't use marshal at
        # all, they're native machine code, so this has no effect
        # there. When True, the loader detects a Python version
        # mismatch at launch and auto-downloads+re-execs under a
        # matching portable interpreter instead of failing outright -
        # see packer.pack()'s docstring for the full mechanism.
        self.enable_version_fallback = enable_version_fallback
        # enable_antisandbox / antisandbox_threshold: refuses to run
        # if enough independent "this looks like an automated analysis
        # VM/sandbox" signals agree at once (low CPU/RAM/uptime/disk,
        # VM-vendor MAC prefix, generic hostname, VM guest-tools
        # artifacts) - see antisandbox.py's module docstring for the
        # full mechanism, weights, and - importantly - its explicit
        # false-positive risk on real but modest hardware (cheap VPS,
        # freshly-reimaged machines, etc). OFF by default for that
        # reason; this does NOT stop static analysis (a script that's
        # only ever read, never executed, never runs these checks at
        # all) - only automated DYNAMIC analysis that actually runs
        # the script in a sandboxed VM.
        self.enable_antisandbox = enable_antisandbox
        self.antisandbox_threshold = antisandbox_threshold
        # bytecode_integrity_check: detects a DIFFERENT kind of tamper
        # from everything else here - not analysis TOOLING (debugger/
        # Frida presence), but the script's OWN CODE being modified
        # while it's running (e.g. a Frida hook replacing a function's
        # compiled bytecode in memory). Snapshots a SHA-256 of every
        # top-level function/method's __code__.co_code right after all
        # of the user's own definitions finish, then periodically
        # re-hashes and compares. OFF by default: unlike
        # periodic_recheck, this can genuinely false-positive on some
        # legitimate dynamic patterns (a decorator that replaces a
        # function object after definition) - see
        # antidebug.get_antidebug_source's docstring for the full
        # mechanism and stated limitations. Only meaningful when
        # anti_debug is also True.
        self.bytecode_integrity_check = bytecode_integrity_check
        # recheck_interval_range: shared by periodic_recheck AND
        # bytecode_integrity_check's background threads - how often
        # (in seconds, randomized within this range each iteration) they
        # re-run their respective checks. Shorter narrows the detection
        # window but costs more CPU/wakeups; longer is cheaper but
        # gives an attacker more time between checks.
        self.recheck_interval_range = recheck_interval_range
        # require_launcher_gate: if True, the protected script refuses
        # to run unless it was started BY its own launcher (bootstrap.py's
        # .py wrapper or native_launcher.py's binary wrapper), which sets
        # a fresh random per-run token in an env var right before
        # starting it. This is what closes the "I found the extracted
        # binary's path on disk, I'll just run it directly and skip the
        # launcher (and every lock-filename/integrity check that only
        # lives in the launcher)" bypass - see native_launcher.py's and
        # bootstrap.py's docstrings for the full rationale.
        self.require_launcher_gate = require_launcher_gate
        # cjk_identifiers: when True, every randomized Python
        # identifier this tool generates (local var/function/class
        # names from identifier_rename.py, and the string-decrypt
        # header's function/table/key/alias names from string_enc.py)
        # is built from random CJK (Han) characters instead of plain
        # ASCII "_abc123"-style names - see core/unicode_names.py's
        # module docstring for the full rationale and the Cython
        # caveat. Does NOT affect the gate env var name
        # (_rand_env_name below) - that name has to survive as an OS
        # environment variable name across platforms/shells, where
        # non-ASCII env var names are unreliable, so it always stays
        # ASCII regardless of this setting. OFF by default: this is a
        # newer, less-battle-tested naming mode than the ASCII one.
        self.cjk_identifiers = cjk_identifiers
        # ssl_pin_sha256: list of SHA-256 SPKI (public-key) certificate
        # fingerprints for `requests`-based HTTPS pinning - see
        # ssl_pinning.py's module docstring for the full mechanism.
        # None/empty means the feature is off (no source injected at
        # all, zero overhead/behavior change) - this is opt-in because
        # it requires the USER to have already generated real pin
        # values for their own server(s) (ssl_pinning.compute_pin_from_der);
        # there's no sensible default pin to ship, and getting this
        # wrong (e.g. pinning to a value that doesn't match the real
        # server) breaks 100% of that program's HTTPS traffic outright
        # - unlike this project's other opt-in hardening flags, a
        # misconfiguration here isn't a stealth/detection trade-off,
        # it's a hard functional break, so it stays off unless the
        # user explicitly supplies fingerprints they've verified.
        self.ssl_pin_sha256 = ssl_pin_sha256 or []
        # hook_detection: when True, checks requests.Session.send /
        # urllib3.connection.HTTPSConnection.connect /
        # http.client.HTTPSConnection.connect for signs of external
        # monkey-patching (e.g. a sitecustomize.py-injected hook
        # reading request/response bodies) and terminates via the
        # same die-helper mechanism packer.py's own integrity checks
        # use - see core/hook_detection.py's module docstring for the
        # full mechanism and, importantly, what this does NOT cover
        # (aiohttp/httpx, sys.addaudithook-based monitoring, and
        # PYTHONPATH injection that cleans up its own traces before
        # the target's own code runs - none of these are silently
        # "handled", they're genuinely out of reach from inside the
        # same process). OFF by default: this is a newer, narrower
        # feature than ssl_pin_sha256, and like every other opt-in
        # hardening flag in this project, should be tested against
        # the actual output before being relied on.
        self.hook_detection = hook_detection
        # Conservative control-flow flattening is opt-in and intentionally
        # defaults OFF until the user's own workload has passed regression tests.
        self.control_flow_obfuscation = bool(control_flow_obfuscation)
        # Constant Protection is an opt-in AST pass for immutable literal
        # values. It runs before identifier renaming/string encryption so
        # the generated helper is handled by those established passes too.
        self.constant_protection = bool(constant_protection)
        # Expression-shape transformation is opt-in and limited to truth-test contexts.
        self.expression_obfuscation = bool(expression_obfuscation)
        # Import rewriting is opt-in and limited to supported absolute imports.
        self.import_obfuscation = bool(import_obfuscation)
        # Attribute obfuscation is conservative and opt-in; only statically
        # proven local instance fields are renamed.
        self.attribute_obfuscation = bool(attribute_obfuscation)
        # Function/data-flow passes are opt-in and conservatively skip scopes
        # whose introspection or control semantics could be changed.
        self.function_transformation = bool(function_transformation)
        self.data_flow_obfuscation = bool(data_flow_obfuscation)


def generate_gate_info() -> dict:
    """
    Generates one fresh {env_name, token, token_hash} triple for a
    build. env_name/token are what the launcher (bootstrap.py /
    native_launcher.py) must set as an environment variable on the
    child process right before starting it - NEVER written to disk
    anywhere, only held in memory for that one build+launch. token_hash
    is what gets baked into the protected script itself (via
    antidebug.get_antidebug_source's gate_token_hash param) for it to
    compare against at its own startup. A fresh token is generated
    every build, so a value observed once isn't replayable against a
    different build.
    """
    env_name = _rand_env_name()
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return {"env_name": env_name, "token": token, "token_hash": token_hash}


def _insert_before_first_active_statement(source: str, injection: str) -> str:
    """
    Parses `source`, finds the first top-level statement that ISN'T a
    function/class definition, import, or a plain assignment (i.e. the
    first statement that actually DOES something - typically a call
    like `main()` at the bottom of a script), and returns source with
    `injection` spliced in as its own line immediately before that
    statement.

    Why this matters specifically for bytecode_integrity_check: if the
    baseline snapshot is naively appended after the ENTIRE source
    (which is what a plain string concatenation does), and the user's
    script calls its own main()/entry point as its last top-level
    statement (an extremely common pattern - `def main(): ...` then
    `main()`), the snapshot would only be taken AFTER main() has
    already finished running - meaning the recheck thread starts with
    no time left to ever catch anything, since the process is already
    about to exit. Splicing the injection in right before the first
    active statement instead means the snapshot captures every
    function/class exactly as fully defined (all definitions above it
    have already run), while still running BEFORE any of the user's
    actual program logic starts - which is the only insertion point
    that's both complete (sees every definition) and useful (leaves
    the recheck thread time to actually run alongside the program).

    Falls back to appending injection at the very END of source if no
    such "first active statement" is found (e.g. a source file that's
    ONLY definitions/imports with no top-level call at all - in that
    case there's nothing to insert before, so appending is equivalent
    and safe) or if source fails to parse for any reason (defensive -
    this should never normally happen since callers already ensure
    source is valid Python by this point in the pipeline).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source + "\n" + injection

    _DEFINITION_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                          ast.Import, ast.ImportFrom)
    insertion_line = None
    for node in tree.body:
        if isinstance(node, _DEFINITION_TYPES):
            continue
        if isinstance(node, ast.Assign) or isinstance(node, ast.AnnAssign):
            # Plain assignments (constants, __all__, etc) are treated
            # like definitions too - they don't run user LOGIC, just
            # set up state, and commonly appear interleaved with
            # definitions at module scope.
            continue
        insertion_line = node.lineno
        break

    if insertion_line is None:
        return source + "\n" + injection

    lines = source.splitlines(keepends=True)
    # lineno is 1-indexed; insert BEFORE that line.
    idx = insertion_line - 1
    return "".join(lines[:idx]) + injection + "\n" + "".join(lines[idx:])


def obfuscate_source(source: str, config: ObfuscationConfig, expected_filename: str = None,
                      gate_info: dict = None) -> str:
    # require_launcher_gate is now MANDATORY for this (.py launcher /
    # packer.pack()) pipeline - not just a recommended default. See
    # packer.pack()'s docstring for the full reasoning: without a real
    # gate token, the AES payload key is fully recoverable by static
    # analysis alone (confirmed happening in practice), which makes
    # require_launcher_gate=False silently ship something with no
    # actual protection despite looking obfuscated. Fail loudly and
    # early here, before any of the (expensive) obfuscation passes
    # below run, rather than deep inside packer.pack().
    if not config.require_launcher_gate:
        raise ValueError(
            "ObfuscationConfig.require_launcher_gate must be True for the .py launcher "
            "pipeline (obfuscate_source/obfuscate_file) - building with it False is no "
            "longer supported, since the AES payload key would otherwise be fully "
            "recoverable by static analysis with no actual protection. Set "
            "require_launcher_gate=True and pass gate_info=obfuscator.generate_gate_info()."
        )
    if not gate_info or not gate_info.get("env_name") or not gate_info.get("token"):
        raise ValueError(
            "obfuscate_source/obfuscate_file requires a real gate_info dict (from "
            "obfuscator.generate_gate_info()) when config.require_launcher_gate is True "
            "(which is now always required for this pipeline) - got: " + repr(gate_info)
        )

    # Run non-executing AST validation before transformations.  This catches
    # invalid input early and records the docstring contract that the source-
    # to-source passes below must preserve.
    ast_integrity.validate_source(source, stage="input")
    original_docstrings = ast_integrity.capture_docstring_contract(source, stage="input")
    gate_token_cache_var = _rand_gate_cache_var(config.cjk_identifiers) if config.require_launcher_gate else ""

    # Keep the module docstring and __future__ directives ahead of every
    # generated block.  Without this, the launcher pipeline's runtime header
    # or junk code can invalidate future imports and make __doc__ disappear.
    module_preamble, source = _extract_future_imports(source)

    # Make runtime file references point at the outer launcher (sys.argv[0]),
    # not a temporary native payload module's __file__. This covers both the
    # regular encrypted-loader pipeline and Cython --embed builds.
    source, native_worker_report = native_worker_compat.patch_runtime_worker_entrypoint(source)
    config.native_worker_compat_report = native_worker_report
    source, worker_gate_report = worker_gate_compat.patch_worker_gate_environment(
        source,
        gate_info.get("env_name") if config.require_launcher_gate else None,
        gate_token_cache_var if config.require_launcher_gate else None,
    )
    config.worker_gate_forwarding_report = worker_gate_report
    ast_integrity.validate_source(source, stage="runtime-worker-entrypoint-compat")
    ast_integrity.assert_docstring_contract(
        original_docstrings, source, stage="runtime-worker-entrypoint-compat"
    )

    if getattr(config, "expression_obfuscation", False):
        source, expression_report = expression_obfuscation.obfuscate_expressions(source)
        config.expression_obfuscation_report = expression_report
        ast_integrity.validate_source(source, stage="expression-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="expression-obfuscation"
        )
    if getattr(config, "control_flow_obfuscation", False):
        source = control_flow.obfuscate_control_flow(source)
    constant_runtime_header = ""
    if getattr(config, "constant_protection", False):
        source, constant_runtime_header, constant_report = constant_protection.protect_constants(
            source, gate_info=gate_info,
            gate_token_cache_var=gate_token_cache_var,
        )
        config.constant_protection_report = constant_report
        ast_integrity.validate_source(source, stage="constant-protection")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="constant-protection"
        )
    if getattr(config, "import_obfuscation", False):
        source, import_report = import_obfuscation.obfuscate_imports(source)
        config.import_obfuscation_report = import_report
        ast_integrity.validate_source(source, stage="import-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="import-obfuscation"
        )
    if getattr(config, "attribute_obfuscation", False):
        source, attribute_report = attribute_obfuscation.obfuscate_attributes(source)
        config.attribute_obfuscation_report = attribute_report
        ast_integrity.validate_source(source, stage="attribute-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="attribute-obfuscation"
        )
    if getattr(config, "function_transformation", False):
        source, function_report = function_transformation.transform_functions(source)
        config.function_transformation_report = function_report
        ast_integrity.validate_source(source, stage="function-transformation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="function-transformation"
        )
    if getattr(config, "data_flow_obfuscation", False):
        source, data_flow_report = data_flow_obfuscation.obfuscate_data_flow(source)
        config.data_flow_obfuscation_report = data_flow_report
        ast_integrity.validate_source(source, stage="data-flow-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="data-flow-obfuscation"
        )
    ast_integrity.validate_source(source, stage="future-import/expression/CFO/constant/import")
    ast_integrity.assert_docstring_contract(
        original_docstrings, source, stage="future-import/expression/CFO/constant"
    )

    # Merge the anti-debug/anti-Frida/anti-VPN source in FIRST, before
    # any of the obfuscation passes run. This way its own logic gets
    # identifier-renamed and its own literal strings (e.g. "TracerPid:",
    # "x64dbg", "frida", the ip-api.com URL) get run through the exact
    # same string-encryption pass as the user's code, instead of being
    # injected later as plaintext boilerplate that anyone (or an AI
    # asked to "decompile this") could just read straight off.
    gate_info = gate_info or {}
    ad_prefix, ad_suffix = antidebug.get_antidebug_source(
        config.anti_debug, config.anti_vpn, config.strict_network_check,
        require_launcher_gate=config.require_launcher_gate,
        gate_env_name=gate_info.get("env_name", ""),
        gate_token_hash=gate_info.get("token_hash", ""),
        periodic_recheck=config.periodic_recheck,
        bytecode_integrity_check=getattr(config, "bytecode_integrity_check", False),
        recheck_interval_range=getattr(config, "recheck_interval_range", (4, 9)),
        gate_token_cache_var=gate_token_cache_var,
    )
    as_source = antisandbox.get_antisandbox_source(
        enabled=config.enable_antisandbox,
        score_threshold=config.antisandbox_threshold,
    )
    _hook_marker = _build_hook_marker() if (config.ssl_pin_sha256 and config.hook_detection) else None
    ssl_pin_source = ssl_pinning.get_ssl_pinning_source(
        config.ssl_pin_sha256, enabled=bool(config.ssl_pin_sha256), hook_marker=_hook_marker
    )
    hook_det_source = hook_detection.get_hook_detection_source(
        enabled=config.hook_detection, known_patch_marker=_hook_marker
    )
    merged_pre = (as_source + "\n" + ad_prefix) if as_source else ad_prefix
    if constant_runtime_header:
        merged_pre = constant_runtime_header + "\n" + merged_pre
    merged_pre = (ssl_pin_source + "\n" + merged_pre) if ssl_pin_source else merged_pre
    merged_pre = (merged_pre + "\n" + hook_det_source) if hook_det_source else merged_pre
    # ad_suffix (bytecode baseline snapshot + its recheck thread) MUST
    # run after every one of the user's own function/class definitions
    # exists, but BEFORE the user's program logic actually starts
    # executing (e.g. before a trailing `main()` call). Critically,
    # this insertion must happen against the RAW user `source` alone -
    # NOT against source already merged with ad_prefix - because
    # ad_prefix ends with its own top-level call (runall(), which
    # kicks off the anti-debug/gate checks), and searching the MERGED
    # text for "the first active statement" would find THAT call
    # instead of the user's own entry point, placing the snapshot
    # before any of the user's functions are even defined yet. See
    # _insert_before_first_active_statement's docstring for the full
    # rationale.
    user_source = _insert_before_first_active_statement(source, ad_suffix) if ad_suffix else source
    working = (merged_pre + "\n" + user_source) if merged_pre else user_source
    ast_integrity.validate_source(working, stage="merged-runtime-prelude")
    working_docstrings = ast_integrity.capture_docstring_contract(
        working, stage="merged-runtime-prelude"
    )

    # 0a. decoy method injection (source -> source, AST based). Must
    # run BEFORE identifier_rename so the decoy method names get
    # processed by the exact same renaming pass as real names (in
    # practice they're already emitted in the same naming format, but
    # running it first also means decoys inserted into a class get
    # counted like any other method by every later pass).
    if getattr(config, "inject_decoy_methods", False):
        working = junk.inject_decoy_methods(working)
        ast_integrity.validate_source(working, stage="decoy-method-injection")
        ast_integrity.assert_docstring_contract(
            working_docstrings, working, stage="decoy-method-injection"
        )

    # 0b. local identifier renaming (source -> source, AST based).
    if config.rename_identifiers:
        import_report = getattr(config, "import_obfuscation_report", None)
        preserved_import_names = getattr(import_report, "preserved_names", set())
        working = identifier_rename.rename_identifiers(
            working,
            use_cjk=config.cjk_identifiers,
            preserve_names=preserved_import_names,
        )
        ast_integrity.validate_source(working, stage="identifier-renaming")
        ast_integrity.assert_docstring_contract(
            working_docstrings, working, stage="identifier-renaming"
        )

    # 1. string literal encryption (source -> source, AST based)
    header = ""
    if config.encrypt_strings:
        working, table, key, decrypt_fn_name = string_enc.encrypt_strings(
            working, min_len=config.min_string_len, use_cjk=config.cjk_identifiers
        )
        header = string_enc.build_runtime_header(
            table, key, decrypt_fn_name,
            gate_env_name=gate_info.get("env_name") if config.require_launcher_gate else None,
            gate_token=gate_info.get("token") if config.require_launcher_gate else None,
            gate_token_cache_var=gate_token_cache_var if config.require_launcher_gate else None,
            use_cjk=config.cjk_identifiers,
        )
        ast_integrity.validate_source(working, stage="string-encryption")
        if working_docstrings.module_present:
            ast_integrity.assert_module_doc_assignment(working, stage="string-encryption")
        ast_integrity.assert_docstring_restore_hooks(
            working,
            expected_count=working_docstrings.definition_count,
            stage="string-encryption",
        )
    else:
        ast_integrity.validate_source(working, stage="pre-encryption")
        ast_integrity.assert_docstring_contract(
            working_docstrings, working, stage="pre-encryption"
        )

    # 2. junk code injection (pure noise, never referenced by real code)
    junk_block = ""
    if config.junk_intensity > 0:
        junk_block = junk.generate_junk_block(config.junk_intensity)

    combined = "\n".join(
        part for part in (module_preamble, junk_block, header, working) if part
    )
    ast_integrity.validate_source(combined, stage="final-launcher-source")
    if working_docstrings.module_present:
        ast_integrity.assert_module_doc_assignment(
            combined, stage="final-launcher-source"
        )

    # 3. compile -> marshal -> encrypt -> loader stub (+ whole-file
    # self-integrity-check and optional filename lock). The loader
    # template itself carries no anti-debug logic anymore - it's all
    # inside this same encrypted blob now, alongside the real script.
    # gate_env_name/gate_token are now mandatory (packer.pack raises
    # if either is missing) - see pack()'s docstring for why: the
    # payload's own AES key must be tied to the launcher gate too, not
    # just the anti-debug check living inside the encrypted payload.
    loader_source = packer.pack(
        combined,
        gate_env_name=gate_info.get("env_name"),
        gate_token=gate_info.get("token"),
        gate_token_cache_var=gate_token_cache_var,
        lock_filename=config.lock_filename,
        expected_filename=expected_filename,
        enable_version_fallback=config.enable_version_fallback,
    )
    return loader_source


def obfuscate_file(input_path: str, output_path: str, config: ObfuscationConfig,
                    gate_info: dict = None):
    """
    gate_info: pass the SAME dict returned by generate_gate_info() that
    you will also pass to bootstrap.wrap_binary_as_py / native_launcher.
    build_native_launcher's gate_env_name/gate_token params for this
    build - the compiled script and its launcher must agree on the
    same env_name/token_hash pair, or the gate check always fails.
    If config.require_launcher_gate is True and gate_info is None,
    one is generated here and returned to the caller (so a caller
    that forgets to pass one explicitly still gets a working,
    internally-consistent pair back, rather than silently building
    a script that can never pass its own gate check).
    Returns (output_path, gate_info_used) - gate_info_used is None
    when require_launcher_gate is off.
    """
    if config.require_launcher_gate and gate_info is None:
        gate_info = generate_gate_info()
    with open(input_path, "r", encoding="utf-8") as f:
        source = f.read()
    expected_filename = os.path.basename(output_path)
    loader = obfuscate_source(source, config, expected_filename=expected_filename, gate_info=gate_info)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(loader)
    return output_path, (gate_info if config.require_launcher_gate else None)


def obfuscate_source_for_cython(source: str, config: ObfuscationConfig, gate_info: dict = None) -> str:
    """
    Same passes as the marshal pipeline (including merging the
    anti-debug source in BEFORE renaming/string-encryption, for the
    same reason - so its own strings get individually encrypted too
    and don't show up in a `strings` dump of the compiled binary).
    Stops short of packer.pack() itself since Cython needs real,
    compilable Python/.pyx source, not a pre-compiled bytecode blob.

    gate_info: same role as in obfuscate_file - pass the dict from
    generate_gate_info() so the compiled binary's gate check agrees
    with what native_launcher.py (or bootstrap.wrap_binary_as_py, if
    the Cython binary gets wrapped that way instead) will set in the
    environment right before running it.
    """
    # Use the same static AST checks as the launcher pipeline.  The checker
    # validates source only; it does not execute or rewrite the user's program.
    ast_integrity.validate_source(source, stage="input")
    original_docstrings = ast_integrity.capture_docstring_contract(source, stage="input")
    gate_info = gate_info or {}
    gate_token_cache_var = _rand_gate_cache_var(config.cjk_identifiers) if config.require_launcher_gate else ""

    # Preserve future-import semantics while keeping the directives ahead of
    # every generated block (anti-debug, string-decrypt header, and junk).
    module_preamble, source = _extract_future_imports(source)

    # Resolve __file__ through the actual process entrypoint. In Cython
    # --embed sys.argv[0] identifies the native executable; in a payload
    # imported from a temporary .so it identifies the outer Python launcher.
    source, native_worker_report = native_worker_compat.patch_runtime_worker_entrypoint(source)
    config.native_worker_compat_report = native_worker_report
    source, worker_gate_report = worker_gate_compat.patch_worker_gate_environment(
        source,
        gate_info.get("env_name") if config.require_launcher_gate else None,
        gate_token_cache_var if config.require_launcher_gate else None,
    )
    config.worker_gate_forwarding_report = worker_gate_report
    ast_integrity.validate_source(source, stage="runtime-worker-entrypoint-compat")
    ast_integrity.assert_docstring_contract(
        original_docstrings, source, stage="runtime-worker-entrypoint-compat"
    )

    if getattr(config, "expression_obfuscation", False):
        source, expression_report = expression_obfuscation.obfuscate_expressions(source)
        config.expression_obfuscation_report = expression_report
        ast_integrity.validate_source(source, stage="expression-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="expression-obfuscation"
        )
    if getattr(config, "control_flow_obfuscation", False):
        source = control_flow.obfuscate_control_flow(source)
    constant_runtime_header = ""
    if getattr(config, "constant_protection", False):
        source, constant_runtime_header, constant_report = constant_protection.protect_constants(
            source, gate_info=gate_info,
            gate_token_cache_var=gate_token_cache_var,
        )
        config.constant_protection_report = constant_report
        ast_integrity.validate_source(source, stage="constant-protection")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="constant-protection"
        )
    if getattr(config, "import_obfuscation", False):
        source, import_report = import_obfuscation.obfuscate_imports(source)
        config.import_obfuscation_report = import_report
        ast_integrity.validate_source(source, stage="import-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="import-obfuscation"
        )
    if getattr(config, "attribute_obfuscation", False):
        source, attribute_report = attribute_obfuscation.obfuscate_attributes(source)
        config.attribute_obfuscation_report = attribute_report
        ast_integrity.validate_source(source, stage="attribute-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="attribute-obfuscation"
        )
    if getattr(config, "function_transformation", False):
        source, function_report = function_transformation.transform_functions(source)
        config.function_transformation_report = function_report
        ast_integrity.validate_source(source, stage="function-transformation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="function-transformation"
        )
    if getattr(config, "data_flow_obfuscation", False):
        source, data_flow_report = data_flow_obfuscation.obfuscate_data_flow(source)
        config.data_flow_obfuscation_report = data_flow_report
        ast_integrity.validate_source(source, stage="data-flow-obfuscation")
        ast_integrity.assert_docstring_contract(
            original_docstrings, source, stage="data-flow-obfuscation"
        )
    ast_integrity.validate_source(source, stage="future-import/expression/CFO/constant/import")
    ast_integrity.assert_docstring_contract(
        original_docstrings, source, stage="future-import/expression/CFO/constant"
    )
    ad_prefix, ad_suffix = antidebug.get_antidebug_source(
        config.anti_debug, config.anti_vpn, config.strict_network_check,
        require_launcher_gate=config.require_launcher_gate,
        gate_env_name=gate_info.get("env_name", ""),
        gate_token_hash=gate_info.get("token_hash", ""),
        periodic_recheck=config.periodic_recheck,
        bytecode_integrity_check=getattr(config, "bytecode_integrity_check", False),
        recheck_interval_range=getattr(config, "recheck_interval_range", (4, 9)),
        gate_token_cache_var=gate_token_cache_var,
    )
    as_source = antisandbox.get_antisandbox_source(
        enabled=config.enable_antisandbox,
        score_threshold=config.antisandbox_threshold,
    )
    _hook_marker = _build_hook_marker() if (config.ssl_pin_sha256 and config.hook_detection) else None
    ssl_pin_source = ssl_pinning.get_ssl_pinning_source(
        config.ssl_pin_sha256, enabled=bool(config.ssl_pin_sha256), hook_marker=_hook_marker
    )
    hook_det_source = hook_detection.get_hook_detection_source(
        enabled=config.hook_detection, known_patch_marker=_hook_marker
    )
    merged_pre = (as_source + "\n" + ad_prefix) if as_source else ad_prefix
    if constant_runtime_header:
        merged_pre = constant_runtime_header + "\n" + merged_pre
    merged_pre = (ssl_pin_source + "\n" + merged_pre) if ssl_pin_source else merged_pre
    merged_pre = (merged_pre + "\n" + hook_det_source) if hook_det_source else merged_pre
    user_source = _insert_before_first_active_statement(source, ad_suffix) if ad_suffix else source
    working = (merged_pre + "\n" + user_source) if merged_pre else user_source
    ast_integrity.validate_source(working, stage="merged-runtime-prelude")
    working_docstrings = ast_integrity.capture_docstring_contract(
        working, stage="merged-runtime-prelude"
    )

    if getattr(config, "inject_decoy_methods", False):
        working = junk.inject_decoy_methods(working)
        ast_integrity.validate_source(working, stage="decoy-method-injection")
        ast_integrity.assert_docstring_contract(
            working_docstrings, working, stage="decoy-method-injection"
        )

    if config.rename_identifiers:
        import_report = getattr(config, "import_obfuscation_report", None)
        preserved_import_names = getattr(import_report, "preserved_names", set())
        working = identifier_rename.rename_identifiers(
            working,
            use_cjk=config.cjk_identifiers,
            preserve_names=preserved_import_names,
        )
        ast_integrity.validate_source(working, stage="identifier-renaming")
        ast_integrity.assert_docstring_contract(
            working_docstrings, working, stage="identifier-renaming"
        )

    header = ""
    if config.encrypt_strings:
        working, table, key, decrypt_fn_name = string_enc.encrypt_strings(
            working, min_len=config.min_string_len, use_cjk=config.cjk_identifiers
        )
        header = string_enc.build_runtime_header(
            table, key, decrypt_fn_name,
            gate_env_name=gate_info.get("env_name") if config.require_launcher_gate else None,
            gate_token=gate_info.get("token") if config.require_launcher_gate else None,
            gate_token_cache_var=gate_token_cache_var if config.require_launcher_gate else None,
            use_cjk=config.cjk_identifiers,
        )
        ast_integrity.validate_source(working, stage="string-encryption")
        if working_docstrings.module_present:
            ast_integrity.assert_module_doc_assignment(working, stage="string-encryption")
        ast_integrity.assert_docstring_restore_hooks(
            working,
            expected_count=working_docstrings.definition_count,
            stage="string-encryption",
        )
    else:
        ast_integrity.validate_source(working, stage="pre-encryption")
        ast_integrity.assert_docstring_contract(
            working_docstrings, working, stage="pre-encryption"
        )

    junk_block = ""
    if config.junk_intensity > 0:
        junk_block = junk.generate_junk_block(config.junk_intensity)

    combined = "\n".join(
        part for part in (module_preamble, junk_block, header, working) if part
    )
    ast_integrity.validate_source(combined, stage="final-cython-source")
    if working_docstrings.module_present:
        ast_integrity.assert_module_doc_assignment(combined, stage="final-cython-source")
    return combined


def obfuscate_file_for_cython(input_path: str, output_pyx_path: str, config: ObfuscationConfig,
                               gate_info: dict = None):
    if config.require_launcher_gate and gate_info is None:
        gate_info = generate_gate_info()
    with open(input_path, "r", encoding="utf-8") as f:
        source = f.read()
    pyx_source = obfuscate_source_for_cython(source, config, gate_info=gate_info)
    with open(output_pyx_path, "w", encoding="utf-8") as f:
        f.write(pyx_source)
    return output_pyx_path, (gate_info if config.require_launcher_gate else None)


def obfuscate_file_for_embed(input_path: str, config: ObfuscationConfig, gate_info: dict = None):
    """
    Same obfuscation passes as the Cython path (obfuscate_source_for_cython) -
    embed_build.py needs the same "obfuscated but still valid, compilable
    Python source" input Cython does, it just skips Cython's own
    transpile step and hands the source straight to compile() + marshal
    instead. Returns (obfuscated_source, gate_info_used) - embed_build.py
    does its own compile()/marshal.dumps(), there's no intermediate file.
    """
    if config.require_launcher_gate and gate_info is None:
        gate_info = generate_gate_info()
    with open(input_path, "r", encoding="utf-8") as f:
        source = f.read()
    pyx_source = obfuscate_source_for_cython(source, config, gate_info=gate_info)
    return pyx_source, (gate_info if config.require_launcher_gate else None)
