"""
leak_scan.py - post-build sanity check: extracts the "sensitive
vocabulary" (real function/class/method names, and notable string
literals like URLs/domains/paths) from the ORIGINAL, pre-obfuscation
source, then scans the actually-built binary/loader file for any of
those tokens still appearing as plaintext.

Why this exists: every fix so far (identifier renaming, string
encryption, bytes-literal ciphertext) has been verified by manually
running `strings` on a build and eyeballing the output - which is
exactly the kind of repetitive manual step that should be automated
and run on every build, not just when something is specifically
suspected. This module doesn't do anything the earlier passes don't
already try to prevent; it's a same-process VERIFICATION that those
passes actually worked on THIS specific build, catching the case
where e.g. a decoy class name happens to collide with a substring of
a suspect list, or a name shows up somewhere unexpected because of
some interaction between passes that wasn't anticipated.

Approach: reads the built file's raw bytes and searches for complete
identifier tokens (not arbitrary substrings) and notable URL/domain
strings. The Cython pipeline scans the compiled application ELF before
an optional integrity guard or one-file launcher wraps it. This avoids
confusing generated launcher helpers with names from the user's source.
It does not invoke the external `strings` command, so it works on
Termux/Android even when binutils is unavailable.

Names also used as attributes on receivers the renamer cannot prove
local are excluded from the leak vocabulary: those spellings must remain
intact for external APIs (for example `thread.start()`).

KNOWN LIMITATION: this is a plaintext scan. It will not find a leaked
name that's reversed, encrypted, fragmented, or otherwise transformed.
It is a useful regression check for verbatim names, not a formal
security guarantee or proof that the whole program is unrecoverable.
"""
import ast
import re


def _collect_external_attribute_names(tree: ast.AST) -> set:
    """Return method-like names that must remain available for external APIs.

    The identifier renamer deliberately preserves ``obj.method`` when the
    receiver cannot be proven to be an instance of a class defined in this
    file.  A name such as ``start`` can therefore be both a locally-defined
    method (which gets renamed) and a required external API attribute
    (for example ``thread.start()``).  A raw binary scan cannot distinguish
    those two uses, so such a spelling must not be treated as a leak token.

    Same-class ``self.method`` / ``cls.method`` references are not considered
    external when the method is defined in the current class.  This keeps
    private methods such as ``self._state()`` eligible for leak checking.
    The analysis is intentionally conservative: uncertain receivers are
    treated as external, preferring a possible missed warning over a false
    leak report.
    """
    external = set()

    class _Scanner(ast.NodeVisitor):
        def __init__(self):
            self.class_stack = []
            self.receiver_stack = []

        def visit_ClassDef(self, node):
            methods = {
                item.name for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            self.class_stack.append((node.name, methods))
            self.generic_visit(node)
            self.class_stack.pop()

        def _visit_function(self, node):
            receiver = None
            if self.class_stack:
                positional = list(node.args.posonlyargs) + list(node.args.args)
                if positional and positional[0].arg in {"self", "cls"}:
                    receiver = positional[0].arg
            self.receiver_stack.append(receiver)
            self.generic_visit(node)
            self.receiver_stack.pop()

        def visit_FunctionDef(self, node):
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node):
            self._visit_function(node)

        def visit_Attribute(self, node):
            current_class = self.class_stack[-1] if self.class_stack else None
            current_receiver = self.receiver_stack[-1] if self.receiver_stack else None
            same_class_receiver = (
                current_class is not None
                and current_receiver is not None
                and isinstance(node.value, ast.Name)
                and node.value.id == current_receiver
                and node.attr in current_class[1]
            )
            class_receiver = (
                current_class is not None
                and isinstance(node.value, ast.Name)
                and node.value.id == current_class[0]
                and node.attr in current_class[1]
            )
            if not (same_class_receiver or class_receiver):
                external.add(node.attr)
            self.generic_visit(node)

    _Scanner().visit(tree)
    return external


def _collect_sensitive_names(source: str) -> set:
    """
    Pulls function/class/method names out of the ORIGINAL source, before
    any obfuscation pass has touched it. Names also used as external
    attributes are excluded because their spelling must stay intact for
    unknown/external receiver APIs.
    These are exactly the identifiers identifier_rename.py exists to
    rename - so if renaming worked, none of these should appear
    verbatim in the compiled output (dunders and __all__ entries are
    expected exceptions and are excluded here too, matching
    identifier_rename.py's own exclusions, so this check doesn't
    cry wolf over names that were never supposed to be renamed).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            n = node.name
            if not (n.startswith("__") and n.endswith("__")):
                names.add(n)

    # Common short names generate too much noise / false-positive risk
    # (e.g. a 3-letter name might legitimately appear inside an
    # unrelated CPython symbol name) - only flag names long enough to
    # be a meaningful, specific signal.
    # Also exclude spellings that the source itself uses as an external
    # attribute API.  Those accesses must remain unchanged by the
    # receiver-aware identifier renamer (e.g. threading.Thread.start),
    # so finding the same bytes in Cython output is not evidence that the
    # locally-defined method of that spelling failed to rename.
    external_attrs = _collect_external_attribute_names(tree)
    return {n for n in names if len(n) >= 4 and n not in external_attrs}


def _collect_notable_strings(source: str) -> set:
    """
    Pulls string literals that look like URLs, domains, or filesystem
    paths out of the original source - the kind of concrete, specific
    value that's most damaging if it leaks (a target hostname, an API
    endpoint, a hardcoded credential-looking path), as opposed to
    generic short strings that would produce mostly noise.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    url_re = re.compile(r"^(https?://|ftp://|www\.)", re.IGNORECASE)
    domain_re = re.compile(r"^[a-zA-Z0-9.-]+\.(com|net|org|io|dev|app|xyz|ru|cn|id)([/:].*)?$")

    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            v = node.value.strip()
            if len(v) < 6 or len(v) > 200:
                continue
            if url_re.match(v) or domain_re.match(v):
                found.add(v)
    return found


def extract_sensitive_vocabulary(source: str) -> dict:
    """
    Returns {"names": set[str], "strings": set[str]} extracted from
    the ORIGINAL (pre-obfuscation) source. Call this once, before
    obfuscate_file/obfuscate_file_for_cython/obfuscate_file_for_embed
    ever touches the source, and pass the result to scan_binary_for_leaks
    after the build finishes.
    """
    return {
        "names": _collect_sensitive_names(source),
        "strings": _collect_notable_strings(source),
    }


def scan_binary_for_leaks(binary_path: str, vocabulary: dict, max_report: int = 30) -> dict:
    """
    Reads binary_path as raw bytes and checks names from the vocabulary
    as complete identifier tokens. URL/domain strings are checked as
    literal substrings.

    Returns:
      {
        "leaked_names": [str, ...],    # real function/class/method names found
        "leaked_strings": [str, ...],  # real URLs/domains found
        "clean": bool,                 # True if both lists are empty
        "scanned_bytes": int,
      }
    leaked_names/leaked_strings are capped at max_report entries each
    (with the true counts still reflected in a "+N more" marker if
    exceeded) so a badly-obfuscated build (e.g. gate/rename accidentally
    disabled) doesn't produce an unreadably long report.
    """
    with open(binary_path, "rb") as f:
        data = f.read()
    data_lower = data.lower()

    def contains_identifier(token: str) -> bool:
        token_bytes = token.lower().encode("utf-8", "ignore")
        if not token_bytes:
            return False
        # A name is leaked only as a complete identifier, not as a
        # substring of a generated helper such as ``_start`` or
        # ``restart_worker``.  Cython metadata stores real names as
        # standalone NUL-/quote-delimited strings, which still match.
        pattern = re.compile(
            rb"(?<![A-Za-z0-9_])" + re.escape(token_bytes) + rb"(?![A-Za-z0-9_])"
        )
        return pattern.search(data_lower) is not None

    leaked_names = []
    for name in sorted(vocabulary.get("names", ())):
        if contains_identifier(name):
            leaked_names.append(name)

    leaked_strings = []
    for s in sorted(vocabulary.get("strings", ())):
        if s.lower().encode("utf-8", "ignore") in data_lower:
            leaked_strings.append(s)

    truncated_names = leaked_names[:max_report]
    truncated_strings = leaked_strings[:max_report]

    return {
        "leaked_names": truncated_names,
        "leaked_names_total": len(leaked_names),
        "leaked_strings": truncated_strings,
        "leaked_strings_total": len(leaked_strings),
        "clean": not leaked_names and not leaked_strings,
        "scanned_bytes": len(data),
    }


def format_report(scan_result: dict, binary_label: str = "") -> str:
    """
    Formats scan_binary_for_leaks's result as a short, human-readable
    Indonesian-language block for printing in the CLI right after a
    build finishes.
    """
    label = f" ({binary_label})" if binary_label else ""
    lines = [f"=== Laporan leak-scan{label} ==="]
    if scan_result["clean"]:
        lines.append(f"[OK] Bersih - {scan_result['scanned_bytes']} bytes discan, "
                      f"gak ada nama fungsi/class asli atau URL/domain asli yang ketemu.")
        return "\n".join(lines)

    if scan_result["leaked_names"]:
        n_total = scan_result["leaked_names_total"]
        shown = ", ".join(scan_result["leaked_names"])
        extra = f" (+{n_total - len(scan_result['leaked_names'])} lagi)" if n_total > len(scan_result["leaked_names"]) else ""
        lines.append(f"[BOCOR] {n_total} nama fungsi/class/method asli masih kebaca: {shown}{extra}")
    if scan_result["leaked_strings"]:
        n_total = scan_result["leaked_strings_total"]
        shown = ", ".join(scan_result["leaked_strings"])
        extra = f" (+{n_total - len(scan_result['leaked_strings'])} lagi)" if n_total > len(scan_result["leaked_strings"]) else ""
        lines.append(f"[BOCOR] {n_total} URL/domain asli masih kebaca: {shown}{extra}")
    lines.append("Cek setting 'Rename identifier' dan 'Encrypt strings' aktif, lalu build ulang.")
    return "\n".join(lines)
