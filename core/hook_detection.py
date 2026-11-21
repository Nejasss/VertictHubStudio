"""
hook_detection.py - returns a source-code string that checks, at
runtime, whether key HTTP-layer functions (requests.Session.send,
urllib3.connection.HTTPSConnection.connect,
http.client.HTTPSConnection.connect) have been monkey-patched by code
OTHER than this project's own ssl_pinning.py, and reacts (via the
same die-helper mechanism as packer.py's integrity checks) if so.

WHY THIS EXISTS
core/ssl_pinning.py's certificate pinning defends against a MITM
attacker OUTSIDE the process (a proxy presenting a forged certificate
for a real domain). It has no visibility into, and cannot defend
against, an attacker who has already gained the ability to run code
INSIDE the same Python process BEFORE the program's own code executes
- e.g. by setting PYTHONPATH to inject a sitecustomize.py, which
Python auto-imports on interpreter startup. That's a fundamentally
different, and much stronger, threat model: someone who can already
control what gets imported before your code runs has effectively
already compromised the execution environment, and this module makes
no claim of fully closing that gap (see the "WHAT THIS DOES NOT COVER"
section below for what remains fundamentally out of reach). What it
DOES catch is a specific, concrete technique that was directly
observed in a real hooking/analysis tool aimed at obfuscated Python
programs: monkey-patching requests.Session.send (or the lower-level
urllib3/http.client connect methods) to read off request/response
bodies - e.g. to log credentials or tokens - BEFORE they'd otherwise
be protected by anything at the network layer.

HOW THE DETECTION WORKS
A monkey-patched function is, structurally, a plain Python function
object assigned over a class attribute that used to hold a bound
method defined inside a specific library module. Reassigning it
necessarily changes two introspectable attributes that a legitimate,
unpatched method never has reason to have:
  - __module__: normally e.g. "requests.sessions" - becomes whatever
    module the ATTACKER's replacement function was defined in
    (typically "sitecustomize", "__main__", or wherever their hook
    lives)
  - __qualname__: normally e.g. "Session.send" - becomes the
    attacker's own function's name
This was verified directly: patching requests.Session.send with even
a completely transparent passthrough wrapper (one that calls the
original function and changes no behavior at all) still changes both
attributes, because the attribute change is a property of REASSIGNING
the class attribute, not of what the new function does. There is no
way to monkey-patch a method this way without this signature changing
- it's not a heuristic that can be evaded by a "cleaner" hook, short
of avoiding monkey-patching this specific set of functions entirely
(which is exactly the point - see "aiohttp"/httpx and sys.addaudithook
in WHAT THIS DOES NOT COVER for techniques that structurally avoid
this signature and are NOT caught here).

TELLING OUR OWN PATCH APART FROM AN ATTACKER'S
core/ssl_pinning.py ALSO monkey-patches urllib3.connection.
HTTPSConnection.connect and http.client.HTTPSConnection.connect (to
add the pin check) - from this detection's point of view, our own
legitimate patch is indistinguishable from an attacker's by
__module__/__qualname__ alone, since both are "a locally-defined
function now sitting where a library method used to be". This is
resolved with a shared, per-build-random marker: when both
ssl_pinning and hook_detection are enabled together, obfuscator.py
generates one (attribute_name, attribute_value) pair and passes it to
BOTH get_ssl_pinning_source(..., hook_marker=...) and this module's
get_hook_detection_source(..., known_patch_marker=...). ssl_pinning
sets that attribute on its own patched functions; this module checks
for a __module__ mismatch FIRST, and only escalates if the mismatched
function ALSO lacks the expected marker attribute/value - so our own
pinning patch is recognized and ignored, while a same-signature
attacker patch (which has no way to know the per-build marker value
in advance, since it's freshly random every build) is not. If
ssl_pinning is not enabled for a given build, known_patch_marker
should be left as None - see get_hook_detection_source's docstring.

WHAT THIS DOES NOT COVER (told plainly, not hidden)
  - aiohttp.ClientSession._request / httpx's transport layer: not
    checked at all in this version. Both exist and would need their
    own verified baseline __module__/__qualname__ - not added here
    without the same direct verification this project's other
    security features go through first (see project history: a
    previous change shipped without full verification broke a real
    build's stdin entirely). A future addition should follow the same
    pattern as urllib3/http.client here, once independently verified.
  - sys.addaudithook-based monitoring (used by some analysis tools to
    log exec/compile/open/socket events): NOT a monkey-patch at all -
    it is a first-class, documented Python API specifically designed
    to add observers without altering any existing function's
    identity, __module__, id(), or behavior. There is no
    introspection point this module (or anything else running in the
    same process, by design of the API) can use to detect that an
    audit hook has been registered, let alone by whom. This is a
    deliberate Python language design trade-off (auditing needs to be
    tamper-evident FROM THE AUDITED CODE's perspective in the sense
    that audited code can't easily remove hooks it doesn't like -
    which cuts both ways: it also means audited code can't easily
    detect being watched this way either), not a gap specific to this
    project.
  - Once PYTHONPATH/sys.path-based injection has ALREADY happened and
    the injecting code has cleaned up its own traces (removed its
    directory from sys.path, unset PYTHONPATH) before the target
    program's own code starts running, there is nothing left in
    either of those to detect retroactively - this module does not
    attempt PYTHONPATH/sys.path forensics for exactly that reason
    (checked directly against a real tool doing this: the cleanup
    happens reliably before the target's own first line runs).
  - Any attacker capable of patching the CPython interpreter itself,
    or reading/writing the process's memory directly (ptrace,
    /proc/pid/mem) has capabilities this module cannot meaningfully
    contend with from user-space Python code - see this project's own
    cython_guard.py memory-check feature for the corresponding
    defense at the native-binary level, which has the same
    fundamental ceiling (an attacker with full memory access to the
    process wins; software running IN that process can only make it
    harder, never impossible).

WHAT HAPPENS ON DETECTION: the same die-helper mechanism packer.py's
own integrity checks use (a randomly-chosen-per-build mechanism -
os._exit via an obfuscated getattr, raise SystemExit, or an infinite
sleep - see packer.py's _build_die_helper docstring for why this
specific mix exists) is invoked. This module does not invent its own
separate termination mechanism; get_hook_detection_source generates
its own die-helper source fragment for standalone use (when this
module is used outside packer.py's own integrated build) via the
same _build_die_helper-equivalent approach, OR (see
build_hook_check_block) can be wired to call an externally-supplied
die-function name, matching whatever mechanism the surrounding
launcher already uses.
"""
import random
import string


def _rand_name(used: set, n: int = 9) -> str:
    while True:
        cand = "_" + "".join(random.choices(string.ascii_lowercase, k=n))
        if cand not in used:
            used.add(cand)
            return cand


# (module, qualname_suffix, import_path, attr_chain) for every function
# this module knows how to check. attr_chain is the dotted path from
# the imported module object to the actual attribute holding the
# function (e.g. "Session.send" means `import_path.Session.send`).
# See this module's docstring for exactly what is and isn't covered.
_CHECK_TARGETS = (
    # (import statement, expression yielding the live function object,
    #  expected __module__ prefix)
    ("import requests", "requests.Session.send", "requests.sessions"),
    ("import urllib3.connection", "urllib3.connection.HTTPSConnection.connect", "urllib3.connection"),
    ("import http.client", "http.client.HTTPSConnection.connect", "http.client"),
    # ssl.SSLContext.wrap_socket / wrap_bio: added alongside
    # ssl_pinning.py's own patch of these two (the coverage that
    # closes the gap for httpx/aiohttp/raw socket+ssl - see
    # ssl_pinning.py's module docstring). Like urllib3.connection and
    # http.client above, and UNLIKE requests.Session.send, these ARE
    # legitimately patched by our own ssl_pinning.py when pinning is
    # enabled, so they need the same known_patch_marker exemption -
    # wired the same way (see obfuscator.py's _build_hook_marker
    # call site, which now passes the marker to ssl_pinning for these
    # two as well, not just the urllib3/http.client pair).
    #
    # Both were confirmed, via a real build run through this exact
    # obfuscator.py pipeline (not just inspected in isolation), to
    # get __module__ == "__main__" once patched by ssl_pinning.py -
    # the packed loader always exec()s the final payload with
    # __name__ == "__main__" (see packer.py), so any module-level
    # function defined in that payload - including our own patch
    # functions - inherits that, exactly the same as the existing
    # urllib3.connection/http.client entries above already rely on.
    ("import ssl", "ssl.SSLContext.wrap_socket", "ssl"),
    ("import ssl", "ssl.SSLContext.wrap_bio", "ssl"),
)


def get_hook_detection_source(enabled: bool = True, known_patch_marker: tuple = None,
                               die_fn_name: str = None) -> str:
    """
    Returns a source-code string that checks requests/urllib3/
    http.client's key connection functions for signs of external
    monkey-patching (see this module's docstring for the full
    mechanism, what it catches, and what it explicitly does not).

    enabled: when False, returns "" (no-op) - same convention as
    ssl_pinning.get_ssl_pinning_source/antidebug.get_antidebug_source.

    known_patch_marker: pass the SAME (attribute_name, attribute_value)
    tuple given to ssl_pinning.get_ssl_pinning_source's hook_marker
    parameter, when ssl_pinning is ALSO enabled for this build - this
    lets this check recognize ssl_pinning's own legitimate patch to
    urllib3.connection.HTTPSConnection.connect / http.client.
    HTTPSConnection.connect and not flag it as an attacker's hook. If
    ssl_pinning is not enabled (or its result isn't going to be
    injected into the same build), leave this as None - a mismatched
    __module__ on those two functions will then always be treated as
    suspicious, which is correct when nothing legitimate in this build
    would have patched them in the first place. requests.Session.send
    is never patched by this project itself, so it's always checked
    without needing a marker exemption.

    die_fn_name: the name of an already-defined, zero-argument
    function to call on detection (matching whatever termination
    mechanism the surrounding launcher already uses - see packer.py's
    _build_die_helper). If None, this function generates its OWN
    minimal die-helper (a plain `raise SystemExit(1)`) for standalone
    use - this covers using hook_detection.py outside of packer.py's
    integrated pipeline (e.g. injecting it into a build that doesn't
    go through packer.pack/pack_with_native_decryptor at all), where
    there is no pre-existing die-helper name to hook into.
    """
    if not enabled:
        return ""

    used = set()
    names = {k: _rand_name(used) for k in (
        "fn_check_one", "fn_check_all", "fn_die_standalone",
    )}

    if known_patch_marker is not None:
        marker_attr, marker_value = known_patch_marker
        marker_check = f' and getattr(_fn, {marker_attr!r}, None) != {marker_value!r}'
    else:
        marker_check = ""

    if die_fn_name is not None:
        die_call = f"{die_fn_name}()"
        die_helper_def = ""
    else:
        die_call = f"{names['fn_die_standalone']}()"
        die_helper_def = f"def {names['fn_die_standalone']}():\n    raise SystemExit(1)\n"

    check_lines = []
    for import_stmt, expr, expected_module_prefix in _CHECK_TARGETS:
        check_lines.append(f'''    try:
        {import_stmt}
        _fn = {expr}
        _mod = getattr(_fn, "__module__", None) or ""
        if not _mod.startswith({expected_module_prefix!r}){marker_check}:
            {names["fn_check_all"]}._suspicious = True
    except ImportError:
        pass
    except Exception:
        pass
''')
    checks_source = "\n".join(check_lines)

    return f'''
{die_helper_def}
def {names["fn_check_all"]}():
    {names["fn_check_all"]}._suspicious = False
{checks_source}
    if {names["fn_check_all"]}._suspicious:
        {die_call}

{names["fn_check_all"]}()
'''
