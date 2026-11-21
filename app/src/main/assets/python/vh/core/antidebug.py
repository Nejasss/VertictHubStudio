"""
antidebug.py - returns a source-code string of runtime self-defense
checks that get merged into the SAME source that goes through
identifier-renaming and string-encryption as the rest of the
protected script (see obfuscator.py) - so this module's own function
names, variable names, and literal strings (API names, process name
lists, the ip-api.com URL, etc) end up just as encrypted/renamed as
the user's own code, not sitting there as plaintext for anyone (or
an AI asked to "just read this file") to recognize at a glance.

Checks included:
 - sys.gettrace() / sys.settrace hook detection (pdb, generic tracers)
 - TracerPid from /proc/self/status (Linux/Android - catches ptrace-
   based attach, which is also how Frida's default mode works)
 - Frida artifact scan (/proc/self/maps markers + default ports)
 - Windows IsDebuggerPresent / CheckRemoteDebuggerPresent
 - Known analysis/debugger process name scan (best-effort)
 - Timing check: a tight loop should complete within a threshold;
   single-stepping under a debugger blows the budget
 - Environment variable tamper markers commonly set by sandboxes
 - Optional: local VPN-adapter scan + network-based proxy/VPN lookup
 - Optional (periodic_recheck): TracerPid, Windows debugger APIs,
   process-name scan, and Frida artifacts, re-run on a background
   daemon thread every few seconds for the life of the process. The
   sys.gettrace() check is deliberately excluded from this (CPython's
   trace function is per-thread, so a background thread can never see
   a tracer set on the main thread) - see periodic_recheck param docs.

Every function/variable name below is generated fresh (random) on
each call to get_antidebug_source(), and the few Windows API/method
names that would otherwise appear as literal attribute lookups
(gettrace, IsDebuggerPresent, CheckRemoteDebuggerPresent) are called
through getattr() instead, so those names end up as ordinary string
constants that the same string-encryption pass protects too.

KNOWN LIMITATION - anti_vpn on Android/Termux (non-root):
  The interface scan reads /proc/net/dev, which is only reliable on
  desktop Linux. On Android 10+, /proc/net/dev is commonly hidden or
  restricted from non-privileged apps (including Termux without
  root) as a platform-level privacy restriction - it has nothing to
  do with the marker list below. In practice this means: a real VPN
  (e.g. Cloudflare WARP, which does create a "tun0"-style interface)
  can be fully active and the check still sees nothing, because the
  process simply isn't allowed to read the system-wide interface
  table. There is no public, unprivileged Android API that exposes
  device-wide VPN status either (confirmed against the full Termux:
  API command set - battery/camera/clipboard/contacts/location/sms/
  telephony/tts/usb/vibrate/volume/wifi info, but nothing for VPN or
  network-interface enumeration). A secondary /proc/self/net/dev
  read is attempted as a low-cost fallback (a process's own netns
  view is sometimes visible even when the global table isn't), but
  this is best-effort and not guaranteed to see anything either.
  Bottom line: anti_vpn should be treated as reliable on desktop
  Linux, and best-effort / not guaranteed on Android or other
  sandboxed/non-root environments - it will not reliably catch VPN
  apps like WARP there. This is a platform restriction, not a bug
  in this tool, and there is currently no known unprivileged
  workaround.

KNOWN LIMITATION - periodic_recheck:
  All the startup checks only ever prove "no debugger/Frida was
  attached at the exact moment this ran". A patient attacker can let
  the script pass that check, THEN attach a debugger/Frida a second
  later once the interesting code is already executing.
  periodic_recheck narrows that window by re-running the same checks
  every few seconds for as long as the process lives, from a
  background daemon thread - so a mid-run attach gets caught on the
  next tick instead of never. It does NOT make the window zero: there
  is always some gap between ticks where a sufficiently fast
  attach-inspect-detach cycle could still slip through unnoticed, and
  a debugger that ALSO patches out (or single-steps around) the
  recheck thread itself defeats this the same way it could defeat the
  startup check. This is a real reduction in exposure, not a
  guarantee - stated plainly rather than oversold.
"""
import random
import string


def _rand_name(used: set, n: int = 9) -> str:
    while True:
        cand = "_" + "".join(random.choices(string.ascii_lowercase, k=n))
        if cand not in used:
            used.add(cand)
            return cand


def get_antidebug_source(enabled: bool = True, anti_vpn: bool = False, strict_network_check: bool = False,
                          require_launcher_gate: bool = False, gate_env_name: str = "",
                          gate_token_hash: str = "", periodic_recheck: bool = False,
                          recheck_interval_range: tuple = (4, 9),
                          bytecode_integrity_check: bool = False,
                          gate_token_cache_var: str = "") -> tuple:
    """
    Returns (prefix_source, suffix_source) - TWO source strings now
    instead of one, because bytecode_integrity_check needs code that
    runs AFTER all of the user's own function/class definitions exist
    (to snapshot their bytecode), not before (where every other check
    in this module runs). Callers that don't care about this distinction
    can simply concatenate prefix_source + user_source + suffix_source;
    suffix_source is "" (empty) whenever bytecode_integrity_check=False,
    so existing behavior (only ever needing a prefix) is unchanged in
    that case.

    require_launcher_gate / gate_env_name / gate_token_hash: closes the
    "run the extracted binary/loader directly, skip the launcher"
    bypass. When require_launcher_gate is True, the very first thing
    this script does (before even the debugger/Frida checks) is look
    up an environment variable (named gate_env_name, itself a random
    per-build name so it can't be grepped for) that the launcher
    (bootstrap.py / native_launcher.py) is expected to have set to a
    fresh random token right before starting this process. The token
    is hashed with SHA-256 and compared against gate_token_hash, which
    was baked in at build time. If the variable is missing or the hash
    doesn't match - which is exactly what happens if someone finds the
    extracted binary/loader on disk and runs it straight, bypassing
    the launcher entirely - this exits immediately, before any of the
    real payload (or even the rest of the anti-debug suite) runs.
    The launcher never writes the token to disk anywhere; it only
    ever lives in the child process's environment for that one launch,
    and it's different every run - so a token seen once (e.g. via
    /proc/<pid>/environ at the moment of a legitimate launch) can't be
    replayed later to fake a "launched properly" run, since gate_token_hash
    only matches that single run's token.

    periodic_recheck / recheck_interval_range: if periodic_recheck is
    True, spawns a daemon thread (started right after the startup
    checks pass) that re-runs the TracerPid/Windows-debugger-API/
    process-name/Frida checks on a loop, sleeping a randomized interval
    (uniformly chosen from recheck_interval_range, in seconds, picked
    fresh each iteration so the interval itself isn't a fixed timing
    signature) between runs. See the module docstring's "KNOWN
    LIMITATION - periodic_recheck" section for what this does and
    doesn't guarantee.

    Deliberately NOT re-run periodically:
    - the sys.gettrace() check: CPython's trace function is set PER
      THREAD, not process-wide - sys.settrace() called on the main
      thread is invisible to sys.gettrace() called from a different
      (e.g. this recheck) thread. Re-running that specific check from
      a background thread would silently never detect anything and
      create a false sense of coverage, so it's excluded rather than
      shipped as a check that looks like it's doing something but
      structurally can't. (TracerPid, by contrast, is read from
      /proc/self/status - OS-level, per-PROCESS state, not per-thread
      - so it works correctly when rechecked from any thread.)
    - the timing check: its threshold assumes it's the very first
      thing to execute; a busy background thread would itself skew
      later timing-check runs and cause false positives.
    - the VPN scan: its strict-network-check mode makes a network
      call, which has no business running repeatedly in the background.

    bytecode_integrity_check: a DIFFERENT kind of tamper detection from
    everything else in this module. Every other check here detects
    ANALYSIS TOOLING (a debugger attached, Frida present, a suspicious
    process running) - none of them look at whether the script's OWN
    code has been modified while running. This one does: after ALL of
    the user's top-level functions and classes have been defined (this
    is why get_antidebug_source now returns a suffix_source that must
    be placed at the very END of the assembled file, not merged in with
    everything else at the top - see obfuscator.py's integration), it
    walks sys.modules["__main__"]'s namespace, finds every function and
    every class's methods, and records a SHA-256 of each one's
    __code__.co_code AND __code__.co_consts together (both are needed -
    the source, not the object identity) into an in-memory baseline
    dict. From then on, a background daemon thread (started alongside
    periodic_recheck's thread if both are enabled, or on its own
    schedule otherwise) periodically re-walks the same namespace and
    re-hashes the same functions, comparing against that baseline. A
    mismatch means a function's actual executed instructions changed
    after the baseline was taken - which is exactly what happens when
    something patches a function's bytecode in memory at runtime (a
    common Frida technique: hooking a function by replacing its
    __code__ object or monkey-patching it to something else entirely).
    This is fundamentally different from (and complementary to) the
    file-level self-hash checks in packer.py/native_launcher.py, which
    only ever verify the file ON DISK hasn't been tampered with - a
    static file check has NOTHING to say about the process's live
    memory once it's already running, which is exactly the gap this
    closes.
    KNOWN LIMITATIONS (stated plainly):
    - Only catches modifications to functions/methods that exist in
      __main__'s namespace at the time the baseline snapshot runs -
      code added dynamically afterward (exec(), a lazily-imported
      module) isn't covered, and there's no way to cover it without
      knowing in advance what will exist.
    - A sufficiently sophisticated attacker who ALSO patches this
      check's own comparison logic (or the recheck thread itself)
      defeats it the same way any runtime self-check can be defeated
      once the attacker has arbitrary code execution in the process -
      this raises the bar for casual tampering, it is not a hardware-
      backed guarantee.
    - Some legitimate dynamic behavior (a decorator that wraps and
      REPLACES a function object after definition, for instance) can
      trigger a false positive here - this is why it's OFF by default,
      unlike periodic_recheck.

    gate_token_cache_var: only meaningful when require_launcher_gate is
    True. Names the custom attribute this module's gate check stashes
    the verified token onto the `sys` module object (via
    setattr(sys, name, value)) right before deleting the token from
    os.environ - see the gate check's own comment for why a module
    ATTRIBUTE is used here rather than a plain variable, and why the
    deletion from os.environ happens at all without that undermining
    this caching. Callers that also use string_enc.py's gate-token-
    mixed key masking (see that module's docstring) MUST pass the
    SAME name here as they pass to string_enc.build_runtime_header's
    corresponding parameter, since that's how the two independently-
    generated pieces of source end up reading from/writing to the
    same sys attribute without either module needing to import the
    other. If left empty, a name is still generated internally (so
    this function remains usable on its own / in tests without a
    caller needing to think about this), but nothing else will know
    that name, which is only a problem if something else also needs
    to read the cached token.
    """
    if not enabled and not require_launcher_gate:
        return "", ""

    used = set()
    names = {k: _rand_name(used) for k in (
        "die", "trace", "sysmon", "tracerpid", "winapi", "procs", "frida",
        "timing", "env", "vpn", "runall", "gate", "recheck_loop",
        "bc_snapshot", "bc_baseline", "bc_walk", "bc_recheck_loop",
    )}
    gate_token_cache_var = gate_token_cache_var or _rand_name(used)

    vpn_call = f'{names["vpn"]}()' if anti_vpn else "pass"
    net_check_flag = "True" if strict_network_check else "False"

    if require_launcher_gate:
        gate_block = f'''
def {names["gate"]}():
    import hashlib as _vhhashlib
    _tok = _vhos.environ.get({gate_env_name!r})
    if not _tok:
        {names["die"]}()
    if _vhhashlib.sha256(_tok.encode("utf-8")).hexdigest() != {gate_token_hash!r}:
        {names["die"]}()
    # Cache the token as a custom attribute on the sys MODULE OBJECT
    # (not a plain local/global variable) BEFORE clearing it from
    # os.environ - string_enc.py's gate-token-mixed key masking (see
    # that module's docstring) needs to re-derive the same mask from
    # this same token every time ANY encrypted string is decrypted for
    # the rest of the process's life, not just once at startup - so
    # the token has to remain accessible somewhere in this process
    # after this point. A module attribute (setattr(_vhsys, name,
    # value) / getattr(_vhsys, name)) is used specifically because
    # identifier_rename.py only ever renames bare Name nodes (plain
    # variables), never Attribute nodes on an imported module object -
    # this code and string_enc.py's generated code are two SEPARATE
    # source fragments assembled at different pipeline stages (this
    # one goes through identifier_rename, string_enc.py's header is
    # added afterward and doesn't), so a plain variable name agreed on
    # between them would silently desync the moment either side's copy
    # got renamed and the other didn't - the attribute name string
    # itself is never a candidate for renaming at all, so both sides
    # always agree on it regardless of which one goes through the
    # renaming pass. Stashing it here (rather than leaving it in
    # os.environ) still achieves the ORIGINAL reason this delete
    # exists: the value no longer appears in os.environ, so it's no
    # longer visible to anything reading this process's environment
    # from OUTSIDE the process itself (e.g. /proc/<pid>/environ, or a
    # child process that inherits environ) - it's simply held on this
    # already-imported module object in this process's own memory
    # instead, which string_enc.py's decrypt path can reach directly
    # without needing the environment variable at all.
    setattr(_vhsys, {gate_token_cache_var!r}, _tok)
    try:
        del _vhos.environ[{gate_env_name!r}]
    except Exception:
        pass'''
        gate_call = f'{names["gate"]}()'
    else:
        gate_block = ""
        gate_call = "pass"

    if not enabled:
        # require_launcher_gate-only mode: skip the rest of the
        # anti-debug suite but still enforce the gate. periodic_recheck
        # has nothing to re-run in this mode (there IS no debug suite),
        # so it's silently ignored here rather than erroring - the gate
        # check itself is a one-time startup verification by nature.
        #
        # BUG FIXED HERE (2026-08-11): gate_block calls {die}() twice
        # (missing/mismatched token), but this template never defined
        # {die} - only the enabled=True template below does. Any build
        # using enabled=False with require_launcher_gate=True (a
        # perfectly reasonable combination: "just the gate check, skip
        # the debugger/Frida/VPN suite") produced source that raised
        # NameError the moment the gate check actually needed to fail
        # closed - the ONE path this check exists to protect. A build
        # gated this way that never hit that codepath during testing
        # would look completely fine right up until someone actually
        # tried running the extracted binary directly without going
        # through the launcher, at which point the intended "refuse to
        # run" turned into an unrelated crash instead - not a security
        # hole (it still fails to run either way), but not the clean
        # rejection this was supposed to produce either, and a
        # NameError traceback leaks the die-function's random name and
        # this module's structure to whoever triggers it.
        template = '''
import os as _vhos
import sys as _vhsys

def {die}():
    try:
        _vhos._exit(1)
    except Exception:
        raise SystemExit(1)

{gate_block}

def {runall}():
    {gate_call}

{runall}()
'''
        return template.format(
            gate_block=gate_block, gate_call=gate_call,
            runall=names["runall"], die=names["die"],
        ), ""

    recheck_lo, recheck_hi = recheck_interval_range
    if periodic_recheck:
        recheck_block = f'''
def {names["recheck_loop"]}():
    import random as _vhrand
    while True:
        _vhtime.sleep(_vhrand.uniform({recheck_lo}, {recheck_hi}))
        {names["tracerpid"]}()
        {names["winapi"]}()
        {names["procs"]}()
        {names["frida"]}()
        {names["sysmon"]}()

def _vh_start_recheck():
    import threading as _vhthreading
    t = _vhthreading.Thread(target={names["recheck_loop"]}, daemon=True)
    t.start()'''
        recheck_start_call = "_vh_start_recheck()"
    else:
        recheck_block = ""
        recheck_start_call = "pass"

    template = '''
import sys as _vhsys
import os as _vhos
import time as _vhtime
import platform as _vhplat

{gate_block}

def {die}():
    try:
        _vhos._exit(1)
    except Exception:
        raise SystemExit(1)

def {trace}():
    if getattr(_vhsys, "gettrace")() is not None:
        {die}()

def {sysmon}():
    # sys.monitoring (PEP 669, Python 3.12+) is the modern replacement
    # for sys.settrace() that debugpy/pydevd (the debugger behind VS
    # Code's Python extension, and one of the most common ways someone
    # attaches a debugger to a running Python process) switched to on
    # 3.12+ - and critically, a tool attached via sys.monitoring is
    # COMPLETELY INVISIBLE to sys.gettrace(), so the {trace}() check
    # above cannot see it at all (confirmed directly: registering a
    # callback via sys.monitoring and then calling sys.gettrace()
    # returns None, not the registered tool - this is not a corner
    # case, it is the normal, documented, and now most common way a
    # modern Python debugger attaches). This closes that gap.
    #
    # Unlike sys.settrace(), which is set PER-THREAD (see {trace}()'s
    # caller docstring for why that means it can only ever be checked
    # from the exact thread being debugged), sys.monitoring's tool
    # registrations are PER-INTERPRETER - visible from ANY thread,
    # including a periodic_recheck background thread - so this check,
    # unlike the sys.gettrace() one, is safe and correct to include in
    # the periodic recheck loop too (see recheck_block below).
    #
    # Scans ALL 6 tool ID slots (0-5), not just sys.monitoring.
    # DEBUGGER_ID - a debugger could register under PROFILER_ID or an
    # unnamed slot specifically to dodge a DEBUGGER_ID-only check
    # (confirmed directly: doing exactly that makes a DEBUGGER_ID-only
    # check see nothing, while scanning all 6 slots still finds it) -
    # ANY tool occupying ANY slot means something is monitoring
    # execution, regardless of which ID it politely claimed to be.
    try:
        _mon = getattr(_vhsys, "monitoring", None)
        if _mon is None:
            return
        for _slot in range(6):
            if getattr(_mon, "get_tool")(_slot) is not None:
                {die}()
    except Exception:
        pass

def {tracerpid}():
    try:
        if _vhplat.system() != "Linux":
            return
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    pid = int(line.split(":", 1)[1].strip())
                    if pid != 0:
                        {die}()
                    break
    except Exception:
        pass

def {winapi}():
    if _vhplat.system() != "Windows":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        if getattr(k32, "IsDebuggerPresent")():
            {die}()
        is_remote = ctypes.c_int(0)
        getattr(k32, "CheckRemoteDebuggerPresent")(
            getattr(k32, "GetCurrentProcess")(), ctypes.byref(is_remote)
        )
        if is_remote.value:
            {die}()
    except Exception:
        pass

def {procs}():
    # Match complete process names, not arbitrary substrings: a protected
    # program named "r2dump" must not match the short debugger name "r2".
    # On Linux, also exclude this process and its descendants. Legitimate
    # applications may launch tools such as radare2 through r2pipe; those
    # child processes are part of the application's own work, not an
    # independently attached debugger.
    suspects = {{
        "x64dbg", "ollydbg", "ida64", "ida", "idaq", "windbg",
        "frida-server", "gdb", "lldb", "radare2", "r2", "dnspy",
        "processhacker", "fiddler", "wireshark",
    }}
    try:
        if _vhplat.system() == "Windows":
            import ctypes
            psapi = ctypes.windll.psapi
            kernel32 = ctypes.windll.kernel32
            own_pid = int(getattr(kernel32, "GetCurrentProcessId")())
            arr = (ctypes.c_uint32 * 1024)()
            needed = ctypes.c_uint32()
            if not getattr(psapi, "EnumProcesses")(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
                return
            count = int(needed.value / ctypes.sizeof(ctypes.c_uint32()))
            for pid in arr[:count]:
                if pid == 0 or int(pid) == own_pid:
                    continue
                hproc = getattr(kernel32, "OpenProcess")(0x0410, False, pid)
                if not hproc:
                    continue
                buf = ctypes.create_unicode_buffer(260)
                getattr(psapi, "GetModuleBaseNameW")(hproc, None, buf, 260)
                getattr(kernel32, "CloseHandle")(hproc)
                name = (buf.value or "").lower()
                if name.endswith(".exe"):
                    name = name[:-4]
                if name in suspects:
                    {die}()
        else:
            proc_dir = "/proc"
            if not _vhos.path.isdir(proc_dir):
                return
            names = {{}}
            children = {{}}
            for pid_text in _vhos.listdir(proc_dir):
                if not pid_text.isdigit():
                    continue
                try:
                    with open(_vhos.path.join(proc_dir, pid_text, "comm"), encoding="utf-8") as f:
                        names[int(pid_text)] = f.read().strip().lower()
                    # /proc/<pid>/stat: after the final ')', fields begin
                    # with state (field 3) then PPID (field 4).
                    with open(_vhos.path.join(proc_dir, pid_text, "stat"), encoding="utf-8") as f:
                        stat_line = f.read()
                    close = stat_line.rfind(")")
                    fields = stat_line[close + 1:].strip().split() if close >= 0 else []
                    if len(fields) >= 2:
                        ppid = int(fields[1])
                        children.setdefault(ppid, []).append(int(pid_text))
                except (OSError, ValueError, IndexError):
                    continue
            own_pid = _vhos.getpid()
            own_tree = {{own_pid}}
            pending = [own_pid]
            while pending:
                parent = pending.pop()
                for child_pid in children.get(parent, ()):
                    if child_pid not in own_tree:
                        own_tree.add(child_pid)
                        pending.append(child_pid)
            for pid, name in names.items():
                if pid in own_tree:
                    continue
                if name in suspects:
                    {die}()
    except Exception:
        pass

def {frida}():
    try:
        if _vhplat.system() == "Linux":
            try:
                with open("/proc/self/maps") as f:
                    maps_data = f.read().lower()
                for marker in ("frida", "gum-js-loop", "gadget"):
                    if marker in maps_data:
                        {die}()
            except Exception:
                pass
        import socket
        for port in (27042, 27043):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            try:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    {die}()
            except Exception:
                pass
            finally:
                s.close()
    except Exception:
        pass

def {bc_walk}():
    # Walks sys.modules["__main__"]'s namespace and yields
    # (qualname, code_object) for every top-level function and every
    # method of every top-level class - deliberately shallow (no
    # recursion into nested closures/dynamically-created functions),
    # which keeps this cheap enough to re-run periodically and matches
    # what a baseline taken once, right after module-level definitions
    # finish, can meaningfully compare against on every later call.
    import types as _vhtypes
    main_mod = _vhsys.modules.get("__main__")
    if main_mod is None:
        return
    for _name, _obj in list(vars(main_mod).items()):
        if isinstance(_obj, _vhtypes.FunctionType):
            yield _name, _obj.__code__
        elif isinstance(_obj, type):
            for _mname, _mobj in list(vars(_obj).items()):
                if isinstance(_mobj, _vhtypes.FunctionType):
                    yield _name + "." + _mname, _mobj.__code__

def {bc_snapshot}():
    import hashlib as _vhhashlib2
    _baseline = {{}}
    for _qualname, _code in {bc_walk}():
        # Hash co_code AND co_consts TOGETHER - Python bytecode stores
        # literal constants (True/False/numbers/strings/etc) in a
        # SEPARATE table (co_consts), referenced from co_code by
        # index, not encoded inline in the instruction bytes. This
        # means "return True" and "return False" compile to the
        # EXACT SAME co_code bytes (a LOAD_CONST-by-index + RETURN)
        # and only differ in what co_consts[0] actually holds - hashing
        # co_code alone would make a patch that flips a return value's
        # underlying constant completely invisible to this check,
        # which defeats the entire point. repr() on co_consts is a
        # simple, deterministic-enough way to fold its contents into
        # the hash without needing a more elaborate serialization.
        _combined = _code.co_code + repr(_code.co_consts).encode("utf-8", "replace")
        _baseline[_qualname] = _vhhashlib2.sha256(_combined).hexdigest()
    return _baseline

def {timing}():
    start = _vhtime.perf_counter()
    acc = 0
    for i in range(200000):
        acc = (acc + i) % 104729
    elapsed = _vhtime.perf_counter() - start
    if elapsed > 1.5:
        {die}()

def {env}():
    tamper_markers = ("PYTHONBREAKPOINT", "PYDEVD_LOAD_VALUES_ASYNC")
    for m in tamper_markers:
        v = _vhos.environ.get(m)
        if v and v not in ("0", ""):
            {die}()

def {vpn}():
    # Narrowed to markers that are near-exclusively VPN software.
    # "ppp" and "tap" were dropped: both legitimately show up on
    # plenty of non-VPN setups (Android mobile-data/tethering
    # links are commonly named ppp0 on many chipsets/vendors,
    # and tap-family names show up on ordinary bridged networking)
    # - keeping them caused this check to kill the program for
    # users who were never running a VPN at all.
    vpn_markers = ("tun", "wg", "utun", "ipsec", "nordlynx")
    for _path in ("/proc/net/dev", "/proc/self/net/dev"):
        # /proc/net/dev (system-wide table) is the primary source on
        # desktop Linux. On Android 10+, non-root apps (Termux
        # included) commonly can't read it at all - this is a
        # platform privacy restriction, not something markers or
        # code here can work around. /proc/self/net/dev (the calling
        # process's own netns view) is tried as a low-cost fallback:
        # on some Android configurations it's visible even when the
        # global table isn't, but this is best-effort and may also
        # come back empty - there is no known unprivileged Android
        # API that reliably exposes VPN status.
        try:
            with open(_path) as f:
                lines = f.readlines()[2:]
            if not lines:
                continue
            for line in lines:
                iface = line.split(":")[0].strip().lower()
                if any(iface.startswith(m) for m in vpn_markers):
                    {die}()
            break
        except Exception:
            continue
    if {net_check_flag}:
        # Opt-in only: a third-party API call is a separate source of
        # false positives from the interface scan above (rate limits,
        # timeouts, and ISPs on CGNAT or certain mobile carriers often
        # get misclassified as "proxy"/"hosting" even with no VPN in
        # use) - so this only runs if explicitly enabled, not just
        # because anti_vpn is on.
        try:
            import urllib.request as _vhur
            import json as _vhjson
            req = _vhur.Request(
                "http://ip-api.com/json/?fields=status,proxy,hosting",
                headers={{"User-Agent": "Mozilla/5.0"}},
            )
            with _vhur.urlopen(req, timeout=3) as resp:
                data = _vhjson.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success" and data.get("proxy"):
                {die}()
        except Exception:
            pass

def {runall}():
    {gate_call}
    {trace}()
    {sysmon}()
    {tracerpid}()
    {winapi}()
    {procs}()
    {frida}()
    {timing}()
    {env}()
    {vpn_call}
    {recheck_start_call}

{recheck_block}

{runall}()
'''

    if bytecode_integrity_check:
        bc_lo, bc_hi = recheck_interval_range
        suffix_source = f'''
{names["bc_baseline"]} = {names["bc_snapshot"]}()

def {names["bc_recheck_loop"]}():
    import random as _vhrand2
    while True:
        _vhtime.sleep(_vhrand2.uniform({bc_lo}, {bc_hi}))
        _current = {names["bc_snapshot"]}()
        for _qualname, _hash in {names["bc_baseline"]}.items():
            if _current.get(_qualname) != _hash:
                {names["die"]}()

def _vh_start_bc_recheck():
    import threading as _vhthreading2
    _t = _vhthreading2.Thread(target={names["bc_recheck_loop"]}, daemon=True)
    _t.start()

_vh_start_bc_recheck()
'''
    else:
        suffix_source = ""

    return template.format(
        die=names["die"], trace=names["trace"], sysmon=names["sysmon"], tracerpid=names["tracerpid"],
        winapi=names["winapi"], procs=names["procs"], frida=names["frida"],
        timing=names["timing"], env=names["env"], vpn=names["vpn"],
        runall=names["runall"], vpn_call=vpn_call, net_check_flag=net_check_flag,
        gate_block=gate_block, gate_call=gate_call,
        recheck_block=recheck_block, recheck_start_call=recheck_start_call,
        bc_walk=names["bc_walk"], bc_snapshot=names["bc_snapshot"],
    ), suffix_source
