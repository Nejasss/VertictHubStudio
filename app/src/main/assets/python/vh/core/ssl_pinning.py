"""
ssl_pinning.py - returns a source-code string that, when merged into
the user's source BEFORE identifier-renaming and string-encryption
(see obfuscator.py, same integration pattern as antidebug.py/junk.py),
transparently adds SPKI (public-key) certificate pinning to every
`requests` call the user's program already makes - without needing
to touch or rewrite any of the user's own requests.get()/post()/
Session() call sites.

WHY THIS EXISTS
Without pinning, a program's HTTPS traffic is only as trustworthy as
whatever CA store the OS/Python ships - which means a MITM proxy
(Burp, mitmproxy) with its own CA certificate installed into that
store (or into Termux's, or pushed via a malicious profile) can
transparently intercept, read, and modify "encrypted" HTTPS traffic
with the client seeing nothing wrong: normal certificate validation
still succeeds, because the proxy's forged certificate for the target
hostname chains up to a CA the client DOES trust. Pinning closes this
specific gap by checking that the server's actual public key matches
a fixed, known-good value BUILT INTO THE PROGRAM, independent of
whatever the OS/user has been tricked into trusting - a MITM proxy's
forged certificate will have a different key, so this fails closed
before any request data is exposed.

WHAT IS PINNED: the SubjectPublicKeyInfo (SPKI) DER blob's SHA-256
hash - NOT the whole certificate. This is deliberate and matches
common mobile-app pinning practice: a certificate is reissued
(different serial, validity dates, signature) far more often than its
underlying key pair changes, so pinning the whole certificate's hash
would break the very first time the legitimate server rotates to a
freshly-issued (but same-key) certificate, forcing an app update just
to keep working. Pinning the public key survives certificate renewal
as long as the key itself isn't rotated, and still fails closed
against any certificate presenting a DIFFERENT key (which is exactly
what a MITM's forged certificate necessarily has, since it doesn't
have the real server's private key).

HOW THE SPKI HASH IS COMPUTED (matches this file's own
extract_spki_der/compute_pin_from_der helpers, used at BUILD TIME to
help the user generate the fingerprints they'll pass in): X.509's
DER encoding is a fixed, standard nested SEQUENCE structure -
Certificate { tbsCertificate { version?, serialNumber, signature,
issuer, validity, subject, subjectPublicKeyInfo, ... }, ... } - so
subjectPublicKeyInfo can be located and sliced out byte-for-byte via
plain ASN.1 TLV (tag-length-value) walking, without needing a full
X.509/ASN.1 parsing library. This was verified against a real TLS
connection's certificate and cross-checked byte-for-byte against
`openssl x509 -pubkey | openssl pkey -pubin -outform DER | openssl
dgst -sha256` - the two matched exactly.

WHAT THIS PROTECTS: `requests` (via urllib3), plain `urllib3` usage,
and stdlib `http.client`/`urllib.request` (urllib.request is built on
http.client, so patching http.client.HTTPSConnection covers both) -
this covers every synchronous HTTP call this project has actually
verified end-to-end. It does NOT cover raw `socket`+`ssl` used
directly (bypassing both http.client and urllib3), nor the async
libraries `aiohttp`/`httpx`, which use entirely different connection
machinery (asyncio transports / httpcore, respectively) that hasn't
been integrated yet - each needs its own verified hook point rather
than being guessed at and shipped untested, which is exactly the kind
of gap that caused this module's own super()/rename bug (see
CORRECTNESS NOTE below) to go unnoticed until tested end-to-end
through a real obfuscated build.

HOW THE PATCH WORKS: it reassigns the `connect` attribute directly on
TWO separate HTTPS connection classes - urllib3.connection.
HTTPSConnection (which `requests` is built on) and http.client.
HTTPSConnection (the stdlib class `urllib.request` uses internally,
and which anything importing http.client directly also uses) - to a
new function that calls the real, original connect() first (so
normal certificate-chain validation still happens exactly as before -
pinning is an ADDITIONAL check, not a replacement for standard
validation) and then extracts and checks the now-connected socket's
peer certificate's SPKI hash against the allowed pin set before
returning. These are two independent, unrelated classes (both named
"HTTPSConnection", but not connected by inheritance beyond a shared
HTTPConnection ancestor - urllib3 does not reuse http.client's
connect() implementation), so each is patched separately; the urllib3
patch is wrapped in its own try/except ImportError since not every
build has urllib3 installed, while the http.client patch is expected
to always succeed (it's stdlib).

MULTIPLE PINS: pin_sha256_hexes accepts a list, not just one hash -
this is standard pinning practice (pin the current key AND a backup
key you've already generated but not yet deployed), so a future
planned key rotation doesn't require shipping a new build the moment
the switch happens; connections succeed if the live certificate's
SPKI matches ANY pin in the set.

FAIL-CLOSED BY DESIGN: any mismatch, or any error while extracting/
computing the peer certificate's SPKI hash, raises
ssl.SSLCertVerificationError and the connection is closed - this
module never falls back to "allow the connection anyway" on a parsing
error, since silently disabling pinning on unexpected input would
defeat the entire point of adding it.
"""
import random
import string


def _rand_name(used: set, n: int = 9) -> str:
    while True:
        cand = "_" + "".join(random.choices(string.ascii_lowercase, k=n))
        if cand not in used:
            used.add(cand)
            return cand


def parse_der_length(data: bytes, offset: int) -> tuple:
    """Build-time helper (also duplicated, generated fresh, into the
    injected source below) - parses one ASN.1 DER length field."""
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset + 1:offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def extract_spki_der(cert_der: bytes) -> bytes:
    """Build-time helper - see this module's docstring for the ASN.1
    structure this walks. Used by compute_pin_from_der / this file's
    CLI-adjacent helpers to let the user generate a real pin value
    from an actual server connection; the injected runtime code below
    contains its own copy (fresh random names) so the check works
    standalone inside the obfuscated program without importing this
    build-time module."""
    assert cert_der[0] == 0x30, "not a DER SEQUENCE (not a valid certificate)"
    _, off = parse_der_length(cert_der, 1)
    assert cert_der[off] == 0x30, "malformed tbsCertificate"
    tbs_len, tbs_val_off = parse_der_length(cert_der, off + 1)
    pos = tbs_val_off
    if cert_der[pos] == 0xA0:  # optional [0] version tag
        vlen, voff = parse_der_length(cert_der, pos + 1)
        pos = voff + vlen
    # serialNumber, signature, issuer, validity, subject - 5 fields to skip
    for _ in range(5):
        length, val_off = parse_der_length(cert_der, pos + 1)
        pos = val_off + length
    # subjectPublicKeyInfo - the field we want, sliced out whole
    assert cert_der[pos] == 0x30, "malformed subjectPublicKeyInfo"
    spki_start = pos
    length, val_off = parse_der_length(cert_der, pos + 1)
    return cert_der[spki_start:val_off + length]


def compute_pin_from_der(cert_der: bytes) -> str:
    """Build-time convenience helper: returns the SHA-256 hex digest
    of a certificate's SPKI, given the certificate's raw DER bytes
    (e.g. from ssl.SSLSocket.getpeercert(binary_form=True)). This is
    what a user runs ONCE against their real server to obtain the pin
    value(s) to pass into get_ssl_pinning_source."""
    import hashlib
    return hashlib.sha256(extract_spki_der(cert_der)).hexdigest()


def get_ssl_pinning_source(pin_sha256_hexes, enabled: bool = True, hook_marker: tuple = None) -> str:
    """
    Returns a source-code string implementing SPKI certificate pinning
    for `requests`, plain `urllib3`, and stdlib `http.client`/
    `urllib.request` HTTPS connections - see this module's docstring
    for the full mechanism, exact coverage, and rationale.

    pin_sha256_hexes: a list of one or more lowercase hex SHA-256
    SPKI fingerprints (each 64 hex characters) - see
    compute_pin_from_der for how to obtain one from a real server.
    A connection is accepted if the live certificate's SPKI hash
    matches ANY entry in this list (see docstring's "MULTIPLE PINS").

    enabled: when False, returns an empty string (no-op) - this
    function is still called unconditionally from
    ObfuscationConfig-driven callers the same way antidebug.py's
    get_antidebug_source is, so the enabled/disabled branch lives
    here rather than forcing every call site to conditionally skip
    the call itself.

    hook_marker: an optional (attr_name, attr_value) tuple - when
    given, both of this module's own patched connect() functions get
    a matching attribute set on them (e.g.
    patched_fn.<attr_name> = <attr_value>). This exists so
    core/hook_detection.py's monkey-patch scan (which flags any
    connect()/send() implementation whose __module__ doesn't match
    what it should be - see that module's docstring) can tell THIS
    module's own legitimate pinning patch apart from an attacker's
    hook patching the exact same functions for a different purpose
    (reading request/response bodies, bypassing the pin check, etc) -
    without this, hook_detection would flag ssl_pinning's own patch as
    suspicious, since both necessarily look identical from the
    __module__/__qualname__ signature alone (both are a locally
    defined function assigned over urllib3/http.client's original
    connect). The caller (obfuscator.py) generates one random
    (attr_name, attr_value) pair per build and passes the SAME pair to
    both get_ssl_pinning_source and hook_detection.get_hook_detection_source,
    so an attacker can't precompute a fixed marker to spoof - it's
    different every build. When hook_marker is None (ssl pinning used
    standalone, without hook_detection enabled), no marker is added
    and the patched functions look exactly as they did before this
    parameter existed - fully backward compatible.

    Raises ValueError at BUILD TIME (not runtime) if pin_sha256_hexes
    is empty while enabled=True - shipping a build with pinning
    "on" but no actual pins configured would silently patch in a
    check that then either passes vacuously or (depending on how a
    half-finished integration is written) rejects every connection;
    neither is a state this should ever produce silently.
    """
    if not enabled:
        return ""
    if not pin_sha256_hexes:
        raise ValueError(
            "get_ssl_pinning_source: enabled=True but pin_sha256_hexes is empty - "
            "provide at least one SHA-256 SPKI fingerprint (see compute_pin_from_der)."
        )

    normalized = []
    for h in pin_sha256_hexes:
        h = h.strip().lower()
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError(f"get_ssl_pinning_source: not a valid 64-char hex SHA-256 fingerprint: {h!r}")
        normalized.append(h)

    used = set()
    names = {k: _rand_name(used) for k in (
        "fn_parse_len", "fn_extract_spki", "fn_check_sock",
        "v_pins", "fn_patch", "v_patched",
        "v_orig_connect_u3", "fn_new_connect_u3",
        "v_orig_connect_hc", "fn_new_connect_hc",
        "v_orig_wrap_socket", "fn_new_wrap_socket",
        "v_orig_wrap_bio", "fn_new_wrap_bio",
        "fn_new_do_handshake", "v_checked",
    )}

    pins_literal = "(" + ", ".join(repr(h) for h in normalized) + ("," if len(normalized) == 1 else "") + ")"

    if hook_marker is not None:
        marker_attr, marker_value = hook_marker
        marker_line_u3 = f'{names["fn_new_connect_u3"]}.{marker_attr} = {marker_value!r}\n        '
        marker_line_hc = f'{names["fn_new_connect_hc"]}.{marker_attr} = {marker_value!r}\n        '
        # Unlike marker_line_u3/hc, these are set as a plain top-level
        # statement AFTER fn_new_wrap_socket/fn_new_wrap_bio's own def
        # block ends, not interpolated into the def body's return path -
        # because both functions are stable, already-fully-defined
        # function objects the moment `def ...:` finishes executing
        # (setting an attribute on a function object never needs to
        # happen "inside" the function itself - unlike the deferred
        # do_handshake wrapper INSIDE fn_new_wrap_bio, which is a
        # different, per-call function object that doesn't exist until
        # fn_new_wrap_bio actually runs, and is correctly left
        # unmarked - see the comment on it below for why). This is a
        # deliberate correction from an earlier version of this
        # coverage, which set no marker for either of these two at all,
        # since core/hook_detection.py didn't check them yet.
        marker_line_ws = f'{names["fn_new_wrap_socket"]}.{marker_attr} = {marker_value!r}\n        '
        marker_line_wb = f'{names["fn_new_wrap_bio"]}.{marker_attr} = {marker_value!r}\n        '
    else:
        marker_line_u3 = ""
        marker_line_hc = ""
        marker_line_ws = ""
        marker_line_wb = ""

    return f'''
def {names["fn_parse_len"]}(_data, _offset):
    _first = _data[_offset]
    if _first & 0x80 == 0:
        return _first, _offset + 1
    _nbytes = _first & 0x7F
    _length = int.from_bytes(_data[_offset + 1:_offset + 1 + _nbytes], "big")
    return _length, _offset + 1 + _nbytes

def {names["fn_extract_spki"]}(_cert_der):
    if _cert_der[0] != 0x30:
        raise ValueError("not a DER certificate")
    _, _off = {names["fn_parse_len"]}(_cert_der, 1)
    if _cert_der[_off] != 0x30:
        raise ValueError("malformed tbsCertificate")
    _tbs_len, _pos = {names["fn_parse_len"]}(_cert_der, _off + 1)
    if _cert_der[_pos] == 0xA0:
        _vlen, _voff = {names["fn_parse_len"]}(_cert_der, _pos + 1)
        _pos = _voff + _vlen
    for _ in range(5):
        _length, _val_off = {names["fn_parse_len"]}(_cert_der, _pos + 1)
        _pos = _val_off + _length
    if _cert_der[_pos] != 0x30:
        raise ValueError("malformed subjectPublicKeyInfo")
    _spki_start = _pos
    _length, _val_off = {names["fn_parse_len"]}(_cert_der, _pos + 1)
    return _cert_der[_spki_start:_val_off + _length]

{names["v_pins"]} = {pins_literal}
{names["v_patched"]} = False

def {names["fn_patch"]}():
    global {names["v_patched"]}
    if {names["v_patched"]}:
        return
    import hashlib as _hl
    import ssl as _sl

    def {names["fn_check_sock"]}(_sock):
        try:
            _der = _sock.getpeercert(binary_form=True)
            _spki = {names["fn_extract_spki"]}(_der)
            _fp = _hl.sha256(_spki).hexdigest()
        except Exception as _e:
            try:
                _sock.close()
            except Exception:
                pass
            raise _sl.SSLCertVerificationError("certificate pin check failed: " + repr(_e))
        if _fp not in {names["v_pins"]}:
            try:
                _sock.close()
            except Exception:
                pass
            raise _sl.SSLCertVerificationError("certificate pin mismatch")

    # Patched by REASSIGNING the connect attribute directly on each
    # target HTTPS connection class, rather than subclassing with an
    # overriding "def connect(self): ...; super().connect()" method.
    # A subclass override relies on Python resolving super() at
    # RUNTIME by looking up a method of the SAME NAME ("connect")
    # on the base class via the MRO - but this project's own
    # identifier-renaming pass renames LOCAL method definitions
    # (including a method named "connect" defined inside this
    # generated code) to a random name, while a name defined on an
    # imported, un-obfuscated base class is correctly left alone. The
    # result: the renamed override method's own super().connect() call
    # still looks up the literal string "connect" on the base class
    # (which the base class still has, unpatched) - so that part
    # keeps working - but the override method itself no longer HAS
    # that name, so calling code doing .connect() on an instance never
    # finds the pinning logic at all and silently falls through to
    # unpinned behavior (confirmed with a real obfuscated build: the
    # override became an AttributeError inside super() in one
    # direction of the same underlying mismatch). Storing the ORIGINAL
    # function in a variable and calling THAT (an ordinary name lookup
    # this project's renaming pass already handles correctly and
    # consistently, since it's just a local variable reference, not an
    # implicit by-name MRO lookup) sidesteps the whole class of
    # problem - there is no method name for a rename pass to disagree
    # with itself about.
    #
    # TWO SEPARATE classes need this patch, independently, because
    # they are NOT related by inheritance despite both being named
    # "HTTPSConnection": urllib3.connection.HTTPSConnection (used by
    # `requests`, which is built on urllib3) and
    # http.client.HTTPSConnection (the stdlib class used directly by
    # `urllib.request`, and by anything importing http.client itself)
    # only share a common HTTPConnection ancestor - urllib3's own
    # HTTPSConnection overrides connect() itself and does not reuse
    # http.client's implementation, so patching one does nothing for
    # the other. Each patch attempt is independently try/excepted:
    # urllib3 may not be installed in every build (nothing to patch
    # then - not an error), while http.client is always present
    # (stdlib), so its patch is expected to always succeed.
    try:
        import urllib3.connection as _u3c
        {names["v_orig_connect_u3"]} = _u3c.HTTPSConnection.connect

        def {names["fn_new_connect_u3"]}(self):
            {names["v_orig_connect_u3"]}(self)
            {names["fn_check_sock"]}(self.sock)

        {marker_line_u3}_u3c.HTTPSConnection.connect = {names["fn_new_connect_u3"]}
    except ImportError:
        pass  # requests/urllib3 not installed in this build

    try:
        import http.client as _hc
        {names["v_orig_connect_hc"]} = _hc.HTTPSConnection.connect

        def {names["fn_new_connect_hc"]}(self):
            {names["v_orig_connect_hc"]}(self)
            {names["fn_check_sock"]}(self.sock)

        {marker_line_hc}_hc.HTTPSConnection.connect = {names["fn_new_connect_hc"]}
    except Exception:
        pass

    # SSLContext.wrap_socket / SSLContext.wrap_bio patch - covers
    # every remaining HTTPS client that the two patches above miss:
    # httpx (both its sync path, built on httpcore -> stdlib ssl
    # directly, and its async path, built on asyncio/anyio ->
    # asyncio.sslproto -> SSLContext.wrap_bio), aiohttp (built on
    # asyncio transports -> the same SSLContext.wrap_bio path), and
    # raw socket+ssl code (ssl.SSLContext.wrap_socket() is the only
    # way to get an SSLSocket in current Python - the legacy top-level
    # ssl.wrap_socket() function was removed in 3.12). Patching these
    # two SSLContext methods directly, instead of chasing each
    # library's own internal connection classes the way the urllib3/
    # http.client patches above do, is deliberate: those internals
    # differ per library and drift across versions, while EVERY one of
    # these libraries necessarily bottoms out in the stdlib ssl
    # module's SSLContext to actually perform a TLS handshake, so this
    # is the one stable choke point common to all of them at once.
    #
    # wrap_socket (sync, used directly by requests/urllib3/http.client
    # too, but those are already covered above - patching this as well
    # is harmless double coverage, not a conflict, since both patches
    # independently call fn_check_sock and either one alone already
    # passes/fails the connection correctly) returns an SSLSocket with
    # the handshake ALREADY COMPLETE by the time it returns (the
    # do_handshake_on_connect=True default), so the peer cert can be
    # read and checked immediately, right here, before returning.
    #
    # wrap_bio is different: it's the non-blocking, buffer-based path
    # asyncio's sslproto.py uses (SSLContext.wrap_bio(incoming,
    # outgoing, ...) -> SSLObject), and the handshake is NOT done yet
    # when wrap_bio returns - the caller (asyncio's internals) drives
    # it forward incrementally via repeated calls to the returned
    # object's own do_handshake() method as bytes arrive on the wire,
    # so there is no single moment right after wrap_bio() itself where
    # a peer certificate is available yet. So instead of checking here,
    # this patches do_handshake() on the specific SSLObject INSTANCE
    # wrap_bio just created (an instance attribute assignment, not a
    # class-level one - this needs to check a fresh, per-connection
    # peer cert on THIS one object, not every SSLObject's do_handshake
    # in the process for all time). getpeercert(binary_form=True)
    # still returns None on every do_handshake() call before the
    # handshake has actually finished (it needs multiple round trips
    # over a real network), so the check is skipped (not silently
    # treated as a pass - {names["v_checked"]} only flips True once a
    # real DER cert is seen and validated) until the call where it
    # finally returns real bytes, at which point the pin is checked
    # exactly once for that connection.
    try:
        import ssl as _sl2

        {names["v_orig_wrap_socket"]} = _sl2.SSLContext.wrap_socket

        def {names["fn_new_wrap_socket"]}(self, sock, *_a, **_kw):
            # server_side is read out of _kw/_a manually, rather than
            # declared as its own named parameter, because a NAMED
            # parameter here gets renamed by this project's own
            # ParamRenamer pass (core/identifier_rename.py) - that
            # pass only skips renaming a parameter when it sees that
            # exact name used as a keyword in some Call INSIDE the
            # file being obfuscated (see _collect_keyword_call_names),
            # and has no way to know this function is also called
            # externally, by stdlib code it can never see, using the
            # literal keyword "server_side" (confirmed via a real
            # obfuscated build: asyncio.sslproto's SSLProtocol.__init__
            # does `self._sslcontext.wrap_socket(..., server_side=...)`,
            # and once the parameter was renamed here but the CALLER
            # still says server_side=, that value silently fell into
            # **_kw while the renamed parameter kept its unrenamed
            # default of False - then forwarding both the (wrong,
            # default) positional value AND the original **_kw (which
            # still has server_side= in it) to the real wrap_socket
            # raised "got multiple values for argument 'server_side'").
            # *_a/**_kw themselves are never renamed by ParamRenamer
            # (it explicitly never touches vararg/kwarg slot names),
            # so reading server_side back out of them here is the one
            # spelling that survives the rename pass correctly no
            # matter what name identifier_rename.py chooses for
            # anything else in this function.
            _server_side = _kw.get("server_side", _a[0] if _a else False)
            _ssock = {names["v_orig_wrap_socket"]}(self, sock, *_a, **_kw)
            # Only check when THIS process is the TLS CLIENT (pinning
            # verifies which SERVER cert we trust) - when server_side
            # is True, this process is instead acting as the TLS
            # server, getpeercert() would be the CONNECTING CLIENT's
            # cert (None for the overwhelmingly common case of no
            # client-cert/mTLS), and checking it against pins meant
            # for the real server would be both wrong and would crash
            # on the None case (confirmed: this exact gap caused a
            # crash in a real server-side wrap_socket call during
            # testing - extract_spki_der(None) raised TypeError)
            if not _server_side:
                {names["fn_check_sock"]}(_ssock)
            return _ssock

        {marker_line_ws}_sl2.SSLContext.wrap_socket = {names["fn_new_wrap_socket"]}
    except Exception:
        pass

    try:
        import ssl as _sl3

        {names["v_orig_wrap_bio"]} = _sl3.SSLContext.wrap_bio

        def {names["fn_new_wrap_bio"]}(self, incoming, outgoing, *_a, **_kw):
            # See fn_new_wrap_socket's comment above for why
            # server_side is read out of _kw/_a manually instead of
            # being its own named parameter - the exact same rename-
            # desync bug applies here (asyncio.sslproto calls
            # wrap_bio(incoming, outgoing, server_side=..., ...) too).
            _server_side = _kw.get("server_side", _a[0] if _a else False)
            _sslobj = {names["v_orig_wrap_bio"]}(self, incoming, outgoing, *_a, **_kw)
            # Same server_side reasoning as fn_new_wrap_socket above -
            # skip entirely when acting as the TLS server.
            if _server_side:
                return _sslobj
            _orig_dh = _sslobj.do_handshake
            {names["v_checked"]} = {{"done": False}}

            def {names["fn_new_do_handshake"]}(*_hargs, **_hkw):
                _result = _orig_dh(*_hargs, **_hkw)
                if not {names["v_checked"]}["done"]:
                    _der = _sslobj.getpeercert(binary_form=True)
                    if _der:
                        {names["fn_check_sock"]}(_sslobj)
                        {names["v_checked"]}["done"] = True
                return _result

            _sslobj.do_handshake = {names["fn_new_do_handshake"]}
            return _sslobj

        {marker_line_wb}_sl3.SSLContext.wrap_bio = {names["fn_new_wrap_bio"]}
    except Exception:
        pass

    {names["v_patched"]} = True

{names["fn_patch"]}()
'''
