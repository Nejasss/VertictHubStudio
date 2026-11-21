"""
crypto.py - two ciphers are available here:

  - XOR + chained-SHA256 keystream (derive_keystream/xor_encrypt/
    xor_decrypt): zero-dependency, stdlib only. Used by
    native_launcher.py and embed_build.py's C-side decrypt (a C
    program can't easily link pycryptodome, so those stay on this).

  - AES-256-GCM (aes_gcm_encrypt/aes_gcm_decrypt): used by packer.py
    for the .py loader's payload. Needs pycryptodome - packer.py's
    generated loader auto-installs it via pip at first run if it's
    missing (see packer.py's template). GCM's authentication tag
    also replaces the separate SHA256 payload-hash check the XOR
    path needs: a tampered ciphertext fails to decrypt at all
    instead of decrypting successfully to garbage.

Neither cipher is "military grade" in the sense of being a vetted,
audited implementation from this codebase - the XOR one is
explicitly just obfuscation. The AES-GCM one delegates all the
actual cryptographic work to pycryptodome (a real, maintained
crypto library), so its cryptographic strength is real; what's
custom here is only the per-build key material generation/splitting
around it, not the cipher primitive itself.
"""
import os
import hashlib
import base64
import random


def derive_keystream(key: bytes, length: int) -> bytes:
    """Derive a keystream of `length` bytes from `key` using chained SHA256."""
    out = bytearray()
    block = key
    while len(out) < length:
        block = hashlib.sha256(block).digest()
        out.extend(block)
    return bytes(out[:length])


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    ks = derive_keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    # symmetric
    return xor_encrypt(data, key)


def random_key(n: int = 32) -> bytes:
    return os.urandom(n)


def b64(data: bytes) -> str:
    return base64.b85encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.b85decode(data.encode())


def hkdf_sha256(raw_material: bytes, length: int = 32, info: bytes = b"vh-aes-key", salt: bytes = b"") -> bytes:
    """
    Minimal HKDF (RFC 5869) built from stdlib hashlib.hmac only - no
    pycryptodome needed for this step, since it also has to run
    inside packer.py's generated .py loader before pycryptodome is
    guaranteed to be installed yet. Turns raw key material (here:
    the reassembled split chunks) into the actual AES key, so
    recovering the chunks alone isn't the same as having the key -
    the derivation step still has to be replicated too.

    info: the default here is a fixed, generic value - callers that
    care about per-build unlinkability (packer.py does, for its
    payload key) should pass a freshly random `info` generated once
    per build instead of relying on this default, since a FIXED info
    string is one less thing a generic "decode any build of this
    tool's .py output" script has to guess - it can just hardcode the
    same known constant packer.py always used to use. See packer.py's
    own usage for how the random info value itself gets stored
    without becoming a second obvious "the key" artifact.
    """
    import hmac
    # extract
    prk = hmac.new(salt or b"\x00" * 32, raw_material, hashlib.sha256).digest()
    # expand
    out = b""
    prev = b""
    counter = 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]


def split_key(key: bytes, n_chunks: int = 6) -> list:
    """
    Split `key` into n_chunks byte-strings of roughly equal length,
    reassembled with b"".join(chunks_in_original_order). packer.py
    stores each chunk under its own randomly-named variable, places
    them at different points in the generated file, and reassembles
    them via a random-looking permutation map rather than a plain
    0..n-1 concatenation - so an attacker has to find every chunk
    AND recover the correct order before they even reach the HKDF
    step above.
    """
    if n_chunks < 1:
        n_chunks = 1
    base_len = len(key) // n_chunks
    remainder = len(key) % n_chunks
    chunks = []
    pos = 0
    for i in range(n_chunks):
        take = base_len + (1 if i < remainder else 0)
        chunks.append(key[pos:pos + take])
        pos += take
    return chunks


def split_key_with_junk(key: bytes, n_real_chunks: int = None, n_junk_chunks: int = None):
    """
    Like split_key(), but interleaves DECOY fragments among the real
    ones - same length distribution, same random-bytes appearance, no
    structural difference an AST/static reader could use to tell them
    apart from the real chunks. Returns (all_fragments, real_indices):
      - all_fragments: list of n_real_chunks + n_junk_chunks byte
        strings, in a shuffled order that mixes real and decoy
      - real_indices: the list of positions INTO all_fragments that
        are the real key chunks, IN THE ORDER THEY MUST BE
        CONCATENATED to reconstruct `key`

    Why this exists (closing the gap real-world extraction demonstrated
    against the previous split_key-only scheme): even with split_key's
    chunks scattered and randomly ordered, EVERY declared chunk was
    always a real piece of the key, and the reassembly EXPRESSION
    itself (e.g. `raw = _a + _b + _c + _d + _e`) was always written out
    verbatim as literal, staticaly-readable code in the SAME generated
    file - so a script that just AST-parses every top-level assignment
    and reads that one reassembly line straight off didn't need to
    guess anything at all. This function's caller (packer.py) is
    expected to NOT emit any comparably readable "here's the order"
    expression - real_indices must be consumed by the CALLER in a way
    that never appears as a literal, human/AST-readable list anywhere
    in the generated output (e.g. baked directly into which specific,
    unlabeled variable-name slots get concatenated, computed from
    something else already present, etc - the exact obfuscation of
    real_indices itself is packer.py's responsibility, this function
    only guarantees the fragments are format-indistinguishable).

    Critically, this function does NOT decide - and packer.py's use of
    it must NOT decide - which fragments are real by any RUNTIME
    check (e.g. "try this combination, see if it authenticates").  A
    runtime trial-and-decide loop is itself a bigger tell than a fixed
    file could ever be: it announces "some of these chunks are
    decoys, and here is exactly the search procedure to find the real
    ones" in the clearest possible terms, which is far worse than the
    problem being fixed here. The selection must be BAKED IN at build
    time as fixed data, so a reader who finds all fragments still has
    to brute-force which combination/order is correct with no hint
    from the program's own logic - AES-GCM's authentication tag
    (already used for the payload cipher) is what makes a wrong
    guess loudly fail instead of silently decrypting to garbage,
    without this module needing to implement any success/failure
    signal of its own.
    """
    if n_real_chunks is None:
        n_real_chunks = random.randint(5, 8)
    if n_junk_chunks is None:
        n_junk_chunks = random.randint(3, 6)

    real_chunks = split_key(key, n_chunks=n_real_chunks)
    # Junk fragments drawn from the same length distribution as real
    # ones (not a fixed size), so fragment length alone doesn't mark
    # a chunk as real or decoy either.
    avg_len = max(1, len(key) // n_real_chunks)
    junk_chunks = [os.urandom(max(1, avg_len + random.randint(-1, 1))) for _ in range(n_junk_chunks)]

    all_fragments = real_chunks + junk_chunks
    order = list(range(len(all_fragments)))
    random.shuffle(order)
    shuffled_fragments = [all_fragments[i] for i in order]

    # real_indices: for each real chunk (in ORIGINAL concatenation
    # order), find its new position in shuffled_fragments.
    real_indices = []
    for i in range(n_real_chunks):
        original_pos = i  # position of this real chunk in all_fragments
        real_indices.append(order.index(original_pos))

    return shuffled_fragments, real_indices


def build_fragment_chain(fragments: list, real_order: list, root_seed: bytes = None,
                          tag_len: int = 4, combine_order: str = "state_first") -> tuple:
    """
    Constructs a forward hash-chain over `fragments` (the SAME
    shuffled real+junk fragment pool split_key_with_junk returns),
    such that recovering `real_order` (the sequence of indices INTO
    fragments that reconstructs the real key, in the correct order)
    requires actually possessing the fragment bytes and trying them,
    rather than reading a static index/offset value out of the file.

    How it works: state starts at root_seed. For each position in
    real_order, this computes tag_i = SHA256(state + fragments[real_order[i]])[:tag_len]
    (or fragments[...] + state - see combine_order below) and advances
    state = SHA256(...) (the full digest, not just the truncated tag)
    for the next step. Returns (root_seed, [tag_0, tag_1, ...]) - both
    are safe to embed directly in the generated source as literal
    bytes, since neither one alone (nor both together, without the
    fragment pool) reveals which fragment index each tag corresponds
    to.

    At runtime (see packer.py's generated fn_pick, which mirrors this
    exact forward construction), reconstructing real_order from
    (root_seed, tags, fragments) means: for each tag in sequence, try
    every remaining candidate fragment, compute the same SHA256(state
    + candidate)[:tag_len] (matching whichever combine_order this
    build used), and take whichever candidate matches - that's the
    correct fragment for this step, and its full digest becomes the
    next state. This is a linear scan (O(n) candidates tried per
    step, O(n * len(real_order)) total) - deliberately NOT
    astronomically expensive (this needs to run at every program
    startup on modest hardware, including phones under Termux), and
    NOT a claim of cryptographic hardness - an attacker who
    understands this exact algorithm can trivially replicate the same
    scan themselves.

    combine_order / tag_len are the direct response to that last
    admission actually happening in practice: a real static-extraction
    script (confirmed working against an unpatched build) hardcoded
    exactly `hashlib.sha256(state + candidate).digest()[:4]` - the
    ONE combine order and tag length every build before this ever
    used, unconditionally. That script works against every prior
    build ever produced by this tool, without modification, because
    the *shape* of the scan (not just its data) was identical every
    time. combine_order ("state_first" -> state+candidate,
    "cand_first" -> candidate+state) and a per-build-randomized
    tag_len (see packer.py's call sites) are chosen ONCE per build and
    baked into both the build-time chain here and the matching
    runtime scan packer.py generates - so a script hardcoded to one
    specific shape now only has roughly a 50% (combine_order alone)
    chance of matching any given build, and silently produces a wrong
    key instead of a working one on a mismatch (AES-GCM's
    authentication tag turns that into a loud decrypt failure, not a
    subtle wrong-output bug - see split_key_with_junk's docstring for
    why a loud failure signal, not this module's own, is what makes a
    wrong guess visible at all). This does not make the algorithm
    unrecoverable - an attacker who dumps enough builds, or who reads
    THIS source file directly, still learns both possible shapes and
    every parameter that can vary - it makes a single static script
    written against one observed build silently stop working against
    the next one, forcing the analysis to be redone per-build instead
    of reused forever.

    tag_len (default 4, i.e. 32 bits) keeps stored tags short (so they
    don't look conspicuously "hash-sized" next to random junk-fragment
    bytes) while keeping the false-positive rate at each scan step low
    (~1 in 4 billion candidates would spuriously match a wrong
    fragment at the default; packer.py varies this per build within a
    range that keeps this property - see its own call sites - at a
    pool size in the dozens, this is not a practical collision concern
    for this obfuscation, not security-critical, purpose).
    """
    if root_seed is None:
        root_seed = os.urandom(32)
    if combine_order not in ("state_first", "cand_first"):
        raise ValueError(f"combine_order must be 'state_first' or 'cand_first', got {combine_order!r}")
    state = root_seed
    tags = []
    for idx in real_order:
        frag = fragments[idx]
        combined = state + frag if combine_order == "state_first" else frag + state
        digest = hashlib.sha256(combined).digest()
        tags.append(digest[:tag_len])
        state = digest
    return root_seed, tags
