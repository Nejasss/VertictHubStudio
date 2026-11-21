"""Builder modul native generik untuk membuka payload launcher.

Modul yang dihasilkan tidak menyimpan key atau ciphertext build tertentu. Data itu
masih menjadi input dari stub launcher, sedangkan rekonstruksi key, AES-GCM,
unmarshal dan dispatch code object terjadi di ekstensi CPython (.so).
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sysconfig
import tempfile
from pathlib import Path


class NativeDecryptorBuildError(RuntimeError):
    """Compiler atau header Python untuk modul decryptor tidak tersedia."""


MODULE_NAME = "_pyobf_native"


def _python_link_flags() -> list[str]:
    """Return flags that bind the extension to the active libpython.

    Many desktop Python executables export CPython API symbols to extensions by
    accident of their linker flags. Termux does not guarantee that behavior, so
    a shared object that leaves `PyExc_*` unresolved can compile successfully
    but fail under dlopen(). Prefer python3-config's embed flags, which track
    the active interpreter's ABI and library directory.
    """
    config = shutil.which("python3-config") or shutil.which("python-config")
    if config:
        for option in ("--embed", "--ldflags"), ("--ldflags",):
            try:
                result = subprocess.run(
                    [config, *option], capture_output=True, text=True, check=True
                )
            except (OSError, subprocess.CalledProcessError):
                continue
            flags = shlex.split(result.stdout.strip())
            if any(flag.startswith("-lpython") or "libpython" in flag for flag in flags):
                return flags

    libdir = sysconfig.get_config_var("LIBDIR")
    candidates = [
        sysconfig.get_config_var("LDLIBRARY"),
        sysconfig.get_config_var("LIBRARY"),
    ]
    for library in (item for item in candidates if item):
        path = Path(libdir or "") / library
        if path.is_file():
            # A direct path is safer than deriving -l from names such as
            # libpython3.12-pic.a on distribution-specific builds.
            return [str(path)]
    raise NativeDecryptorBuildError(
        "Tidak menemukan linker flags libpython. Install paket python-dev/python-devel "
        "yang menyediakan python3-config untuk interpreter build."
    )


_C_SOURCE = r'''#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <marshal.h>
#include <string.h>

static PyObject *digest_concat(PyObject *sha256, PyObject *left, PyObject *right) {
    if (!PyBytes_Check(left) || !PyBytes_Check(right)) {
        PyErr_SetString(PyExc_TypeError, "fragment must be bytes");
        return NULL;
    }
    Py_ssize_t n1 = PyBytes_GET_SIZE(left), n2 = PyBytes_GET_SIZE(right);
    PyObject *joined = PyBytes_FromStringAndSize(NULL, n1 + n2);
    if (!joined) return NULL;
    memcpy(PyBytes_AS_STRING(joined), PyBytes_AS_STRING(left), (size_t)n1);
    memcpy(PyBytes_AS_STRING(joined) + n1, PyBytes_AS_STRING(right), (size_t)n2);
    PyObject *h = PyObject_CallFunctionObjArgs(sha256, joined, NULL);
    Py_DECREF(joined);
    if (!h) return NULL;
    PyObject *out = PyObject_CallMethod(h, "digest", NULL);
    Py_DECREF(h);
    return out;
}

static PyObject *hmac_digest(PyObject *hmac_new, PyObject *key, PyObject *message, PyObject *sha256) {
    PyObject *h = PyObject_CallFunctionObjArgs(hmac_new, key, message, sha256, NULL);
    if (!h) return NULL;
    PyObject *out = PyObject_CallMethod(h, "digest", NULL);
    Py_DECREF(h);
    return out;
}

static PyObject *join_bytes(PyObject *items) {
    PyObject *empty = PyBytes_FromStringAndSize("", 0);
    if (!empty) return NULL;
    PyObject *out = PyObject_CallMethod(empty, "join", "O", items);
    Py_DECREF(empty);
    return out;
}

static void clear_bytes(PyObject *obj) {
    if (obj && PyBytes_Check(obj)) {
        volatile unsigned char *p = (volatile unsigned char *)PyBytes_AS_STRING(obj);
        Py_ssize_t n = PyBytes_GET_SIZE(obj);
        while (n-- > 0) *p++ = 0;
    }
}

static PyObject *run_payload(PyObject *self, PyObject *args) {
    PyObject *fragments, *seed, *tags, *nonce, *ciphertext, *tag;
    PyObject *hashlib = NULL, *sha256 = NULL, *hmac = NULL, *hmac_new = NULL;
    PyObject *pool = NULL, *state = NULL, *picked = NULL, *raw = NULL, *info = NULL;
    PyObject *zero = NULL, *prk = NULL, *prev = NULL, *out = NULL, *key = NULL;
    PyObject *aes = NULL, *new_fn = NULL, *mode = NULL;
    PyObject *posargs = NULL, *kwargs = NULL, *cipher = NULL, *plaintext = NULL;
    PyObject *code = NULL;
    PyObject *result = NULL;

    if (!PyArg_ParseTuple(args, "OOOOOO", &fragments, &seed, &tags, &nonce, &ciphertext, &tag)) return NULL;
    if (!PyBytes_Check(seed) || !PyBytes_Check(nonce) || !PyBytes_Check(ciphertext) || !PyBytes_Check(tag)) {
        PyErr_SetString(PyExc_TypeError, "native payload metadata must be bytes");
        return NULL;
    }

    hashlib = PyImport_ImportModule("hashlib");
    hmac = PyImport_ImportModule("hmac");
    if (!hashlib || !hmac) goto done;
    sha256 = PyObject_GetAttrString(hashlib, "sha256");
    hmac_new = PyObject_GetAttrString(hmac, "new");
    if (!sha256 || !hmac_new) goto done;

    pool = PySequence_List(fragments);
    picked = PyList_New(0);
    state = Py_NewRef(seed);
    if (!pool || !picked || !state) goto done;

    Py_ssize_t tag_count = PySequence_Size(tags);
    if (tag_count < 1) { PyErr_SetString(PyExc_ValueError, "invalid fragment chain"); goto done; }
    for (Py_ssize_t i = 0; i < tag_count; i++) {
        PyObject *expected = PySequence_GetItem(tags, i);
        if (!expected) goto done;
        if (!PyBytes_Check(expected)) { Py_DECREF(expected); PyErr_SetString(PyExc_TypeError, "chain tag must be bytes"); goto done; }
        int found = 0;
        Py_ssize_t candidates = PyList_GET_SIZE(pool);
        for (Py_ssize_t j = 0; j < candidates; j++) {
            PyObject *candidate = PyList_GET_ITEM(pool, j);
            PyObject *digest = DIGEST_CONCAT_CALL_PLACEHOLDER;
            if (!digest) { Py_DECREF(expected); goto done; }
            Py_ssize_t want = PyBytes_GET_SIZE(expected), got = PyBytes_GET_SIZE(digest);
            int match = got >= want && memcmp(PyBytes_AS_STRING(digest), PyBytes_AS_STRING(expected), (size_t)want) == 0;
            if (match) {
                if (PyList_Append(picked, candidate) < 0 || PySequence_DelItem(pool, j) < 0) {
                    Py_DECREF(digest); Py_DECREF(expected); goto done;
                }
                Py_SETREF(state, digest);
                found = 1;
                break;
            }
            Py_DECREF(digest);
        }
        Py_DECREF(expected);
        if (!found) { PyErr_SetString(PyExc_ValueError, "fragment chain verification failed"); goto done; }
    }

    Py_ssize_t picked_count = PyList_GET_SIZE(picked);
    if (picked_count < 2) { PyErr_SetString(PyExc_ValueError, "incomplete fragment chain"); goto done; }
    info = Py_NewRef(PyList_GET_ITEM(picked, picked_count - 1));
    PyObject *real_parts = PyList_GetSlice(picked, 0, picked_count - 1);
    if (!info || !real_parts) goto done;
    raw = join_bytes(real_parts);
    Py_DECREF(real_parts);
    if (!raw) goto done;

    zero = PyBytes_FromStringAndSize(NULL, 32);
    if (!zero) goto done;
    memset(PyBytes_AS_STRING(zero), 0, 32);
    prk = hmac_digest(hmac_new, zero, raw, sha256);
    if (!prk) goto done;
    prev = PyBytes_FromStringAndSize("", 0);
    out = PyBytes_FromStringAndSize("", 0);
    if (!prev || !out) goto done;
    for (unsigned char counter = 1; PyBytes_GET_SIZE(out) < 32; counter++) {
        Py_ssize_t a = PyBytes_GET_SIZE(prev), b = PyBytes_GET_SIZE(info);
        PyObject *material = PyBytes_FromStringAndSize(NULL, a + b + 1);
        if (!material) goto done;
        memcpy(PyBytes_AS_STRING(material), PyBytes_AS_STRING(prev), (size_t)a);
        memcpy(PyBytes_AS_STRING(material) + a, PyBytes_AS_STRING(info), (size_t)b);
        PyBytes_AS_STRING(material)[a + b] = (char)counter;
        PyObject *next = hmac_digest(hmac_new, prk, material, sha256);
        Py_DECREF(material);
        if (!next) goto done;
        Py_SETREF(prev, next);
        /* Bangun buffer 'out' baru secara eksplisit (bukan lewat
           PyBytes_Concat) - PyBytes_Concat mengasumsikan pemanggil
           adalah pemilik eksklusif (refcount==1) atas objek bytes
           yang di-in-place-modify, TAPI 'out' diinisialisasi dari
           PyBytes_FromStringAndSize("", 0) yang oleh CPython bisa
           saja dikembalikan sebagai singleton bytes-kosong yang
           di-share/di-intern di seluruh interpreter (perilaku ini
           bervariasi antar versi CPython dan TIDAK dijamin stabil
           lintas versi - termasuk berbeda antara build desktop dan
           build Termux/Android untuk versi Python yang sama).
           Me-mutate objek yang mungkin di-share seperti itu adalah
           undefined behavior: bisa sukses di satu interpreter/versi
           dan diam-diam menghasilkan buffer yang salah/corrupt di
           interpreter/versi lain - persis pola silent-failure yang
           sulit dilacak dari luar. PyBytes_FromStringAndSize(NULL, n)
           selalu mengalokasikan objek BARU yang exclusive-owned oleh
           kode ini, jadi tidak ada masalah aliasing/sharing sama
           sekali. */
        Py_ssize_t out_old_len = PyBytes_GET_SIZE(out);
        Py_ssize_t prev_len = PyBytes_GET_SIZE(prev);
        PyObject *out_new = PyBytes_FromStringAndSize(NULL, out_old_len + prev_len);
        if (!out_new) goto done;
        memcpy(PyBytes_AS_STRING(out_new), PyBytes_AS_STRING(out), (size_t)out_old_len);
        memcpy(PyBytes_AS_STRING(out_new) + out_old_len, PyBytes_AS_STRING(prev), (size_t)prev_len);
        Py_SETREF(out, out_new);
    }
    key = PyBytes_FromStringAndSize(PyBytes_AS_STRING(out), 32);
    if (!key) goto done;

    aes = PyImport_ImportModule("Crypto.Cipher.AES");
    if (!aes) goto done;
    new_fn = PyObject_GetAttrString(aes, "new");
    mode = PyObject_GetAttrString(aes, "MODE_GCM");
    if (!new_fn || !mode) goto done;
    posargs = PyTuple_Pack(2, key, mode);
    kwargs = PyDict_New();
    if (!posargs || !kwargs || PyDict_SetItemString(kwargs, "nonce", nonce) < 0) goto done;
    cipher = PyObject_Call(new_fn, posargs, kwargs);
    if (!cipher) goto done;
    plaintext = PyObject_CallMethod(cipher, "decrypt_and_verify", "OO", ciphertext, tag);
    if (!plaintext) goto done;

    code = PyMarshal_ReadObjectFromString(
        PyBytes_AS_STRING(plaintext), PyBytes_GET_SIZE(plaintext)
    );
    if (!code || !PyCode_Check(code)) {
        Py_XDECREF(code);
        code = NULL;
        if (!PyErr_Occurred()) PyErr_SetString(PyExc_ValueError, "native payload is not a code object");
        goto done;
    }
    result = PyImport_ExecCodeModule("_pyobf_payload", code);
    clear_bytes(plaintext);
done:
    clear_bytes(raw); clear_bytes(info); clear_bytes(prk); clear_bytes(prev);
    clear_bytes(out); clear_bytes(key); clear_bytes(plaintext);
    Py_XDECREF(hashlib); Py_XDECREF(sha256); Py_XDECREF(hmac); Py_XDECREF(hmac_new);
    Py_XDECREF(pool); Py_XDECREF(state); Py_XDECREF(picked); Py_XDECREF(raw); Py_XDECREF(info);
    Py_XDECREF(zero); Py_XDECREF(prk); Py_XDECREF(prev); Py_XDECREF(out); Py_XDECREF(key);
    Py_XDECREF(aes); Py_XDECREF(new_fn); Py_XDECREF(mode);
    Py_XDECREF(posargs); Py_XDECREF(kwargs); Py_XDECREF(cipher); Py_XDECREF(plaintext);
    Py_XDECREF(code);
    return result;
}

static PyMethodDef methods[] = {
    {"run", run_payload, METH_VARARGS, "Decrypt and dispatch a packed code object."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef moduledef = {PyModuleDef_HEAD_INIT, "_pyobf_native", NULL, -1, methods};
PyMODINIT_FUNC PyInit__pyobf_native(void) { return PyModule_Create(&moduledef); }
'''


def _get_c_source(combine_order: str = "state_first") -> str:
    """Returns _C_SOURCE with its single digest_concat(...) call site
    filled in to match combine_order - "state_first" (the only shape
    every build before this ever used) computes SHA256(state +
    candidate); "cand_first" instead computes SHA256(candidate +
    state). This is the C-side half of the SAME per-build variation
    core/packer.py applies to every OTHER fragment chain in this
    project - see crypto.build_fragment_chain's combine_order
    docstring for the full rationale (a real static-extraction script,
    confirmed working, hardcoded exactly one shape because every build
    ever produced used it unconditionally). This specific chain (the
    one protecting raw_material / the outer combined launcher source,
    reconstructed via this .so's run_payload rather than in Python)
    was the one the confirmed extraction actually walked through to
    reach the embedded main binary, so it is not optional to leave
    unvaried alongside the others.

    A simple literal string substitution, not an f-string over the
    whole ~200-line C source, deliberately: converting the whole
    thing risks silently mismatching THE MANY literal { and } already
    in this C code (every block, every struct initializer) against
    f-string's escaping rules, for a change that only ever needs to
    touch one call site.
    """
    if combine_order not in ("state_first", "cand_first"):
        raise ValueError(f"combine_order must be 'state_first' or 'cand_first', got {combine_order!r}")
    call = (
        "digest_concat(sha256, state, candidate)" if combine_order == "state_first"
        else "digest_concat(sha256, candidate, state)"
    )
    if "DIGEST_CONCAT_CALL_PLACEHOLDER" not in _C_SOURCE:
        raise RuntimeError("_C_SOURCE is missing its digest_concat call placeholder - source was edited incorrectly")
    return _C_SOURCE.replace("DIGEST_CONCAT_CALL_PLACEHOLDER", call)


def build_native_decryptor(combine_order: str = "state_first") -> tuple[bytes, str]:
    """Build ekstensi untuk interpreter build saat ini dan mengembalikan bytes-nya.

    combine_order: passed straight through to _get_c_source - MUST be
    the same value the caller uses for the raw_material fragment
    chain's build_fragment_chain(..., combine_order=...) call in
    core/packer.py's pack_with_native_decryptor, since this .so's
    compiled-in digest_concat() call order is what reconstructs that
    exact chain at runtime (see run_payload in the C source above) -
    a mismatch here means every real build/run of the resulting
    launcher fails its own chain verification, not just an attacker's.
    """
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    include = sysconfig.get_paths().get("include")
    if not compiler or not include or not Path(include, "Python.h").is_file():
        raise NativeDecryptorBuildError(
            "Native decryptor membutuhkan gcc/clang dan header Python development. "
            "Di Termux: pkg install clang python python-dev"
        )
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    with tempfile.TemporaryDirectory(prefix="pyobf-native-") as tmp:
        root = Path(tmp)
        source = root / "native_decryptor.c"
        output = root / f"{MODULE_NAME}{suffix}"
        source.write_text(_get_c_source(combine_order), encoding="utf-8")
        link_flags = _python_link_flags()
        command = [
            compiler, "-O2", "-fPIC", "-shared", "-Wl,--no-undefined",
            f"-I{include}", str(source), "-o", str(output), *link_flags,
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0 or not output.is_file():
            detail = (result.stderr or result.stdout or "compiler tidak menghasilkan modul").strip()
            raise NativeDecryptorBuildError(f"Build native decryptor gagal: {detail}")

        # Strip symbols/debug info before this .so ever gets encrypted
        # and embedded - same reasoning and same pattern as
        # embed_build.py's post-link strip of the main launcher binary
        # (see that module's own strip_bin call). This matters here
        # specifically because pack_with_native_decryptor's runtime
        # loader (core/packer.py's fn_run) has to DECRYPT this blob
        # back to a real .so file on disk (mkstemp + os.fdopen, since
        # a Python C extension can only be dlopen()'d from an actual
        # file, not loaded from an in-memory buffer) for the whole
        # duration of the run - so an unstripped .so leaves function
        # names (run_payload, PyInit__pyobf_native, etc.) and other
        # debug metadata sitting on disk in plaintext for that entire
        # window, readable via nm/objdump/strings by anyone who can
        # read that temp file while it exists. Stripping here, before
        # the AES-GCM encryption in pack_with_native_decryptor even
        # happens, means the decrypted-at-runtime copy is ALSO
        # stripped, closing that window - encryption alone only
        # protects the blob at rest inside the .py launcher, not what
        # gets written back to disk to actually run it.
        strip_bin = shutil.which("strip")
        if strip_bin:
            subprocess.run([strip_bin, "--strip-all", str(output)], capture_output=True)

        return output.read_bytes(), suffix
