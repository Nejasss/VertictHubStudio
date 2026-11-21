#!/usr/bin/env python3
"""Cross-compiles PyCryptodome for Android ARM64 (CPython 3.14) without host sysconfig leakage."""
import os
import struct
import subprocess
import sys
import sysconfig


def verify_aarch64_elf(path: str) -> None:
    with open(path, "rb") as f:
        hdr = f.read(20)
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        raise RuntimeError(f"Not an ELF file: {path}")
    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]
    if ei_class != 2 or e_machine != 183:  # ELFCLASS64=2, EM_AARCH64=183
        raise RuntimeError(
            f"Invalid ELF architecture for {path}: class={ei_class}, e_machine={e_machine} (expected EM_AARCH64=183)"
        )


def main() -> int:
    ws = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
    android_home = os.environ["ANDROID_HOME"]
    ndk_version = os.environ["NDK_VERSION"]
    src_dir = "/tmp/pycrypto_src/pycryptodome-3.21.0"
    cross_dir = "/tmp/pycrypto_cross"
    os.makedirs(cross_dir, exist_ok=True)

    toolchain = os.path.join(android_home, "ndk", ndk_version, "toolchains", "llvm", "prebuilt", "linux-x86_64")
    cc = os.path.join(toolchain, "bin", "aarch64-linux-android24-clang")
    ar = os.path.join(toolchain, "bin", "llvm-ar")
    py314_inc = os.path.join(ws, "native", "python314", "include", "python3.14")

    if not os.path.isfile(cc):
        raise FileNotFoundError(f"NDK clang not found: {cc}")
    if not os.path.isdir(py314_inc):
        raise FileNotFoundError(f"CPython 3.14 include dir not found: {py314_inc}")

    # Wrapper linker: buang flag -L/-I kosong maupun path host x86_64 (/usr/*, /lib*)
    ld_wrapper = os.path.join(cross_dir, "aarch64-ld-wrapper.sh")
    with open(ld_wrapper, "w", encoding="utf-8", newline="\n") as f:
        f.write(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "ARGS=()\n"
            "SKIP_NEXT=0\n"
            "for arg in \"$@\"; do\n"
            "  if [ \"$SKIP_NEXT\" -eq 1 ]; then\n"
            "    SKIP_NEXT=0\n"
            "    continue\n"
            "  fi\n"
            "  [ -z \"$arg\" ] && continue\n"
            "  case \"$arg\" in\n"
            "    -L|-I)\n"
            "      SKIP_NEXT=1\n"
            "      continue\n"
            "      ;;\n"
            "    -L/usr/*|-L/lib*|-I/usr/*)\n"
            "      continue\n"
            "      ;;\n"
            "    *)\n"
            "      ARGS+=(\"$arg\")\n"
            "      ;;\n"
            "  esac\n"
            "done\n"
            f'exec "{cc}" -shared "${{ARGS[@]}}"\n'
        )
    os.chmod(ld_wrapper, 0o755)

    # Set LIBDIR=None & LIBPL=None agar distutils tidak menyisipkan argumen -L kosong
    base_vars = dict(sysconfig.get_config_vars())
    base_vars.update(
        {
            "CC": cc,
            "CXX": os.path.join(toolchain, "bin", "aarch64-linux-android24-clang++"),
            "AR": ar,
            "ARFLAGS": "rcs",
            "LDSHARED": ld_wrapper,
            "BLDSHARED": ld_wrapper,
            "LDCXXSHARED": ld_wrapper,
            "OPT": "-O2 -fPIC",
            "CFLAGS": f"-O2 -fPIC -DLTC_NO_ASM -I{py314_inc}",
            "PY_CFLAGS": f"-O2 -fPIC -DLTC_NO_ASM -I{py314_inc}",
            "PY_CORE_CFLAGS": f"-O2 -fPIC -DLTC_NO_ASM -I{py314_inc}",
            "CPPFLAGS": f"-I{py314_inc}",
            "LDFLAGS": "",
            "PY_LDFLAGS": "",
            "LIBDIR": None,
            "LIBPL": None,
            "INCLUDEPY": py314_inc,
            "CONFINCLUDEPY": py314_inc,
            "EXT_SUFFIX": ".cpython-314-aarch64-linux-android.so",
            "SO": ".cpython-314-aarch64-linux-android.so",
            "MULTIARCH": "aarch64-linux-android",
            "HOST_GNU_TYPE": "aarch64-unknown-linux-android",
            "BUILD_GNU_TYPE": "x86_64-pc-linux-gnu",
            "CCSHARED": "-fPIC",
            "SHLIB_SUFFIX": ".so",
        }
    )

    sysconfig_py = os.path.join(cross_dir, "_sysconfigdata__android_aarch64.py")
    with open(sysconfig_py, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"build_time_vars = {repr(base_vars)}\n")

    env = os.environ.copy()
    env["_PYTHON_SYSCONFIGDATA_NAME"] = "_sysconfigdata__android_aarch64"
    env["PYTHONPATH"] = cross_dir + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["CC"] = cc
    env["AR"] = ar
    env["LDSHARED"] = ld_wrapper
    env["OPT"] = "-O2 -fPIC"
    env["CFLAGS"] = f"-O2 -fPIC -DLTC_NO_ASM -I{py314_inc}"
    env["LDFLAGS"] = ""

    subprocess.run([sys.executable, "setup.py", "build_ext", "--inplace"], cwd=src_dir, env=env, check=True)

    so_count = 0
    for r, _, files in os.walk(os.path.join(src_dir, "lib", "Crypto")):
        for fn in files:
            if fn.endswith(".so"):
                full_so = os.path.join(r, fn)
                verify_aarch64_elf(full_so)
                so_count += 1

    if so_count == 0:
        raise RuntimeError("No compiled PyCryptodome .so extensions produced!")

    print(f"[OK] Cross-compiled and ELF-verified {so_count} ARM64 PyCryptodome extensions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
