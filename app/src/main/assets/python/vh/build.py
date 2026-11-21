"""
build.py - wraps PyInstaller to compile an obfuscated loader .py
into a standalone binary. Also strips build artifacts that could
leak info (e.g. the .spec file, build/ cache with intermediate .pyc).
"""
import os
import shutil
import subprocess
import sys


def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa
        return True
    except ImportError:
        return False


def install_pyinstaller():
    raise RuntimeError("Offline Mode: PyInstaller tidak tersedia secara lokal dan auto-install online dinonaktifkan.")


def build_binary(loader_path: str, output_dir: str, name: str, onefile: bool = True, console: bool = True, hidden_imports=None):
    if not ensure_pyinstaller():
        install_pyinstaller()

    os.makedirs(output_dir, exist_ok=True)
    work_dir = os.path.join(output_dir, "_vh_build_tmp")
    spec_dir = os.path.join(output_dir, "_vh_spec_tmp")
    dist_dir = os.path.join(output_dir, "_vh_dist_tmp")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(spec_dir, exist_ok=True)
    os.makedirs(dist_dir, exist_ok=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile" if onefile else "--onedir",
        "--name", name,
        "--distpath", dist_dir,
        "--workpath", work_dir,
        "--specpath", spec_dir,
    ]
    if not console:
        cmd.append("--windowed")
    # The real script's `import` statements are hidden inside the
    # encrypted payload and invisible to PyInstaller's static source
    # scan, so anything it would normally auto-detect must be passed
    # explicitly here or the build silently omits it (ModuleNotFoundError
    # at runtime, only inside the compiled binary).
    for mod in (hidden_imports or []):
        cmd += ["--hidden-import", mod]
    cmd.append(loader_path)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # cleanup temp dirs before raising
        shutil.rmtree(work_dir, ignore_errors=True)
        shutil.rmtree(spec_dir, ignore_errors=True)
        shutil.rmtree(dist_dir, ignore_errors=True)
        raise RuntimeError(f"PyInstaller failed:\n{result.stdout}\n{result.stderr}")

    # locate the produced binary
    produced = None
    if onefile:
        candidate = os.path.join(dist_dir, name)
        if os.path.exists(candidate):
            produced = candidate
        elif os.path.exists(candidate + ".exe"):
            produced = candidate + ".exe"
    else:
        produced = os.path.join(dist_dir, name)

    final_path = None
    if produced:
        final_path = os.path.join(output_dir, os.path.basename(produced))
        if os.path.isdir(produced):
            if os.path.exists(final_path):
                shutil.rmtree(final_path)
            shutil.move(produced, final_path)
        else:
            shutil.move(produced, final_path)

    # cleanup temp dirs, keep only the final artifact
    shutil.rmtree(work_dir, ignore_errors=True)
    shutil.rmtree(spec_dir, ignore_errors=True)
    shutil.rmtree(dist_dir, ignore_errors=True)

    return final_path
