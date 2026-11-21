"""
sitecustomize.py - Android SELinux W^X Native Extension Loader for VertictHub Studio.

Maps Python C extensions (stdlib lib-dynload & PyCryptodome _raw_* modules)
to `libvh_ext_<module>.so` inside Android `nativeLibraryDir` (`VH_NATIVE_LIB_DIR`),
ensuring Android PackageManager extracts them and dlopen succeeds on Android 10+.
"""
import importlib.abc
import importlib.machinery
import os
import sys


class _AndroidNativeLibFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        native_dir = os.environ.get("VH_NATIVE_LIB_DIR", "").strip()
        if not native_dir or not os.path.isdir(native_dir):
            return None
        so_name = f"libvh_ext_{fullname.replace('.', '_')}.so"
        so_path = os.path.join(native_dir, so_name)
        if os.path.isfile(so_path):
            loader = importlib.machinery.ExtensionFileLoader(fullname, so_path)
            return importlib.machinery.ModuleSpec(fullname, loader, origin=so_path)
        return None


if not any(isinstance(f, _AndroidNativeLibFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _AndroidNativeLibFinder())
