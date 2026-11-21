#!/usr/bin/env python3
"""Offline integration tests for studio_bridge and vh.core."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app", "src", "main", "assets", "python"))

import studio_bridge  # noqa: E402
from vh.core import runtime_fetch, libpython_fetch  # noqa: E402


class TestOfflineCoreIntegration(unittest.TestCase):
    SAMPLE_CODE = (
        "def greet(user_name: str) -> str:\n"
        "    token = 'SECRET_API_KEY_9988'\n"
        "    return f'Hello {user_name}: {token}'\n\n"
        "print(greet('VertictHub'))\n"
    )

    def test_01_all_34_core_modules_import(self):
        res = json.loads(studio_bridge.verify_core_modules())
        self.assertTrue(res["ok"])
        self.assertEqual(res["total"], 34)
        self.assertEqual(res["verified_count"], 34)

    def test_02_ast_analysis_valid_and_syntax_error(self):
        ok_res = json.loads(studio_bridge.analyze_ast(self.SAMPLE_CODE, "demo.py"))
        self.assertTrue(ok_res["ok"])
        self.assertTrue(ok_res["valid_syntax"])
        self.assertGreater(ok_res["ast_node_count"], 10)

        bad_res = json.loads(studio_bridge.analyze_ast("def broken(:\n  pass", "broken.py"))
        self.assertTrue(bad_res["ok"])
        self.assertFalse(bad_res["valid_syntax"])
        self.assertEqual(bad_res["syntax_error"]["lineno"], 1)

    def test_03_obfuscation_pipeline_transforms_output(self):
        cfg = json.dumps({
            "encrypt_strings": True,
            "rename_identifiers": True,
            "constant_protection": True,
            "junk_intensity": 4,
            "anti_debug": True,
            "require_launcher_gate": False,
        })
        res = json.loads(studio_bridge.run_obfuscation(self.SAMPLE_CODE, "demo.py", cfg))
        self.assertTrue(res["ok"], msg=res)
        self.assertNotIn("SECRET_API_KEY_9988", res["obfuscated_source"])

    def test_04_packed_loader_build(self):
        res = json.loads(studio_bridge.run_build(self.SAMPLE_CODE, "demo.py", "packed_loader", "{}"))
        self.assertTrue(res["ok"], msg=res)
        self.assertEqual(res["artifact_filename"], "demo_protected.py")
        self.assertIn("marshal", res["artifact_content"])

    def test_05_offline_fetchers_never_touch_network(self):
        with self.assertRaises(runtime_fetch.RuntimeFetchError):
            runtime_fetch.ensure_python(3, 99)
        self.assertIsNone(libpython_fetch.find_local_libpython_dir(3, 99))


if __name__ == "__main__":
    unittest.main()
