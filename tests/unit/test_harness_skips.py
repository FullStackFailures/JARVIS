"""The skip decorators must carry explicit reasons (release-gate rule: no silent/unexplained skips)."""

import unittest

from tests.harness import linux_only, windows_only


class SkipDecorators(unittest.TestCase):
    def test_bare_and_reasoned_forms_carry_reasons(self):
        @windows_only
        class A(unittest.TestCase):
            def test_x(self): ...

        @windows_only("needs Win32 pipes for the DACL read-back")
        class B(unittest.TestCase):
            def test_x(self): ...

        @linux_only
        def f(): ...

        for obj in (A, B, f):
            self.assertGreaterEqual(len(getattr(obj, "_skip_reason", "")), 8, obj)
        self.assertIn("DACL", B._skip_reason)

    def test_empty_reason_rejected(self):
        with self.assertRaises(ValueError):
            windows_only("  ")
