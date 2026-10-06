"""Test harness: platform/kind tags and a runner that reports results per tag.

Tags: UNIT, CONTRACT, INTEGRATION (real code paths on this machine), ACCEPTANCE,
REGRESSION, LINUX, WINDOWS, FAKE_REASONER / STUB_HTTP (labelled test doubles).
Tests that need another OS are SKIPPED with a reason, never silently passed.
"""

from __future__ import annotations

import json
import os
import platform as _pf
import sys
import unittest
from collections import Counter, defaultdict

ON_LINUX = sys.platform.startswith("linux")
ON_WINDOWS = sys.platform == "win32"


def tags(*names: str):
    def deco(obj):
        obj._tags = tuple(getattr(obj, "_tags", ())) + names
        return obj
    return deco


def _only(tag: str, ok: bool, default_reason: str):
    """Decorator factory usable bare (@linux_only) or with a specific reason (@linux_only("uses POSIX sleep"))."""
    def make(reason: str):
        def deco(obj):
            obj = tags(tag)(obj)
            obj._skip_reason = reason  # recorded even when the test is NOT skipped (checked by test_harness_skips)
            return unittest.skipUnless(ok, reason)(obj)
        return deco

    def decorator(arg=None):
        if isinstance(arg, str):
            if not arg.strip():
                raise ValueError("skip reason must not be empty")
            return make(arg)
        if arg is None:
            return make(default_reason)
        return make(default_reason)(arg)
    return decorator


linux_only = _only("LINUX", ON_LINUX, "requires Linux (POSIX semantics / AF_UNIX / systemd)")
windows_only = _only("WINDOWS", ON_WINDOWS, "requires Windows (Win32 APIs, PowerShell/cmd, named pipes)")


def tags_of(test: unittest.TestCase) -> set[str]:
    out: set[str] = set()
    if not hasattr(test, "_testMethodName"):
        return {"SETUP"}
    method = getattr(test, test._testMethodName, None)
    for src in (type(test), method):
        out.update(getattr(src, "_tags", ()))
    mod = type(test).__module__
    for part, tag in (("unit", "UNIT"), ("integration", "INTEGRATION"), ("contract", "CONTRACT"),
                      ("acceptance", "ACCEPTANCE"), ("regression", "REGRESSION")):
        if f".{part}." in f".{mod}.":
            out.add(tag)
    return out


class TaggedResult(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.by_tag: dict[str, Counter] = defaultdict(Counter)
        self.skips: list[tuple[str, str]] = []
        self.records: list[dict] = []

    def _record(self, test, outcome, reason=""):
        self.records.append({"id": test.id() if hasattr(test, "id") else str(test),
                             "class": type(test).__name__, "module": type(test).__module__,
                             "tags": sorted(tags_of(test)), "outcome": outcome, "reason": reason})

    def _count(self, test, key):
        for t in tags_of(test) or {"UNTAGGED"}:
            self.by_tag[t][key] += 1

    def addSuccess(self, test):
        super().addSuccess(test); self._count(test, "pass"); self._record(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err); self._count(test, "fail"); self._record(test, "fail")

    def addError(self, test, err):
        super().addError(test, err); self._count(test, "error"); self._record(test, "error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason); self._count(test, "skip"); self.skips.append((str(test), reason)); self._record(test, "skip", reason)


def run(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    sys.path.insert(0, os.path.join(root, "src"))
    sys.path.insert(0, root)
    pattern = "test_*.py"
    suite = unittest.defaultTestLoader.discover(here, pattern=pattern, top_level_dir=root)
    runner = unittest.TextTestRunner(resultclass=TaggedResult, verbosity=2 if "-v" in argv else 1)
    res = runner.run(suite)
    print("\n== Results by tag ==")
    for t in sorted(res.by_tag):
        c = res.by_tag[t]
        print(f"  {t:<14} pass={c['pass']:<4} fail={c['fail']:<3} error={c['error']:<3} skip={c['skip']}")
    if res.skips:
        print("\n== Skipped (with reason) ==")
        for name, why in res.skips:
            print(f"  {name}: {why}")
    bad = [n for n, why in res.skips if len((why or "").strip()) < 8]
    if bad:
        print(f"\nFAIL: {len(bad)} skipped test(s) without an explicit reason: {bad}")
    out = os.environ.get("JARVIS_TEST_REPORT") or os.path.join(root, "build", f"test-report-{sys.platform}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"platform": sys.platform, "os": _pf.platform(), "python": sys.version.split()[0],
                   "ci": bool(os.environ.get("CI")), "generated": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
                   "tests": res.records}, fh, indent=1)
    print(f"\nreport: {out}")
    print(f"platform={sys.platform} python={sys.version.split()[0]}")
    return 0 if res.wasSuccessful() and not bad else 1
