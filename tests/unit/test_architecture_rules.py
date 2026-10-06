"""Static architecture rules (enforced, not just documented)."""

import ast
import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "jarvis"
LAYERS = {  # package -> packages it may NOT import
    "common": {"osal", "core", "tools", "policy", "registry", "models", "brain", "cli", "security", "config"},
    "osal": {"core", "tools", "policy", "registry", "models", "brain", "cli", "security", "config"},
    "tools": {"brain", "models", "cli", "daemon", "ipc"},   # tools never reason or talk to clients
    "policy": {"models", "brain"},                          # model output can never reach into the policy engine
    "registry": {"brain", "models", "cli", "daemon", "ipc"},
}


def imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module


class Layering(unittest.TestCase):
    def test_leaf_packages_do_not_import_upward(self):
        bad = []
        for pkg, forbidden in LAYERS.items():
            for f in (SRC / pkg).rglob("*.py"):
                for mod in imports(f):
                    parts = mod.split(".")
                    if parts[0] == "jarvis" and len(parts) > 1 and parts[1] in forbidden:
                        bad.append(f"{f.relative_to(SRC)} imports {mod}")
        self.assertEqual(bad, [])

    def test_providers_only_imported_inside_models_or_runtime(self):
        bad = []
        for f in SRC.rglob("*.py"):
            rel = f.relative_to(SRC).parts
            if rel[0] in {"models", "cli"} or rel[:2] == ("core", "runtime.py"):
                continue
            for mod in imports(f):
                if mod.startswith(("jarvis.models.ollama", "jarvis.models.remote")):
                    bad.append(f"{f.relative_to(SRC)} imports {mod}")
        self.assertEqual(bad, [])

    def test_platform_checks_only_in_osal(self):
        pat = re.compile(r"sys\.platform|platform\.system\(|os\.name\b")
        bad = [str(f.relative_to(SRC)) for f in SRC.rglob("*.py")
               if f.relative_to(SRC).parts[0] != "osal" and pat.search(f.read_text(encoding="utf-8"))]
        self.assertEqual(bad, [])

    def test_no_shell_true_anywhere(self):
        bad = [str(f.relative_to(SRC)) for f in SRC.rglob("*.py")
               if re.search(r"shell\s*=\s*True", f.read_text(encoding="utf-8"))]
        self.assertEqual(bad, [])

    def test_no_directory_named_platform(self):
        self.assertFalse((SRC / "platform").exists())


if __name__ == "__main__":
    unittest.main()
