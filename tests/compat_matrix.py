"""Generate docs/compat-matrix.md from per-OS test reports (build/test-report-*.json).

Cells are derived ONLY from recorded test outcomes. A platform with no report is "NOT RUN", never inferred.
MANUAL and HARDWARE columns are deliberately empty: nothing writes them except a human with evidence.

    python -m tests.run                      # writes build/test-report-<platform>.json
    python -m tests.compat_matrix            # merges every build/test-report-*.json
"""

from __future__ import annotations

import glob
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# test class -> feature. Unmapped classes land under "(unmapped)" so gaps are visible, not hidden.
FEATURES = {
    "Basic": "Request pipeline (route/plan/policy/execute/verify/compose)",
    "Scenarios": "Required M1 scenarios (IP, disk, ports, services, processes, apps, denial, cancel, honesty)",
    "Cancellation": "Cancellation of running commands",
    "AppLaunchWithFixture": "Application launch + verification",
    "ModelBackendUnavailable": "Model backend failure handling",
    "GatewayLogic": "Model gateway (fake reasoner, labelled)",
    "AdaptersAgainstStubServer": "Ollama/remote adapters (stub HTTP, labelled)",
    "ExecutorTests": "Executor (validate/policy/approval/retry/verify)",
    "AuditFailClosed": "Audit fail-closed",
    "ExecutorFailClosed": "Executor fail-closed on policy failure",
    "PolicyTable": "Policy table",
    "PolicyRows": "Policy rows (destructive, taint, full access)",
    "AuditTests": "Audit hash chain",
    "AuditAndLogs": "Audit tamper detection + secret redaction in files",
    "AuditMultiWriter": "Audit multi-process writers",
    "RedactionTests": "Secret redaction",
    "LogCanary": "Secret redaction in log files",
    "ConfigTests": "Configuration",
    "CancelTokenTests": "Cancel token",
    "ManifestContractTests": "Tool manifest contracts",
    "RegistryQuery": "Registry capability query",
    "Layering": "Architecture/platform-isolation rules (AST)",
    "NetParsers": "Network parsers (pure; not adapter validation)",
    "DesktopParsers": "Desktop parsers (pure; not adapter validation)",
    "SystemdParsing": "systemd parser (pure; not adapter validation)",
    "NotesTool": "notes.write",
    "CrossPlatformOsal": "OSAL contract (real host)",
    "LinuxAdapter": "Linux adapter specifics",
    "Cli": "CLI (in-process runtime)",
    "CliSubprocess": "CLI -> jarvisd (subprocess)",
    "DaemonIpc": "jarvisd IPC (auth, approvals, cancel, framing)",
    "DaemonLifecycle": "jarvisd lifecycle (stale endpoint, cleanup, permissions)",
    "Handshake": "IPC mutual HMAC handshake (protocol logic)",
    "HandshakeDoesNotBlockAccept": "IPC handshake off the accept thread (real daemon)",
    "PeerIdentityPolicy": "IPC peer-identity policy (fail-closed)",
    "ImpostorServer": "IPC client rejects impostor server (mutual auth)",
    "PolicyStrings": "Windows IPC: SID/SDDL/pipe-name construction (pure, FAKE_WINAPI-adjacent)",
    "ListenerLogic": "Windows secure pipe listener logic (FAKE_WINAPI)",
    "PeerVerification": "Windows peer SID check logic (FAKE_WINAPI)",
    "AdapterWiring": "Windows adapter IPC wiring (FAKE_WINAPI)",
    "TokenFileOrdering": "Token file: restrict-before-write ordering (FAKE_WINAPI)",
    "SkipDecorators": "Test harness: explicit skip reasons",
    "WindowsAdapter": "Windows adapter specifics (real Windows only)",
    "WindowsPipeline": "Windows pipeline (real Windows only)",
    "WindowsIpcHardening": "Windows IPC hardening H-1 (real pipe DACL, first-instance, peer PID/SID, token ACL)",
    "SuccessClaimDetector": "Honesty: false-success-claim detector (test helper)",
    "WindowsPathWithSpaceRouting": "Routing: fs.read with Windows drive paths containing spaces",
    "Regressions": "Regressions",
}
PLATFORMS = [("linux", "Linux"), ("win32", "Windows")]


def load_reports(paths: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            rep = json.load(fh)
        out[rep["platform"]] = rep
    return out


def cell(tests: list[dict], report: dict | None) -> str:
    if report is None:
        return "NOT RUN"
    if not tests:
        return "no tests"
    c = defaultdict(int)
    for t in tests:
        c[t["outcome"]] += 1
    if c["fail"] or c["error"]:
        return f"FAIL ({c['pass']} pass, {c['fail'] + c['error']} fail)"
    if c["pass"] == 0:
        return f"SKIPPED ({c['skip']})"
    return f"PASS ({c['pass']})" + (f" +{c['skip']} skipped" if c["skip"] else "")


def render(reports: dict[str, dict]) -> str:
    rows: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for plat, rep in reports.items():
        for t in rep["tests"]:
            rows[FEATURES.get(t["class"], f"(unmapped) {t['class']}")][plat].append(t)
    lines = [
        "# Compatibility matrix (generated)",
        "",
        "Generated by `python -m tests.compat_matrix` from `build/test-report-*.json`. Do not edit by hand.",
        "A platform with no report is **NOT RUN** - it is never inferred from another platform. "
        "PASS means automated tests passed on that OS *in that report's environment*; it is not a statement about other "
        "distributions, desktop environments, or hardware. MANUAL / HARDWARE columns are filled only by a human with evidence.",
        "",
        "## Reports merged",
        "",
    ]
    for key, label in PLATFORMS:
        rep = reports.get(key)
        lines.append(f"- {label}: " + (f"`{rep['os']}`, Python {rep['python']}, generated {rep['generated']}, "
                                       f"{'CI' if rep['ci'] else 'local run'}, {len(rep['tests'])} tests" if rep
                                       else "**NOT RUN** (no report present)"))
    lines += ["", "## Feature x platform", "",
              "| Feature | Linux (automated) | Windows (automated) | MANUAL | HARDWARE |",
              "|---|---|---|---|---|"]
    for feat in sorted(rows):
        per = rows[feat]
        lines.append(f"| {feat} | {cell(per.get('linux', []), reports.get('linux'))} | "
                     f"{cell(per.get('win32', []), reports.get('win32'))} |  |  |")
    skips = [(p, t) for p, r in reports.items() for t in r["tests"] if t["outcome"] == "skip"]
    lines += ["", "## Skipped tests (with reasons)", ""]
    if skips:
        for p, t in sorted(skips, key=lambda x: (x[0], x[1]["id"])):
            lines.append(f"- `{p}` `{t['id']}` - {t['reason']}")
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    paths = (argv if argv is not None else sys.argv[1:]) or sorted(glob.glob(os.path.join(ROOT, "build", "test-report-*.json")))
    if not paths:
        print("no reports found; run `python -m tests.run` first", file=sys.stderr)
        return 1
    text = render(load_reports(paths))
    out = os.path.join(ROOT, "docs", "compat-matrix.md")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
