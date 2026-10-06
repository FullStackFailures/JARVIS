# Testing strategy

Runner: `python -m tests.run` (stdlib unittest + tag report; pytest was not installable in the authoring
environment, the suite does not require it). `-v` for verbose.

Tags: UNIT, CONTRACT, INTEGRATION (real code paths), ACCEPTANCE (real agent pipeline), REGRESSION,
LINUX / WINDOWS (platform-gated; skipped with an explicit reason elsewhere; the runner FAILS on a skip without one), SECURITY, and labelled doubles:
FAKE_WINAPI (fake Win32 collaborators; proves ordering/validation logic only, never counted as Windows evidence),
FAKE_REASONER (scripted Reasoner; tests gateway logic only) and STUB_HTTP (real local HTTP server
speaking Ollama/OpenAI formats; tests real adapters, not real models).
No tool outputs are faked. Test-only tools (`test.*`) are real Tool subclasses used to drive the executor.

Coverage areas: policy table, audit chain/tamper/redaction, config precedence, manifest contracts,
parsers (pure), executor (malformed args, timeout, cancel, retries, refs, contract violation, policy denial,
audit fail-closed), OSAL (process/timeout/cancel/output bound, listing, desktop-entry fixture),
gateway, acceptance cases from the brief, CLI subprocess, architecture rules, regressions.

Each run writes `build/test-report-<platform>.json`; `python -m tests.compat_matrix` merges reports into
`docs/compat-matrix.md` (platform without a report = NOT RUN; MANUAL/HARDWARE columns stay empty).
Windows tests (`windows_only`) skip elsewhere and are listed with their reason.

Not covered: the real Windows pipe DACL/peer check (WindowsIpcHardening exists, never run), anything on Windows (written, NOT VERIFIED), real LLM output quality, GUI sessions, window verification,
real `systemctl`, interactive TTY approval prompt, Python 3.11, ruff/mypy/import-linter (not installable here).
CI (`.github/workflows/ci.yml`) defines the Ubuntu+Windows matrix, daemon smoke and matrix merge; **never executed**.
