# Changelog

## 0.1.0 - Milestone 1 (foundation)
- OSAL (`jarvis.osal`) with Linux and Windows adapters; capability inventory.
- Tool contract + registry; 16 tools (see docs/TOOL_CONTRACTS.md).
- Deterministic policy engine (RESTRICTED/NORMAL/FULL_ACCESS), approval providers (fail closed), hash-chained audit log, redaction.
- Model gateway (native / Ollama / OpenAI-compatible) with health levels, fallback, privacy gating.
- Native Brain control plane (router, templates, composer, recovery); executor with timeouts, cancellation, verification.
- CLI: --version --doctor --self-test --status --tools --tasks --logs --audit-verify.
- Tagged unittest suite (106 tests). Deferred: see docs/ARCHITECTURE.md "Deferred".

## 0.1.0 (M1 closure, 2026-10-04)
- Added jarvisd + IPC v1, `jarvis ask/daemon/audit`, `--yes` (ASK only), `jarvisd` script, `main.py`.
- Added tools: system.service_status, net.port_owner, process.list, fs.search, fs.read, apps.status, notes.write; renamed system.ip -> net.get_addresses, filesystem.* -> fs.*.
- Added ToolRegistry.query; executor fails closed on policy failure.
- FIX: audit chain head read inside BEGIN IMMEDIATE (multi-process collision found by daemon tests).
- FIX: PowerShell destructive cmdlets are DENY (were ASK).
- Added compat-matrix generator, .importlinter, Windows verification procedure, windows_only tests; removed empty stub packages.

## 0.1.0 (M1 release-gate hardening, 2026-10-05)
- IPC: own mutual HMAC handshake on a per-connection thread with deadline, caps and rate-limited failure audit; client authenticates the server; fail-closed peer identity.
- Windows (NOT VERIFIED): owner-only named-pipe DACL, first-instance, reject-remote, SID pipe name, peer PID->SID verification, token file + run dir DACL (`osal/windows/{pipe_policy,winsec,pipe}.py`).
- OSAL: `create_ipc_listener`, `restrict_to_current_user`; config `ipc.*`.
- Tests: 180 -> 237 (handshake 13, hardening 12, Windows logic 24 FAKE_WINAPI, skip guard 2, WindowsIpcHardening 6 windows-only); corrected Windows-only tests.
- CI rewritten (static + matrix + smoke + artifacts); pyproject ruff/mypy config revised; docs reconciled with reality.
- FIX: `--doctor` reported services.query as 'not implemented' although system.service_status exists; now DEGRADED with an honest reason.

## 0.1.0 (mypy on Windows, 2026-10-05)
`mypy src` on real Windows reported 10 errors (all typing, no runtime bug). Reproduced 8 on Linux with `mypy --platform win32 src`; the other 2 were fixed from the report.
- `osal/linux/adapter.py` (7: `geteuid`, `getpgid`, `SIGKILL`, `killpg`, `AF_UNIX`, `SO_PEERCRED`): typeshed declares these POSIX-only under `sys.platform != "win32"`, so a Windows-targeted check flags the Linux adapter. Fix: the three POSIX-only methods (`privilege_state`, `kill_process_tree`, `peer_is_current_user`) start with `if sys.platform == "win32": raise OsalUnavailable(...)`. mypy treats the rest of the body as unreachable for win32 and still fully checks it on Linux. No `type: ignore`, no exclusion; runtime behavior on Linux unchanged (sys.platform use stays inside osal/).
- `ipc/client.py` (1: `Client()` returns `Connection | PipeConnection` on Windows, annotated as `Connection`): the attribute is now typed with the structural `BytesConnection` protocol (send_bytes/recv_bytes/poll/close) defined in `ipc/handshake.py`.
- `config/schema.py` (1): `default_factory=lambda: ["native"]` is inferred as `list[str]`, not `list[Literal[...]]`. Fix: a typed `_default_fallback_order() -> list[BackendName]` and a `BackendName` alias.
- `cli/selftest.py` (1): `JarvisConfig(models={...dict...})` passed a dict to a model-typed field. Fix: pass `ModelsConfig(...)`.

## 0.1.0 (Windows full-suite findings, 2026-10-05)
Found by running the full suite on real Windows 10 / Python 3.13 (4 failures). Fixes are NOT yet re-run on Windows.
- **Product bug** `read the file C:\Users\Jane Doe\...\note.txt` was UNSUPPORTED: the read template matched a drive path only up to the first space (any Windows profile with a space broke `fs.read`). The template now matches drive paths lazily up to trailing punctuation. Regression tests `WindowsPathWithSpaceRouting`. Known remaining limitation: the list/search templates still stop a *unquoted* path at a space; quote the path ("...").
- **Test bug** `test_failure_text_never_claims_success` banned the substring "done", failing on the honest "I have not done anything." Replaced by `success_claims()`, which flags success words only when not negated in the same sentence (with its own detector tests). JARVIS's wording is unchanged.
- **Test assumption** `test_process_list_contains_own_pid`: the agent lists the top 15 processes by memory, so the test process is legitimately absent on a busy host. The test now asserts the truncation metadata is consistent and checks own-PID presence on the unbounded OSAL listing. Tool behavior unchanged.
- **Test assumption (H-1)** `test_peer_verification_with_a_real_child_process` compared the pipe's client PID with `Popen.pid`. Probable cause (to be confirmed by the re-run): inside a venv `python.exe` is a launcher that spawns the base interpreter, so the process holding the pipe is a *descendant* of `Popen.pid`. The test now has the child report `os.getpid()`, asserts equality with `GetNamedPipeClientProcessId`, and asserts the PID is in the spawned process tree. `client_pid`/`verify_peer` are unchanged; no verification was weakened.
- Lint/type: ruff and mypy are now clean on Linux (fixed 11 ruff and 28 mypy findings: unused variables, `datetime.UTC`, a `TimeoutError` alias, a variable redefinition in `pipe.py`, annotations in `winsec.py`, `applications.py`, `runtime.py`, `commands.py`, `recovery.py`).
