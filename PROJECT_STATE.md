# PROJECT_STATE (release-gate pass, 2026-10-05)

Read this first when resuming. Everything below was observed by executing code in the session environment, except lines marked NOT VERIFIED.

## Repository
`/home/claude/jarvis` (src layout `src/jarvis/`, Python >=3.11 declared, 3.13.15 used). Baseline spec: `/mnt/user-data/uploads/JARVIS_ARCHITECTURE.md`.
Run tests: `cd /home/claude/jarvis && PYTHONPATH=src python3 -m tests.run` (writes `build/test-report-linux.json`), then `python3 -m tests.compat_matrix`.

## Verified on Linux (Ubuntu 24.04 container, headless, root, no systemd)
- 241 tests: 223 pass, 18 skipped (all `windows_only`, each with an explicit reason), 0 fail. `--self-test`: 20 passed, 0 failed. `--doctor` OK (contract violations: 0).
- `jarvisd` + `jarvis ask` over AF_UNIX: hello, IP, denial, approval round-trip, `--yes` (ASK only), fail-closed without TTY, cross-client cancel (~30 ms), disconnect cancels tasks, bad token rejected, stale endpoint replaced, clean shutdown, 0600/0700 permissions, malformed/oversized frames survive.
- Audit chain intact, tamper detected (even with triggers dropped), multi-process append safe. Secret canary absent from audit and every file under the data dir.
- 16 tools; `registry.query`; executor fails closed on policy crash.

## Windows evidence received (reported by the user, 2026-10-05; no report artifact in this repo yet)
Real Windows 10, Python 3.13: install, `--doctor`, `--self-test`, daemon/IPC, terminal IP, destructive DENY, approval flow, timeout, cancellation
and audit verify worked manually. The full suite ran with 4 failures; all four were diagnosed and corrected in the next change (see CHANGELOG
"Windows full-suite findings"). **The corrected code has NOT been re-run on Windows**, so the Windows status remains NOT VERIFIED until it is.
Static checks run on Linux after the fixes: ruff clean, mypy clean (`mypy src`, Linux branches only). import-linter could not be installed (PyPI 403): not run.

## Windows results reported by the user after the fixes (not re-captured here)
Full suite 241 tests: 223 pass, 18 skipped, 0 fail/error; Windows `--self-test` 18 passed, 0 failed, 2 skipped; ruff clean; import-linter 3 contracts kept.
`mypy src` on Windows had 10 typing errors; fixed in the "mypy on Windows" CHANGELOG entry and checked here only with `mypy --platform win32` (emulation). **A real Windows `mypy src` re-run is still required.** CI is still NOT EXECUTED.

## NOT VERIFIED (do not claim otherwise)
- Anything on Windows (adapter, named pipe, services, app discovery, taskkill tree-kill, PowerShell recipes). 18 `windows_only` tests exist and have never run, including 6 `WindowsIpcHardening` tests that are the only evidence for H-1.
- H-1 Windows IPC hardening (owner-only pipe DACL, FIRST_PIPE_INSTANCE, PIPE_REJECT_REMOTE_CLIENTS, SID pipe name, peer PID->SID check, token/run-dir DACL): code complete; only the ordering/validation logic is tested (24 FAKE_WINAPI tests on Linux).
- CI file never executed. ruff, mypy, import-linter never run (PyPI blocked). Python 3.11 never run.
- Real `systemctl` path of `system.service_status` (only the pure parser ran; here SSH reports honest `unknown`).
- Interactive TTY approval prompt; real Ollama/API backends (stub servers only); `pip install` of console scripts `jarvis`/`jarvisd`.

## Known gaps (see IMPLEMENTATION_PLAN.md H-1..H-7)
Task section-27 fields absent; interactive TTY approval untested (H-3); end-to-end taint chain test absent; no native packaging (M3).

## Hardening completed in the release-gate pass
- H-2: own mutual HMAC handshake (`ipc/handshake.py`), per-connection admission thread, handshake deadline, pending cap with shedding, rate-limited failure audit, fail-closed peer identity (`ipc.require_peer_identity`), client authenticates the server (impostor rejected). Verified on Linux with a real daemon, including a mutation check.
- CI: `ci.yml` rewritten (static job + test matrix ubuntu/windows x py3.11/3.13 + smoke + artifacts + matrix). NEVER EXECUTED.
- Test harness: skip decorators carry explicit reasons; the runner fails on any skip without one.
- Windows-only tests re-checked: fixed wrong attribute names (`ShellInfo.name`, `PortOwnerResult.owners`) and a `whoami /priv` approval test that could never prompt (whoami is on the read-only allow-list).

## Defects found and fixed during the audit
1. Daemon/IPC did not exist (claimed milestone complete without it). 2. Audit seq collision between processes. 3. PowerShell destructive cmdlets were ASK. 4. Daemon shutdown raced audit close.

## EXACT NEXT ACTION
Do NOT start M2 yet. (0) Read the 'M1 release gate' section of IMPLEMENTATION_PLAN.md. (1) Push the repo to a CI runner and obtain a `windows-latest` run; fix the first-run findings; commit the regenerated `docs/compat-matrix.md` with a real Windows column. (2) Have a human execute `docs/WINDOWS_VERIFICATION.md` B-D. (3) Only then begin M2 as scoped in IMPLEMENTATION_PLAN.md. If no Windows access is possible, ask the user whether to proceed to M2 with Windows explicitly carried as NOT VERIFIED.
