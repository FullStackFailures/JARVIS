# Windows verification procedure (M1)

**Status of every Windows item in this repository: NOT VERIFIED.** The adapter, named-pipe IPC and `windows_only`
tests were written without access to Windows. Nothing here may be reported as working on Windows until the evidence
below exists. Two ways to produce it: the `windows-latest` CI job (automatic), or the manual run below on a real
Windows 10/11 machine. CI proves "a clean GitHub runner"; the manual run is the only thing that proves real desktops
(Start-menu apps, sshd installed or not, non-admin vs admin).

## A. Automated (PowerShell, from the repo root, Python 3.11+)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m jarvis --version
python -m jarvis --doctor            # must name windows, shell, privilege (elevated or not), tools with contract violations: 0
python -m jarvis --self-test         # expect 0 failed; SKIP lines must each carry a reason
python -m tests.run                  # writes build\test-report-win32.json; expect 0 failures, windows_only tests EXECUTED
python -m tests.compat_matrix        # Windows column must now read PASS/FAIL, not NOT RUN
```
Pass criteria: `tests.run` exits 0 and `WindowsAdapter` / `WindowsPipeline` / `WindowsIpcHardening` classes show PASS (not SKIPPED) in the matrix.
If `WindowsIpcHardening.test_pipe_dacl_is_owner_only` fails, first decide whether the pipe or our read-back method (`GetNamedPipeInfo` by path) is wrong; do not skip it.

Note for virtual environments: `sys.executable` inside a venv is a launcher that starts the base interpreter as a child process, so the
PID of the process that connects to the pipe is a descendant of `Popen.pid`. Tests must compare against the PID the child reports itself.
Paths under a profile with a space (`C:\Users\Jane Doe`) are a supported case for `read the file <path>`.

## B. Daemon / IPC (two PowerShell windows)

```powershell
# window 1
python -m jarvis.daemon --home $env:TEMP\jh
# window 2
python -m jarvis --home $env:TEMP\jh daemon status      # RUNNING pid=...
python -m jarvis --home $env:TEMP\jh ask "get my local IP using the terminal"
python -m jarvis --home $env:TEMP\jh ask "run command: del C:\x"           # expect [FAILED] ... denied by policy
python -m jarvis --home $env:TEMP\jh ask "check whether SSH is running"    # a real state or an honest 'unknown' - never invented
python -m jarvis --home $env:TEMP\jh ask "run command: ping -n 30 127.0.0.1"   # answer y; then Ctrl-C -> expect [CANCELLED] and no ping.exe left (Get-Process ping)
python -m jarvis --home $env:TEMP\jh audit verify
python -m jarvis --home $env:TEMP\jh daemon stop
```

## C. Named-pipe and file-permission checks (H-1 hardening; record the output)

```powershell
Get-ChildItem \\.\pipe\ | Where-Object Name -like 'jarvisd-*'       # exists while daemon runs, gone afterwards
icacls "$env:TEMP\jh\run"                                           # record who has access to the token file
```
Expected after H-1: the pipe name contains your user SID (`whoami /user`), `icacls` on the run dir and token shows exactly one
access entry (your SID, no inheritance, no Everyone/Users/Authenticated Users), and a second `python -m jarvis.daemon` for the same
home refuses to start (first-instance). Also run from a second, different local user (`runas`): `jarvis daemon status` must NOT
reach the daemon (access denied on the pipe), and the daemon must not log the token.
STATUS: implemented, NOT VERIFIED. Residual risks that remain even when verified: PID-reuse window in the peer check;
administrators/SYSTEM can take ownership; do not claim parity with the Linux path until these steps are recorded.

## D. Manual observations to record in the compat matrix MANUAL column
1. `--doctor` as non-admin vs "Run as administrator": privilege line differs, no other crash.
2. `open my browser` with a Start-menu browser installed: process/window verified, honest message if only partial.
3. `service_state` for `sshd` when OpenSSH Server is (a) installed+running, (b) installed+stopped, (c) not installed.
4. Paths with spaces and non-ASCII usernames for `--home`.
5. Windows PowerShell 5.1 vs PowerShell 7 as the parent shell.

Send back: `build\test-report-win32.json`, the `--doctor` output, and the output of sections B and C.
