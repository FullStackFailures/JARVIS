# Security policy (deterministic; no LLM in the decision path)

Modes: RESTRICTED (read-only grants), NORMAL (adds apps.launch, proc.exec[_readonly], fs.write),
FULL_ACCESS (adds priv.elevate — but no broker exists in M1, so elevation is always DENIED).
The doctor shows whether the *process itself* is already elevated (e.g. running as root).

Decision = f(risk, mode, grants, taint): LOW => ALLOW; MEDIUM => ASK (ALLOW for `auto_allow_medium`,
default `apps.open`, when untainted; DENY in RESTRICTED); HIGH => DENY unless FULL_ACCESS, then ASK.
Tainted arguments (derived from untrusted tool output) never get auto-allow.

Terminal: argv only. Interpreters/destructive commands DENY; network egress HIGH; allowlisted read-only
commands with validated arguments resolve only from trusted system directories (never cwd/relative) => LOW;
exact built-in OSAL recipes LOW; unknown commands MEDIUM/ASK.
Filesystem: roots default to home, cwd, temp; sensitive paths (.ssh etc.) DENY; out-of-scope MEDIUM.

Approval: fail closed — DenyAll by default, Interactive only on a TTY, Static for tests.
Audit: every decision, approval, attempt and result; append-only + hash chain; verify with `--audit-verify`.
Secrets: redacted by key name, value pattern and registered values before storage; remote AI needs explicit
`allow_task_content`.

IPC: mutual HMAC handshake off the accept thread (deadline, pending cap, rate-limited audit); peer identity fail-closed
(Linux SO_PEERCRED; Windows PID->SID, NOT VERIFIED); Windows pipe/token/run-dir owner-only DACL (NOT VERIFIED). Residual: PID reuse window,
administrators/SYSTEM can still take ownership, audit chain has no external anchor.

Known gaps: command classification is an allowlist/denylist heuristic, not a sandbox; no OS-level
isolation; broker/elevation deferred; Windows policy paths and the Windows IPC hardening are untested on Windows.
