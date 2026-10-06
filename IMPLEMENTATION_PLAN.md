# Implementation plan

Source of truth for scope: `JARVIS_ARCHITECTURE.md` section 31. Status as of 2026-10-05 (M1 release-gate pass).

Status words: DONE+VERIFIED(platform) / DONE+NOT VERIFIED / PARTIAL / NOT STARTED. Nothing is inferred across platforms.

| Milestone | What the architecture says | Reality in the repository | Status |
|---|---|---|---|
| M1 kernel vertical slice | contracts, registry, OSAL, policy, audit, executor, native-lite brain, daemon + CLI | All present. Linux: 237 tests, 219 pass, 18 Windows-only skipped, 0 fail. Windows and CI: **NOT VERIFIED** | **Linux: DONE+VERIFIED. Windows: DONE+NOT VERIFIED. Not closed cross-platform.** |
| M2 gateway + Ollama + API + wizard + secrets | model gateway, real backends, first-run wizard | Gateway + Ollama + OpenAI-compatible adapters exist, stub-tested only. **Missing:** wizard, secret storage UX, real-Ollama kill/restore scenario | PARTIAL (adapters pre-built; wizard NOT STARTED) |
| M3 packaging + daemon lifecycle | Windows exe + installer, Linux launcher + systemd user unit | Console scripts `jarvis`/`jarvisd` and `main.py` only | NOT STARTED |
| M4 planner | planner, plan validation, DAG execution | **Exists in M1:** deterministic template planner (+ optional reasoner-backed planner), plan validation, DAG execution with parallel steps and resource locks. **Missing:** model-driven re-planning loop, chained plans (fs.read -> action) | PARTIAL (deterministic planner DONE+VERIFIED Linux; model-driven planning NOT STARTED) |
| M5 verification + recovery | postconditions, retry, recovery | **Exists in M1:** mandatory tool postconditions, REQUESTED/EXECUTED/VERIFIED/FAILED distinction, mechanical retry, `RecoveryEngine` strategy table (alternate browser/command recipes). **Missing:** model-driven diagnosis, diagnostic playbooks ("why is my network down") | PARTIAL (DONE+VERIFIED Linux for the table-driven part) |
| M6 cancellation + tasks | cancel tokens, task manager | **Exists in M1:** cancel tokens, process-tree kill, cross-client cancel over IPC, disconnect-cancels, task history. **Missing:** task priority/budget/taint_set fields (D-14), pause/resume | PARTIAL (core DONE+VERIFIED Linux; Windows tree-kill NOT VERIFIED) |
| M7.. | desktop control, browser, vision, voice, memory/RAG, scheduler/events, coding agent, DeepSec, remote, UI, privilege broker | Not started. Placeholder packages were deleted (D-15) | NOT STARTED |

## M1 release gate (what still blocks calling M1 cross-platform closed)
1. A green `windows-latest` run of `.github/workflows/ci.yml` (never executed; ruff, mypy, import-linter have never run anywhere).
2. The new `WindowsIpcHardening` tests passing on Windows: they are the only evidence for H-1 (pipe DACL, first-instance, peer PID/SID, token ACL).
3. Download the Windows report, run `python -m tests.compat_matrix`, commit the regenerated `docs/compat-matrix.md`.
4. A human executes `docs/WINDOWS_VERIFICATION.md` sections B-E and records MANUAL cells.
5. A Python 3.11 run of the suite (only compile-level checks were possible here).

## Hardening backlog
- H-1 Windows owner-only DACL, peer PID/SID check, SID pipe name: **IMPLEMENTED, NOT VERIFIED** (logic tested with FAKE_WINAPI doubles on Linux).
- H-2 Handshake off the accept thread with timeout: **DONE+VERIFIED on Linux** (real daemon tests + mutation check). Windows reuses the same code path; NOT VERIFIED there.
- H-3 pty-based test of the interactive `Allow? [y/N]` path: OPEN.
- H-4 Real-systemd test for `system.service_status`: OPEN.
- H-5 Python 3.11 run: OPEN (compile-level only).
- H-6 End-to-end taint chain test: OPEN (needs a chaining planner).
- H-7 Task section-27 fields with their enforcing component (D-14): OPEN.

## Recommended next milestone
**Do not start M2 until the release gate above has Windows evidence.** If CI/Windows access is available: push, fix first-run findings, then M2 as scoped
(`jarvis setup` wizard, keyring-first secret storage, `jarvis models test`, Ollama health tiers with kill/restore, external API consent routing, keys-never-in-logs canary).
If the user decides to proceed without Windows evidence, M2 starts with Windows explicitly carried as NOT VERIFIED. M3 (packaging) does not depend on M2 and may be pulled forward.
