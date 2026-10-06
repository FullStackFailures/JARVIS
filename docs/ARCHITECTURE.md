# JARVIS Milestone 1 — Architecture (as built)

Baseline: JARVIS_ARCHITECTURE.md (accepted). This document describes what exists in 0.1.0.

## Layers (imports flow downward only; enforced by `tests/unit/test_architecture_rules.py`)
    cli
    core (agent, executor, planner, context, task_manager, runtime)
    brain  tools  policy  registry  models  security  config
    core.models (data models)
    osal (imports only common)      common

`sys.platform`/`os.name` checks live only in `osal/` (`osal/host.py` exposes `IS_WINDOWS`/`IS_POSIX`).

## Pipeline
submit -> control fast-path ("stop") -> route -> context packet -> plan -> validate ->
per step: resolve `${sN.data.x}` refs -> JSON-schema argument validation -> policy ->
approval (ASK) -> resource locks -> run in thread pool with timeout/cancel -> output-schema
check -> postcondition + tool verification -> ledger -> response composed from the ledger only.

Outcomes: VERIFIED, EXECUTED (NOT VERIFIED), PARTIAL, FAILED, CANCELLED, NEEDS INPUT, UNSUPPORTED, REPLY.
Success wording is produced only for VERIFIED steps.

## Native Brain
A deterministic control plane (router with goal templates, composer, recovery table), not an LLM.
`NativeLiteReasoner` refuses to generate text. Requests outside its templates go to a gateway
reasoner (Ollama / external) or yield UNSUPPORTED naming the backends tried. Deferred capabilities
(screenshot, browser automation...) yield UNSUPPORTED naming the milestone.

## Model gateway
Backends: native, ollama (REST via urllib, proxies bypassed), remote (OpenAI-compatible).
Three-level health (server / model / generation), cached. Retries only for retryable errors;
one schema-repair retry. `privacy_class=local_only` never reaches a non-local backend; the remote
backend additionally needs `allow_task_content`. `route()` never raises.

## Audit and secrets
SQLite append-only audit (UPDATE/DELETE triggers + SHA-256 chain; tampering detected by verify even
if triggers are dropped). Redaction occurs before hashing. The executor refuses to run a step if the
audit write fails. Secrets: env, .env, keyring; never logged.

## Daemon and IPC (M1)
`jarvisd` (foreground) owns the Runtime; `jarvis` is a thin client. Transport: stdlib `multiprocessing.connection`
(AF_UNIX on Linux) or our own `SecurePipeListener` (named pipe on Windows, owner-only DACL) with a mutual HMAC-SHA256
challenge-response (`ipc/handshake.py`) run on a per-connection admission thread (deadline, pending cap, shedding, rate-limited failure audit);
the peer user is checked first and fail-closed (`ipc.require_peer_identity`); frames are JSON (pydantic discriminated union,
size-capped, no pickle). Approvals are fail-closed, answerable only by the session that owns the task. A client disconnect
cancels that session's tasks. `jarvis --status` labels whether numbers come from the daemon or a local snapshot.
Known limits: the Windows hardening (DACL, first-instance, PID->SID) is implemented but NOT VERIFIED on Windows; PID-reuse window in the
peer check; administrators can still take ownership of the pipe/token; no external anchor for the audit chain.

## Deferred (not implemented, not faked)
First-run wizard, privileged broker (interface only; `priv.elevate` always denied), desktop/window control, browser
automation, screen/vision, voice, memory/RAG, scheduler/events beyond the in-process bus, coding/security/remote
integrations, GUI, native packaging (.exe / launcher; M3). Windows adapter and named-pipe IPC are written but have
**not been executed on Windows**.
