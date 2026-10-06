# Tool contracts

Every tool is a `Tool` subclass with a `ToolManifest`; `ToolRegistry.validate_all()` rejects violations
(`--doctor` prints the count; unit tests enforce it).

Manifest fields: name (`ns.verb`), description, input_schema (object, `additionalProperties:false`),
output_schema (object), platforms, requires_capability, methods, risk (LOW/MEDIUM/HIGH),
permissions (from the known token set), side_effects, idempotent, timeout_ms, cancellable,
execution_modes, resources (lock keys), postcondition (mandatory), result_taint, examples.
Rules: non-cancellable tools may not exceed 120 s; unknown permission tokens are rejected.

Result: `ToolResult{ok, tool, step_id, platform, method_used, data, error{cls,message,retryable}, duration_ms,
verified, verification_note, taint, attempts}`. Failure classes: invalid_arguments, policy_denied,
unavailable, unknown_tool, not_found, permission, timeout, cancelled, command_failed, dependency_failed,
resource_busy, verification_failed, tool_error, contract_violation, internal.

Executor guarantees: arguments validated before policy; output validated against output_schema
(violation => contract_violation); retries only for retryable failures of idempotent tools
(`limits.mechanical_retries`, default 1); timeouts and cancellation kill the work.

Implemented tools (16; `python -m jarvis --tools` is authoritative):

| tool | risk | notes |
|---|---|---|
| system.hostname / info / memory / disk | LOW | psutil-backed via OSAL; disk path checked against scopes |
| system.service_status | LOW | state in running/stopped/failed/not_found/unknown; `unknown` => step fails honestly (tool_verified) |
| net.get_addresses | LOW | |
| net.port_owner | LOW | result states visibility full/partial; "no owner" is only claimed when visibility is full |
| process.list | LOW | |
| fs.list / fs.search | LOW | scope-checked, sensitive names skipped, bounded by depth/entries/time, cancel-aware |
| fs.read | LOW | **result taint = UNTRUSTED** |
| apps.discover / apps.status | LOW | |
| apps.open | MEDIUM | process-verified, window not checked |
| notes.write | LOW (sole write exception) | confined to the notes dir, create-exclusive, append opt-in, fsync + hash read-back |
| terminal.execute | MEDIUM | `argv` list only, never a shell; read-only allow-list auto-approved, everything else ASK or DENY |

Contract rule: LOW-risk tools may not declare write/egress/UI side effects except `notes.write`.
Capability lookup: `ToolRegistry.query(intent, platform, granted_perms, limit)` returns candidates only; policy decides.
