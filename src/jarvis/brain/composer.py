"""Compose user-facing responses strictly from the result ledger (never from intent).

The wording rule: success language is only produced for VERIFIED outcomes.
"""

from __future__ import annotations

from typing import Any

from jarvis.core.context import ContextPacket
from jarvis.core.models import Outcome, Step, StepState, StepStatus, Task, ToolResult

GIB = 1024**3


def _gib(n: int | float) -> str:
    return f"{n / GIB:.1f} GiB"


def _human_duration(seconds: float) -> str:
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    parts = [f"{d}d" if d else "", f"{h}h" if h else "", f"{m}m" if m or not (d or h) else ""]
    return " ".join(p for p in parts if p)


# ---------------------------------------------------------------------------- per-tool renderers
def _r_hostname(r: ToolResult) -> str:
    d = r.data
    extra = f" (FQDN {d['fqdn']})" if d.get("fqdn") and d["fqdn"] != d["hostname"] else ""
    return f"Hostname: {d['hostname']}{extra}"


def _r_ip(r: ToolResult) -> str:
    d = r.data
    primary = d.get("primary_ipv4")
    iface = next((a["interface"] for a in d.get("addresses", []) if a["address"] == primary), None)
    line = f"Local IP address: {primary}" + (f" (interface {iface})" if iface else "")
    others = [f"{a['address']} ({a['interface']})" for a in d.get("addresses", [])
              if a["family"] == "ipv4" and a["address"] != primary and not a["is_loopback"]]
    if others:
        line += "\nOther IPv4 addresses: " + ", ".join(others)
    return line


def _r_memory(r: ToolResult) -> str:
    d = r.data
    swap = f"; swap {_gib(d['swap_used'])} of {_gib(d['swap_total'])} used" if d.get("swap_total") else ""
    return (f"RAM: {_gib(d['total'])} total, {_gib(d['available'])} available "
            f"({d['percent']:.0f}% in use){swap}")


def _r_disk(r: ToolResult) -> str:
    d = r.data
    line = (f"Disk ({d['path']}): {_gib(d['used'])} used of {_gib(d['total'])} "
            f"({d['percent']:.0f}%), {_gib(d['free'])} free")
    for p in d.get("partitions", [])[:8]:
        line += f"\n  {p['path']}: {_gib(p['free'])} free of {_gib(p['total'])}"
    return line


def _r_info(r: ToolResult) -> str:
    d = r.data
    name = d.get("distro") or d["os"].capitalize()
    cpu = f"{d['cpu_logical']} logical cores" if d.get("cpu_logical") else "unknown core count"
    return (f"OS: {name} (kernel/release {d['os_release']}, {d['arch']}); CPU: {cpu}, "
            f"{d['cpu_percent']:.0f}% busy; uptime {_human_duration(d['uptime_s'])}")


def _r_list(r: ToolResult) -> str:
    d = r.data
    lines = [f"{d['total']} entr{'y' if d['total'] == 1 else 'ies'} in {d['path']}"
             + (" (list truncated)" if d["truncated"] else "")]
    for e in d["entries"][:40]:
        suffix = "/" if e["type"] == "dir" else ""
        size = f"  ({e['size']} B)" if e["type"] == "file" and e.get("size") is not None else ""
        lines.append(f"  {e['name']}{suffix}{size}")
    if len(d["entries"]) > 40:
        lines.append(f"  ... and {len(d['entries']) - 40} more shown in the data")
    return "\n".join(lines)


def _r_discover(r: ToolResult) -> str:
    d = r.data
    apps = d["apps"]
    if not apps:
        return "No matching applications were found." if d["total_installed"] else \
            "No applications were discovered on this system."
    lines = [f"{d['matched']} application(s)" + (f" matched (of {d['total_installed']} installed)"
             if d["matched"] != d["total_installed"] else " installed") + ":"]
    for a in apps[:25]:
        lines.append(f"  {a['name']}  [{a['kind']}]")
    if d["matched"] > 25:
        lines.append(f"  ... and {d['matched'] - 25} more")
    return "\n".join(lines)


def _r_open(r: ToolResult) -> str:
    d = r.data
    pid = f", pid {d['observed_pids'][0]}" if d.get("observed_pids") else ""
    return f"Opened {d['name']}{pid}. Verified by process check; window state was not checked."


def _r_terminal(r: ToolResult) -> str:
    d = r.data
    parsed = d.get("parsed") or {}
    if parsed.get("primary_ipv4"):
        iface = next((a["interface"] for a in parsed["addresses"]
                      if a["address"] == parsed["primary_ipv4"] and a["interface"] != "?"), None)
        others = [a["address"] for a in parsed["addresses"] if a["family"] == "ipv4"
                  and a["address"] != parsed["primary_ipv4"] and not a["is_loopback"]]
        line = f"Local IP address: {parsed['primary_ipv4']}" + (f" (interface {iface})" if iface else "")
        if others:
            line += "\nOther IPv4 addresses: " + ", ".join(others)
        return line + f"\n(from `{' '.join(d['argv'])}`, exit {d['exit_code']}, {d['duration_ms']} ms)"
    out = d["stdout"].strip()
    shown = out if len(out) <= 1500 else out[:1500] + "\n... (output shortened)"
    head = f"`{' '.join(d['argv'])}` exited {d['exit_code']} in {d['duration_ms']} ms on {d['platform']}"
    body = f":\n{shown}" if shown else " with no output"
    if d["stderr"].strip():
        body += f"\n[stderr] {d['stderr'].strip()[:500]}"
    return head + body


def _r_service(r: ToolResult) -> str:
    d = r.data
    label = d.get("resolved_name") or d["name"]
    line = f"Service {label}: {d['state'].upper()}"
    if d.get("enabled") is not None:
        line += f" ({'enabled' if d['enabled'] else 'disabled'} at boot)"
    if d.get("listening_ports"):
        line += "; listening on port(s) " + ", ".join(str(p) for p in d["listening_ports"])
    elif d["state"] == "running":
        line += "; listening ports not visible to me"
    if d.get("detail"):
        line += f"\n  ({d['detail']})"
    return line + f"\n  (source: {d['method']})"


def _r_port(r: ToolResult) -> str:
    d = r.data
    if not d["listeners"]:
        base = f"No process was found using port {d['port']}."
    else:
        rows = []
        for item in d["listeners"]:
            who = f"{item.get('process') or 'unknown process'} (pid {item['pid']})" if item.get("pid") else \
                "an owner I cannot see"
            rows.append(f"  {item['proto']} {item['address']}:{item['port']}  {item.get('status') or ''}  {who}")
        base = f"Port {d['port']} is in use:\n" + "\n".join(rows)
    if d["visibility"] == "partial":
        base += f"\n  (visibility partial: {d.get('note') or 'some owners are hidden without privilege'})"
    return base


def _r_processes(r: ToolResult) -> str:
    d = r.data
    lines = [f"{d['total']} process(es)" + (f"; showing {len(d['processes'])}" if d["truncated"] else "")]
    for p in d["processes"][:30]:
        mem = f"{p['memory_rss'] / 1024**2:.0f} MiB" if p.get("memory_rss") else "?"
        cpu = f"  cpu {p['cpu_percent']:.0f}%" if p.get("cpu_percent") is not None else ""
        lines.append(f"  {p['pid']:>7}  {p['name']}  {mem}{cpu}")
    return "\n".join(lines)


def _r_search(r: ToolResult) -> str:
    d = r.data
    if not d["hits"]:
        why = f" (search stopped: {d['stopped_reason']})" if d.get("stopped_reason") else ""
        return f"No matches under {d['root']}{why}; {d['examined']} entries examined."
    lines = [f"{len(d['hits'])} match(es) under {d['root']}" + (f" (search stopped: {d['stopped_reason']})"
                                                                 if d.get("stopped_reason") else "") + ":"]
    for h in d["hits"][:40]:
        lines.append(f"  {h['path']}{'/' if h['type'] == 'dir' else ''}")
    return "\n".join(lines)


def _r_read(r: ToolResult) -> str:
    d = r.data
    head = f"{d['path']} ({d['size']} B" + (f", first {d['bytes_read']} B shown" if d["truncated"] else "") + ")"
    return head + ":\n" + d["content"][:4000] + ("\n... (shortened)" if len(d["content"]) > 4000 else "")


def _r_note(r: ToolResult) -> str:
    d = r.data
    return f"{'Saved' if d['created'] else 'Appended to'} note {d['path']} ({d['bytes_written']} B); re-read and checked."


def _r_appstatus(r: ToolResult) -> str:
    d = r.data
    if d["ambiguous"]:
        return f"Several applications match {d['query']!r}: {', '.join(d['candidate_names'])}. Which one?"
    if not d["installed"] and not d["running"]:
        return f"{d['query']!r} is not in the application inventory and no process by that name is running."
    name = d.get("name") or d["query"]
    if d["running"] is None:
        return f"{name} is installed, but I cannot tell whether it is running (no process name to match)."
    return f"{name} is {'RUNNING (pid ' + ', '.join(map(str, d['pids'][:5])) + ')' if d['running'] else 'not running'}."


RENDERERS = {
    "system.hostname": _r_hostname, "net.get_addresses": _r_ip, "system.memory": _r_memory,
    "system.disk": _r_disk, "system.info": _r_info, "fs.list": _r_list,
    "system.service_status": _r_service, "net.port_owner": _r_port, "process.list": _r_processes,
    "fs.search": _r_search, "fs.read": _r_read, "notes.write": _r_note, "apps.status": _r_appstatus,
    "apps.discover": _r_discover, "apps.open": _r_open, "terminal.execute": _r_terminal,
}


# ---------------------------------------------------------------------------- failures
def _failure_line(step: Step, st: StepState) -> str:
    r = st.result
    label = step.description or step.tool
    if st.status == StepStatus.SKIPPED:
        return f"{label}: not attempted ({st.note or 'an earlier step did not succeed'})"
    if st.status == StepStatus.CANCELLED:
        return f"{label}: cancelled"
    if r is None or r.error is None:
        return f"{label}: failed ({st.note or 'unknown reason'})"
    if step.tool == "apps.discover" and r.ok:
        d = r.data
        if d.get("ambiguous"):
            return (f"Several installed applications match: {', '.join(d['candidate_names'])}. "
                    "Which one do you mean?")
        if step.arguments.get("kind") and not step.arguments.get("query"):
            kind = str(step.arguments["kind"]).replace("_", " ")
            return f"No {kind} was found on this system."
        return f"No installed application matches {step.arguments.get('query')!r}."
    return f"{label}: {r.error.message}"


def outcome_of(task: Task, cancelled: bool) -> Outcome:
    states = list(task.step_states.values())
    if cancelled:
        return Outcome.CANCELLED
    if not states:
        return Outcome.FAILED
    verified = [s for s in states if s.status == StepStatus.VERIFIED]
    executed = [s for s in states if s.status == StepStatus.EXECUTED]
    bad = [s for s in states if s.status in {StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED}]
    if bad:
        return Outcome.PARTIAL if (verified or executed) else Outcome.FAILED
    if executed:
        return Outcome.EXECUTED_UNVERIFIED
    return Outcome.VERIFIED


def render_task(task: Task, outcome: Outcome, unhandled: list[tuple[str, str]]) -> str:
    assert task.plan is not None
    lines: list[str] = []
    step_by_id = {s.id: s for s in task.plan.steps}
    good: list[str] = []
    bad: list[str] = []
    bad_items: list[tuple[str, StepStatus]] = []
    for step in task.plan.steps:
        st = task.step_states.get(step.id)
        if st is None:
            continue
        if st.status in {StepStatus.VERIFIED, StepStatus.EXECUTED} and st.result is not None:
            fn = RENDERERS.get(step.tool)
            text = fn(st.result) if fn else f"{step.tool} returned data"
            if st.status == StepStatus.EXECUTED:
                text += "  [not verified]"
            good.append(text)
        else:
            line = _failure_line(step_by_id[step.id], st)
            bad.append(line)
            bad_items.append((line, st.status))

    root_causes = [text for text, status in bad_items if status != StepStatus.SKIPPED]
    if root_causes:
        bad = root_causes  # consequences ("not attempted") add noise once the cause is shown

    if outcome == Outcome.CANCELLED:
        lines.append("Cancelled. No further actions will be taken for this request.")
        lines.extend(good)
        lines.extend(bad[:3])
    elif outcome == Outcome.FAILED:
        lines.append("I could not do that:")
        lines.extend(f"  {b}" for b in bad)
    elif outcome == Outcome.PARTIAL:
        lines.append("Partial result:")
        lines.extend(good)
        lines.extend(f"  Problem - {b}" for b in bad)
    elif outcome == Outcome.EXECUTED_UNVERIFIED:
        lines.append("Executed, but I could not verify the result:")
        lines.extend(good)
    else:
        lines.extend(good)
    for n in task.notes:
        lines.append(f"Note: {n}")
    for clause, why in unhandled:
        lines.append(f"Not handled: \"{clause}\" - {why}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------- conversation
def render_reply(kind: str, packet: ContextPacket, state: dict[str, Any]) -> str:
    env = packet.environment
    tools: list[str] = state.get("tools", [])
    if kind == "greeting":
        return (f"Hello. JARVIS is running on {env['os']} in {env['permission_mode']} mode. "
                "I can report system facts, list files, find and open applications, and run read-only "
                "terminal commands.")
    if kind == "identity":
        return ("I'm JARVIS, an AI computer assistant running on this machine. My built-in brain is a "
                "deterministic control plane (routing, planning templates, policy, verification). It "
                "handles known system, file, application and terminal requests; open-ended reasoning "
                "needs a configured Local AI or External API backend.")
    if kind == "how_are_you":
        return f"Running normally: {len(tools)} tools registered; " + "; ".join(state.get("backend_lines", []))
    if kind == "thanks":
        return "You're welcome."
    if kind == "capabilities":
        return ("Available tools: " + ", ".join(tools) + ". Not implemented yet: desktop control, browser "
                "automation, vision, voice, research, memory, scheduling, coding and remote systems.")
    if kind == "backend":
        return "\n".join(state.get("backend_lines", ["JARVIS Brain: ACTIVE"]))
    if kind == "last_task":
        t: Task | None = state.get("last_task")
        if t is None:
            return "I haven't run anything yet in this session."
        first = (t.final_response or "").splitlines()[0] if t.final_response else ""
        return f"My last task was \"{t.goal}\": {t.outcome.value if t.outcome else t.status.value}. {first}"
    if kind == "running":
        active: list[Task] = state.get("active", [])
        if not active:
            return "Nothing is running right now."
        return "Running now: " + "; ".join(f"\"{t.goal}\" ({t.status.value})" for t in active)
    return "I'm here."
