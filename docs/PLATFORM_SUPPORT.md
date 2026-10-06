# Platform support (0.1.0)

IMPL = code exists. TESTED = executed by the suite **on that OS** (see generated `compat-matrix.md`). "pure" = a parser
executed on Linux; that validates parsing only, never the adapter.

| Capability | Linux IMPL | Linux TESTED | Windows IMPL | Windows TESTED |
|---|---|---|---|---|
| hostname/memory/disk/info | yes | yes | yes (psutil) | **NOT VERIFIED** |
| net.get_addresses | yes | yes | yes | NOT VERIFIED |
| net.port_owner | yes (psutil; partial visibility reported when unprivileged) | yes (real listener) | yes | NOT VERIFIED |
| process.list | yes | yes (own PID) | yes | NOT VERIFIED |
| system.service_status | systemd `show` parser + process-scan + honest `unknown` | process-scan/`unknown` path yes; **real systemctl NOT VERIFIED** (no systemd in container) | psutil service API | NOT VERIFIED |
| terminal.execute (argv, timeout, cancel, tree-kill) | yes (process group) | yes | yes (`taskkill /T`) | NOT VERIFIED |
| IP via terminal recipes | `ip -j`, `hostname -I` | yes (`hostname -I`; `ip` absent in container) | PowerShell JSON, `ipconfig` | parsers pure only |
| apps.discover / apps.status | .desktop (XDG, flatpak, snap), PATH | yes (fixture + real) | registry App Paths, Get-StartApps | parser pure only |
| apps.open + process verification | yes | yes (fixture, `sleep`) | yes | NOT VERIFIED |
| fs.list / fs.read / fs.search / notes.write | yes | yes | yes | NOT VERIFIED |
| IPC transport | AF_UNIX 0600 in 0700 dir, SO_PEERCRED, mutual HMAC handshake | yes | named pipe `\\.\pipe\jarvisd-<SID>`: owner-only DACL, first-instance, reject-remote, PID->SID peer check, token ACL, same handshake | logic only (FAKE_WINAPI on Linux); **real behaviour NOT VERIFIED** |
| desktop/window/clipboard/screen/audio | unavailable (deferred) | inventory reports it | unavailable | inventory reports it |
| privilege broker | interface only | - | interface only | - |

Environment of record: Ubuntu 24.04, Python 3.13, headless, root. Other distros, systemd hosts, Wayland/X11 sessions and
Python 3.11 are **UNTESTED**. Windows: procedure in `WINDOWS_VERIFICATION.md`; CI file written, **never executed**.
