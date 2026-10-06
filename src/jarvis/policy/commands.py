"""Command classification data for terminal.execute. Pure data + pure functions.

Names are canonical lowercase stems (no directory, no .exe). Allow-listing is by exact
executable name resolved from trusted system directories AND a per-command argument
validator; everything else is unknown (needs approval) or categorically refused.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

# Interpreters/shells can run arbitrary code from their arguments: refused in Milestone 1.
INTERPRETERS = frozenset(
    "sh bash zsh fish dash ksh csh tcsh ash busybox cmd powershell pwsh wsl wscript cscript mshta "
    "python python2 python3 py perl ruby node nodejs deno bun php lua awk gawk sed env xargs "
    "eval exec nohup timeout nice time watch script screen tmux".split()
)

# Destructive, privilege-changing, persistence-creating or system-modifying commands.
DESTRUCTIVE = frozenset(
    "rm rmdir unlink shred del erase rd format dd wipefs fdisk sfdisk parted diskpart "
    "shutdown reboot poweroff halt init telinit kill killall pkill taskkill truncate mv move "
    "ren rename chmod chown chgrp chattr icacls takeown cacls sudo su doas runas pkexec passwd "
    "useradd userdel usermod groupadd groupdel net netsh reg regedit sc schtasks crontab at "
    "systemctl service rc-service launchctl mount umount swapon swapoff iptables ip6tables nft "
    "ufw firewall-cmd apt apt-get dpkg dnf yum rpm pacman zypper apk snap flatpak pip pip3 "
    "npm npx yarn gem cargo go winget choco scoop msiexec bcdedit sysctl modprobe insmod rmmod "
    "setenforce visudo ln link tee cp copy xcopy robocopy install patch "
    # PowerShell cmdlets/aliases that delete, modify, execute or reconfigure (command_stem lower-cases argv0)
    "remove-item ri move-item mi rename-item rni copy-item cpi set-content sc add-content ac clear-content "
    "clc out-file new-item ni set-item set-itemproperty sp remove-itemproperty new-itemproperty "
    "stop-process spps stop-service spsv start-service sasv restart-service set-service new-service "
    "remove-service restart-computer stop-computer invoke-expression iex invoke-command icm start-process saps "
    "set-executionpolicy format-volume clear-disk remove-partition set-acl new-localuser remove-localuser "
    "add-localgroupmember register-scheduledtask unregister-scheduledtask set-netfirewallrule "
    "new-netfirewallrule remove-netfirewallrule disable-netadapter enable-psremoting".split()
)

# Network egress / lateral movement / data exfiltration capable.
NETWORK_EGRESS = frozenset(
    "curl wget nc ncat netcat socat ssh scp sftp ftp tftp telnet rsync nmap masscan "
    "invoke-webrequest iwr invoke-restmethod irm start-bitstransfer certutil bitsadmin".split()
)

_IMMEDIATE_DENY_PREFIXES = ("mkfs",)


def command_stem(argv0: str) -> str:
    base = argv0.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".com", ".bat", ".cmd", ".ps1", ".sh", ".py"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


def category(argv0: str) -> str:
    """One of: interpreter | destructive | network | other."""
    s = command_stem(argv0)
    if s in INTERPRETERS or re.fullmatch(r"python[0-9.]*", s):
        return "interpreter"
    if s in DESTRUCTIVE or s.startswith(_IMMEDIATE_DENY_PREFIXES):
        return "destructive"
    if s in NETWORK_EGRESS:
        return "network"
    return "other"


# ------------------------------------------------------------------ read-only allow-list
ArgCheck = Callable[[Sequence[str]], bool]


def _flags_only(allowed: str) -> ArgCheck:
    def check(args: Sequence[str]) -> bool:
        for a in args:
            if not (a.startswith("-") and not a.startswith("--") and set(a[1:]) <= set(allowed)):
                return False
        return True

    return check


def _no_args(args: Sequence[str]) -> bool:
    return len(args) == 0


def _any_args_no_paths(allowed_long: frozenset[str], allowed_short: str) -> ArgCheck:
    def check(args: Sequence[str]) -> bool:
        for a in args:
            if a.startswith("--"):
                if a not in allowed_long:
                    return False
            elif a.startswith("-"):
                if not set(a[1:]) <= set(allowed_short):
                    return False
            else:
                return False
        return True

    return check


def _ip_check(args: Sequence[str]) -> bool:
    flags_ok = {"-j", "-json", "-br", "-brief", "-4", "-6", "-s", "-o", "-d", "-details"}
    rest = list(args)
    while rest and rest[0] in flags_ok:
        rest.pop(0)
    if not rest:
        return False
    obj = rest.pop(0)
    if obj not in {"addr", "address", "a", "link", "l", "route", "r", "neigh", "neighbor", "n"}:
        return False
    if not rest:
        return True
    if rest[0] in {"show", "list", "ls", "sh"}:
        return all(re.fullmatch(r"[A-Za-z0-9_.:\-]+", x) is not None for x in rest[1:]) and not any(
            x in {"flush", "add", "del", "delete", "set", "change", "replace", "exec"} for x in rest
        )
    return False


def _ss_check(args: Sequence[str]) -> bool:
    return _flags_only("tuaxlnpsHe46o")(args)


def _netstat_check(args: Sequence[str]) -> bool:
    return _flags_only("tuaxlnpsoeb4r6")(args)


def _uname_check(args: Sequence[str]) -> bool:
    return _flags_only("asnrvmpio")(args)


def _hostname_check(args: Sequence[str]) -> bool:
    # Bare ``hostname`` and display flags only: ``hostname NAME`` would CHANGE the hostname.
    return all(a in {"-I", "-i", "-f", "-s", "-d", "-A", "-a", "/?", "-fqdn", "--fqdn"} for a in args)


def _whoami_check(args: Sequence[str]) -> bool:
    return all(a in {"/all", "/groups", "/priv", "/user", "-a"} for a in args) if args else True


def _date_check(args: Sequence[str]) -> bool:
    # ``date MMDDhhmm`` sets the clock; only +FORMAT and a few display flags are allowed.
    return all(a.startswith("+") or a in {"-u", "-I", "--utc", "-R", "--iso-8601"} for a in args)


def _ipconfig_check(args: Sequence[str]) -> bool:
    return all(a.lower() in {"/all", "-all"} for a in args)


def _systeminfo_check(args: Sequence[str]) -> bool:
    return len(args) == 0


def _tasklist_check(args: Sequence[str]) -> bool:
    return all(a.lower() in {"/v", "/svc", "/fo", "table", "list", "csv"} for a in args)


def _getmac_check(args: Sequence[str]) -> bool:
    return all(a.lower() in {"/v", "/fo", "table", "list", "csv"} for a in args)


READONLY_COMMANDS: dict[str, ArgCheck] = {
    "hostname": _hostname_check,
    "whoami": _whoami_check,
    "uname": _uname_check,
    "uptime": _any_args_no_paths(frozenset({"--pretty", "--since"}), "ps"),
    "date": _date_check,
    "id": _flags_only("ugGnr"),
    "df": _any_args_no_paths(frozenset({"--human-readable", "--total"}), "hHTaikl"),
    "free": _any_args_no_paths(frozenset({"--human", "--si", "--total"}), "bkmgthwsl"),
    "ip": _ip_check,
    "ss": _ss_check,
    "pwd": _no_args,
    "ipconfig": _ipconfig_check,
    "systeminfo": _systeminfo_check,
    "netstat": _netstat_check,
    "tasklist": _tasklist_check,
    "getmac": _getmac_check,
}

# ``ls`` is read-only but takes paths, which are separately scope-checked by the policy.
PATH_TAKING_READONLY = frozenset({"ls", "dir"})


def ls_flags_ok(args: Sequence[str]) -> tuple[bool, list[str]]:
    """Return (flags_ok, positional_paths) for ls/dir."""
    paths: list[str] = []
    for a in args:
        if a.startswith("--"):
            if a not in {"--all", "--almost-all", "--human-readable", "--classify", "--color=never"}:
                return False, []
        elif a.startswith("-") and len(a) > 1:
            if not set(a[1:]) <= set("alAhFtrSR1"):
                return False, []
        elif a.startswith("/") and len(a) == 2 and a[1].isalpha() and a.lower() != "/c":
            continue  # Windows dir switches like /a /b
        else:
            paths.append(a)
    return True, paths


SHELL_METACHARS = re.compile(r"[;&|<>`$\n\r]|\$\(")


def looks_like_shell_pipeline(text: str) -> bool:
    return SHELL_METACHARS.search(text) is not None
