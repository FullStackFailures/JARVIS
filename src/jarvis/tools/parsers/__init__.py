"""Structured parsers for command output (pure functions; unit-testable on any OS)."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from typing import Any

Parser = Callable[[list[str], str], dict[str, Any]]


def _addr(interface: str, address: str, family: str | None = None) -> dict[str, Any] | None:
    raw = address.split("%", 1)[0].split("/", 1)[0].strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    return {
        "interface": interface,
        "family": family or ("ipv4" if ip.version == 4 else "ipv6"),
        "address": raw,
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
    }


def _stem(argv0: str) -> str:
    base = argv0.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def parse_ip_json(stdout: str) -> list[dict[str, Any]]:
    """Linux ``ip -j addr``."""
    data = json.loads(stdout)
    out: list[dict[str, Any]] = []
    for link in data:
        for ai in link.get("addr_info", []):
            fam = {"inet": "ipv4", "inet6": "ipv6"}.get(ai.get("family", ""))
            if not fam:
                continue
            rec = _addr(link.get("ifname", "?"), ai.get("local", ""), fam)
            if rec:
                out.append(rec)
    return out


def parse_hostname_dash_i(stdout: str) -> list[dict[str, Any]]:
    """Linux ``hostname -I`` (space-separated addresses, no interface names)."""
    out = []
    for tok in stdout.split():
        rec = _addr("?", tok)
        if rec:
            out.append(rec)
    return out


def parse_powershell_ip_json(stdout: str) -> list[dict[str, Any]]:
    """Windows ``Get-NetIPAddress | Select InterfaceAlias,IPAddress,AddressFamily | ConvertTo-Json``."""
    data = json.loads(stdout)
    if isinstance(data, dict):
        data = [data]
    out = []
    for item in data:
        rec = _addr(str(item.get("InterfaceAlias", "?")), str(item.get("IPAddress", "")))
        if rec:
            out.append(rec)
    return out


_IPCONFIG_SKIP = re.compile(
    r"mask|gateway|subnet|dns|dhcp|lease|server|masque|passerelle|m[aá]scara|puerta", re.IGNORECASE
)
_IPCONFIG_ADAPTER = re.compile(r"^(?P<name>\S.*?):\s*$")
_IPCONFIG_LINE = re.compile(r"^\s+(?P<label>[^:]+?)[ .]*:\s*(?P<value>\S+)\s*$")


def parse_ipconfig(stdout: str) -> list[dict[str, Any]]:
    """Windows ``ipconfig``. Best-effort and English-label-biased; prefer the JSON recipe."""
    out = []
    adapter = "?"
    for line in stdout.splitlines():
        m = _IPCONFIG_ADAPTER.match(line)
        if m and not line.startswith(" "):
            adapter = m.group("name").replace("adapter ", "").strip()
            continue
        m = _IPCONFIG_LINE.match(line)
        if not m or _IPCONFIG_SKIP.search(m.group("label")):
            continue
        value = re.sub(r"\(.*?\)", "", m.group("value"))
        rec = _addr(adapter, value)
        if rec:
            out.append(rec)
    return out


def parse_net_addresses(argv: list[str], stdout: str) -> dict[str, Any]:
    exe = _stem(argv[0]) if argv else ""
    try:
        if exe == "ip":
            addrs = parse_ip_json(stdout)
        elif exe == "hostname":
            addrs = parse_hostname_dash_i(stdout)
        elif exe in {"powershell", "pwsh"}:
            addrs = parse_powershell_ip_json(stdout)
        elif exe == "ipconfig":
            addrs = parse_ipconfig(stdout)
        else:
            return {"addresses": [], "parse_error": f"no net.addresses parser for {exe!r}"}
    except (json.JSONDecodeError, TypeError, AttributeError, KeyError) as exc:
        return {"addresses": [], "parse_error": f"{type(exc).__name__}: {exc}"}
    primary = next(
        (a["address"] for a in addrs
         if a["family"] == "ipv4" and not a["is_loopback"] and not a["is_link_local"]),
        None,
    )
    return {"addresses": addrs, "primary_ipv4": primary}


PARSERS: dict[str, Parser] = {"net.addresses": parse_net_addresses}
