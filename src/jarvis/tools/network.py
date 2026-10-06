"""net.* tools: local addresses and port ownership."""

from __future__ import annotations

from typing import Any

from jarvis.core.models import Postcondition
from jarvis.osal.types import OsalError, dump
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.base import Tool, ToolContext, ToolOutput, failure_from_osal

_NS = {"type": ["string", "null"]}


class NetGetAddresses(Tool):
    manifest = build_manifest(
        "net.get_addresses",
        "Local network addresses per interface plus the primary outbound IPv4 address.",
        obj({}),
        obj(
            {
                "addresses": {"type": "array", "items": {"type": "object"}},
                "primary_ipv4": _NS,
                "interface_count": {"type": "integer"},
            },
            ["addresses", "primary_ipv4"],
        ),
        permissions=["net.read"],
        methods=["psutil+routing-table"],
        postcondition=Postcondition(
            kind="truthy", path="data.primary_ipv4", description="a non-loopback IPv4 address exists"
        ),
        tags=["network", "ip", "address", "net"],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        try:
            addrs = ctx.osal.network_addresses()
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        return ToolOutput(
            {
                "addresses": [dump(a) for a in addrs],
                "primary_ipv4": ctx.osal.primary_ipv4(addrs),
                "interface_count": len({a.interface for a in addrs}),
            },
            method="psutil+routing-table",
        )


class NetPortOwner(Tool):
    manifest = build_manifest(
        "net.port_owner",
        "Find which process holds a TCP listening port or UDP port. Reports visibility=partial when the "
        "OS hides other users' sockets instead of claiming the port is free.",
        obj(
            {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "proto": {"enum": ["tcp", "udp"]},
            },
            ["port"],
        ),
        obj(
            {
                "port": {"type": "integer"},
                "listeners": {"type": "array", "items": {"type": "object"}},
                "visibility": {"enum": ["full", "partial"]},
                "note": _NS,
            },
            ["port", "listeners", "visibility"],
        ),
        permissions=["net.read", "proc.read"],
        methods=["psutil.net_connections"],
        postcondition=Postcondition(kind="field_present", path="data.listeners",
                                    description="the connection table was queried"),
        tags=["network", "port", "process", "listening"],
        examples=[{"port": 8080}],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        try:
            res = ctx.osal.port_owner(int(args["port"]), str(args.get("proto", "tcp")))
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        return ToolOutput(dump(res), method="psutil.net_connections")


TOOLS = [NetGetAddresses, NetPortOwner]
