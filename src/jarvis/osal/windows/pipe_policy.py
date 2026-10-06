"""Pure (no ctypes, no Windows calls) helpers for the Windows IPC hardening.

Importable and unit-tested on every OS. These functions only build/validate strings; they do NOT prove that
Windows enforces the resulting descriptors - that needs the windows_only tests running on Windows/CI.
"""

from __future__ import annotations

import re

_SID_RE = re.compile(r"^S-1-[0-9]+(-[0-9]+){1,15}$")
_DISC_RE = re.compile(r"[^A-Za-z0-9]")


class InvalidSid(ValueError):
    pass


def validate_sid(sid: str) -> str:
    """Return ``sid`` unchanged if it is a well-formed SID string, else raise.

    The SID is interpolated into SDDL and into a pipe name, so anything outside ``S-1-<n>(-<n>)+`` must be
    refused (SDDL injection / path tricks)."""
    if not isinstance(sid, str) or not _SID_RE.fullmatch(sid):
        raise InvalidSid(f"not a valid SID string: {sid!r}")
    return sid


def pipe_address(sid: str, discriminator: str = "") -> str:
    """``\\\\.\\pipe\\jarvisd-<SID>[-<disc>]`` - one pipe per user, named by SID (not by the spoofable user name)."""
    validate_sid(sid)
    disc = _DISC_RE.sub("", discriminator)[:16]
    return rf"\\.\pipe\jarvisd-{sid}" + (f"-{disc}" if disc else "")


def owner_only_pipe_sddl(sid: str) -> str:
    """Protected DACL granting GENERIC_ALL to exactly one SID. No inheritance, no Everyone/Anonymous/Network ACE.
    (SYSTEM and Administrators are deliberately NOT listed: they can still take ownership; this is not a
    defence against a compromised administrator.)"""
    return f"D:P(A;;GA;;;{validate_sid(sid)})"


def owner_only_file_sddl(sid: str, *, directory: bool) -> str:
    """Protected DACL granting FILE_ALL_ACCESS to one SID; for directories children inherit it (OICI)."""
    flags = "OICI" if directory else ""
    return f"D:P(A;{flags};FA;;;{validate_sid(sid)})"


def dacl_grants_only(sddl: str, sid: str) -> bool:
    """True iff the SDDL string is a protected DACL whose only ACE is an Allow for ``sid``.

    Used to check descriptors read back from Windows. Accepts the textual form Windows returns
    (which may spell the flags differently, e.g. ``D:PAI``)."""
    validate_sid(sid)
    m = re.fullmatch(r"(?:O:[^G D]*)?(?:G:[^D]*)?D:(?P<flags>[A-Z]*)(?P<aces>(\([^)]*\))+)(?:S:.*)?", sddl.strip())
    if not m or "P" not in m.group("flags"):
        return False
    aces = re.findall(r"\(([^)]*)\)", m.group("aces"))
    if len(aces) != 1:
        return False
    parts = aces[0].split(";")
    return len(parts) >= 6 and parts[0] == "A" and parts[5] == sid
