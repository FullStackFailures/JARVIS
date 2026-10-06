"""Pure parsers for freedesktop.org data (desktop entries, mimeapps.list).

No OS calls happen here, so these are unit-testable on any platform.
"""

from __future__ import annotations

import configparser
import re
import shlex

_FIELD_CODE = re.compile(r"%[fFuUdDnNickvm]")


def parse_desktop_entry(text: str) -> dict[str, str] | None:
    """Return the [Desktop Entry] group as a dict, or None if absent/invalid."""
    parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    parser.optionxform = str  # type: ignore[assignment,method-assign]  # keys are case-sensitive
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    if not parser.has_section("Desktop Entry"):
        return None
    return dict(parser.items("Desktop Entry"))


def exec_to_argv(exec_value: str) -> list[str] | None:
    """Convert a desktop-entry Exec= value to argv, dropping field codes.

    A token containing a field code is dropped entirely (we never pass files/URLs
    implicitly). Returns None when the value cannot be parsed.
    """
    try:
        tokens = shlex.split(exec_value, posix=True)
    except ValueError:
        return None
    argv: list[str] = []
    for tok in tokens:
        if "%%" in tok:
            tok = tok.replace("%%", "%")
            argv.append(tok)
            continue
        if _FIELD_CODE.search(tok):
            continue
        argv.append(tok)
    return argv or None


def parse_mimeapps(text: str) -> dict[str, list[str]]:
    """Return {mime: [desktop ids]} from the [Default Applications] group."""
    parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read_string(text)
    except configparser.Error:
        return {}
    if not parser.has_section("Default Applications"):
        return {}
    out: dict[str, list[str]] = {}
    for mime, value in parser.items("Default Applications"):
        ids = [v.strip() for v in value.split(";") if v.strip()]
        if ids:
            out[mime] = ids
    return out
