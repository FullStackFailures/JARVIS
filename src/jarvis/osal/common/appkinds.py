"""Shared, data-driven application classification tables (no OS calls)."""

from __future__ import annotations

# Canonical executable stem (lowercase, no extension) -> (display name, kind)
KNOWN_APPS: dict[str, tuple[str, str]] = {
    # browsers
    "firefox": ("Firefox", "browser"),
    "google-chrome": ("Google Chrome", "browser"),
    "google-chrome-stable": ("Google Chrome", "browser"),
    "chrome": ("Google Chrome", "browser"),
    "chromium": ("Chromium", "browser"),
    "chromium-browser": ("Chromium", "browser"),
    "brave": ("Brave", "browser"),
    "brave-browser": ("Brave", "browser"),
    "microsoft-edge": ("Microsoft Edge", "browser"),
    "msedge": ("Microsoft Edge", "browser"),
    "opera": ("Opera", "browser"),
    "vivaldi": ("Vivaldi", "browser"),
    "epiphany": ("GNOME Web", "browser"),
    "librewolf": ("LibreWolf", "browser"),
    # terminals
    "gnome-terminal": ("GNOME Terminal", "terminal"),
    "konsole": ("Konsole", "terminal"),
    "xfce4-terminal": ("Xfce Terminal", "terminal"),
    "xterm": ("XTerm", "terminal"),
    "alacritty": ("Alacritty", "terminal"),
    "kitty": ("kitty", "terminal"),
    "wezterm": ("WezTerm", "terminal"),
    "tilix": ("Tilix", "terminal"),
    "foot": ("foot", "terminal"),
    "terminator": ("Terminator", "terminal"),
    "x-terminal-emulator": ("Terminal", "terminal"),
    "wt": ("Windows Terminal", "terminal"),
    # editors / IDEs
    "code": ("Visual Studio Code", "editor"),
    "code-oss": ("Code - OSS", "editor"),
    "codium": ("VSCodium", "editor"),
    "subl": ("Sublime Text", "editor"),
    "gedit": ("gedit", "editor"),
    "kate": ("Kate", "editor"),
    "notepad": ("Notepad", "editor"),
    "notepad++": ("Notepad++", "editor"),
    "pycharm": ("PyCharm", "editor"),
    "idea": ("IntelliJ IDEA", "editor"),
    # file managers
    "nautilus": ("Files", "file_manager"),
    "dolphin": ("Dolphin", "file_manager"),
    "thunar": ("Thunar", "file_manager"),
    "nemo": ("Nemo", "file_manager"),
    "explorer": ("File Explorer", "file_manager"),
    # media
    "vlc": ("VLC media player", "media"),
    "mpv": ("mpv", "media"),
    "spotify": ("Spotify", "media"),
    # office
    "libreoffice": ("LibreOffice", "office"),
    "soffice": ("LibreOffice", "office"),
}

CATEGORY_KINDS: list[tuple[str, str]] = [
    ("webbrowser", "browser"),
    ("terminalemulator", "terminal"),
    ("texteditor", "editor"),
    ("ide", "editor"),
    ("filemanager", "file_manager"),
    ("player", "media"),
    ("audiovideo", "media"),
    ("office", "office"),
]

# Used by the PATH fallback scan so apps without a launcher entry are still found.
PATH_SCAN_NAMES: list[str] = [
    n for n, (_, kind) in KNOWN_APPS.items() if kind in {"browser", "terminal", "editor"}
]

# Windows ProgId prefix -> canonical browser executable stem
WINDOWS_PROGID_BROWSERS: list[tuple[str, str]] = [
    ("firefoxurl", "firefox"),
    ("firefoxhtml", "firefox"),
    ("chromehtml", "chrome"),
    ("msedgehtm", "msedge"),
    ("msedgeurl", "msedge"),
    ("bravehtml", "brave"),
    ("braveurl", "brave"),
    ("operastable", "opera"),
    ("operahtml", "opera"),
    ("vivaldihtm", "vivaldi"),
]


def stem(name: str) -> str:
    """Lowercase executable stem without directory or Windows extension."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".com", ".bat", ".cmd"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


def classify(name: str, exec_stem: str | None, categories: list[str] | None) -> str:
    if exec_stem and exec_stem in KNOWN_APPS:
        return KNOWN_APPS[exec_stem][1]
    lowered = [c.strip().lower() for c in (categories or []) if c.strip()]
    for needle, kind in CATEGORY_KINDS:
        if needle in lowered:
            return kind
    low_name = name.lower()
    for key, (display, kind) in KNOWN_APPS.items():
        if display.lower() == low_name or key == low_name:
            return kind
    return "other"


def browser_from_progid(progid: str | None) -> str | None:
    if not progid:
        return None
    low = progid.lower()
    for prefix, stem_name in WINDOWS_PROGID_BROWSERS:
        if low.startswith(prefix):
            return stem_name
    return None
