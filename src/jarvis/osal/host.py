"""The only place outside adapters that inspects the host OS family."""

import os

IS_WINDOWS: bool = os.name == "nt"
IS_POSIX: bool = os.name == "posix"
