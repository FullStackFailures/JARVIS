"""Thin ctypes facade over the Win32 security/pipe calls jarvisd needs.

STATUS: written without access to Windows. Nothing in this file has been executed on Windows by its author.
The module imports on every OS (ctypes DLLs are loaded lazily inside ``WinSecurityApi.__init__``, which raises
OsalUnavailable off Windows), so the logic that *uses* the facade can be tested on Linux against a fake with the
same interface (see ``SecurityApi``). Those tests prove our control flow, not Windows behaviour.

Every foreign function declares argtypes/restype explicitly: without them 64-bit HANDLE/pointer values are
truncated to 32-bit ints by ctypes' default ``c_int`` return type.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any, Protocol

from jarvis.osal.types import OsalError, OsalUnavailable
from jarvis.osal.windows.pipe_policy import validate_sid

# --- constants (winnt.h / winbase.h / aclapi.h) ------------------------------------------------------------------
PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_UNLIMITED_INSTANCES = 255
NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF
PIPE_BUFSIZE = 8192

TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_INSUFFICIENT_BUFFER = 122
SDDL_REVISION_1 = 1
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
INVALID_HANDLE = ctypes.c_void_p(-1).value


class SecurityApi(Protocol):
    """The seam used by osal.windows.pipe / the Windows adapter (and replaced by a fake in Linux unit tests)."""

    def current_user_sid(self) -> str: ...
    def process_user_sid(self, pid: int) -> str | None: ...
    def client_pid(self, pipe_handle: int) -> int: ...
    def create_secure_pipe(self, name: str, sddl: str, *, first: bool) -> int: ...
    def close_handle(self, handle: int) -> None: ...
    def set_dacl_from_sddl(self, path: str, sddl: str) -> None: ...
    def read_dacl_sddl(self, path: str) -> str: ...


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", ctypes.c_uint32), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", ctypes.c_int32)]


def _last_error(what: str) -> OsalError:
    code = ctypes.get_last_error() if sys.platform == "win32" else 0
    return OsalError("failed", f"{what} failed (Win32 error {code})")


class WinSecurityApi:
    """Real implementation. Only constructible on Windows."""

    _k: Any  # kernel32 / advapi32 WinDLLs and ctypes.wintypes (typeshed has no WinDLL off Windows)
    _a: Any
    _wt: Any

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OsalUnavailable("WinSecurityApi is only available on Windows")
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        adv = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
        H, V, D, B, W = wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR

        k32.GetCurrentProcess.restype = H
        k32.GetCurrentProcess.argtypes = []
        k32.OpenProcess.restype = H
        k32.OpenProcess.argtypes = [D, B, D]
        k32.CloseHandle.restype = B
        k32.CloseHandle.argtypes = [H]
        k32.LocalFree.restype = V
        k32.LocalFree.argtypes = [V]
        k32.CreateNamedPipeW.restype = H
        k32.CreateNamedPipeW.argtypes = [W, D, D, D, D, D, D, V]
        k32.GetNamedPipeClientProcessId.restype = B
        k32.GetNamedPipeClientProcessId.argtypes = [H, ctypes.POINTER(D)]
        adv.OpenProcessToken.restype = B
        adv.OpenProcessToken.argtypes = [H, D, ctypes.POINTER(H)]
        adv.GetTokenInformation.restype = B
        adv.GetTokenInformation.argtypes = [H, ctypes.c_int, V, D, ctypes.POINTER(D)]
        adv.ConvertSidToStringSidW.restype = B
        adv.ConvertSidToStringSidW.argtypes = [V, ctypes.POINTER(wintypes.LPWSTR)]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = B
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            W, D, ctypes.POINTER(V), ctypes.POINTER(D)]
        adv.GetSecurityDescriptorDacl.restype = B
        adv.GetSecurityDescriptorDacl.argtypes = [V, ctypes.POINTER(B), ctypes.POINTER(V), ctypes.POINTER(B)]
        adv.SetNamedSecurityInfoW.restype = D
        adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, D, V, V, V, V]
        adv.GetNamedSecurityInfoW.restype = D
        adv.GetNamedSecurityInfoW.argtypes = [W, ctypes.c_int, D, ctypes.POINTER(V), ctypes.POINTER(V),
                                              ctypes.POINTER(V), ctypes.POINTER(V), ctypes.POINTER(V)]
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = B
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            V, D, D, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(D)]
        self._k, self._a, self._wt = k32, adv, wintypes

    # ------------------------------------------------------------------ identities
    def _sid_string(self, psid: int | None) -> str:
        out = self._wt.LPWSTR()
        if not self._a.ConvertSidToStringSidW(psid, ctypes.byref(out)):
            raise _last_error("ConvertSidToStringSidW")
        try:
            return str(out.value)
        finally:
            self._k.LocalFree(ctypes.cast(out, ctypes.c_void_p))

    def _token_user_sid(self, process_handle: int) -> str:
        token = self._wt.HANDLE()
        if not self._a.OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token)):
            raise _last_error("OpenProcessToken")
        try:
            need = self._wt.DWORD(0)
            self._a.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(need))
            if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER or need.value == 0:
                raise _last_error("GetTokenInformation(size)")
            buf = ctypes.create_string_buffer(need.value)
            if not self._a.GetTokenInformation(token, TOKEN_USER_CLASS, buf, need, ctypes.byref(need)):
                raise _last_error("GetTokenInformation")
            # TOKEN_USER begins with SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; }
            psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            return validate_sid(self._sid_string(psid))
        finally:
            self._k.CloseHandle(token)

    def current_user_sid(self) -> str:
        return self._token_user_sid(self._k.GetCurrentProcess())

    def process_user_sid(self, pid: int) -> str | None:
        """SID of the user owning process ``pid``; None if the process cannot be opened/queried."""
        h = self._k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None
        try:
            return self._token_user_sid(h)
        except OsalError:
            return None
        finally:
            self._k.CloseHandle(h)

    def client_pid(self, pipe_handle: int) -> int:
        pid = self._wt.DWORD(0)
        if not self._k.GetNamedPipeClientProcessId(pipe_handle, ctypes.byref(pid)):
            raise _last_error("GetNamedPipeClientProcessId")
        return int(pid.value)

    # ------------------------------------------------------------------ security descriptors
    def _sd_from_sddl(self, sddl: str) -> ctypes.c_void_p:
        psd = ctypes.c_void_p()
        if not self._a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, ctypes.byref(psd), None):
            raise _last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        return psd

    def create_secure_pipe(self, name: str, sddl: str, *, first: bool) -> int:
        """One overlapped, message-mode, byte-limited pipe instance with the given DACL; remote clients refused.

        ``first=True`` adds FILE_FLAG_FIRST_PIPE_INSTANCE so creation FAILS if any other process already owns
        this pipe name (pipe squatting)."""
        psd = self._sd_from_sddl(sddl)
        try:
            sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), psd, 0)
            flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
            mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS
            h = self._k.CreateNamedPipeW(name, flags, mode, PIPE_UNLIMITED_INSTANCES, PIPE_BUFSIZE, PIPE_BUFSIZE,
                                         NMPWAIT_WAIT_FOREVER, ctypes.byref(sa))
            if h is None or h == INVALID_HANDLE:
                raise _last_error("CreateNamedPipeW")
            return int(h)
        finally:
            self._k.LocalFree(psd)

    def close_handle(self, handle: int) -> None:
        self._k.CloseHandle(handle)

    def set_dacl_from_sddl(self, path: str, sddl: str) -> None:
        """Replace the DACL of a file/directory with the (protected) one in ``sddl``."""
        psd = self._sd_from_sddl(sddl)
        try:
            present, defaulted, pacl = self._wt.BOOL(), self._wt.BOOL(), ctypes.c_void_p()
            if not self._a.GetSecurityDescriptorDacl(psd, ctypes.byref(present), ctypes.byref(pacl),
                                                     ctypes.byref(defaulted)) or not present.value:
                raise _last_error("GetSecurityDescriptorDacl")
            rc = self._a.SetNamedSecurityInfoW(path, SE_FILE_OBJECT,
                                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                               None, None, pacl, None)
            if rc != 0:
                raise OsalError("failed", f"SetNamedSecurityInfoW failed (Win32 error {rc})")
        finally:
            self._k.LocalFree(psd)

    def read_dacl_sddl(self, path: str) -> str:
        psd = ctypes.c_void_p()
        rc = self._a.GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, None, None,
                                           ctypes.byref(psd))
        if rc != 0:
            raise OsalError("failed", f"GetNamedSecurityInfoW failed (Win32 error {rc})")
        try:
            out = self._wt.LPWSTR()
            if not self._a.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, ctypes.byref(out), None):
                raise _last_error("ConvertSecurityDescriptorToStringSecurityDescriptorW")
            try:
                return str(out.value)
            finally:
                self._k.LocalFree(ctypes.cast(out, ctypes.c_void_p))
        finally:
            self._k.LocalFree(psd)
