"""Windows IPC hardening - logic tests that run on EVERY OS.

LABEL: FAKE_WINAPI. The collaborators below (SecurityApi, _winapi, PipeConnection) are fakes, so these tests prove
our ordering / validation / cleanup logic and string construction. They do NOT prove that Windows enforces the DACL,
honours FILE_FLAG_FIRST_PIPE_INSTANCE, or reports client PIDs - only the windows_only tests on Windows/CI can.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.ipc.auth import write_token
from jarvis.osal.types import OsalError
from jarvis.osal.windows import pipe_policy as pp
from jarvis.osal.windows.adapter import WindowsAdapter
from jarvis.osal.windows.pipe import ERROR_NO_DATA, SecurePipeListener, verify_peer
from tests.harness import tags

SID = "S-1-5-21-1004336348-1177238915-682003330-1001"
OTHER = "S-1-5-21-1004336348-1177238915-682003330-1002"


class FakeApi:
    def __init__(self, sid=SID):
        self.sid, self.calls, self.next_handle = sid, [], 100
        self.pid_sid, self.client = {}, 4242
        self.closed, self.dacls = [], {}
        self.fail_client = False

    def current_user_sid(self):
        return self.sid

    def process_user_sid(self, pid):
        return self.pid_sid.get(pid)

    def client_pid(self, h):
        if self.fail_client:
            raise OsalError("failed", "GetNamedPipeClientProcessId failed")
        return self.client

    def create_secure_pipe(self, name, sddl, *, first):
        self.calls.append(("create", name, sddl, first))
        self.next_handle += 1
        return self.next_handle

    def close_handle(self, h):
        self.closed.append(h)

    def set_dacl_from_sddl(self, path, sddl):
        self.dacls[path] = sddl
        self.calls.append(("dacl", path, sddl, Path(path).stat().st_size if Path(path).exists() else None))

    def read_dacl_sddl(self, path):
        return self.dacls[path]


class FakeOverlapped:
    def __init__(self, err=0):
        self.event, self.err, self.cancelled, self.results = object(), err, False, 0

    def cancel(self):
        self.cancelled = True

    def GetOverlappedResult(self, wait):
        self.results += 1
        return 0, self.err


class FakeWin:
    INFINITE = -1

    def __init__(self, ov=None, connect_exc=None, wait_exc=None):
        self.ov, self.connect_exc, self.wait_exc = ov or FakeOverlapped(), connect_exc, wait_exc

    def ConnectNamedPipe(self, h, overlapped):
        if self.connect_exc:
            raise self.connect_exc
        return self.ov

    def WaitForMultipleObjects(self, handles, wait_all, timeout):
        if self.wait_exc:
            raise self.wait_exc
        return 0


def winerr(code):
    e = OSError("x")
    e.winerror = code
    return e


@tags("UNIT", "FAKE_WINAPI")
class PolicyStrings(unittest.TestCase):
    def test_pipe_name_is_sid_based_and_discriminated(self):
        self.assertEqual(pp.pipe_address(SID), rf"\\.\pipe\jarvisd-{SID}")
        self.assertTrue(pp.pipe_address(SID, "ab12!!cd").endswith("-ab12cd"))

    def test_sid_injection_into_sddl_or_name_is_refused(self):
        for bad in (SID + ")(A;;GA;;;WD", "WD", "", "S-1-5", "S-1-5-21-1\\..\\x", SID + " ", None):
            with self.subTest(bad=bad):
                with self.assertRaises(pp.InvalidSid):
                    pp.pipe_address(bad)  # type: ignore[arg-type]
                with self.assertRaises(pp.InvalidSid):
                    pp.owner_only_pipe_sddl(bad)  # type: ignore[arg-type]

    def test_pipe_sddl_has_exactly_one_allow_ace_and_is_protected(self):
        sddl = pp.owner_only_pipe_sddl(SID)
        self.assertEqual(sddl, f"D:P(A;;GA;;;{SID})")
        self.assertTrue(pp.dacl_grants_only(sddl, SID))
        for everyone in ("WD", "AN", "NU", "BU", "S-1-1-0"):
            self.assertNotIn(everyone, sddl.replace(SID, ""))

    def test_dir_sddl_inherits_and_file_sddl_does_not(self):
        self.assertIn("OICI", pp.owner_only_file_sddl(SID, directory=True))
        self.assertNotIn("OICI", pp.owner_only_file_sddl(SID, directory=False))

    def test_dacl_check_rejects_extra_aces_unprotected_and_other_sids(self):
        self.assertFalse(pp.dacl_grants_only(f"D:P(A;;GA;;;{SID})(A;;GR;;;WD)", SID))
        self.assertFalse(pp.dacl_grants_only(f"D:(A;;GA;;;{SID})", SID))          # not protected
        self.assertFalse(pp.dacl_grants_only(f"D:P(A;;GA;;;{OTHER})", SID))
        self.assertFalse(pp.dacl_grants_only(f"D:P(D;;GA;;;{SID})", SID))          # deny ACE is not a grant
        self.assertTrue(pp.dacl_grants_only(f"O:{SID}G:{SID}D:PAI(A;;FA;;;{SID})", SID))


@tags("UNIT", "FAKE_WINAPI")
class ListenerLogic(unittest.TestCase):
    def make(self, win=None):
        api = FakeApi()
        made = []
        lst = SecurePipeListener(r"\\.\pipe\t", "D:P(A;;GA;;;X)", api, winapi=win or FakeWin(),
                                 connection_factory=lambda h: made.append(h) or ("conn", h))
        return api, lst, made

    def test_first_instance_flag_only_on_first_creation_and_sddl_always_passed(self):
        api, lst, _ = self.make()
        lst.accept(); lst.accept()
        firsts = [c[3] for c in api.calls if c[0] == "create"]
        self.assertEqual(firsts, [True, False, False])
        self.assertTrue(all(c[2] == "D:P(A;;GA;;;X)" for c in api.calls))

    def test_accept_returns_the_oldest_instance(self):
        api, lst, made = self.make()
        self.assertEqual(lst.accept(), ("conn", 101))
        self.assertEqual(lst.accept(), ("conn", 102))

    def test_close_releases_every_pending_instance_once_and_blocks_accept(self):
        api, lst, _ = self.make()
        lst.accept()
        lst.close(); lst.close()
        self.assertEqual(sorted(api.closed), [102])
        with self.assertRaises(OSError):
            lst.accept()

    def test_client_already_gone_is_not_an_error(self):
        api, lst, made = self.make(FakeWin(connect_exc=winerr(ERROR_NO_DATA)))
        self.assertEqual(lst.accept(), ("conn", 101))

    def test_other_connect_errors_close_the_handle_and_propagate(self):
        api, lst, _ = self.make(FakeWin(connect_exc=winerr(5)))
        with self.assertRaises(OSError):
            lst.accept()
        self.assertIn(101, api.closed)

    def test_cancelled_wait_cancels_waits_for_the_overlapped_then_closes_once(self):
        ov = FakeOverlapped()
        api, lst, _ = self.make(FakeWin(ov=ov, wait_exc=KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            lst.accept()
        self.assertTrue(ov.cancelled)
        self.assertGreaterEqual(ov.results, 1)
        self.assertEqual(api.closed.count(101), 1)

    def test_overlapped_failure_is_reported_and_handle_closed(self):
        api, lst, _ = self.make(FakeWin(ov=FakeOverlapped(err=995)))
        with self.assertRaises(OSError):
            lst.accept()
        self.assertIn(101, api.closed)


@tags("UNIT", "FAKE_WINAPI")
class PeerVerification(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.api.pid_sid = {4242: SID, 5000: OTHER}

    def test_same_sid_true(self):
        self.assertIs(verify_peer(self.api, 7, SID), True)

    def test_different_sid_false(self):
        self.api.client = 5000
        self.assertIs(verify_peer(self.api, 7, SID), False)

    def test_unknown_process_is_undetermined_not_accepted(self):
        self.api.client = 9999
        self.assertIsNone(verify_peer(self.api, 7, SID))

    def test_pid_lookup_failure_is_undetermined(self):
        self.api.fail_client = True
        self.assertIsNone(verify_peer(self.api, 7, SID))

    def test_own_process_short_circuit(self):
        self.api.client = os.getpid()
        self.api.pid_sid = {}
        self.assertIs(verify_peer(self.api, 7, SID), True)


@tags("UNIT", "FAKE_WINAPI")
class AdapterWiring(unittest.TestCase):
    def adapter(self, api=None):
        a = WindowsAdapter()
        a._security_api = api or FakeApi()
        return a

    def test_endpoint_uses_the_sid_not_the_user_name(self):
        ep = self.adapter().ipc_endpoint(Path("."), "")
        self.assertEqual(ep.family, "AF_PIPE")
        self.assertEqual(ep.address, rf"\\.\pipe\jarvisd-{SID}")

    def test_endpoint_refuses_a_malformed_sid(self):
        with self.assertRaises(pp.InvalidSid):
            self.adapter(FakeApi(sid="not-a-sid")).ipc_endpoint(Path("."), "")

    def test_listener_is_created_with_the_owner_only_descriptor(self):
        api = FakeApi()
        a = self.adapter(api)
        ep = a.ipc_endpoint(Path("."), "")
        with mock.patch("jarvis.osal.windows.pipe.SecurePipeListener") as cls:
            a.create_ipc_listener(ep)
        _, args, _ = cls.mock_calls[0]
        self.assertEqual(args[0], ep.address)
        self.assertEqual(args[1], f"D:P(A;;GA;;;{SID})")
        self.assertIs(args[2], api)

    def test_peer_check_delegates_with_own_sid_and_maps_errors_to_none(self):
        api = FakeApi(); api.pid_sid = {4242: SID}
        a = self.adapter(api)
        self.assertIs(a.peer_is_current_user(55), True)
        api.fail_client = True
        self.assertIsNone(a.peer_is_current_user(55))

    def test_restrict_applies_directory_vs_file_descriptor(self):
        api = FakeApi(); a = self.adapter(api)
        a.restrict_to_current_user(Path("C:/x/run"), directory=True)
        a.restrict_to_current_user(Path("C:/x/run/t"))
        self.assertIn("OICI", api.calls[0][2])
        self.assertNotIn("OICI", api.calls[1][2])


@tags("UNIT", "FAKE_WINAPI")
class TokenFileOrdering(unittest.TestCase):
    def test_file_is_locked_down_before_the_secret_is_written(self):
        class Recorder:
            def __init__(self):
                self.sizes = []

            def restrict_to_current_user(self, path, *, directory=False):
                self.sizes.append((Path(path).name, directory, Path(path).stat().st_size if not directory else None))
                return True

        rec = Recorder()
        d = Path(tempfile.mkdtemp()) / "run"
        token = write_token(d, rec)  # type: ignore[arg-type]
        self.assertEqual(rec.sizes[0], ("run", True, None))
        name, is_dir, size_at_restrict = rec.sizes[1]
        self.assertEqual((name, is_dir, size_at_restrict), ("jarvisd.token.tmp", False, 0))
        self.assertEqual((d / "jarvisd.token").read_bytes(), token)

    def test_failed_restriction_leaves_no_token_behind(self):
        class Failing:
            def restrict_to_current_user(self, path, *, directory=False):
                if not directory:
                    raise OsalError("permission", "denied")
                return True

        d = Path(tempfile.mkdtemp()) / "run"
        with self.assertRaises(OsalError):
            write_token(d, Failing())  # type: ignore[arg-type]
        self.assertFalse((d / "jarvisd.token").exists())
        self.assertFalse((d / "jarvisd.token.tmp").exists())
