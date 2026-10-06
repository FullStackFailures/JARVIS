"""Pure parsers: run on every OS (they take text, not OS state)."""

import unittest

from jarvis.osal.linux.desktop import exec_to_argv, parse_desktop_entry, parse_mimeapps
from jarvis.osal.windows.adapter import parse_get_startapps_json
from jarvis.tools.parsers import parse_net_addresses

IP_JSON = '[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1"}]},' \
          '{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.1.25"},{"family":"inet6","local":"fe80::1"}]}]'
IPCONFIG = """Windows IP Configuration

Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : 10.0.0.7
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""
PS_JSON = '[{"InterfaceAlias":"Ethernet","IPAddress":"10.1.2.3","AddressFamily":2}]'


class NetParsers(unittest.TestCase):
    def test_ip_json(self):
        r = parse_net_addresses(["ip", "-j", "addr"], IP_JSON)
        self.assertEqual(r["primary_ipv4"], "192.168.1.25")

    def test_hostname_dash_i(self):
        r = parse_net_addresses(["hostname", "-I"], "192.168.5.9 fe80::2\n")
        self.assertEqual(r["primary_ipv4"], "192.168.5.9")

    def test_ipconfig(self):
        r = parse_net_addresses(["ipconfig"], IPCONFIG)
        self.assertEqual(r["primary_ipv4"], "10.0.0.7")

    def test_powershell_json(self):
        r = parse_net_addresses(["powershell", "-NoProfile"], PS_JSON)
        self.assertEqual(r["primary_ipv4"], "10.1.2.3")

    def test_garbage_does_not_raise_or_invent_an_address(self):
        for argv in (["ip"], ["powershell"], ["hostname"], ["ipconfig"], ["weird"]):
            r = parse_net_addresses(argv, "<<not parseable>>")
            self.assertIsNone(r.get("primary_ipv4"), argv)

    def test_loopback_and_link_local_never_primary(self):
        r = parse_net_addresses(["hostname", "-I"], "127.0.0.1 169.254.3.4\n")
        self.assertIsNone(r["primary_ipv4"])


class DesktopParsers(unittest.TestCase):
    def test_desktop_entry(self):
        d = parse_desktop_entry("[Desktop Entry]\nName=Foo\nExec=foo %U\nCategories=WebBrowser;\n")
        self.assertEqual(d["Name"], "Foo")
        self.assertIsNone(parse_desktop_entry("garbage"))

    def test_exec_field_codes_dropped(self):
        self.assertEqual(exec_to_argv("firefox %u"), ["firefox"])
        self.assertEqual(exec_to_argv('"/opt/my app/run" --flag %F'), ["/opt/my app/run", "--flag"])
        self.assertIsNone(exec_to_argv('unterminated "quote'))

    def test_mimeapps(self):
        m = parse_mimeapps("[Default Applications]\nx-scheme-handler/http=firefox.desktop;\n")
        self.assertIn("x-scheme-handler/http", m)

    def test_windows_startapps_json(self):
        r = parse_get_startapps_json('[{"Name":"Edge","AppID":"MSEdge"},{"Name":"Calc","AppID":"X!App"}]')
        self.assertEqual(r[0], ("Edge", "MSEdge"))
        self.assertEqual(parse_get_startapps_json("not json"), [])
        self.assertEqual(parse_get_startapps_json('{"Name":"One","AppID":"A"}'), [("One", "A")])


if __name__ == "__main__":
    unittest.main()
