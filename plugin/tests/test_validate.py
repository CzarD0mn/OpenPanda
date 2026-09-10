import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "octoprint_bambu" / "validate.py"


def load():
    spec = importlib.util.spec_from_file_location("octoprint_bambu_validate", ROOT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


V = load()


class ValidateTests(unittest.TestCase):
    def test_print_name_allows_typical_bambu_files(self):
        self.assertEqual(V.safe_print_name("benchy_0.16mm_PLA.3mf"), "benchy_0.16mm_PLA.3mf")
        self.assertEqual(V.safe_print_name("foo.gcode"), "foo.gcode")
        self.assertEqual(V.safe_print_name("foo.GCODE"), "foo.GCODE")

    def test_print_name_rejects_paths_and_other_types(self):
        for name in (
            "../etc/passwd.3mf",
            "/tmp/x.3mf",
            "x/y.3mf",
            r"x\y.3mf",
            "",
            "noext",
            "file.stl",
            "a" * 200 + ".3mf",
            None,
            123,
            "..hidden.3mf",
            "file.3mf;rm",
            "file.3mf\n",
        ):
            self.assertIsNone(V.safe_print_name(name), msg=repr(name))

    def test_host_accepts_ipv4_and_hostname(self):
        self.assertTrue(V.is_valid_lan_host("192.168.1.50"))
        self.assertTrue(V.is_valid_lan_host("printer.local"))
        self.assertTrue(V.is_valid_lan_host("bambu.home.arpa"))

    def test_host_rejects_urls_and_junk(self):
        for host in (
            "",
            "http://192.168.1.50",
            "192.168.1.50/admin",
            "host name",
            "../secret",
            "a" * 300,
            None,
        ):
            self.assertFalse(V.is_valid_lan_host(host), msg=repr(host))

    def test_serial_and_access_code(self):
        self.assertTrue(V.is_valid_serial("00M00A123456789"))
        self.assertFalse(V.is_valid_serial("short"))
        self.assertTrue(V.is_valid_access_code("12345678"))
        self.assertFalse(V.is_valid_access_code("abc"))
        self.assertFalse(V.is_valid_access_code("code with space"))

    def test_mqtt_port_is_8883_only(self):
        self.assertTrue(V.is_valid_mqtt_port(8883))
        self.assertTrue(V.is_valid_mqtt_port("8883"))
        self.assertFalse(V.is_valid_mqtt_port(1883))
        self.assertFalse(V.is_valid_mqtt_port(443))
        self.assertFalse(V.is_valid_mqtt_port("not-a-port"))


if __name__ == "__main__":
    unittest.main()
