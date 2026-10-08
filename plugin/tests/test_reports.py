import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "octoprint_openpanda"


def _install_stubs():
    paho = types.ModuleType("paho")
    paho_mqtt = types.ModuleType("paho.mqtt")
    paho_client = types.ModuleType("paho.mqtt.client")
    paho_client.CallbackAPIVersion = types.SimpleNamespace(VERSION2=2)

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.published = []

        def publish(self, topic, body):
            self.published.append((topic, body))

        def disconnect(self):
            return

    paho_client.Client = FakeClient
    sys.modules["paho"] = paho
    sys.modules["paho.mqtt"] = paho_mqtt
    sys.modules["paho.mqtt.client"] = paho_client

    octoprint = types.ModuleType("octoprint")
    octoprint_plugin = types.ModuleType("octoprint.plugin")
    for name in (
        "SettingsPlugin",
        "AssetPlugin",
        "TemplatePlugin",
        "StartupPlugin",
        "ShutdownPlugin",
        "SimpleApiPlugin",
    ):
        setattr(octoprint_plugin, name, type(name, (), {}))
    octoprint.plugin = octoprint_plugin
    sys.modules["octoprint"] = octoprint
    sys.modules["octoprint.plugin"] = octoprint_plugin


def load_package():
    """Import the real plugin package with OctoPrint and paho stubbed."""
    _install_stubs()
    for key in list(sys.modules):
        if key == "octoprint_openpanda" or key.startswith("octoprint_openpanda."):
            del sys.modules[key]
    spec = importlib.util.spec_from_file_location(
        "octoprint_openpanda",
        PKG / "__init__.py",
        submodule_search_locations=[str(PKG)],
    )
    pkg = importlib.util.module_from_spec(spec)
    sys.modules["octoprint_openpanda"] = pkg
    spec.loader.exec_module(pkg)
    return pkg


class Log:
    def __init__(self):
        self.lines = []

    def _add(self, level, msg, *args, **_kwargs):
        self.lines.append((level, msg % args if args else msg))

    def info(self, *a, **k):
        self._add("info", *a, **k)

    def warning(self, *a, **k):
        self._add("warning", *a, **k)

    def error(self, *a, **k):
        self._add("error", *a, **k)

    def exception(self, *a, **k):
        self._add("exception", *a, **k)


class Msg:
    def __init__(self, payload):
        self.payload = payload


ACCESS_CODE = "s3cr3tAC"


class ClientMessageTests(unittest.TestCase):
    def setUp(self):
        self.pkg = load_package()
        self.client_mod = sys.modules["octoprint_openpanda.client"]
        self.reports = []
        self.log = Log()
        self.client = self.client_mod.BambuLanClient(
            host="192.168.1.50",
            access_code=ACCESS_CODE,
            serial="00M00A123456789",
            on_report=self.reports.append,
            logger=self.log,
            tls_fingerprint="a" * 64,
        )

    def test_malformed_payloads_never_raise(self):
        for payload in (
            b"[" * 200000 + b"]" * 200000,  # RecursionError in json
            b"\xff\xfe not utf-8",
            b"{not json",
            b"",
            b"[1, 2, 3]",
            b'"just a string"',
        ):
            self.client._on_message(None, None, Msg(payload))
        self.assertEqual(self.reports, [])

    def test_handler_exception_is_contained_and_logged(self):
        def boom(_payload):
            raise OverflowError("int too large to convert to float")

        self.client.on_report = boom
        self.client._on_message(None, None, Msg(b'{"print": {}}'))
        self.assertTrue(any(level == "exception" for level, _ in self.log.lines))

    def test_valid_report_still_delivered(self):
        self.client._on_message(None, None, Msg(b'{"print": {"mc_percent": 5}}'))
        self.assertEqual(self.reports, [{"print": {"mc_percent": 5}}])

    def test_logs_never_contain_access_code(self):
        self.client._on_message(None, None, Msg(b"[" * 100000))
        self.client.on_report = lambda _p: 1 / 0
        self.client._on_message(None, None, Msg(b"{}"))
        for _level, line in self.log.lines:
            self.assertNotIn(ACCESS_CODE, line)


class PluginReportTests(unittest.TestCase):
    def setUp(self):
        self.pkg = load_package()
        self.plugin = self.pkg.OpenPandaPlugin()
        self.plugin._logger = Log()
        self.plugin._identifier = "openpanda"
        self.sent = []
        self.plugin._plugin_manager = types.SimpleNamespace(
            send_plugin_message=lambda ident, msg: self.sent.append(msg)
        )

    def _report(self, print_):
        self.plugin._on_report(json.loads(json.dumps({"print": print_})))
        return self.sent[-1]

    def test_normal_report(self):
        self.assertEqual(
            self._report({"gcode_state": "RUNNING", "mc_percent": 42}),
            {"state": "RUNNING", "progress": 42.0},
        )

    def test_progress_clamped_and_non_finite_dropped(self):
        self.assertEqual(self._report({"mc_percent": 150})["progress"], 100.0)
        self.assertEqual(self._report({"mc_percent": -3})["progress"], 0.0)
        for bad in (10 ** 400, "nan", "inf", [1], {"x": 1}):
            msg = self._report({"gcode_state": "RUNNING", "mc_percent": bad})
            self.assertNotIn("progress", msg, msg=repr(bad)[:40])
        self.plugin._on_report({"print": {"mc_percent": float("nan")}})
        self.assertNotIn("progress", self.sent[-1])

    def test_non_string_state_replaced(self):
        self.assertEqual(self._report({"gcode_state": {"evil": 1}})["state"], "UNKNOWN")

    def test_send_failure_is_contained(self):
        def boom(*_a, **_k):
            raise RuntimeError("socket gone")

        self.plugin._plugin_manager = types.SimpleNamespace(send_plugin_message=boom)
        self.plugin._on_report({"print": {"mc_percent": 1}})
        self.assertTrue(any(l == "exception" for l, _ in self.plugin._logger.lines))

    def test_non_dict_payloads_ignored(self):
        for payload in (None, [], "x", {"print": "x"}):
            self.plugin._on_report(payload)
        self.assertEqual(self.sent, [])


class ApiProtectionTests(unittest.TestCase):
    def test_api_is_admin_only_and_protected(self):
        plugin = load_package().OpenPandaPlugin()
        self.assertIs(plugin.is_api_adminonly(), True)
        self.assertIs(plugin.is_api_protected(), True)


class LightCommandTests(unittest.TestCase):
    def setUp(self):
        pkg = load_package()
        self.plugin = pkg.OpenPandaPlugin()
        self.calls = []
        self.plugin._client = types.SimpleNamespace(
            set_chamber_light=self.calls.append
        )

    def test_string_values_parsed(self):
        for value, expected in (("false", False), ("0", False), ("off", False),
                                ("true", True), ("on", True), (True, True), (0, False)):
            self.calls.clear()
            self.assertIsNone(self.plugin.on_api_command("light", {"on": value}))
            self.assertEqual(self.calls, [expected], msg=repr(value))

    def test_unknown_values_rejected(self):
        for value in ("maybe", None, 2, [], {}):
            result = self.plugin.on_api_command("light", {"on": value})
            self.assertEqual(result, {"error": "invalid_on"}, msg=repr(value))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
