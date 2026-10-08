import importlib.util
import sys
import types
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "octoprint_openpanda"


def _load_client_module():
    """Load client.py with paho stubbed so no network or broker is needed."""
    events = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.on_connect = None
            self.on_message = None

        def username_pw_set(self, username, password):
            events.append(("auth", username))

        def tls_set_context(self, ctx):
            events.append(("tls_context",))

        def connect(self, *args, **kwargs):
            events.append(("mqtt_connect",))

        def loop_forever(self):
            return

        def disconnect(self):
            return

        def publish(self, *args, **kwargs):
            return

    paho = types.ModuleType("paho")
    paho_mqtt = types.ModuleType("paho.mqtt")
    paho_client = types.ModuleType("paho.mqtt.client")
    paho_client.CallbackAPIVersion = types.SimpleNamespace(VERSION2=2)
    paho_client.Client = FakeClient
    sys.modules["paho"] = paho
    sys.modules["paho.mqtt"] = paho_mqtt
    sys.modules["paho.mqtt.client"] = paho_client

    pkg = types.ModuleType("octoprint_openpanda")
    pkg.__path__ = [str(PKG)]
    sys.modules["octoprint_openpanda"] = pkg
    mods = {}
    for name in ("tls", "validate", "client"):
        spec = importlib.util.spec_from_file_location(
            "octoprint_openpanda." + name, PKG / (name + ".py")
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["octoprint_openpanda." + name] = mod
        spec.loader.exec_module(mod)
        mods[name] = mod
    return mods, events


class Log:
    def __getattr__(self, _name):
        return lambda *a, **k: None


class MalformedPinTests(unittest.TestCase):
    """A configured-but-unusable pin must fail closed, never fall back to TOFU."""

    def setUp(self):
        self.mods, self.events = _load_client_module()
        self.client = self.mods["client"]
        self.tofu_calls = []
        self.client.capture_peer_fingerprint = lambda *a, **k: (
            self.tofu_calls.append(a) or "b" * 64
        )

    def _make(self, pin, mode="pin"):
        stored = []
        inst = self.client.BambuLanClient(
            host="192.168.1.50",
            access_code="12345678",
            serial="00M00A123456789",
            on_report=lambda *_: None,
            logger=Log(),
            tls_mode=mode,
            tls_fingerprint=pin,
            on_fingerprint=stored.append,
        )
        return inst, stored

    def test_malformed_pins_rejected_before_any_network(self):
        fp = "ab" * 32
        for pin in (
            "sha256 Fingerprint=" + ":".join([fp[i : i + 2].upper() for i in range(0, 64, 2)]),
            "SHA256:" + fp,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1 length
            fp[:-1],
            "not-a-fingerprint",
        ):
            with self.assertRaises(ValueError, msg=pin):
                self._make(pin)
        self.assertEqual(self.tofu_calls, [])
        self.assertEqual(self.events, [])

    def test_unknown_mode_falls_back_to_pin_and_still_rejects(self):
        with self.assertRaises(ValueError):
            self._make("junk", mode="bogus")

    def test_empty_pin_still_uses_tofu(self):
        inst, stored = self._make("")
        inst._loop()
        self.assertEqual(len(self.tofu_calls), 1)
        self.assertEqual(stored, ["b" * 64])

    def test_valid_pin_formats_skip_tofu(self):
        fp = "ab" * 32
        for pin in (fp, fp.upper(), ":".join(fp[i : i + 2] for i in range(0, 64, 2))):
            inst, stored = self._make(pin)
            self.assertEqual(inst.tls_fingerprint, fp)
        self.assertEqual(self.tofu_calls, [])

    def test_malformed_pin_ignored_in_non_pin_modes(self):
        inst, _ = self._make("junk", mode="system")
        self.assertEqual(inst.tls_fingerprint, "")


if __name__ == "__main__":
    unittest.main()
