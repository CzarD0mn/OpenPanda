import hashlib
import importlib.util
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

TLS_PATH = Path(__file__).resolve().parents[1] / "octoprint_openpanda" / "tls.py"


def load_tls():
    spec = importlib.util.spec_from_file_location("octoprint_openpanda_tls", TLS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tls = load_tls()


def _fingerprint_pem(cert_path):
    der = subprocess.check_output(
        ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
        stderr=subprocess.DEVNULL,
    )
    return hashlib.sha256(der).hexdigest()


def _make_cert(directory, name):
    key = directory / ("%s.key" % name)
    crt = directory / ("%s.crt" % name)
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=%s" % name,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return str(crt), str(key), _fingerprint_pem(str(crt))


class TlsServer:
    def __init__(self, cert, key):
        self.received = []
        self.errors = []
        self._ready = threading.Event()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._sock.listen(8)
        self._sock.settimeout(8)
        self._thread.start()
        self._ready.set()
        return self

    def _run(self):
        try:
            while True:
                try:
                    conn, _addr = self._sock.accept()
                except OSError:
                    break
                conn.settimeout(3)
                try:
                    ssock = self._ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError, ConnectionError) as exc:
                    self.errors.append(str(exc))
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                ssock.settimeout(2)
                try:
                    data = ssock.recv(4096)
                    self.received.append(data)
                except socket.timeout:
                    self.received.append(b"")
                except (ssl.SSLError, OSError, ConnectionError):
                    self.received.append(b"")
                try:
                    ssock.close()
                except OSError:
                    pass
        finally:
            try:
                self._sock.close()
            except OSError:
                pass

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


class TlsPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.cert_a, cls.key_a, cls.fp_a = _make_cert(root, "printer-a")
        cls.cert_b, cls.key_b, cls.fp_b = _make_cert(root, "printer-b")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_fingerprints_differ(self):
        self.assertNotEqual(self.fp_a, self.fp_b)
        self.assertEqual(len(self.fp_a), 64)

    def test_compare_digest_rejects_mismatch_and_junk(self):
        self.assertTrue(tls.fingerprints_match(self.fp_a, self.fp_a.upper()))
        self.assertTrue(tls.fingerprints_match(self.fp_a, ":".join(self.fp_a[i : i + 2] for i in range(0, 64, 2))))
        self.assertFalse(tls.fingerprints_match(self.fp_a, self.fp_b))
        self.assertFalse(tls.fingerprints_match(self.fp_a, ""))
        self.assertFalse(tls.fingerprints_match(self.fp_a, "deadbeef"))

    def test_tofu_probe_sends_no_application_data(self):
        server = TlsServer(self.cert_a, self.key_a).start()
        time.sleep(0.05)
        fp = tls.capture_peer_fingerprint("127.0.0.1", server.port, timeout=5)
        time.sleep(0.2)
        server.close()
        self.assertEqual(fp, self.fp_a)
        self.assertTrue(server.received, "server should accept the TLS probe")
        self.assertEqual(server.received[0], b"")

    def test_matching_pin_allows_write_after_handshake(self):
        server = TlsServer(self.cert_a, self.key_a).start()
        time.sleep(0.05)
        ctx = tls.make_pinning_context(self.fp_a)
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
            ssock = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
            ssock.sendall(b"MQTT-CONNECT-SECRET")
            ssock.close()
        time.sleep(0.2)
        server.close()
        self.assertEqual(server.received, [b"MQTT-CONNECT-SECRET"])

    def test_mismatched_pin_raises_before_any_mqtt_bytes(self):
        server = TlsServer(self.cert_a, self.key_a).start()
        time.sleep(0.05)
        ctx = tls.make_pinning_context(self.fp_b)
        sent = False
        with self.assertRaises(tls.TlsPinMismatch):
            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
                ssock = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
                ssock.sendall(b"MQTT-CONNECT-SECRET")
                sent = True
        time.sleep(0.2)
        server.close()
        self.assertFalse(sent)
        for chunk in server.received:
            self.assertNotIn(b"MQTT", chunk)
            self.assertNotIn(b"SECRET", chunk)

    def test_tofu_then_swapped_cert_blocks_mqtt_auth(self):
        first = TlsServer(self.cert_a, self.key_a).start()
        time.sleep(0.05)
        pinned = tls.capture_peer_fingerprint("127.0.0.1", first.port, timeout=5)
        time.sleep(0.15)
        first.close()
        self.assertEqual(pinned, self.fp_a)

        mitm = TlsServer(self.cert_b, self.key_b).start()
        time.sleep(0.05)
        ctx = tls.make_pinning_context(pinned)
        with self.assertRaises(tls.TlsPinMismatch):
            with socket.create_connection(("127.0.0.1", mitm.port), timeout=5) as raw:
                ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        time.sleep(0.2)
        mitm.close()
        for chunk in mitm.received:
            self.assertEqual(chunk, b"")

    def test_wrap_socket_without_pin_fails_closed(self):
        with self.assertRaises(tls.TlsPinMismatch):
            tls.make_pinning_context("")
        with self.assertRaises(tls.TlsPinMismatch):
            tls.make_pinning_context("not-a-fingerprint")

    def test_deferred_handshake_cannot_send_before_pin(self):
        server = TlsServer(self.cert_a, self.key_a).start()
        time.sleep(0.05)
        ctx = tls.make_pinning_context(self.fp_b)
        ssock = None
        try:
            with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
                with self.assertRaises(tls.TlsPinMismatch):
                    ssock = ctx.wrap_socket(
                        raw,
                        server_hostname="127.0.0.1",
                        do_handshake_on_connect=False,
                    )
                    ssock.sendall(b"MQTT-CONNECT-SECRET")
        finally:
            if ssock is not None:
                try:
                    ssock.close()
                except OSError:
                    pass
            time.sleep(0.2)
            server.close()
        for chunk in server.received:
            self.assertNotIn(b"MQTT-CONNECT-SECRET", chunk)


class ClientAuthTimingTests(unittest.TestCase):
    """paho Client is stubbed so we can prove auth is not attached before TOFU."""

    def test_auth_not_attached_until_pin_exists(self):
        import sys
        import types

        events = []

        class FakeClient:
            def __init__(self, *args, **kwargs):
                self.on_connect = None
                self.on_message = None

            def username_pw_set(self, username, password):
                events.append(("auth", username, password))

            def tls_set_context(self, ctx):
                events.append(("tls_context", type(ctx).__name__))

            def connect(self, host, port, keepalive=30):
                events.append(("mqtt_connect", host, port))

            def disconnect(self):
                events.append(("disconnect",))

            def loop_forever(self):
                return

            def subscribe(self, *args, **kwargs):
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
        pkg.__path__ = [str(TLS_PATH.parent)]
        sys.modules["octoprint_openpanda"] = pkg
        sys.modules["octoprint_openpanda.tls"] = tls

        validate_path = TLS_PATH.parent / "validate.py"
        spec_v = importlib.util.spec_from_file_location(
            "octoprint_openpanda.validate", validate_path
        )
        validate = importlib.util.module_from_spec(spec_v)
        spec_v.loader.exec_module(validate)
        sys.modules["octoprint_openpanda.validate"] = validate

        client_path = TLS_PATH.parent / "client.py"
        spec_c = importlib.util.spec_from_file_location(
            "octoprint_openpanda.client", client_path
        )
        client_mod = importlib.util.module_from_spec(spec_c)
        spec_c.loader.exec_module(client_mod)

        class Log:
            def info(self, *args, **kwargs):
                return

            def warning(self, *args, **kwargs):
                return

            def error(self, *args, **kwargs):
                return

            def exception(self, *args, **kwargs):
                return

        with self.assertRaises(ValueError):
            client_mod.BambuLanClient(
                host="http://evil.example",
                access_code="12345678",
                serial="00M00A123456789",
                on_report=lambda *_: None,
                logger=Log(),
            )

        inst = client_mod.BambuLanClient(
            host="192.168.1.50",
            access_code="12345678",
            serial="00M00A123456789",
            on_report=lambda *_: None,
            logger=Log(),
            tls_fingerprint="a" * 64,
        )
        self.assertFalse(inst._auth_attached)
        self.assertEqual(events, [])
        inst._attach_auth()
        self.assertEqual(events, [("auth", "bblp", "12345678")])
        self.assertTrue(inst._auth_attached)
        inst.stop_print()


if __name__ == "__main__":
    unittest.main()
