import hashlib
import json
import re
import ssl
import threading

import paho.mqtt.client as mqtt

REPORT_TOPIC = "device/{serial}/report"
REQUEST_TOPIC = "device/{serial}/request"

PRINT_NAME = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._\- ]{0,118}\.(3mf|gcode)$",
    re.IGNORECASE,
)

TLS_PIN = "pin"
TLS_SYSTEM = "system"
TLS_INSECURE = "insecure_lan"


def safe_print_name(name):
    if not isinstance(name, str):
        return None
    if "/" in name or "\\" in name or ".." in name:
        return None
    if len(name) > 128:
        return None
    if not PRINT_NAME.match(name):
        return None
    return name


def cert_fingerprint(der_bytes):
    return hashlib.sha256(der_bytes).hexdigest()


class TlsPinMismatch(Exception):
    pass


class BambuLanClient:
    """LAN MQTTS client for Bambu Lab printers.

    Auth: username = bblp, password = LAN access code.
    Default TLS mode is certificate pinning (TOFU). Bambu printers use a
    self-signed cert, so public-CA verification fails; pinning still stops
    a later MITM from swapping the cert. ``insecure_lan`` is opt-in only.
    """

    def __init__(
        self,
        host,
        access_code,
        serial,
        on_report,
        logger,
        tls_mode=TLS_PIN,
        tls_fingerprint="",
        on_fingerprint=None,
    ):
        self.host = host
        self.serial = serial
        self.on_report = on_report
        self._logger = logger
        self.tls_mode = tls_mode if tls_mode in {TLS_PIN, TLS_SYSTEM, TLS_INSECURE} else TLS_PIN
        self.tls_fingerprint = (tls_fingerprint or "").strip().lower()
        self.on_fingerprint = on_fingerprint
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="octobambu-%s" % serial[-6:],
            userdata=None,
        )
        self._client.username_pw_set("bblp", access_code)
        self._client.tls_set_context(self._ssl_context())
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    def _ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.tls_mode == TLS_SYSTEM:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            return ctx
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if self.tls_mode == TLS_INSECURE:
            self._logger.warning(
                "tls_mode=insecure_lan: MQTT certificate is not verified"
            )
        return ctx

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="octobambu-mqtt").start()

    def stop(self):
        try:
            self._client.disconnect()
        except Exception:
            pass

    def _loop(self):
        self._client.connect(self.host, 8883, keepalive=30)
        self._client.loop_forever()

    def _peer_fingerprint(self):
        sock = self._client.socket()
        if sock is None or not hasattr(sock, "getpeercert"):
            return None
        der = sock.getpeercert(binary_form=True)
        if not der:
            return None
        return cert_fingerprint(der)

    def _enforce_pin(self):
        if self.tls_mode != TLS_PIN:
            return
        fp = self._peer_fingerprint()
        if not fp:
            raise TlsPinMismatch("MQTT peer certificate missing")
        if not self.tls_fingerprint:
            self.tls_fingerprint = fp
            if self.on_fingerprint:
                self.on_fingerprint(fp)
            self._logger.info("TOFU pinned printer cert sha256:%s", fp[:16])
            return
        if fp != self.tls_fingerprint:
            self._logger.error("TLS pin mismatch — refusing MQTT session")
            raise TlsPinMismatch("tls_fingerprint does not match peer cert")

    def _on_connect(self, client, _userdata, _flags, reason_code, _properties=None):
        try:
            self._enforce_pin()
        except TlsPinMismatch:
            client.disconnect()
            return
        if reason_code != 0 and getattr(reason_code, "value", reason_code) not in (0, "Success"):
            self._logger.warning("MQTT connect rc=%s", reason_code)
            return
        topic = REPORT_TOPIC.format(serial=self.serial)
        client.subscribe(topic)
        self._logger.info("Subscribed %s", topic)
        self.push({"pushing": {"sequence_id": "0", "command": "pushall"}})

    def _on_message(self, _client, _userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except ValueError:
            return
        if not isinstance(payload, dict):
            return
        self.on_report(payload)

    def push(self, body):
        topic = REQUEST_TOPIC.format(serial=self.serial)
        self._client.publish(topic, json.dumps(body))

    def pause(self):
        self.push({"print": {"sequence_id": "0", "command": "pause"}})

    def resume(self):
        self.push({"print": {"sequence_id": "0", "command": "resume"}})

    def stop(self):
        self.push({"print": {"sequence_id": "0", "command": "stop"}})

    def start_print(self, filename):
        safe = safe_print_name(filename)
        if not safe:
            self._logger.warning("Rejected print file name")
            return False
        self.push(
            {
                "print": {
                    "sequence_id": "0",
                    "command": "gcode_file",
                    "param": safe,
                }
            }
        )
        return True

    def set_chamber_light(self, on):
        self.push(
            {
                "system": {
                    "sequence_id": "0",
                    "command": "ledctrl",
                    "led_node": "chamber_light",
                    "led_mode": "on" if on else "off",
                }
            }
        )
