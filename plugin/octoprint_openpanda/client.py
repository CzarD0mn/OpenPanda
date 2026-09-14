import json
import threading

import paho.mqtt.client as mqtt

from .tls import (
    TLS_INSECURE,
    TLS_MODES,
    TLS_PIN,
    TLS_SYSTEM,
    TlsPinMismatch,
    capture_peer_fingerprint,
    make_insecure_context,
    make_pinning_context,
    make_system_context,
    normalize_fingerprint,
)
from .validate import (
    MQTT_PORT,
    is_valid_access_code,
    is_valid_lan_host,
    is_valid_serial,
    safe_print_name,
)

REPORT_TOPIC = "device/{serial}/report"
REQUEST_TOPIC = "device/{serial}/request"


class BambuLanClient:
    """LAN MQTTS client for Bambu Lab printers.

    Auth: username = bblp, password = LAN access code.

    Default TLS mode is certificate pinning. The pin is enforced inside
    SSL wrap/handshake — before MQTT CONNECT, so the access code is not
    sent to a peer whose cert does not match. An empty stored pin is
    filled with a TLS-only TOFU probe that also sends no MQTT credentials.
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
        port=MQTT_PORT,
    ):
        if not is_valid_lan_host(host):
            raise ValueError("invalid host")
        if not is_valid_serial(serial):
            raise ValueError("invalid serial")
        if not is_valid_access_code(access_code):
            raise ValueError("invalid access code")
        if int(port) != MQTT_PORT:
            raise ValueError("invalid mqtt port")
        self.host = host.strip()
        self.serial = serial.strip().upper()
        self._access_code = access_code
        self.port = MQTT_PORT
        self.on_report = on_report
        self._logger = logger
        self.tls_mode = tls_mode if tls_mode in TLS_MODES else TLS_PIN
        self.tls_fingerprint = normalize_fingerprint(tls_fingerprint)
        self.on_fingerprint = on_fingerprint
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="openpanda-%s" % self.serial[-6:],
            userdata=None,
        )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._auth_attached = False

    def _ssl_context(self):
        if self.tls_mode == TLS_SYSTEM:
            return make_system_context()
        if self.tls_mode == TLS_INSECURE:
            self._logger.warning(
                "tls_mode=insecure_lan: MQTT certificate is not verified"
            )
            return make_insecure_context()
        return make_pinning_context(self.tls_fingerprint)

    def _attach_auth(self):
        if self._auth_attached:
            return
        self._client.username_pw_set("bblp", self._access_code)
        self._auth_attached = True

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="openpanda-mqtt").start()

    def disconnect(self):
        try:
            self._client.disconnect()
        except Exception:
            pass

    def _loop(self):
        try:
            if self.tls_mode == TLS_PIN and not self.tls_fingerprint:
                fp = capture_peer_fingerprint(self.host, self.port)
                self.tls_fingerprint = fp
                if self.on_fingerprint:
                    self.on_fingerprint(fp)
                self._logger.info(
                    "TOFU captured printer cert sha256:%s (no MQTT auth sent)",
                    fp[:16],
                )
            self._attach_auth()
            self._client.tls_set_context(self._ssl_context())
            self._client.connect(self.host, self.port, keepalive=30)
            self._client.loop_forever()
        except TlsPinMismatch:
            self._logger.error("TLS pin mismatch — refusing MQTT session")
        except Exception:
            self._logger.exception("MQTT loop ended")

    def _on_connect(self, client, _userdata, _flags, reason_code, _properties=None):
        if reason_code != 0 and getattr(reason_code, "value", reason_code) not in (
            0,
            "Success",
        ):
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

    def stop_print(self):
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
