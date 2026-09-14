export const PLUGIN_FILES: { path: string; body: string }[] = [
  {
    path: "octoprint_openpanda/tls.py",
    body: `def capture_peer_fingerprint(host, port, timeout=10):
    """TLS-only probe. No MQTT CONNECT and no access code are sent."""
    ...

def make_pinning_context(expected_fingerprint):
    # wrap_socket returns PinnedSSLSocket
    # send/recv raise TlsPinMismatch until SHA-256 matches
    ...
`,
  },
  {
    path: "octoprint_openpanda/client.py",
    body: `class BambuLanClient:
    """MQTTS client. Pin is enforced BEFORE MQTT CONNECT."""

    def _loop(self):
        if self.tls_mode == TLS_PIN and not self.tls_fingerprint:
            fp = capture_peer_fingerprint(self.host, self.port)
            self.tls_fingerprint = fp  # TOFU, no MQTT auth yet
        self._attach_auth()  # username_pw_set only after pin exists
        self._client.tls_set_context(self._ssl_context())
        self._client.connect(self.host, self.port, keepalive=30)

    def start_print(self, filename):
        safe = safe_print_name(filename)
        if not safe:
            return False
        self.push({"print": {"command": "gcode_file", "param": safe}})
        return True
`,
  },
  {
    path: "octoprint_openpanda/__init__.py",
    body: `class OpenPandaPlugin(...):
    def get_settings_defaults(self):
        return {
            "host": "", "access_code": "", "serial": "",
            "tls_mode": "pin", "tls_fingerprint": "",
            "mqtt_port": 8883,
        }

    def get_settings_restricted_paths(self):
        return {"admin": [["access_code"], ["tls_fingerprint"]]}

    def is_api_adminonly(self):
        return True

    def _connect(self):
        if not is_valid_lan_host(host):
            return
        if not is_valid_serial(serial):
            return
        if not is_valid_access_code(code):
            return
        if not is_valid_mqtt_port(port):
            return
        self._client = BambuLanClient(...)

    def on_api_command(self, command, data):
        if command == "print":
            name = safe_print_name((data or {}).get("file"))
            if not name:
                return dict(error="invalid_file")
            self._client.start_print(name)
        elif command == "stop":
            self._client.stop_print()
`,
  },
  {
    path: "SECURITY.md",
    body: `Default TLS: pin (SHA-256) during wrap/handshake, before MQTT CONNECT.
TOFU probe: TLS only — access code is not sent.
Print names: basename .3mf / .gcode only.
Host/serial/port validated. MQTT port must be 8883.
Plugin API: admin only.
Access code: restricted setting, never logged.
Web console: refuses LAN MQTT; simulation only.
`,
  },
];
