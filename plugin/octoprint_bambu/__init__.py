import octoprint.plugin

from .client import BambuLanClient, safe_print_name


class BambuPlugin(
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.AssetPlugin,
    octoprint.plugin.TemplatePlugin,
    octoprint.plugin.StartupPlugin,
    octoprint.plugin.ShutdownPlugin,
    octoprint.plugin.SimpleApiPlugin,
):
    def __init__(self):
        self._client = None

    def get_settings_defaults(self):
        return {
            "host": "",
            "access_code": "",
            "serial": "",
            "model": "X1 Carbon",
            "mqtt_port": 8883,
            "tls_mode": "pin",
            "tls_fingerprint": "",
        }

    def get_settings_restricted_paths(self):
        return {"admin": [["access_code"], ["tls_fingerprint"]], "user": [], "never": []}

    def on_after_startup(self):
        self._connect()

    def on_shutdown(self):
        if self._client:
            self._client.stop()
            self._client = None

    def _connect(self):
        host = (self._settings.get(["host"]) or "").strip()
        code = self._settings.get(["access_code"]) or ""
        serial = (self._settings.get(["serial"]) or "").strip()
        if not (host and code and serial):
            self._logger.info("Bambu LAN settings incomplete")
            return
        if self._client:
            self._client.stop()
        self._client = BambuLanClient(
            host=host,
            access_code=code,
            serial=serial,
            on_report=self._on_report,
            logger=self._logger,
            tls_mode=self._settings.get(["tls_mode"]) or "pin",
            tls_fingerprint=self._settings.get(["tls_fingerprint"]) or "",
            on_fingerprint=self._store_fingerprint,
        )
        self._client.start()

    def _store_fingerprint(self, fingerprint):
        self._settings.set(["tls_fingerprint"], fingerprint)
        self._settings.save()

    def _on_report(self, payload):
        print_ = payload.get("print") if isinstance(payload, dict) else None
        if not isinstance(print_, dict):
            return
        gcode_state = print_.get("gcode_state", "IDLE")
        try:
            percent = float(print_.get("mc_percent", 0) or 0)
        except (TypeError, ValueError):
            percent = 0.0
        self._plugin_manager.send_plugin_message(
            self._identifier,
            {"state": gcode_state, "progress": percent},
        )

    def get_api_commands(self):
        return dict(pause=[], resume=[], stop=[], print=["file"], light=["on"])

    def is_api_adminonly(self):
        return True

    def on_api_command(self, command, data):
        if not self._client:
            return
        if command == "pause":
            self._client.pause()
        elif command == "resume":
            self._client.resume()
        elif command == "stop":
            self._client.stop()
        elif command == "print":
            name = safe_print_name((data or {}).get("file"))
            if not name:
                return dict(error="invalid_file")
            self._client.start_print(name)
        elif command == "light":
            self._client.set_chamber_light(bool((data or {}).get("on")))

    def get_template_configs(self):
        return [dict(type="settings", custom_bindings=False)]

    def get_assets(self):
        return dict(js=["js/bambu.js"], css=["css/bambu.css"])

    def get_update_information(self):
        return dict(
            bambu=dict(
                displayName="OctoBambu",
                displayVersion=self._plugin_version,
                type="github_release",
                user="CzarD0mn",
                repo="OctoBambu",
                current=self._plugin_version,
            )
        )


__plugin_name__ = "OctoBambu"
__plugin_pythoncompat__ = ">=3.9,<4"
__plugin_implementation__ = BambuPlugin()
