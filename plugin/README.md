# OctoBambu

OctoPrint plugin for Bambu Lab printers over LAN MQTT.

## Security

- MQTTS on port 8883. Default TLS mode is **certificate pinning** (TOFU). The first successful connection stores a SHA-256 fingerprint of the printer certificate; a later mismatch drops the session.
- `tls_mode=system` verifies against public CAs (usually fails on Bambu’s self-signed cert).
- `tls_mode=insecure_lan` disables verification — opt-in only, MITM possible.
- Print file names must be a basename matching `[name].3mf` or `[name].gcode` (no paths).
- Plugin API commands are admin-only. The LAN access code is a restricted setting and is never logged.
- Do not expose MQTT 8883 or OctoPrint to the public internet.

The in-browser console is a **simulator**. It cannot open MQTTS to a printer on your LAN.

## Install

Copy `plugin/` into an OctoPrint environment and install with `pip install .` from that folder, or drop the package in Plugin Manager. Enable LAN mode on the printer, then set host, access code, and serial.
