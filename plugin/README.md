# OctoBambu

OctoPrint plugin for Bambu Lab printers over LAN MQTT.

## Security

- MQTTS on port 8883. Default TLS mode is **certificate pinning**.
- The pin is checked during the TLS handshake, **before** MQTT CONNECT, so the LAN access code is not sent to a host whose certificate does not match.
- If no fingerprint is stored yet, a TLS-only TOFU probe captures the cert. That probe sends no MQTT credentials. The following MQTT session must present the same cert.
- `tls_mode=system` verifies against public CAs (usually fails on Bambu’s self-signed cert).
- `tls_mode=insecure_lan` disables verification — opt-in only, MITM possible.
- Print file names must be a basename matching `[name].3mf` or `[name].gcode` (no paths).
- Host, serial, access-code format, and port are validated before connect.
- Plugin API commands are admin-only. The LAN access code is a restricted setting and is never logged.
- Do not expose MQTT 8883 or OctoPrint to the public internet.

The in-browser console is a **simulator**. It cannot open MQTTS to a printer on your LAN.

## Install

Copy `plugin/` into an OctoPrint environment and install with `pip install .` from that folder, or drop the package in Plugin Manager. Enable LAN mode on the printer, then set host, access code, and serial.
