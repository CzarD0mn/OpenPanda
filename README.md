# OpenPanda

Independent OctoPrint plugin that talks to Bambu Lab printers over LAN MQTT, plus a simulated control console.

## Names

**OpenPanda** is this project’s name. It is not affiliated with, endorsed by, or a product of Bambu Lab or OctoPrint / Gina Häußge.

References to Bambu Lab, OctoPrint, printer models, and LAN MQTT fields describe the machines and protocols the plugin speaks. Those names and marks belong to their owners. This repo does not claim them.

## Security (0.6.0)

- Default TLS is **certificate pinning**. The pin is enforced during the TLS handshake, **before** MQTT CONNECT, so the access code is not sent to a swapped cert.
- First-time TOFU is a TLS-only probe (no MQTT credentials). Later sessions must present the same SHA-256 fingerprint.
- Print file names must be a basename ending in `.3mf` or `.gcode`.
- Host, serial, access-code format, and port `8883` are validated before connect.
- Plugin API is admin-only. Access code is a restricted setting and is never logged.
- The web console **refuses** a live LAN handshake. It cannot open MQTTS to your printer.

See [plugin/SECURITY.md](plugin/SECURITY.md).

## Plugin

Install from [`plugin/`](plugin/) into OctoPrint ≥ 1.10. Enable LAN mode on the printer, then set host, access code, and serial.
