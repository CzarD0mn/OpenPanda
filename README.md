# OctoBambu

OctoPrint plugin for Bambu Lab printers over LAN MQTT, plus a simulated control console.

## Security (0.5.0)

- Default TLS is **certificate pinning** (TOFU SHA-256). `insecure_lan` is opt-in.
- Print file names must be a basename ending in `.3mf` or `.gcode`.
- Plugin API is admin-only. Access code is a restricted setting and is never logged.
- The web console **refuses** a live LAN handshake. It cannot open MQTTS to your printer.

See [plugin/SECURITY.md](plugin/SECURITY.md).

## Plugin

Install from [`plugin/`](plugin/) into OctoPrint ≥ 1.10. Enable LAN mode on the printer, then set host, access code, and serial.
