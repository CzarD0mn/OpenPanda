# Security notes

| Control | Default |
| --- | --- |
| MQTT TLS | Pin (TOFU SHA-256) |
| Print names | Basename `.3mf` / `.gcode` only |
| Plugin API | Admin session / API key |
| Access code | Restricted OctoPrint setting, not logged |
| Web console handshake | Refuses LAN connect; simulation only |

Bambu LAN MQTT uses a self-signed certificate. Pinning is the supported way to talk to the printer without leaving the session open to a swapped cert. Clear `tls_fingerprint` after replacing the printer or factory-resetting it.
