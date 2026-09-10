# Security notes

| Control | Default |
| --- | --- |
| MQTT TLS | Pin (SHA-256), enforced in the TLS wrap **before** MQTT CONNECT |
| First-time pin | TLS-only TOFU probe — no access code on the wire |
| Print names | Basename `.3mf` / `.gcode` only |
| Host / serial / port | Validated before connect; MQTT port must be 8883 |
| Plugin API | Admin session / API key |
| Access code | Restricted OctoPrint setting, not logged, attached only after pin capture |
| Web console handshake | Refuses LAN connect; simulation only |

Bambu LAN MQTT uses a self-signed certificate. Pinning is the supported way to talk to the printer without leaving the session open to a swapped cert.

The pin is **not** checked in `on_connect`. A mismatch raises during `wrap_socket` / `do_handshake`, so paho never writes the MQTT CONNECT packet (username `bblp` + access code) to that peer.

Clear `tls_fingerprint` after replacing the printer or factory-resetting it. Prefer pasting the printer cert fingerprint into settings so TOFU is not needed on a new LAN.
