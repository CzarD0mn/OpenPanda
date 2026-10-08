# Security notes

| Control | Default |
| --- | --- |
| MQTT TLS | Pin (SHA-256), enforced in the TLS wrap **before** MQTT CONNECT |
| First-time pin | TLS-only TOFU probe — no access code on the wire |
| Malformed pin | Refuse to connect — never treated as empty, never falls back to TOFU |
| Print names | Basename `.3mf` / `.gcode` only |
| Host / serial / port | Validated before connect; MQTT port must be 8883 |
| Plugin API | Admin session / API key |
| Access code | Restricted OctoPrint setting, not logged, attached only after pin capture |
| Web console handshake | Refuses LAN connect; simulation only |

Bambu LAN MQTT uses a self-signed certificate. Pinning is the supported way to talk to the printer without leaving the session open to a swapped cert.

The pin is **not** checked in `on_connect`. A mismatch raises during `wrap_socket` / `do_handshake`, so paho never writes the MQTT CONNECT packet (username `bblp` + access code) to that peer.

## Pin mismatch, TOFU, and replacing a printer

On a pin mismatch the plugin refuses the session and logs both the expected and the seen SHA-256 fingerprint. On TOFU it logs the full fingerprint it trusted.

A mismatch means either the printer's certificate really changed (replacement, factory reset, some firmware updates) or something on the LAN is impersonating the printer. The plugin cannot tell these apart.

**Do not just clear `tls_fingerprint` to make a mismatch go away.** An empty pin re-runs TOFU, which trusts whatever answers on port 8883 at that moment. If an attacker caused the mismatch (for example with ARP spoofing), clearing the pin hands them the next TOFU and your LAN access code.

Instead, verify the printer's current fingerprint out-of-band and paste it:

```sh
openssl s_client -connect PRINTER_IP:8883 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2
```

Paste only the hex digest (colons are fine; the `sha256 Fingerprint=` label is not accepted). Run the check from a machine you trust, ideally over a different path than OctoPrint uses (for example wired directly or on the printer's own switch port), and compare it with the "seen" fingerprint in the OctoPrint log. If they match from two vantage points, paste it into `tls_fingerprint`. If they differ, treat the network as compromised.

The same applies to the TOFU fingerprint logged on first connect: compare it out-of-band once, then keep it.
