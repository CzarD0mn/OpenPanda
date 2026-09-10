import hashlib
import hmac
import re
import socket
import ssl

TLS_PIN = "pin"
TLS_SYSTEM = "system"
TLS_INSECURE = "insecure_lan"
TLS_MODES = {TLS_PIN, TLS_SYSTEM, TLS_INSECURE}
FINGERPRINT_HEX = re.compile(r"^[0-9a-f]{64}$")


class TlsPinMismatch(Exception):
    pass


def cert_fingerprint(der_bytes):
    if not der_bytes:
        return ""
    return hashlib.sha256(der_bytes).hexdigest()


def normalize_fingerprint(value):
    if not isinstance(value, str):
        return ""
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", value).lower()
    if not FINGERPRINT_HEX.match(hex_only):
        return ""
    return hex_only


def fingerprints_match(seen, expected):
    a = normalize_fingerprint(seen)
    b = normalize_fingerprint(expected)
    if not a or not b:
        return False
    return hmac.compare_digest(a, b)


def verify_pinned_socket(ssock, expected_fingerprint):
    expected = normalize_fingerprint(expected_fingerprint)
    if not expected:
        raise TlsPinMismatch("TLS pin missing — refusing handshake")
    try:
        der = ssock.getpeercert(binary_form=True)
    except Exception as exc:
        raise TlsPinMismatch("MQTT peer certificate missing") from exc
    seen = cert_fingerprint(der)
    if not fingerprints_match(seen, expected):
        raise TlsPinMismatch("tls_fingerprint does not match peer cert")
    return seen


class PinnedSSLSocket:
    """SSL socket proxy that blocks MQTT I/O until the pin matches."""

    def __init__(self, ssock, expected_fingerprint):
        object.__setattr__(self, "_ssock", ssock)
        object.__setattr__(self, "_expected", expected_fingerprint)
        object.__setattr__(self, "_pinned", False)
        try:
            der = ssock.getpeercert(binary_form=True)
        except Exception:
            der = None
        if der:
            self._verify()

    def _verify(self):
        verify_pinned_socket(self._ssock, self._expected)
        object.__setattr__(self, "_pinned", True)

    def do_handshake(self, *args, **kwargs):
        result = self._ssock.do_handshake(*args, **kwargs)
        self._verify()
        return result

    def _ensure_pinned(self):
        if self._pinned:
            return
        try:
            der = self._ssock.getpeercert(binary_form=True)
        except Exception:
            der = None
        if der:
            self._verify()
        else:
            self.do_handshake()
        if not self._pinned:
            raise TlsPinMismatch("TLS pin not verified — refusing MQTT I/O")

    def send(self, *args, **kwargs):
        self._ensure_pinned()
        return self._ssock.send(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        self._ensure_pinned()
        return self._ssock.sendall(*args, **kwargs)

    def write(self, *args, **kwargs):
        self._ensure_pinned()
        return self._ssock.write(*args, **kwargs)

    def recv(self, *args, **kwargs):
        self._ensure_pinned()
        return self._ssock.recv(*args, **kwargs)

    def recv_into(self, *args, **kwargs):
        self._ensure_pinned()
        return self._ssock.recv_into(*args, **kwargs)

    def makefile(self, *args, **kwargs):
        self._ensure_pinned()
        return self._ssock.makefile(*args, **kwargs)

    def close(self, *args, **kwargs):
        return self._ssock.close(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._ssock, name)

    def __setattr__(self, name, value):
        if name in {"_ssock", "_expected", "_pinned"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._ssock, name, value)


def make_pinning_context(expected_fingerprint):
    expected = normalize_fingerprint(expected_fingerprint)
    if not expected:
        raise TlsPinMismatch("TLS pin missing — refusing handshake")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    original_wrap = ctx.wrap_socket

    def wrap_socket(sock, *args, **kwargs):
        ssock = original_wrap(sock, *args, **kwargs)
        try:
            return PinnedSSLSocket(ssock, expected)
        except TlsPinMismatch:
            try:
                ssock.close()
            except Exception:
                pass
            raise

    ctx.wrap_socket = wrap_socket
    return ctx


def make_system_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    return ctx


def make_insecure_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def capture_peer_fingerprint(host, port, timeout=10):
    """TLS-only probe. No MQTT CONNECT and no access code are sent."""
    ctx = make_insecure_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            fp = cert_fingerprint(der)
            if not normalize_fingerprint(fp):
                raise TlsPinMismatch("MQTT peer certificate missing")
            return fp
