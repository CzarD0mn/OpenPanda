import re

PRINT_NAME = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._\- ]{0,118}\.(3mf|gcode)\Z",
    re.IGNORECASE,
)
HOST_IP = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\Z"
)
HOST_DNS = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\Z",
    re.IGNORECASE,
)
HOST_LOCAL = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.local)?\Z",
    re.IGNORECASE,
)
SERIAL = re.compile(r"^[A-Z0-9]{8,32}\Z")
ACCESS_CODE = re.compile(r"^[0-9A-Za-z]{6,16}\Z")
MQTT_PORT = 8883


def safe_print_name(name):
    if not isinstance(name, str):
        return None
    if "/" in name or "\\" in name or ".." in name:
        return None
    if len(name) > 128:
        return None
    if any(ord(c) < 32 for c in name):
        return None
    if not PRINT_NAME.match(name):
        return None
    return name


def is_valid_lan_host(host):
    if not isinstance(host, str):
        return False
    trimmed = host.strip()
    if not trimmed or len(trimmed) > 253:
        return False
    if "://" in trimmed or "/" in trimmed or " " in trimmed:
        return False
    if trimmed.startswith(".") or trimmed in {".", ".."}:
        return False
    return bool(
        HOST_IP.match(trimmed)
        or HOST_DNS.match(trimmed)
        or HOST_LOCAL.match(trimmed)
    )


def is_valid_serial(serial):
    if not isinstance(serial, str):
        return False
    return bool(SERIAL.match(serial.strip().upper()))


def is_valid_access_code(code):
    if not isinstance(code, str):
        return False
    return bool(ACCESS_CODE.match(code.strip()))


def is_valid_mqtt_port(port):
    try:
        return int(port) == MQTT_PORT
    except (TypeError, ValueError):
        return False
