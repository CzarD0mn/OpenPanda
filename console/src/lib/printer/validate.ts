const SAFE_PRINT_FILE = /^[A-Za-z0-9][A-Za-z0-9._\- ]{0,118}\.(3mf|gcode)$/i;
const HOST =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})$/i;
const SERIAL = /^[A-Z0-9]{8,32}$/;
const ACCESS_CODE = /^[0-9A-Za-z]{6,16}$/;

export function isSafePrintFileName(name: string): boolean {
  if (!name || name.length > 128) return false;
  if (name.includes("/") || name.includes("\\") || name.includes("..")) {
    return false;
  }
  if ([...name].some((c) => c.charCodeAt(0) < 32)) return false;
  return SAFE_PRINT_FILE.test(name);
}

export function isValidLanHost(host: string): boolean {
  const trimmed = host.trim();
  if (!trimmed || trimmed.length > 253) return false;
  if (trimmed.includes("://") || trimmed.includes("/") || trimmed.includes(" ")) {
    return false;
  }
  return HOST.test(trimmed);
}

export function isValidSerial(serial: string): boolean {
  return SERIAL.test(serial.trim().toUpperCase());
}

export function isValidAccessCode(code: string): boolean {
  return ACCESS_CODE.test(code.trim());
}

export function lanHandshakeBlockedReason(): string {
  return "This console cannot open MQTTS to a printer on your LAN. Use the simulated printer here, or install the plugin on OctoPrint on the same network as the machine.";
}
