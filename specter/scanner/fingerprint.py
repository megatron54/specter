"""Device fingerprinting.

Identifies device types based on MAC OUI, open ports, and mDNS service data.
"""

from dataclasses import dataclass, field

# Known MAC OUI prefixes for common IoT manufacturers
OUI_DATABASE: dict[str, str] = {
    "f4:f5:d8": "Google Inc.",
    "54:60:09": "Google Inc.",
    "30:fd:38": "Google Inc.",
    "a4:77:33": "Google Inc.",
    "1c:f2:9a": "Google Inc.",
    "48:d6:d5": "Google Inc.",
    "e4:f0:42": "Google Inc.",
    "d4:a9:28": "Samsung Electronics",
    "8c:79:f5": "Samsung Electronics",
    "ac:23:3f": "Shenzhen Tuya",
    "70:b3:d5": "Espressif (ESP32/ESP8266)",
    "24:6f:28": "Espressif (ESP32/ESP8266)",
    "dc:4f:22": "Espressif (ESP32/ESP8266)",
}


@dataclass
class DeviceProfile:
    """Fingerprinted device profile."""

    ip: str
    mac: str
    vendor: str = "Unknown"
    device_type: str = "Unknown"
    services: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def lookup_oui(mac: str) -> str:
    """Look up manufacturer by MAC OUI prefix.

    Args:
        mac: MAC address in format 'xx:xx:xx:xx:xx:xx'.

    Returns:
        Manufacturer name or 'Unknown'.
    """
    prefix = mac.lower()[:8]
    return OUI_DATABASE.get(prefix, "Unknown")


def fingerprint_device(ip: str, mac: str, services: list[str] | None = None) -> DeviceProfile:
    """Create a device profile from available information.

    Args:
        ip: Device IP address.
        mac: Device MAC address.
        services: List of mDNS service types the device advertises.

    Returns:
        DeviceProfile with best-guess identification.
    """
    vendor = lookup_oui(mac)
    device_type = "Unknown"
    svc_list = services or []

    # Classify by service advertisements
    if "_googlecast._tcp.local." in svc_list:
        device_type = "Google Cast"
    elif "_mqtt._tcp.local." in svc_list:
        device_type = "MQTT Device"
    elif "_hap._tcp.local." in svc_list:
        device_type = "HomeKit Device"

    # Refine by vendor
    if vendor == "Google Inc." and device_type == "Unknown":
        device_type = "Google Device"
    elif vendor == "Samsung Electronics":
        device_type = "Samsung Device"
    elif "Tuya" in vendor:
        device_type = "Tuya IoT Device"
    elif "Espressif" in vendor:
        device_type = "ESP-based IoT Device"

    return DeviceProfile(
        ip=ip,
        mac=mac,
        vendor=vendor,
        device_type=device_type,
        services=svc_list,
    )
