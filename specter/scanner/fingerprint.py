"""Device fingerprinting.

Identifies device types based on MAC OUI, open ports, and mDNS service data.
Uses the full IEEE OUI database (39,000+ vendors) for accurate manufacturer identification.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

# Load full OUI database
_OUI_DB_PATH = Path(__file__).parent / "oui_database.json"
_OUI_DB: dict[str, str] = {}

if _OUI_DB_PATH.exists():
    with open(_OUI_DB_PATH, "r") as f:
        _OUI_DB = json.load(f)


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
    """Look up manufacturer by MAC OUI prefix using full IEEE database.

    Args:
        mac: MAC address in format 'xx:xx:xx:xx:xx:xx'.

    Returns:
        Manufacturer name or 'Unknown'.
    """
    prefix = mac.lower()[:8]
    return _OUI_DB.get(prefix, "Unknown")


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
    vendor_lower = vendor.lower()

    # Classify by service advertisements
    if "_googlecast._tcp.local." in svc_list:
        device_type = "Google Cast"
    elif "_airplay._tcp.local." in svc_list:
        device_type = "Apple AirPlay"
    elif "_raop._tcp.local." in svc_list:
        device_type = "Apple AirPlay"
    elif "_mqtt._tcp.local." in svc_list:
        device_type = "MQTT Device"
    elif "_hap._tcp.local." in svc_list:
        device_type = "HomeKit Device"
    elif "_ipp._tcp.local." in svc_list or "_printer._tcp.local." in svc_list:
        device_type = "Printer"
    elif "_smb._tcp.local." in svc_list:
        device_type = "File Server"
    elif "_http._tcp.local." in svc_list:
        device_type = "HTTP Device"

    # Refine by vendor if still unknown
    if device_type == "Unknown":
        if "google" in vendor_lower:
            device_type = "Google Device"
        elif "samsung" in vendor_lower:
            device_type = "Samsung Device"
        elif "apple" in vendor_lower:
            device_type = "Apple Device"
        elif "amazon" in vendor_lower:
            device_type = "Amazon Device"
        elif "tuya" in vendor_lower or "smartlife" in vendor_lower:
            device_type = "Tuya IoT"
        elif "espressif" in vendor_lower:
            device_type = "ESP IoT Device"
        elif "xiaomi" in vendor_lower or "beijing xiaomi" in vendor_lower:
            device_type = "Xiaomi Device"
        elif "tp-link" in vendor_lower or "tplink" in vendor_lower:
            device_type = "TP-Link Device"
        elif "philips" in vendor_lower or "signify" in vendor_lower:
            device_type = "Philips/Hue"
        elif "sonos" in vendor_lower:
            device_type = "Sonos Speaker"
        elif "ring" in vendor_lower:
            device_type = "Ring Device"
        elif "nest" in vendor_lower:
            device_type = "Nest Device"
        elif "epson" in vendor_lower or "seiko epson" in vendor_lower:
            device_type = "Printer"
        elif "hp" in vendor_lower or "hewlett" in vendor_lower:
            device_type = "Printer/PC"
        elif "intel" in vendor_lower or "dell" in vendor_lower or "lenovo" in vendor_lower:
            device_type = "Computer"
        elif "murata" in vendor_lower or "hon hai" in vendor_lower or "foxconn" in vendor_lower:
            device_type = "Consumer Electronics"

    return DeviceProfile(
        ip=ip,
        mac=mac,
        vendor=vendor,
        device_type=device_type,
        services=svc_list,
    )
