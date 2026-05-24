"""Device name resolution.

Attempts to resolve friendly names for network devices using multiple methods:
1. mDNS service properties (fn, n, md fields)
2. Google Cast API (port 8008, unauthenticated)
3. NetBIOS name resolution
4. SSDP/UPnP device descriptions
5. Reverse DNS lookup
6. DHCP hostname (from router, if available)
"""

import socket
import struct
from xml.etree import ElementTree

import httpx


def resolve_names(hosts: list[dict], service_map: dict, services: list) -> dict[str, str]:
    """Resolve device names using all available methods.

    Args:
        hosts: List of dicts with 'ip' and 'mac' keys.
        service_map: Map of IP -> list of mDNS service types.
        services: Raw mDNS service objects.

    Returns:
        Dict mapping IP -> friendly name.
    """
    name_map: dict[str, str] = {}

    # 1. mDNS service properties
    for svc in services:
        if svc.host and svc.host not in name_map:
            friendly = (
                svc.properties.get("fn") or
                svc.properties.get("n") or
                svc.properties.get("md") or
                svc.properties.get("name") or
                ""
            )
            if friendly:
                name_map[svc.host] = friendly
            elif svc.name:
                # Extract name from service name (e.g., "Living Room._googlecast._tcp.local.")
                parts = svc.name.split("._")
                if parts:
                    name_map[svc.host] = parts[0]

    # 2. Google Cast API (unauthenticated, port 8008)
    for host in hosts:
        ip = host["ip"] if isinstance(host, dict) else host.ip
        if ip in name_map:
            continue
        svc_list = service_map.get(ip, [])
        if "_googlecast._tcp.local." in svc_list:
            try:
                resp = httpx.get(f"http://{ip}:8008/setup/eureka_info", timeout=2.0)
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get("name", "")
                    if name:
                        name_map[ip] = name
            except Exception:
                pass

    # 3. NetBIOS name resolution
    for host in hosts:
        ip = host["ip"] if isinstance(host, dict) else host.ip
        if ip in name_map:
            continue
        name = _netbios_lookup(ip)
        if name:
            name_map[ip] = name

    # 4. SSDP/UPnP — query device description XML
    for host in hosts:
        ip = host["ip"] if isinstance(host, dict) else host.ip
        if ip in name_map:
            continue
        name = _upnp_lookup(ip)
        if name:
            name_map[ip] = name

    # 5. Reverse DNS
    for host in hosts:
        ip = host["ip"] if isinstance(host, dict) else host.ip
        if ip in name_map:
            continue
        name = _reverse_dns(ip)
        if name:
            name_map[ip] = name

    return name_map


def _netbios_lookup(ip: str) -> str | None:
    """Query NetBIOS name for a host (Windows/Samba devices)."""
    try:
        # NetBIOS Name Service query on UDP 137
        # Transaction ID + flags + questions + etc
        payload = (
            b"\xa2\x48"  # Transaction ID
            b"\x00\x00"  # Flags
            b"\x00\x01"  # Questions
            b"\x00\x00"  # Answer RRs
            b"\x00\x00"  # Authority RRs
            b"\x00\x00"  # Additional RRs
            b"\x20"      # Name length (32)
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Encoded * (wildcard)
            b"\x00"      # Null terminator
            b"\x00\x21"  # Type: NBSTAT
            b"\x00\x01"  # Class: IN
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 57:
            # Parse response — name starts after header
            num_names = data[56]
            if num_names > 0:
                # First name entry starts at offset 57, 18 bytes each
                name_bytes = data[57:57 + 15]
                name = name_bytes.decode("ascii", errors="ignore").strip()
                if name and name != "\x00" * 15:
                    return name
    except (socket.timeout, OSError):
        pass
    return None


def _upnp_lookup(ip: str) -> str | None:
    """Try to get device name from UPnP device description."""
    # Common UPnP description URLs
    urls = [
        f"http://{ip}:49152/description.xml",
        f"http://{ip}:1900/description.xml",
        f"http://{ip}:8080/description.xml",
        f"http://{ip}/description.xml",
        f"http://{ip}:49153/dmr/SamsungMRDesc.xml",
        f"http://{ip}:8001/api/v2/",
    ]
    try:
        client = httpx.Client(timeout=1.5)
        for url in urls:
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    content = resp.text
                    # Try JSON (Samsung TV API)
                    if url.endswith("/api/v2/"):
                        try:
                            data = resp.json()
                            name = data.get("device", {}).get("name") or data.get("name")
                            if name:
                                return name
                        except Exception:
                            pass
                    # Try XML (UPnP)
                    elif "<friendlyName>" in content:
                        try:
                            # Handle namespaces
                            content_clean = content.replace(' xmlns="', ' xmlns_="')
                            root = ElementTree.fromstring(content_clean)
                            fn = root.find(".//friendlyName")
                            if fn is not None and fn.text:
                                return fn.text
                        except Exception:
                            pass
            except (httpx.ConnectError, httpx.ReadTimeout):
                continue
        client.close()
    except Exception:
        pass
    return None


def _reverse_dns(ip: str) -> str | None:
    """Attempt reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Filter out generic PTR records
        if hostname and not hostname.startswith(ip.replace(".", "-")) and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass
    return None
