"""TCP port scanner for service discovery.

Scans target hosts for open ports and attempts banner grabbing
to identify unauthenticated services (HTTP APIs, MQTT brokers, etc.).
"""

import socket
import threading
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common IoT/interesting ports to scan
IOT_PORTS = [
    80, 443, 8080, 8443, 8008, 8009,   # HTTP/HTTPS/Cast
    8001, 8002,                          # Samsung TV WebSocket
    1883, 8883,                          # MQTT
    5353,                                # mDNS
    6668, 6669,                          # Tuya local
    554, 8554,                           # RTSP (cameras)
    5000, 5001,                          # Synology/UPnP
    49152, 49153, 49154,                 # UPnP
    22, 23, 2323,                        # SSH/Telnet
    21,                                  # FTP
    9090, 9100,                          # Various admin panels
    3000, 4000,                          # Dev servers
    1900,                                # SSDP
    5555,                                # Android ADB
]


@dataclass
class OpenPort:
    """A discovered open port with optional banner."""

    port: int
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    unauthenticated: bool = False


@dataclass
class ScanResult:
    """Port scan results for a single host."""

    ip: str
    open_ports: list[OpenPort] = field(default_factory=list)


# Known service identification by port and banner
SERVICE_MAP = {
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
    8008: "google-cast-http",
    8009: "google-cast-tls",
    8001: "samsung-tv-ws",
    8002: "samsung-tv-wss",
    1883: "mqtt",
    8883: "mqtt-tls",
    554: "rtsp",
    22: "ssh",
    23: "telnet",
    2323: "telnet-alt",
    21: "ftp",
    6668: "tuya-local",
    5555: "adb",
    1900: "ssdp",
}


def scan_port(ip: str, port: int, timeout: float = 1.5) -> OpenPort | None:
    """Scan a single port on a host.

    Returns:
        OpenPort if port is open, None if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Try banner grab
            banner = ""
            try:
                # Send a probe for HTTP-like services
                if port in (80, 8080, 8008, 8001, 8002, 3000, 4000, 5000, 9090):
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
                elif port in (1883,):
                    pass  # MQTT needs specific handshake
                else:
                    sock.sendall(b"\r\n")
                sock.settimeout(0.8)
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except (socket.timeout, OSError):
                pass

            service = SERVICE_MAP.get(port, "unknown")
            # Detect if service appears unauthenticated
            unauth = _check_unauthenticated(port, banner)

            sock.close()
            return OpenPort(port=port, service=service, banner=banner[:200], unauthenticated=unauth)
        sock.close()
    except (socket.timeout, OSError):
        pass
    return None


def _check_unauthenticated(port: int, banner: str) -> bool:
    """Heuristic: does this service appear to respond without auth?"""
    if not banner:
        return False
    banner_lower = banner.lower()
    # HTTP 200 without auth redirect = likely open
    if "200 ok" in banner_lower:
        return True
    # HTTP without 401/403
    if banner_lower.startswith("http/") and "401" not in banner and "403" not in banner:
        return True
    # MQTT connack
    if port == 1883 and len(banner) > 0:
        return True
    # Telnet prompt
    if port in (23, 2323) and ("login" in banner_lower or ">" in banner or "#" in banner):
        return True
    return False


def port_scan(ip: str, ports: list[int] | None = None, max_workers: int = 50, timeout: float = 1.5) -> ScanResult:
    """Scan multiple ports on a single host concurrently.

    Args:
        ip: Target IP address.
        ports: List of ports to scan. Defaults to IOT_PORTS.
        max_workers: Number of concurrent threads.
        timeout: Timeout per port in seconds.

    Returns:
        ScanResult with all open ports.
    """
    target_ports = ports or IOT_PORTS
    result = ScanResult(ip=ip)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in target_ports}
        for future in as_completed(futures):
            open_port = future.result()
            if open_port:
                result.open_ports.append(open_port)

    # Sort by port number
    result.open_ports.sort(key=lambda p: p.port)
    return result
