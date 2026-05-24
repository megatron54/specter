"""ARP-based network scanner.

Performs ARP sweep across a subnet to discover all live hosts,
collecting IP and MAC addresses for further fingerprinting.
"""

from dataclasses import dataclass
from scapy.all import ARP, Ether, srp


@dataclass
class Host:
    """A discovered network host."""

    ip: str
    mac: str
    vendor: str = "Unknown"


def arp_scan(subnet: str, timeout: float = 2.0, retries: int = 2) -> list[Host]:
    """Perform an ARP scan with multiple passes to catch sleepy devices.

    Args:
        subnet: CIDR notation (e.g., '192.168.1.0/24').
        timeout: Seconds to wait for responses per pass.
        retries: Number of ARP sweep passes (catches devices that miss first packet).

    Returns:
        List of discovered hosts (deduplicated by IP).
    """
    seen: dict[str, str] = {}  # ip -> mac

    for attempt in range(retries):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        # Use shorter timeout on retry passes (devices already primed)
        t = timeout if attempt == 0 else 1.0
        result = srp(packet, timeout=t, verbose=False, retry=0)[0]
        for _, received in result:
            if received.psrc not in seen:
                seen[received.psrc] = received.hwsrc

    return [Host(ip=ip, mac=mac) for ip, mac in seen.items()]
