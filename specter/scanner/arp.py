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


def arp_scan(subnet: str, timeout: float = 3.0) -> list[Host]:
    """Perform an ARP scan on the given subnet.

    Args:
        subnet: CIDR notation (e.g., '192.168.1.0/24').
        timeout: Seconds to wait for responses.

    Returns:
        List of discovered hosts.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    result = srp(packet, timeout=timeout, verbose=False)[0]

    hosts = []
    for _, received in result:
        hosts.append(
            Host(
                ip=received.psrc,
                mac=received.hwsrc,
            )
        )
    return hosts
