"""Continuous network monitoring — detects new/departed devices in real-time.

Runs periodic ARP scans in the background, tracks device state changes,
and emits events when devices join or leave the network.
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from scapy.all import conf


@dataclass
class DeviceEvent:
    """A network device state change event."""

    timestamp: str
    event_type: str  # "joined", "left", "returned"
    ip: str
    mac: str
    name: str = ""


class NetworkMonitor:
    """Background network monitor that detects device arrivals/departures.

    Args:
        subnet: Network subnet to monitor (e.g., "192.168.1.0/24").
        interval: Seconds between scans.
        on_event: Callback fired for each device event.
        offline_threshold: Number of missed scans before marking device as "left".
    """

    def __init__(
        self,
        subnet: Optional[str] = None,
        interval: float = 30.0,
        on_event: Optional[Callable[[DeviceEvent], None]] = None,
        offline_threshold: int = 3,
    ):
        if not subnet:
            ip = conf.route.route("0.0.0.0")[1]
            subnet = f"{ip}/24"
        self.subnet = subnet
        self.interval = interval
        self.on_event = on_event
        self.offline_threshold = offline_threshold

        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Tracking state: mac -> {ip, mac, name, last_seen, missed_count, online}
        self.known_devices: dict[str, dict] = {}
        self.events: list[DeviceEvent] = []

    def start(self) -> None:
        """Start background monitoring."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def get_online_devices(self) -> list[dict]:
        """Return currently online devices."""
        return [d for d in self.known_devices.values() if d.get("online")]

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        from specter.scanner.arp import arp_scan

        while self._running:
            try:
                hosts = arp_scan(self.subnet, timeout=3.0)
                current_macs = set()

                for host in hosts:
                    current_macs.add(host.mac)

                    if host.mac not in self.known_devices:
                        # New device
                        self.known_devices[host.mac] = {
                            "ip": host.ip,
                            "mac": host.mac,
                            "name": "",
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                            "missed_count": 0,
                            "online": True,
                        }
                        self._emit(DeviceEvent(
                            timestamp=datetime.now().isoformat(),
                            event_type="joined",
                            ip=host.ip,
                            mac=host.mac,
                        ))
                    else:
                        dev = self.known_devices[host.mac]
                        was_offline = not dev["online"]
                        dev["ip"] = host.ip
                        dev["last_seen"] = datetime.now().isoformat()
                        dev["missed_count"] = 0
                        dev["online"] = True

                        if was_offline:
                            self._emit(DeviceEvent(
                                timestamp=datetime.now().isoformat(),
                                event_type="returned",
                                ip=host.ip,
                                mac=host.mac,
                            ))

                # Check for departed devices
                for mac, dev in self.known_devices.items():
                    if mac not in current_macs and dev["online"]:
                        dev["missed_count"] += 1
                        if dev["missed_count"] >= self.offline_threshold:
                            dev["online"] = False
                            self._emit(DeviceEvent(
                                timestamp=datetime.now().isoformat(),
                                event_type="left",
                                ip=dev["ip"],
                                mac=mac,
                            ))

            except Exception:
                pass

            # Wait for next interval
            for _ in range(int(self.interval)):
                if not self._running:
                    break
                time.sleep(1)

    def _emit(self, event: DeviceEvent) -> None:
        """Store and emit a device event."""
        self.events.append(event)
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass
