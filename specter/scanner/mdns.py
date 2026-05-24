"""mDNS service discovery.

Discovers IoT devices advertising services via mDNS/DNS-SD,
with a focus on Google Cast devices (_googlecast._tcp.local.).
"""

from dataclasses import dataclass, field
from zeroconf import ServiceBrowser, Zeroconf, ServiceStateChange
import time


# Services to scan for — comprehensive list for IoT/consumer devices
SERVICES = [
    "_googlecast._tcp.local.",
    "_googlerpc._tcp.local.",
    "_mqtt._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_hap._tcp.local.",           # HomeKit
    "_airplay._tcp.local.",       # Apple AirPlay
    "_raop._tcp.local.",          # Apple Remote Audio
    "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.",
    "_ipp._tcp.local.",           # Printing
    "_ipps._tcp.local.",          # Printing (secure)
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",  # Printing raw
    "_scanner._tcp.local.",
    "_smb._tcp.local.",           # Samba/file sharing
    "_afpovertcp._tcp.local.",    # Apple file sharing
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",  # Apple companion
    "_homekit._tcp.local.",
    "_trel._udp.local.",          # Thread
    "_meshcop._udp.local.",       # Thread mesh
    "_matter._tcp.local.",        # Matter smart home
    "_matterc._udp.local.",       # Matter commissioning
    "_esphomelib._tcp.local.",    # ESPHome
    "_arduino._tcp.local.",
    "_workstation._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_rdp._tcp.local.",
    "_samsung-dm._tcp.local.",    # Samsung device management
    "_samsungtvremote._tcp.local.",
]


@dataclass
class MDNSService:
    """A discovered mDNS service."""

    name: str
    service_type: str
    host: str
    port: int
    properties: dict = field(default_factory=dict)


class MDNSScanner:
    """Scans for mDNS services on the local network."""

    def __init__(self):
        self.services: list[MDNSService] = []
        self._zeroconf: Zeroconf | None = None

    def _on_service_state_change(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if state_change is not ServiceStateChange.Added:
            return

        info = zeroconf.get_service_info(service_type, name)
        if info is None:
            return

        addresses = info.parsed_addresses()
        host = addresses[0] if addresses else "unknown"
        properties = {
            k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
            for k, v in info.properties.items()
        }

        self.services.append(
            MDNSService(
                name=name,
                service_type=service_type,
                host=host,
                port=info.port,
                properties=properties,
            )
        )

    def scan(self, duration: float = 5.0, service_types: list[str] | None = None) -> list[MDNSService]:
        """Scan for mDNS services.

        Args:
            duration: Max time to listen for advertisements (seconds).
            service_types: List of service types to scan for. Defaults to SERVICES.

        Returns:
            List of discovered services.
        """
        self.services = []
        self._zeroconf = Zeroconf()
        types_to_scan = service_types or SERVICES

        browsers = []
        for stype in types_to_scan:
            browser = ServiceBrowser(self._zeroconf, stype, handlers=[self._on_service_state_change])
            browsers.append(browser)

        # Wait up to duration, but exit early if no new services for 1.5s
        end_time = time.time() + duration
        last_count = 0
        stable_since = time.time()

        while time.time() < end_time:
            time.sleep(0.3)
            current_count = len(self.services)
            if current_count > last_count:
                last_count = current_count
                stable_since = time.time()
            elif time.time() - stable_since > 1.5:
                break  # No new services for 1.5s — done

        self._zeroconf.close()
        return self.services
