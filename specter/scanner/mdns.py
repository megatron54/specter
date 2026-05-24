"""mDNS service discovery.

Discovers IoT devices advertising services via mDNS/DNS-SD,
with a focus on Google Cast devices (_googlecast._tcp.local.).
"""

from dataclasses import dataclass, field
from zeroconf import ServiceBrowser, Zeroconf, ServiceStateChange
import time


# Services to scan for
SERVICES = [
    "_googlecast._tcp.local.",
    "_mqtt._tcp.local.",
    "_http._tcp.local.",
    "_hap._tcp.local.",       # HomeKit
    "_ssdp._udp.local.",
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
            duration: How long to listen for advertisements (seconds).
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

        time.sleep(duration)
        self._zeroconf.close()

        return self.services
