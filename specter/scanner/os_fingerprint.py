"""OS Fingerprinting module based on network characteristics.

Uses TTL analysis, TCP window size, TCP options, and open port heuristics
to determine the operating system of a remote host without authentication.
"""

from dataclasses import dataclass, field
from scapy.all import IP, TCP, ICMP, sr1, conf
import socket

conf.verb = 0  # Suppress scapy output

COMMON_PORTS = [80, 443, 22, 135, 445, 139, 5353, 62078, 8080, 3389]


@dataclass
class OSFingerprint:
    os_family: str = "Unknown"
    os_detail: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


def _ping_ttl(ip: str) -> int | None:
    """Send ICMP echo and return TTL from reply."""
    pkt = IP(dst=ip) / ICMP()
    resp = sr1(pkt, timeout=2)
    if resp:
        return resp.ttl
    return None


def _tcp_probe(ip: str, port: int) -> dict | None:
    """Send TCP SYN and return SYN-ACK characteristics."""
    pkt = IP(dst=ip) / TCP(dport=port, flags="S", options=[
        ("MSS", 1460), ("WScale", 7), ("NOP", None),
        ("SAckOK", b""), ("Timestamp", (12345, 0))
    ])
    resp = sr1(pkt, timeout=2)
    if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:
        tcp = resp[TCP]
        opts = {name: val for name, val in tcp.options}
        return {
            "window": tcp.window,
            "options": opts,
            "options_order": [name for name, _ in tcp.options],
        }
    return None


def _scan_ports(ip: str, ports: list[int]) -> list[int]:
    """Quick SYN scan for a set of ports, returns open ones."""
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1)
        if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:
            open_ports.append(port)
            # Send RST to close
            sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=0.5)
    return open_ports


def _normalize_ttl(ttl: int) -> int:
    """Map observed TTL to initial TTL."""
    if ttl <= 64:
        return 64
    elif ttl <= 128:
        return 128
    else:
        return 255


def fingerprint_os(ip: str) -> OSFingerprint:
    """Fingerprint the OS of a remote host based on network characteristics.

    Args:
        ip: Target IP address.

    Returns:
        OSFingerprint dataclass with os_family, os_detail, confidence, and evidence.
    """
    result = OSFingerprint()
    scores: dict[str, float] = {}

    # --- TTL Analysis ---
    ttl = _ping_ttl(ip)
    if ttl is not None:
        initial_ttl = _normalize_ttl(ttl)
        result.evidence.append(f"TTL={ttl} (initial={initial_ttl})")
        if initial_ttl == 128:
            scores["Windows"] = scores.get("Windows", 0) + 0.3
        elif initial_ttl == 64:
            scores["Linux"] = scores.get("Linux", 0) + 0.2
            scores["macOS"] = scores.get("macOS", 0) + 0.2
            scores["iOS"] = scores.get("iOS", 0) + 0.1
            scores["Android"] = scores.get("Android", 0) + 0.1
        elif initial_ttl == 255:
            scores["Network Device"] = scores.get("Network Device", 0) + 0.4

    # --- TCP Probe ---
    probe = None
    for port in [80, 443, 22, 135]:
        probe = _tcp_probe(ip, port)
        if probe:
            break

    if probe:
        win = probe["window"]
        opts = probe["options"]
        opts_order = probe["options_order"]

        result.evidence.append(f"TCP window={win}")
        result.evidence.append(f"TCP options order={opts_order}")

        # Window size heuristics
        if win in (65535, 8192, 65534):
            scores["Windows"] = scores.get("Windows", 0) + 0.25
            result.evidence.append("Window size consistent with Windows")
        elif win in (5840, 29200, 28960):
            scores["Linux"] = scores.get("Linux", 0) + 0.25
            result.evidence.append("Window size consistent with Linux")
        elif win == 65535 and "Timestamp" in opts:
            scores["macOS"] = scores.get("macOS", 0) + 0.2

        # TCP options analysis
        if "WScale" in opts:
            wscale = opts["WScale"]
            if wscale == 8:
                scores["Windows"] = scores.get("Windows", 0) + 0.1
            elif wscale == 7:
                scores["Linux"] = scores.get("Linux", 0) + 0.1
            elif wscale in (5, 6):
                scores["macOS"] = scores.get("macOS", 0) + 0.1

        if "Timestamp" not in opts:
            scores["Windows"] = scores.get("Windows", 0) + 0.1
            result.evidence.append("No TCP timestamp (common on Windows)")

        if "SAckOK" in opts and "Timestamp" in opts:
            if opts_order[:3] == ["MSS", "SAckOK", "Timestamp"]:
                scores["Linux"] = scores.get("Linux", 0) + 0.15
                result.evidence.append("Options order matches Linux")
            elif opts_order[:2] == ["MSS", "NOP"]:
                scores["Windows"] = scores.get("Windows", 0) + 0.1

    # --- Open Port Heuristics ---
    open_ports = _scan_ports(ip, [135, 445, 5353, 62078])

    if open_ports:
        result.evidence.append(f"Open ports from heuristic set: {open_ports}")

    if 135 in open_ports or 445 in open_ports:
        scores["Windows"] = scores.get("Windows", 0) + 0.3
        result.evidence.append("Ports 135/445 indicate Windows")

    if 62078 in open_ports and 5353 in open_ports:
        scores["macOS"] = scores.get("macOS", 0) + 0.3
        result.evidence.append("Ports 5353+62078 indicate macOS")
    elif 62078 in open_ports:
        scores["iOS"] = scores.get("iOS", 0) + 0.3
        result.evidence.append("Port 62078 indicates iOS")

    # --- Determine winner ---
    if not scores:
        result.os_family = "Unknown"
        result.confidence = 0.0
        return result

    best = max(scores, key=scores.get)  # type: ignore[arg-type]
    result.os_family = best
    result.confidence = min(round(scores[best], 2), 1.0)

    # Detail mapping
    detail_map = {
        "Windows": "Windows 10/11" if scores.get("Windows", 0) > 0.4 else "Windows (version unknown)",
        "Linux": "Linux 5.x" if scores.get("Linux", 0) > 0.3 else "Linux (version unknown)",
        "macOS": "macOS/iOS",
        "iOS": "iOS device",
        "Android": "Android device",
        "Network Device": "Router/Switch (TTL 255)",
    }
    result.os_detail = detail_map.get(best, best)

    return result
