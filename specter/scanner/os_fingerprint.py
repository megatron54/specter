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
    resp = sr1(pkt, timeout=0.8)
    if resp:
        return resp.ttl
    return None


def _tcp_probe(ip: str, port: int) -> dict | None:
    """Send TCP SYN and return SYN-ACK characteristics."""
    pkt = IP(dst=ip) / TCP(dport=port, flags="S", options=[
        ("MSS", 1460), ("WScale", 7), ("NOP", None),
        ("SAckOK", b""), ("Timestamp", (12345, 0))
    ])
    resp = sr1(pkt, timeout=0.8)
    if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:
        tcp = resp[TCP]
        opts = {name: val for name, val in tcp.options}
        return {
            "window": tcp.window,
            "ttl": resp.ttl,
            "options": opts,
            "options_order": [name for name, _ in tcp.options],
            "df": bool(resp[IP].flags & 0x2),  # Don't Fragment bit
        }
    return None


def _scan_ports(ip: str, ports: list[int]) -> list[int]:
    """Quick SYN scan for a set of ports, returns open ones."""
    from scapy.all import sr
    # Send all probes at once for speed
    pkts = [IP(dst=ip) / TCP(dport=p, flags="S") for p in ports]
    answered, _ = sr(pkts, timeout=1.0, verbose=0)
    open_ports = []
    for sent, recv in answered:
        if recv.haslayer(TCP) and recv[TCP].flags & 0x12 == 0x12:
            open_ports.append(recv[TCP].sport)
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
        df = probe.get("df", False)

        # Use TTL from TCP response too (more reliable than ICMP which may be blocked)
        if ttl is None and "ttl" in probe:
            ttl = probe["ttl"]
            initial_ttl = _normalize_ttl(ttl)
            result.evidence.append(f"TTL={ttl} (initial={initial_ttl}, from TCP)")
            if initial_ttl == 128:
                scores["Windows"] = scores.get("Windows", 0) + 0.3
            elif initial_ttl == 64:
                scores["Linux"] = scores.get("Linux", 0) + 0.2
                scores["macOS"] = scores.get("macOS", 0) + 0.2
                scores["iOS"] = scores.get("iOS", 0) + 0.1
                scores["Android"] = scores.get("Android", 0) + 0.1
            elif initial_ttl == 255:
                scores["Network Device"] = scores.get("Network Device", 0) + 0.4

        result.evidence.append(f"TCP window={win}")
        result.evidence.append(f"TCP options order={opts_order}")
        if df:
            result.evidence.append("DF bit set")

        # Window size heuristics (expanded)
        if win in (65535, 8192, 65534):
            scores["Windows"] = scores.get("Windows", 0) + 0.25
            result.evidence.append("Window size consistent with Windows")
        elif win in (5840, 29200, 28960, 64240, 65160):
            scores["Linux"] = scores.get("Linux", 0) + 0.25
            result.evidence.append("Window size consistent with Linux")
        elif win == 65535 and "Timestamp" in opts:
            scores["macOS"] = scores.get("macOS", 0) + 0.25
            result.evidence.append("Window 65535 + Timestamp = likely macOS/iOS")
        elif win in (16384, 32768, 4128):
            scores["Network Device"] = scores.get("Network Device", 0) + 0.2
            result.evidence.append("Window size consistent with embedded/network device")
        elif win in (14600, 26883, 26880):
            scores["Android"] = scores.get("Android", 0) + 0.2
            result.evidence.append("Window size consistent with Android")

        # DF bit: Linux and macOS almost always set DF
        if df:
            scores["Linux"] = scores.get("Linux", 0) + 0.05
            scores["macOS"] = scores.get("macOS", 0) + 0.05

        # TCP options analysis
        if "WScale" in opts:
            wscale = opts["WScale"]
            if wscale == 8:
                scores["Windows"] = scores.get("Windows", 0) + 0.1
            elif wscale == 7:
                scores["Linux"] = scores.get("Linux", 0) + 0.1
            elif wscale in (5, 6):
                scores["macOS"] = scores.get("macOS", 0) + 0.1
                scores["iOS"] = scores.get("iOS", 0) + 0.05

        if "Timestamp" not in opts:
            scores["Windows"] = scores.get("Windows", 0) + 0.15
            result.evidence.append("No TCP timestamp (common on Windows)")

        if "SAckOK" in opts and "Timestamp" in opts:
            if opts_order[:3] == ["MSS", "SAckOK", "Timestamp"]:
                scores["Linux"] = scores.get("Linux", 0) + 0.15
                result.evidence.append("Options order matches Linux")
            elif opts_order[:2] == ["MSS", "NOP"]:
                scores["Windows"] = scores.get("Windows", 0) + 0.1

    # --- Open Port Heuristics ---
    open_ports = _scan_ports(ip, [135, 445, 5353, 62078, 8008, 8443, 548, 3689])

    if open_ports:
        result.evidence.append(f"Open ports from heuristic set: {open_ports}")

    if 135 in open_ports or 445 in open_ports:
        scores["Windows"] = scores.get("Windows", 0) + 0.3
        result.evidence.append("Ports 135/445 indicate Windows")

    if 62078 in open_ports and 5353 in open_ports:
        scores["iOS"] = scores.get("iOS", 0) + 0.35
        result.evidence.append("Ports 5353+62078 indicate iOS")
    elif 62078 in open_ports:
        scores["iOS"] = scores.get("iOS", 0) + 0.3
        result.evidence.append("Port 62078 indicates iOS")

    if 548 in open_ports or 3689 in open_ports:
        scores["macOS"] = scores.get("macOS", 0) + 0.25
        result.evidence.append("AFP/DAAP ports indicate macOS")

    if 8008 in open_ports:
        scores["IoT"] = scores.get("IoT", 0) + 0.3
        result.evidence.append("Port 8008 indicates Google Cast/IoT")

    # 5353 alone (mDNS) without Apple ports suggests Linux/Android
    if 5353 in open_ports and 62078 not in open_ports and 548 not in open_ports:
        scores["Linux"] = scores.get("Linux", 0) + 0.05
        scores["Android"] = scores.get("Android", 0) + 0.05

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
        "Linux": "Linux 5.x/6.x" if scores.get("Linux", 0) > 0.3 else "Linux (version unknown)",
        "macOS": "macOS (Apple)",
        "iOS": "iOS (iPhone/iPad)",
        "Android": "Android device",
        "Network Device": "Router/Switch (TTL 255)",
        "IoT": "IoT / Smart Device",
    }
    result.os_detail = detail_map.get(best, best)

    return result
