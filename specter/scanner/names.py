"""Device name resolution.

Attempts to resolve friendly names for network devices using multiple methods:
1. mDNS service properties (fn, n, md fields)
2. Google Cast API (port 8008, unauthenticated)
3. NetBIOS name resolution
4. SSDP/UPnP device descriptions
5. Reverse DNS lookup
6. DHCP hostname (from router, if available)
"""

import socket
import struct
from xml.etree import ElementTree

import httpx


def resolve_names(hosts: list[dict], service_map: dict, services: list) -> dict[str, str]:
    """Resolve device names using all available methods (parallelized).

    Args:
        hosts: List of dicts with 'ip' and 'mac' keys.
        service_map: Map of IP -> list of mDNS service types.
        services: Raw mDNS service objects.

    Returns:
        Dict mapping IP -> friendly name.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    name_map: dict[str, str] = {}

    # 1. mDNS service properties (instant, no network)
    for svc in services:
        if svc.host and svc.host not in name_map:
            friendly = (
                svc.properties.get("fn") or
                svc.properties.get("n") or
                svc.properties.get("md") or
                svc.properties.get("name") or
                ""
            )
            if friendly:
                name_map[svc.host] = friendly
            elif svc.name:
                parts = svc.name.split("._")
                if parts:
                    name_map[svc.host] = parts[0]

    # 2. Google Cast API (only for cast devices — fast, targeted)
    for host in hosts:
        ip = host["ip"] if isinstance(host, dict) else host.ip
        if ip in name_map:
            continue
        svc_list = service_map.get(ip, [])
        if "_googlecast._tcp.local." in svc_list:
            try:
                resp = httpx.get(f"http://{ip}:8008/setup/eureka_info", timeout=1.0)
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get("name", "")
                    if name:
                        name_map[ip] = name
            except Exception:
                pass

    # Remaining hosts that still need names — resolve in parallel
    unresolved = [
        (host["ip"] if isinstance(host, dict) else host.ip)
        for host in hosts
        if (host["ip"] if isinstance(host, dict) else host.ip) not in name_map
    ]

    if not unresolved:
        return name_map

    # Detect gateway once
    gateway_ip = None
    try:
        from scapy.all import conf
        gateway_ip = conf.route.route("0.0.0.0")[2]
    except Exception:
        pass

    def _resolve_single(ip: str) -> tuple[str, str | None]:
        """Try fast methods for a single IP, return first hit."""
        # mDNS unicast query — ask device directly for its hostname
        name = _mdns_unicast_query(ip)
        if name:
            return ip, name
        # NetBIOS (fast UDP)
        name = _netbios_lookup(ip)
        if name:
            return ip, name
        # SSDP — catches TVs, routers, media devices
        name = _ssdp_discover(ip)
        if name:
            return ip, name
        # Reverse DNS (usually instant)
        name = _reverse_dns(ip)
        if name:
            return ip, name
        # DHCP hostname
        name = _dhcp_hostname_via_dns(ip, gateway_ip)
        if name:
            return ip, name
        return ip, None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_resolve_single, ip): ip for ip in unresolved}
        try:
            for future in as_completed(futures, timeout=10):
                try:
                    ip, name = future.result(timeout=1)
                    if name:
                        name_map[ip] = name
                except Exception:
                    pass
        except TimeoutError:
            pass  # Some hosts didn't resolve in time — that's fine

    return name_map


def _mdns_unicast_query(ip: str) -> str | None:
    """Send a unicast mDNS query directly to a device asking for its hostname.

    Constructs a reverse PTR query for the IP (e.g., 34.1.168.192.in-addr.arpa)
    sent directly to the device on port 5353. Most devices with mDNS respond
    with their .local hostname within ~50ms.

    Also tries querying _services._dns-sd._udp.local for service enumeration.
    """
    import struct

    # Build reverse DNS name for PTR query
    octets = ip.split(".")
    ptr_name = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"

    # Build mDNS query packet
    transaction_id = b"\x00\x00"
    flags = b"\x00\x00"  # Standard query
    questions = b"\x00\x01"
    answer_rrs = b"\x00\x00"
    authority_rrs = b"\x00\x00"
    additional_rrs = b"\x00\x00"

    # Encode domain name
    qname = b""
    for label in ptr_name.split("."):
        qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"

    qtype = b"\x00\x0c"   # PTR
    qclass = b"\x80\x01"  # IN, unicast-response requested

    packet = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + qname + qtype + qclass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.6)
        sock.sendto(packet, (ip, 5353))
        data, _ = sock.recvfrom(1024)
        sock.close()

        # Parse response — look for PTR answer
        if len(data) > 12:
            answer_count = struct.unpack("!H", data[6:8])[0]
            if answer_count > 0:
                # Find the answer section (skip header + question)
                offset = 12
                # Skip question name
                while offset < len(data) and data[offset] != 0:
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2
                        break
                    offset += data[offset] + 1
                else:
                    offset += 1
                offset += 4  # Skip QTYPE + QCLASS

                # Parse answer — skip name (likely a pointer)
                if offset < len(data):
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2
                    else:
                        while offset < len(data) and data[offset] != 0:
                            offset += data[offset] + 1
                        offset += 1

                    if offset + 10 <= len(data):
                        offset += 8  # Skip TYPE(2) + CLASS(2) + TTL(4)
                        rdlength = struct.unpack("!H", data[offset:offset + 2])[0]
                        offset += 2

                        # Read the PTR domain name
                        hostname = _decode_dns_name(data, offset)
                        if hostname:
                            # Clean up: remove .local suffix
                            hostname = hostname.rstrip(".")
                            if hostname.endswith(".local"):
                                hostname = hostname[:-6]
                            return hostname

    except (socket.timeout, OSError):
        pass

    # Fallback: try A record query for common .local names
    return None


def _decode_dns_name(data: bytes, offset: int) -> str:
    """Decode a DNS name from packet data, handling compression pointers."""
    parts = []
    seen_offsets = set()
    while offset < len(data):
        if offset in seen_offsets:
            break
        seen_offsets.add(offset)
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            # Compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            return ".".join(parts) + ("." if parts else "") + _decode_dns_name(data, pointer)
        offset += 1
        parts.append(data[offset:offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(parts)


def _ssdp_discover(ip: str) -> str | None:
    """Send a unicast SSDP M-SEARCH to a device and parse its friendly name.

    SSDP (UPnP) devices respond with a LOCATION header pointing to their
    device description XML which contains the friendly name.
    """
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        sock.sendto(msearch, (ip, 1900))
        data, _ = sock.recvfrom(2048)
        sock.close()

        response = data.decode("utf-8", errors="ignore")

        # Look for LOCATION header and fetch device description
        import re
        location = re.search(r"LOCATION:\s*(http://[^\r\n]+)", response, re.IGNORECASE)
        if location:
            try:
                resp = httpx.get(location.group(1), timeout=0.8)
                if resp.status_code == 200 and "<friendlyName>" in resp.text:
                    fn = re.search(r"<friendlyName>([^<]+)</friendlyName>", resp.text)
                    if fn:
                        return fn.group(1)
            except Exception:
                pass

        # Try parsing SERVER header for device name
        server = re.search(r"SERVER:\s*([^\r\n]+)", response, re.IGNORECASE)
        if server:
            name = server.group(1).strip()
            # Only use if it looks like a device name, not generic
            if name and "UPnP" not in name and "Linux" not in name and len(name) < 50:
                return name

    except (socket.timeout, OSError):
        pass

    return None


def _netbios_lookup(ip: str) -> str | None:
    """Query NetBIOS name for a host (Windows/Samba devices)."""
    try:
        # NetBIOS Name Service query on UDP 137
        # Transaction ID + flags + questions + etc
        payload = (
            b"\xa2\x48"  # Transaction ID
            b"\x00\x00"  # Flags
            b"\x00\x01"  # Questions
            b"\x00\x00"  # Answer RRs
            b"\x00\x00"  # Authority RRs
            b"\x00\x00"  # Additional RRs
            b"\x20"      # Name length (32)
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Encoded * (wildcard)
            b"\x00"      # Null terminator
            b"\x00\x21"  # Type: NBSTAT
            b"\x00\x01"  # Class: IN
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 57:
            # Parse response — name starts after header
            num_names = data[56]
            if num_names > 0:
                # First name entry starts at offset 57, 18 bytes each
                name_bytes = data[57:57 + 15]
                name = name_bytes.decode("ascii", errors="ignore").strip()
                if name and name != "\x00" * 15:
                    return name
    except (socket.timeout, OSError):
        pass
    return None


def _upnp_lookup(ip: str) -> str | None:
    """Try to get device name from UPnP device description."""
    # Common UPnP description URLs
    urls = [
        f"http://{ip}:49152/description.xml",
        f"http://{ip}:1900/description.xml",
        f"http://{ip}:8080/description.xml",
        f"http://{ip}/description.xml",
        f"http://{ip}:49153/dmr/SamsungMRDesc.xml",
        f"http://{ip}:8001/api/v2/",
    ]
    try:
        client = httpx.Client(timeout=0.8)
        for url in urls:
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    content = resp.text
                    # Try JSON (Samsung TV API)
                    if url.endswith("/api/v2/"):
                        try:
                            data = resp.json()
                            name = data.get("device", {}).get("name") or data.get("name")
                            if name:
                                return name
                        except Exception:
                            pass
                    # Try XML (UPnP)
                    elif "<friendlyName>" in content:
                        try:
                            # Handle namespaces
                            content_clean = content.replace(' xmlns="', ' xmlns_="')
                            root = ElementTree.fromstring(content_clean)
                            fn = root.find(".//friendlyName")
                            if fn is not None and fn.text:
                                return fn.text
                        except Exception:
                            pass
            except (httpx.ConnectError, httpx.ReadTimeout):
                continue
        client.close()
    except Exception:
        pass
    return None


def _reverse_dns(ip: str) -> str | None:
    """Attempt reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Filter out generic PTR records
        if hostname and not hostname.startswith(ip.replace(".", "-")) and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass
    return None


def _http_probe(ip: str) -> str | None:
    """Probe HTTP services to extract device name from response.

    Checks common ports and parses:
    - HTML <title> tags
    - Server headers
    - JSON responses with name/device fields
    """
    import re

    ports_to_try = [80, 8080, 443, 8008, 8443]
    client = httpx.Client(timeout=1.0, verify=False, follow_redirects=True)

    for port in ports_to_try:
        scheme = "https" if port in (443, 8443) else "http"
        try:
            resp = client.get(f"{scheme}://{ip}:{port}/")
            if resp.status_code == 200:
                content = resp.text
                # Try JSON with name field
                if resp.headers.get("content-type", "").startswith("application/json"):
                    try:
                        data = resp.json()
                        name = (
                            data.get("name") or
                            data.get("device_name") or
                            data.get("deviceName") or
                            data.get("friendly_name") or
                            data.get("device", {}).get("name") if isinstance(data.get("device"), dict) else None
                        )
                        if name:
                            client.close()
                            return name
                    except Exception:
                        pass

                # Try HTML title
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", content, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                    # Filter out generic titles
                    generic = {"200 ok", "index", "home", "login", "welcome", "", "document"}
                    if title.lower() not in generic and len(title) < 60:
                        client.close()
                        return title

                # Check Server header for device identification
                server = resp.headers.get("server", "")
                if server and server.lower() not in ("nginx", "apache", "httpd", "lighttpd", ""):
                    # Server headers like "EPSON HTTP" or "SHIP 2.0" identify devices
                    client.close()
                    return server

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout, Exception):
            continue

    client.close()
    return None


def _dhcp_hostname_via_dns(ip: str, gateway_ip: str | None = None) -> str | None:
    """Try to resolve hostname via the router's DNS.

    Many routers register DHCP client hostnames in their local DNS,
    accessible as <hostname>.local or via PTR record.
    """
    import struct

    # Build a PTR query for the IP
    # e.g., 192.168.1.34 -> 34.1.168.192.in-addr.arpa
    octets = ip.split(".")
    ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa"

    # If we have a gateway, try querying it as DNS server
    dns_servers = []
    if gateway_ip:
        dns_servers.append(gateway_ip)
    dns_servers.append("127.0.0.1")  # Local resolver

    for dns_server in dns_servers:
        try:
            # Build DNS query packet
            transaction_id = b"\xaa\xbb"
            flags = b"\x01\x00"  # Standard query, recursion desired
            questions = b"\x00\x01"
            answer_rrs = b"\x00\x00"
            authority_rrs = b"\x00\x00"
            additional_rrs = b"\x00\x00"

            # Encode PTR name
            qname = b""
            for label in ptr_name.split("."):
                qname += struct.pack("B", len(label)) + label.encode()
            qname += b"\x00"

            qtype = b"\x00\x0c"   # PTR
            qclass = b"\x00\x01"  # IN

            packet = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + qname + qtype + qclass

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.8)
            sock.sendto(packet, (dns_server, 53))
            data, _ = sock.recvfrom(1024)
            sock.close()

            # Parse response — check if we got an answer
            answer_count = struct.unpack("!H", data[6:8])[0]
            if answer_count > 0:
                # Skip header (12 bytes) + question section
                offset = 12
                # Skip question name
                while data[offset] != 0:
                    if data[offset] & 0xC0 == 0xC0:  # Pointer
                        offset += 2
                        break
                    offset += data[offset] + 1
                else:
                    offset += 1
                offset += 4  # Skip QTYPE + QCLASS

                # Parse answer
                # Skip name (might be pointer)
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1

                # Skip TYPE(2) + CLASS(2) + TTL(4)
                offset += 8
                rdlength = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2

                # Parse PTR RDATA (domain name)
                hostname_parts = []
                end = offset + rdlength
                while offset < end and data[offset] != 0:
                    if data[offset] & 0xC0 == 0xC0:
                        # Pointer — follow it
                        ptr_offset = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
                        while data[ptr_offset] != 0:
                            label_len = data[ptr_offset]
                            hostname_parts.append(data[ptr_offset+1:ptr_offset+1+label_len].decode("ascii", errors="ignore"))
                            ptr_offset += label_len + 1
                        break
                    label_len = data[offset]
                    hostname_parts.append(data[offset+1:offset+1+label_len].decode("ascii", errors="ignore"))
                    offset += label_len + 1

                if hostname_parts:
                    # Return just the hostname part (first label usually)
                    hostname = hostname_parts[0]
                    # Filter out PTR-style names
                    if not hostname.replace("-", "").replace(".", "").isdigit():
                        return hostname

        except (socket.timeout, OSError, struct.error, IndexError):
            continue

    return None
