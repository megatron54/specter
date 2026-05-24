"""Vulnerability flagging module for port scan results."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Vulnerability:
    port: int
    service: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    cve: Optional[str] = None
    remediation: str = ""


# Known vulnerable software patterns: (regex, severity, title, description, cve, remediation)
BANNER_VULN_PATTERNS: list[tuple[str, str, str, str, Optional[str], str]] = [
    (
        r"dropbear[_ ](?:ssh[_ ])?0\.(?:4[0-9]|5[0-3])",
        "high",
        "Outdated Dropbear SSH",
        "Dropbear SSH version with known vulnerabilities detected.",
        "CVE-2016-7406",
        "Update Dropbear to the latest version.",
    ),
    (
        r"openssh[_ ](?:6\.[0-6]|5\.|4\.|3\.)",
        "high",
        "Outdated OpenSSH",
        "OpenSSH version with known vulnerabilities detected.",
        "CVE-2016-0777",
        "Update OpenSSH to the latest version.",
    ),
    (
        r"vsftpd 2\.3\.4",
        "critical",
        "vsftpd 2.3.4 Backdoor",
        "This version of vsftpd contains a known backdoor.",
        "CVE-2011-2523",
        "Upgrade vsftpd immediately.",
    ),
    (
        r"proftpd 1\.3\.[0-3]",
        "high",
        "Outdated ProFTPD",
        "ProFTPD version with known remote code execution vulnerabilities.",
        "CVE-2015-3306",
        "Update ProFTPD to the latest version.",
    ),
    (
        r"apache/2\.2\.",
        "medium",
        "Outdated Apache 2.2",
        "Apache 2.2.x is end-of-life and has multiple known vulnerabilities.",
        None,
        "Upgrade to Apache 2.4.x or later.",
    ),
    (
        r"lighttpd/1\.[0-3]\.",
        "medium",
        "Outdated Lighttpd",
        "Older Lighttpd version with potential vulnerabilities.",
        None,
        "Update Lighttpd to the latest stable version.",
    ),
    (
        r"mini_httpd",
        "medium",
        "mini_httpd detected",
        "mini_httpd is often found on embedded devices with limited security.",
        None,
        "Replace with a more secure web server or restrict access.",
    ),
    (
        r"mosquitto.*1\.[0-4]\.",
        "high",
        "Outdated Mosquitto MQTT Broker",
        "Older Mosquitto version with known vulnerabilities.",
        None,
        "Update Mosquitto to the latest version and enable TLS.",
    ),
]


def _check_port_rules(ip: str, port_info: dict) -> list[Vulnerability]:
    """Check a single port against known vulnerability rules."""
    vulns: list[Vulnerability] = []
    port = port_info["port"]
    service = port_info.get("service", "unknown")
    banner = port_info.get("banner", "")
    unauth = port_info.get("unauth", False)
    banner_lower = banner.lower()

    # Telnet
    if port in (23, 2323) or service.lower() == "telnet":
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="critical",
            title="Telnet Service Exposed",
            description=f"Telnet on port {port} provides unencrypted remote access. "
                        "Credentials are transmitted in plaintext.",
            remediation="Disable Telnet and use SSH instead.",
        ))
        # Check banner for default credentials hints
        if re.search(r"default password|admin", banner_lower):
            vulns.append(Vulnerability(
                port=port,
                service=service,
                severity="critical",
                title="Default/Admin Credentials in Telnet Banner",
                description="Telnet banner suggests default or admin credentials are in use.",
                remediation="Change default credentials immediately and disable Telnet.",
            ))

    # FTP
    if port == 21 or service.lower() == "ftp":
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="high",
            title="FTP Service Exposed",
            description="FTP often transmits credentials in plaintext.",
            remediation="Use SFTP or FTPS instead. Disable anonymous access.",
        ))

    # Android ADB
    if port == 5555:
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="critical",
            title="Android ADB Exposed",
            description="Android Debug Bridge on port 5555 allows full device control "
                        "without authentication.",
            remediation="Disable ADB over network or restrict access via firewall.",
        ))

    # MQTT without TLS
    if port == 1883 or (service.lower() == "mqtt" and port != 8883):
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="high",
            title="MQTT Without TLS",
            description="MQTT broker on port 1883 communicates without encryption. "
                        "IoT messages can be intercepted.",
            remediation="Enable TLS (port 8883) and require authentication.",
        ))

    # Unauthenticated web interface
    if port in (80, 8080) and unauth:
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="medium",
            title="Unauthenticated Web Interface",
            description=f"Web interface on port {port} responds without requiring authentication.",
            remediation="Enable authentication on the web interface.",
        ))

    # RTSP
    if port == 554 or service.lower() == "rtsp":
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="high",
            title="RTSP Stream Exposed",
            description="RTSP on port 554 may allow unauthorized access to camera streams.",
            remediation="Require authentication for RTSP and restrict network access.",
        ))

    # Google Cast
    if port == 8008:
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="medium",
            title="Google Cast API Exposed",
            description="Google Cast port 8008 leaks device information without authentication.",
            remediation="Isolate casting devices on a separate network segment.",
        ))

    # Samsung TV
    if port in (8001, 8002):
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="medium",
            title="Samsung TV Control API Exposed",
            description=f"Samsung TV API on port {port} allows unauthenticated control.",
            remediation="Isolate smart TVs on a separate network segment.",
        ))

    # Printer RAW
    if port == 9100:
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="low",
            title="Printer RAW Port Exposed",
            description="Port 9100 allows sending print jobs without authentication.",
            remediation="Restrict printer access via firewall or VLAN segmentation.",
        ))

    # SSH with password auth
    if (port == 22 or service.lower() == "ssh") and "password" in banner_lower:
        vulns.append(Vulnerability(
            port=port,
            service=service,
            severity="info",
            title="SSH Password Authentication Enabled",
            description="SSH is available with password authentication.",
            remediation="Consider using key-based authentication only.",
        ))

    # Generic unauth flag - escalate if no other vuln was found for this port
    if unauth and port not in (80, 8080):
        # Only add if we haven't already flagged something worse
        existing_severities = [SEVERITY_ORDER.get(v.severity, 4) for v in vulns]
        min_existing = min(existing_severities) if existing_severities else 4
        if min_existing > SEVERITY_ORDER["medium"]:
            vulns.append(Vulnerability(
                port=port,
                service=service,
                severity="medium",
                title="Unauthenticated Service Access",
                description=f"Service on port {port} ({service}) is accessible without authentication.",
                remediation="Enable authentication or restrict access.",
            ))

    # Banner-based version checks
    for pattern, severity, title, description, cve, remediation in BANNER_VULN_PATTERNS:
        if re.search(pattern, banner_lower):
            vulns.append(Vulnerability(
                port=port,
                service=service,
                severity=severity,
                title=title,
                description=description,
                cve=cve,
                remediation=remediation,
            ))

    return vulns


def check_vulnerabilities(ip: str, open_ports: list[dict]) -> list[Vulnerability]:
    """Analyze open ports and flag potential vulnerabilities.

    Args:
        ip: Target IP address.
        open_ports: List of dicts with keys: port, service, banner, unauth.

    Returns:
        List of Vulnerability instances sorted by severity (critical first).
    """
    vulnerabilities: list[Vulnerability] = []

    for port_info in open_ports:
        vulns = _check_port_rules(ip, port_info)
        vulnerabilities.extend(vulns)

    vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 4))
    return vulnerabilities
