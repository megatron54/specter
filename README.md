# Specter

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-packet_crafting-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-web_dashboard-009688?logo=fastapi&logoColor=white)
![Typer](https://img.shields.io/badge/Typer-CLI-black)
![WebSockets](https://img.shields.io/badge/WebSockets-real--time-4B32C3)
![License](https://img.shields.io/badge/License-MIT-green)

**IoT network reconnaissance and security-testing framework** for local networks. Specter discovers devices, fingerprints their OS/vendor, scans for open/unauthenticated services, flags known vulnerabilities, and includes active testing modules (ARP spoofing, MITM traffic inspection, and vendor-specific device control) for authorized security assessments.

> ⚠️ **This is an offensive security tool.** It can disconnect devices, intercept traffic, and issue unauthenticated commands to real hardware. Read the [Ethical Use & Disclaimer](#ethical-use--disclaimer) section before running it.

## Ethical Use & Disclaimer

Specter performs **active network attacks** (ARP spoofing, man-in-the-middle interception, unauthenticated device control, factory resets, mass disconnection). These are the same techniques used in real intrusions.

- **Only run this against networks and devices you own, or have explicit written authorization to test.**
- Unauthorized ARP poisoning, traffic interception, or device tampering is illegal in most jurisdictions (e.g. under the U.S. CFAA, UK Computer Misuse Act, and equivalent laws elsewhere) and can disrupt production networks or third-party devices.
- This project exists to demonstrate security-research and red-team engineering skills in a controlled lab/home-network context — it is **not** intended for use on networks belonging to others, public/shared Wi-Fi, workplaces, or IoT devices you do not control.
- The author assumes no liability for misuse. Use at your own risk and in accordance with local law.

## What It Does

- **Discovery** — ARP scanning + mDNS/SSDP enumeration to map every device on the local subnet
- **Fingerprinting** — vendor identification via MAC OUI lookup, OS detection via TTL/TCP-window/DF-bit heuristics, device-type classification
- **Port scanning** — TCP scan with service/banner detection and unauthenticated-service flagging
- **Vulnerability flagging** — banner-based matching against known CVEs (e.g. outdated OpenSSH/Dropbear) with severity and remediation notes
- **Active testing modules**:
  - `kill` / `nuke` — ARP-poison and disconnect one device or the entire subnet
  - `mitm` — ARP-poison a target, sniff and reconstruct its traffic (DNS queries, HTTP requests, credential-pattern matches)
  - `cast` — control/query Google Cast devices (info, reboot, factory reset, DND, alarms, saved Wi-Fi networks, Bluetooth scan)
  - `tv` — control unauthenticated Samsung Smart TV APIs (info, power, volume, mute, installed apps)
- **Web dashboard** — FastAPI + WebSocket UI (`specter web`) exposing scan results and live attack status in real time
- **Reporting** — JSON device inventory and findings export

## Installation

```bash
git clone https://github.com/megatron54/specter.git
cd specter
pip install -e .
# or: pip install -r requirements.txt
```

Most commands require raw-socket access (ARP/packet crafting), so run with elevated privileges (`sudo` on Linux/macOS, Administrator on Windows) in a lab environment you control.

## Usage

```bash
specter scan                      # discover all devices on the local network
specter scan --ports              # also port-scan every discovered host
specter portscan <ip>             # scan ports on a specific device
specter cast <action> <ip>        # control a Google Cast device (info, reboot, reset, dnd, alarms, wifi, bluetooth, nightmode)
specter tv <action> <ip>          # control a Samsung Smart TV (info, off, mute, volup, voldown, apps)
specter kill <ip>                 # disconnect a single device via ARP poisoning
specter nuke [all|gateway]        # disconnect every device on the subnet
specter mitm <ip>                 # ARP-poison and sniff a device's traffic
specter web                       # launch the FastAPI web dashboard
```

Run `specter --help` or `specter <command> --help` for the full flag list (e.g. `--subnet`, `--timeout`, `--gateway`, `--duration`).

## Tech Stack

- **Python 3.11+**
- **Scapy** — ARP scanning, ARP poisoning, and packet sniffing
- **Zeroconf** — mDNS/SSDP service discovery
- **FastAPI + Uvicorn + WebSockets** — web dashboard and real-time attack/scan updates
- **Typer + Rich** — CLI interface and formatted terminal output
- **httpx** — HTTP calls to IoT device APIs (Cast, Samsung TV)

## Project Structure

```
specter/
├── cli.py                  Typer CLI entry point (scan, portscan, cast, tv, kill, nuke, mitm, web)
├── scanner/
│   ├── arp.py               ARP-based host discovery
│   ├── mdns.py               mDNS/SSDP service enumeration
│   ├── fingerprint.py        Device-type fingerprinting
│   ├── os_fingerprint.py      OS detection (TTL, TCP window, DF bit)
│   ├── ports.py               TCP port scanning + banner grabbing
│   ├── vulns.py               Banner-based CVE/vulnerability flagging
│   ├── names.py               Device name resolution
│   └── monitor.py             Continuous network monitoring
├── killswitch/
│   ├── arp_poison.py          ARP poisoning (single target, MITM, whole-network)
│   ├── sniffer.py             Traffic capture + DNS/HTTP/credential extraction
│   ├── dns_spoof.py           DNS response spoofing
│   └── cred_harvester.py      Credential pattern matching from captured traffic
├── modules/
│   ├── google_cast.py         Google Cast device control
│   ├── samsung_tv.py          Samsung Smart TV control
│   ├── tuya.py                 Tuya IoT device control
│   └── printer.py              Network printer interaction
└── web/
    ├── app.py                  FastAPI backend (REST + WebSocket)
    └── report.py               Report generation
```

## License

MIT

## Autor

**Miguel Serra Ferrando** — Telecommunications Engineer
[GitHub](https://github.com/megatron54) · [LinkedIn](https://www.linkedin.com/in/miguel-serra-ferrando) · [Email](mailto:miguel.serra.ferrando@gmail.com)
