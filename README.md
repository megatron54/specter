# Specter

**IoT network reconnaissance framework** — discover and fingerprint devices on local networks.

Specter performs passive and active scanning to identify IoT devices, open ports, services, and potential vulnerabilities. Designed for ethical security auditing of home and small-office networks.

## Features

- **Device discovery** — ARP scanning and mDNS/SSDP enumeration
- **Port scanning** — TCP SYN scan with service fingerprinting
- **OS detection** — TTL and TCP window size heuristics
- **Vendor identification** — MAC address OUI lookup
- **Report generation** — JSON output with device inventory and open services
- **Non-intrusive mode** — Passive-only discovery without sending probes

## Usage

```bash
python specter.py --interface eth0 --subnet 192.168.1.0/24
```

### Options

| Flag | Description |
|------|-------------|
| `--interface` | Network interface to scan from |
| `--subnet` | Target CIDR range |
| `--passive` | Passive discovery only (no probes) |
| `--ports` | Port range (default: top 1000) |
| `--output` | Output file path (JSON) |

## Tech Stack

- Python 3.10+
- Scapy (packet crafting and sniffing)
- Nmap service probes (fingerprint database)

## Disclaimer

This tool is intended for authorized security testing only. Only scan networks you own or have explicit permission to test. Unauthorized network scanning may violate local laws.

## License

MIT
