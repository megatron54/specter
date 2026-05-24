# Specter

Network IoT reconnaissance and control framework.

Specter discovers, fingerprints, and interacts with IoT devices on your local network. It demonstrates how insecure local APIs can be exploited to take control of smart home devices without physical access.

## Features

### Phase 1 — IoT Discovery & Control
- **Network scanning** — ARP sweep + mDNS/SSDP service discovery
- **Device fingerprinting** — Identify device types by MAC OUI, open ports, and service advertisements
- **Google Cast module** — Enumerate and control Google Home/Nest devices via their local API (reboot, factory reset, WiFi enumeration, Do Not Disturb, etc.)

### Phase 2 — Network Kill Switch
- **ARP denial** — Surgically disconnect any device from the network by poisoning its ARP cache
- **Selective targeting** — Choose specific devices from the discovery results

## Installation

```bash
git clone https://github.com/megatron54/specter.git
cd specter
python -m venv venv
venv\Scripts\activate      # Windows
pip install -e .
```

## Usage

```bash
# Discover devices on the network
specter scan

# Show detailed info about a discovered device
specter info <device-id>

# Control a Google Home device
specter cast reboot <device-ip>
specter cast dnd <device-ip> --enable

# Kill switch (Phase 2)
specter kill <target-ip>

# Launch web dashboard
specter web
```

## Requirements

- Python 3.11+
- Administrator/root privileges (for ARP scanning and packet crafting)
- Network access to target devices (same subnet)

## Legal Disclaimer

This tool is intended **exclusively for authorized security testing and educational purposes**. Unauthorized access to devices you do not own is illegal. The authors assume no liability for misuse. Always obtain explicit permission before testing on any network or device.

## License

MIT
