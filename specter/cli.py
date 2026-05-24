"""Specter CLI — main entry point.

Usage:
    specter scan          Discover devices on the local network
    specter info <ip>     Show details for a specific device
    specter cast <cmd>    Control Google Cast devices
    specter kill <ip>     Disconnect a device from the network
    specter web           Launch the web dashboard
"""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="specter", help="Network IoT reconnaissance and control framework.")
console = Console()


@app.command()
def scan(
    subnet: str = typer.Option(None, "--subnet", "-s", help="Target subnet (e.g., 192.168.1.0/24). Auto-detected if omitted."),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Scan timeout in seconds."),
):
    """Discover all devices on the local network."""
    from specter.scanner.arp import arp_scan
    from specter.scanner.mdns import MDNSScanner
    from specter.scanner.fingerprint import fingerprint_device, lookup_oui

    if not subnet:
        # Auto-detect subnet from default interface
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

    # Display results
    table = Table(title=f"Discovered Devices ({len(hosts)} hosts)")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="green")
    table.add_column("Vendor", style="yellow")
    table.add_column("Type", style="magenta")
    table.add_column("Services", style="dim")

    for host in hosts:
        host.vendor = lookup_oui(host.mac)
        svc_list = service_map.get(host.ip, [])
        profile = fingerprint_device(host.ip, host.mac, svc_list)
        table.add_row(
            host.ip,
            host.mac,
            profile.vendor,
            profile.device_type,
            ", ".join(s.replace("._tcp.local.", "") for s in svc_list) or "-",
        )

    console.print(table)


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
def kill(
    target: str = typer.Argument(help="Target device IP to disconnect."),
    gateway: str = typer.Option(None, "--gateway", "-g", help="Gateway IP. Auto-detected if omitted."),
    duration: int = typer.Option(0, "--duration", "-d", help="Duration in seconds (0 = until Ctrl+C)."),
):
    """Disconnect a device from the network via ARP poisoning."""
    from specter.killswitch.arp_poison import ARPPoisoner

    if not gateway:
        from scapy.all import conf
        gateway = conf.route.route("0.0.0.0")[2]
        console.print(f"[dim]Auto-detected gateway: {gateway}[/dim]")

    console.print(f"[bold red]Killing {target} (gateway: {gateway})[/bold red]")
    console.print("[dim]Press Ctrl+C to stop and restore ARP.[/dim]")

    poisoner = ARPPoisoner(target_ip=target, gateway_ip=gateway)
    poisoner.start()

    try:
        if duration > 0:
            import time
            time.sleep(duration)
        else:
            import time
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[yellow]Restoring ARP tables...[/yellow]")
        poisoner.stop()
        console.print("[green]Done. Target should reconnect shortly.[/green]")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind address."),
    port: int = typer.Option(8080, "--port", "-p", help="Port number."),
):
    """Launch the Specter web dashboard."""
    import uvicorn
    console.print(f"[bold]Starting Specter dashboard at http://{host}:{port}[/bold]")
    uvicorn.run("specter.web.app:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    app()
