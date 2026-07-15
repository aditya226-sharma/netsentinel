"""NetSentinel CLI - Command-line interface built with Typer and Rich.

Provides comprehensive commands for network traffic analysis, monitoring,
and reporting using a beautiful terminal interface.
"""

from __future__ import annotations

import json
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from config.settings import get_config, Config
from database.db_manager import DatabaseManager
from utils.logger import setup_logger, setup_root_logger
from utils.helpers import human_readable_bytes, get_timestamp

VERSION = "1.0.0"

BANNER = r"""
    _   __     __  _____                     __
   / | / /__  / /_/ ___/____  ___  _____   / /___  __  ______
  /  |/ / _ \/ __/\__ \/ __ \/ _ \/ __ |  / / __ \/ / / / __ \
 / /|  /  __/ /_ ___/ / /_/ /  __/ /_/ / / / /_/ / /_/ / / / /
/_/ |_/\___/\__//____/ .___/\___/\__, (_)/_/\____/\__,_/_/ /_/
                    /_/          /____/
"""

console = Console()
app = typer.Typer(
    name="netsentinel",
    help="NetSentinel - Network Traffic Analysis & Security Monitoring Framework",
    add_completion=False,
)


def _init_subsystems(
    config: Config | None = None,
) -> tuple[Config, DatabaseManager]:
    """Initialize core subsystems: config, logger, database."""
    if config is None:
        config = get_config()

    setup_root_logger(
        level=config.logging.level,
        log_file=config.logging.file,
        max_bytes=config.logging.max_size,
        backup_count=config.logging.backup_count,
    )

    db_path = Path(config.database.path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    db_manager = DatabaseManager(config.database.path)
    db_manager.initialize()

    return config, db_manager


def _print_banner() -> None:
    """Print the NetSentinel ASCII banner."""
    text = Text(BANNER, style="bold cyan")
    console.print(text)
    console.print(
        Panel(
            f"[bold white]Network Traffic Analysis & Security Monitoring[/]\n"
            f"[dim]Version {VERSION}[/]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


@app.command()
def start(
    interface: Optional[str] = typer.Option(None, "-i", "--interface", help="Network interface to capture on"),
    port: int = typer.Option(8000, "-p", "--port", help="API server port"),
    host: str = typer.Option("0.0.0.0", "--host", help="API server bind address"),
) -> None:
    """Start NetSentinel with API server and packet capture."""
    _print_banner()

    with console.status("[bold green]Initializing subsystems...[/]", spinner="dots"):
        config, db_manager = _init_subsystems()

    console.print("[bold green]✓[/] Configuration loaded")
    console.print("[bold green]✓[/] Database initialized")

    capture_iface = interface or config.capture.interface
    if not capture_iface:
        from modules.interface_detector import InterfaceDetector
        detector = InterfaceDetector()
        capture_iface = detector.get_default_interface()

    console.print(f"[bold green]✓[/] Capture interface: [cyan]{capture_iface or '(auto-detect)'}[/]")

    with console.status("[bold green]Initializing modules...[/]", spinner="dots"):
        from modules.bandwidth_monitor import BandwidthMonitor
        from modules.device_discovery import DeviceDiscovery
        from modules.dns_analytics import DNSAnalytics
        from modules.traffic_stats import TrafficStats
        from modules.alert_engine import AlertEngine
        from modules.certificate_inspector import CertificateInspector
        from modules.flow_monitor import FlowMonitor
        from plugins.loader import PluginLoader
        from capture.engine import PacketCaptureEngine

        bandwidth_monitor = BandwidthMonitor(interface=capture_iface)
        device_discovery = DeviceDiscovery(db_manager)
        dns_analytics = DNSAnalytics(db_manager)
        traffic_stats = TrafficStats(db_manager, interface=capture_iface)
        alert_engine = AlertEngine(db_manager, config)
        certificate_inspector = CertificateInspector()
        flow_monitor = FlowMonitor(db_manager)
        plugin_loader = PluginLoader(config.plugins.directory, db_manager)

        def packet_callback(packet):
            """Process each captured packet through all modules."""
            try:
                bandwidth_monitor.process_packet(packet)
                device_discovery.process_packet(packet)
                dns_analytics.process_packet(packet)
                traffic_stats.process_packet(packet)
                flow_monitor.process_packet(packet)
            except Exception:
                pass

        capture_engine = PacketCaptureEngine(
            interface=capture_iface,
            bpf_filter=config.capture.bpf_filter or None,
            packet_callback=packet_callback,
            db_manager=db_manager,
        )

    console.print("[bold green]✓[/] All modules initialized")

    with console.status("[bold green]Loading plugins...[/]", spinner="dots"):
        plugin_loader.load_all_plugins()

    loaded_plugins = plugin_loader.get_loaded_plugins()
    if loaded_plugins:
        console.print(f"[bold green]✓[/] Loaded {len(loaded_plugins)} plugin(s)")
    else:
        console.print("[dim]  No plugins loaded[/]")

    with console.status("[bold green]Starting packet capture...[/]", spinner="dots"):
        capture_engine.start()

    console.print(f"[bold green]✓[/] Packet capture started on [cyan]{capture_iface}[/]")

    from api.app import create_app, AppState

    state = AppState(
        db_manager=db_manager,
        capture_engine=capture_engine,
        device_discovery=device_discovery,
        bandwidth_monitor=bandwidth_monitor,
        dns_analytics=dns_analytics,
        certificate_inspector=certificate_inspector,
        traffic_stats=traffic_stats,
        flow_monitor=flow_monitor,
        alert_engine=alert_engine,
        plugin_loader=plugin_loader,
        current_interface=capture_iface,
    )

    app_instance = create_app(state)

    console.print(f"[bold green]✓[/] API server starting on [cyan]http://{host}:{port}[/]")
    console.print()
    console.print("[bold]Endpoints:[/]")
    console.print(f"  Dashboard:  [link=http://{host}:{port}]http://{host}:{port}[/]")
    console.print(f"  API Docs:   [link=http://{host}:{port}/api/docs]http://{host}:{port}/api/docs[/]")
    console.print(f"  Health:     [link=http://{host}:{port}/api/health]http://{host}:{port}/api/health[/]")
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/]")

    import uvicorn

    try:
        uvicorn.run(
            app_instance,
            host=host,
            port=port,
            log_level="info",
            access_log=True,
        )
    except KeyboardInterrupt:
        pass
    finally:
        with console.status("[bold yellow]Shutting down...[/]", spinner="dots"):
            capture_engine.stop()
            plugin_loader.unload_all()
            db_manager.close()
        console.print("[bold green]NetSentinel stopped.[/]")


@app.command()
def dashboard(
    interface: Optional[str] = typer.Option(None, "-i", "--interface", help="Network interface"),
    port: int = typer.Option(8000, "-p", "--port", help="API server port"),
    host: str = typer.Option("0.0.0.0", "--host", help="API server bind address"),
) -> None:
    """Start NetSentinel and open the web dashboard."""
    url = f"http://localhost:{port}"
    console.print(f"[cyan]Opening dashboard at {url}...[/]")
    webbrowser.open(url)
    start(interface=interface, port=port, host=host)


@app.command()
def capture(
    interface: Optional[str] = typer.Option(None, "-i", "--interface", help="Network interface"),
    bpf: Optional[str] = typer.Option(None, "-f", "--filter", help="BPF filter expression"),
    count: int = typer.Option(0, "-c", "--count", help="Number of packets to capture (0=infinite)"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path"),
) -> None:
    """Start packet capture in foreground with real-time display."""
    from capture.engine import PacketCaptureEngine
    from modules.interface_detector import InterfaceDetector

    detector = InterfaceDetector()
    capture_iface = interface or detector.get_default_interface()

    console.print(Panel(
        f"[bold]Packet Capture[/]\n"
        f"Interface: [cyan]{capture_iface or '(auto)'}[/]\n"
        f"BPF Filter: [cyan]{bpf or '(none)'}[/]\n"
        f"Packet Limit: [cyan]{count or 'unlimited'}[/]",
        border_style="cyan",
    ))

    packet_counter = {"count": 0, "bytes": 0}
    lock = threading.Lock()
    stop_event = threading.Event()

    def stats_callback(packet):
        with lock:
            packet_counter["count"] += 1
            packet_counter["bytes"] += len(packet)

    def signal_handler(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    engine = PacketCaptureEngine(
        interface=capture_iface,
        bpf_filter=bpf,
        packet_callback=stats_callback,
    )

    def display_loop():
        """Update the display periodically."""
        while not stop_event.is_set():
            with lock:
                count_val = packet_counter["count"]
                bytes_val = packet_counter["bytes"]

            table = Table(title="Capture Statistics", border_style="cyan")
            table.add_column("Metric", style="bold")
            table.add_column("Value", style="green")
            table.add_row("Packets", str(count_val))
            table.add_row("Bytes", human_readable_bytes(bytes_val))
            table.add_row("Interface", capture_iface or "(auto)")

            if stop_event.is_set():
                break

            console.clear()
            console.print(table)
            console.print("\n[dim]Press Ctrl+C to stop[/]")
            time.sleep(1)

    try:
        engine.start()

        if count > 0:
            original_callback = stats_callback

            def count_limited_callback(packet):
                original_callback(packet)
                with lock:
                    if packet_counter["count"] >= count:
                        stop_event.set()

            engine._callback = count_limited_callback

        display_thread = threading.Thread(target=display_loop, daemon=True)
        display_thread.start()

        while not stop_event.is_set():
            time.sleep(0.5)

    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()

        if output:
            console.print(f"[yellow]Capture data not saved (raw capture requires scapy wrpcap)[/]")
            console.print(f"[dim]Total: {packet_counter['count']} packets, {human_readable_bytes(packet_counter['bytes'])}[/]")
        else:
            console.print(f"\n[bold]Capture stopped.[/]")
            console.print(f"Total: {packet_counter['count']} packets, {human_readable_bytes(packet_counter['bytes'])}")


@app.command()
def report(
    format: str = typer.Option("html", "-f", "--format", help="Report format (html, pdf, json, csv)"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path"),
    hours: int = typer.Option(24, "-t", "--hours", help="Time range in hours"),
) -> None:
    """Generate a traffic analysis report."""
    from reports.generator import ReportGenerator

    console.print(f"[cyan]Generating {format.upper()} report for the last {hours} hours...[/]")

    config, db_manager = _init_subsystems()

    generator = ReportGenerator(db_manager, output_dir=config.reports.output_dir)

    with console.status(f"[bold green]Generating {format.upper()} report...[/]", spinner="dots"):
        try:
            if format.lower() == "html":
                filepath = generator.generate_html(hours=hours)
            elif format.lower() == "pdf":
                filepath = generator.generate_pdf(hours=hours)
            elif format.lower() == "json":
                filepath = generator.generate_json(hours=hours)
            elif format.lower() == "csv":
                filepath = generator.generate_csv(hours=hours)
            else:
                console.print(f"[bold red]Unsupported format: {format}[/]")
                raise typer.Exit(1)
        except Exception as e:
            console.print(f"[bold red]Report generation failed: {e}[/]")
            raise typer.Exit(1)
        finally:
            db_manager.close()

    console.print(f"[bold green]✓[/] Report generated: [cyan]{filepath}[/]")


@app.command()
def devices() -> None:
    """List all known network devices."""
    config, db_manager = _init_subsystems()

    try:
        device_list = db_manager.get_devices()
    finally:
        db_manager.close()

    if not device_list:
        console.print("[yellow]No devices found. Start capture to discover devices.[/]")
        return

    table = Table(title="Network Devices", border_style="cyan")
    table.add_column("MAC", style="cyan", no_wrap=True)
    table.add_column("IP", style="green")
    table.add_column("Hostname", style="yellow")
    table.add_column("Vendor", style="magenta")
    table.add_column("OS", style="blue")
    table.add_column("Status", justify="center")
    table.add_column("Last Seen", style="dim")

    for device in device_list:
        status = "[green]Active[/]" if device.get("is_active") else "[red]Inactive[/]"
        last_seen = device.get("last_seen", "")[:19].replace("T", " ")

        table.add_row(
            device.get("mac", ""),
            device.get("ip", ""),
            device.get("hostname", ""),
            device.get("vendor", "Unknown"),
            device.get("os_fingerprint", "Unknown"),
            status,
            last_seen,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(device_list)} device(s)[/]")


@app.command()
def alerts(
    severity: Optional[str] = typer.Option(None, "-s", "--severity", help="Filter by severity (info, warning, critical, error)"),
    limit: int = typer.Option(20, "-n", "--limit", help="Maximum number of alerts to show"),
) -> None:
    """Show recent security alerts."""
    config, db_manager = _init_subsystems()

    try:
        alert_list = db_manager.get_alerts(limit=limit, severity_filter=severity)
    finally:
        db_manager.close()

    if not alert_list:
        console.print("[yellow]No alerts found.[/]")
        return

    severity_colors = {
        "critical": "bold red",
        "error": "red",
        "warning": "yellow",
        "info": "cyan",
    }

    table = Table(title="Security Alerts", border_style="cyan")
    table.add_column("Time", style="dim")
    table.add_column("Severity", justify="center")
    table.add_column("Name", style="bold")
    table.add_column("Message")
    table.add_column("Source IP", style="green")

    for alert in alert_list:
        sev = alert.get("severity", "info")
        color = severity_colors.get(sev, "white")
        timestamp = alert.get("timestamp", "")[:19].replace("T", " ")

        table.add_row(
            timestamp,
            f"[{color}]{sev.upper()}[/]",
            alert.get("name", ""),
            alert.get("message", "")[:80],
            alert.get("source_ip", ""),
        )

    console.print(table)
    console.print(f"\n[dim]Showing {len(alert_list)} alert(s)[/]")


@app.command()
def interfaces() -> None:
    """List all network interfaces."""
    from modules.interface_detector import InterfaceDetector

    detector = InterfaceDetector()
    iface_list = detector.get_interfaces()

    if not iface_list:
        console.print("[yellow]No interfaces found.[/]")
        return

    table = Table(title="Network Interfaces", border_style="cyan")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("IP", style="green")
    table.add_column("MAC", style="yellow")
    table.add_column("Speed", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Type", style="magenta")

    for iface in iface_list:
        speed = f"{iface.get('speed', 0)} Mbps" if iface.get("speed") else "N/A"
        status = "[green]Up[/]" if iface.get("status") == "up" else "[red]Down[/]"

        table.add_row(
            iface.get("name", ""),
            iface.get("ip", ""),
            iface.get("mac", ""),
            speed,
            status,
            iface.get("type", "unknown"),
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(iface_list)} interface(s)[/]")


@app.command()
def stats() -> None:
    """Show current traffic statistics."""
    config, db_manager = _init_subsystems()

    try:
        traffic_stats_list = db_manager.get_traffic_stats(limit=1)
        protocol_dist = db_manager.get_protocol_distribution()
        top_talkers = db_manager.get_top_talkers(limit=5)
    finally:
        db_manager.close()

    panel_content = []

    if traffic_stats_list:
        latest = traffic_stats_list[0]
        pps = latest.get("packets_per_sec", 0)
        bps = latest.get("bytes_per_sec", 0)
        panel_content.append(f"[bold]Packets/sec:[/] {pps:.1f}")
        panel_content.append(f"[bold]Bytes/sec:[/] {human_readable_bytes(bps)}")
    else:
        panel_content.append("[dim]No traffic statistics available yet.[/]")

    console.print(Panel(
        "\n".join(panel_content),
        title="[bold]Traffic Statistics[/]",
        border_style="cyan",
    ))

    if protocol_dist:
        proto_table = Table(title="Protocol Distribution", border_style="cyan")
        proto_table.add_column("Protocol", style="cyan")
        proto_table.add_column("Packets", justify="right", style="green")

        total = sum(protocol_dist.values())
        for proto, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True)[:10]:
            pct = (count / total * 100) if total > 0 else 0
            proto_table.add_row(proto, f"{count} ({pct:.1f}%)")

        console.print(proto_table)

    if top_talkers:
        talker_table = Table(title="Top Talkers", border_style="cyan")
        talker_table.add_column("IP Address", style="cyan")
        talker_table.add_column("Total Bytes", justify="right", style="green")

        for talker in top_talkers:
            talker_table.add_row(
                talker.get("ip", ""),
                human_readable_bytes(talker.get("total_bytes", 0)),
            )

        console.print(talker_table)


@app.command()
def export(
    format: str = typer.Option("json", "-f", "--format", help="Export format (json, csv)"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path"),
) -> None:
    """Export all data to a file."""
    from datetime import datetime

    config, db_manager = _init_subsystems()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not output:
        output = f"netsentinel_export_{timestamp}.{format}"

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = {
            "export_timestamp": get_timestamp(),
            "devices": db_manager.get_devices(),
            "alerts": db_manager.get_alerts(limit=10000),
            "dns_logs": db_manager.get_dns_logs(limit=10000),
            "tls_metadata": db_manager.get_tls_metadata(limit=10000),
            "traffic_stats": db_manager.get_traffic_stats(limit=10000),
            "sessions": db_manager.get_sessions(limit=10000),
        }
    finally:
        db_manager.close()

    if format.lower() == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    elif format.lower() == "csv":
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Table", "Record"])

            for table_name, records in data.items():
                if isinstance(records, list):
                    for record in records:
                        writer.writerow([table_name, json.dumps(record, default=str)])
                else:
                    writer.writerow([table_name, json.dumps(records, default=str)])
    else:
        console.print(f"[bold red]Unsupported format: {format}[/]")
        raise typer.Exit(1)

    console.print(f"[bold green]✓[/] Data exported to [cyan]{output_path}[/]")


@app.command()
def update() -> None:
    """Check for NetSentinel updates."""
    console.print(Panel(
        "[bold]Update Check[/]\n\n"
        f"Current version: [cyan]{VERSION}[/]\n\n"
        "[yellow]Auto-update is not yet implemented.[/]\n"
        "Visit https://github.com/netsentinel/netsentinel for updates.",
        title="[bold]NetSentinel Update[/]",
        border_style="yellow",
    ))


def main() -> None:
    """Entry point for the NetSentinel CLI."""
    if len(sys.argv) == 1:
        _print_banner()
        console.print("[dim]Use 'netsentinel --help' for available commands.[/]\n")
        app()
    else:
        app()


if __name__ == "__main__":
    main()
