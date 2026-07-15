"""Report generator for NetSentinel.

Generates comprehensive traffic analysis reports in multiple formats:
HTML (with interactive charts), PDF, JSON, and CSV.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from database.db_manager import DatabaseManager
from utils.helpers import human_readable_bytes, get_timestamp
from utils.logger import setup_logger

logger = setup_logger("netsentinel.reports.generator")

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generates traffic analysis reports from database data.

    Args:
        db_manager: Initialized DatabaseManager instance.
        output_dir: Directory to write generated reports to.

    Usage:
        gen = ReportGenerator(db_manager)
        filepath = gen.generate_html(hours=24)
    """

    def __init__(
        self,
        db_manager: DatabaseManager,
        output_dir: str = "reports/output",
    ) -> None:
        self._db = db_manager
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _collect_data(self, hours: int = 24) -> dict[str, Any]:
        """Gather all relevant statistics and data from the database.

        Args:
            hours: Number of hours of data to include.

        Returns:
            Dictionary containing all report data.
        """
        logger.info("Collecting data for last %d hours", hours)

        devices = self._db.get_devices()
        alerts = self._db.get_alerts(limit=500)
        dns_logs = self._db.get_dns_logs(limit=500)
        tls_metadata = self._db.get_tls_metadata(limit=500)
        traffic_stats = self._db.get_traffic_stats(limit=1000)
        protocol_dist = self._db.get_protocol_distribution()
        top_talkers = self._db.get_top_talkers(limit=20)
        bandwidth_timeline = self._db.get_bandwidth_timeline(minutes=hours * 60)
        sessions = self._db.get_sessions(limit=500)

        total_packets = sum(s.get("packets", 0) for s in sessions)
        total_bytes = sum(s.get("bytes", 0) for s in sessions)

        active_devices = sum(1 for d in devices if d.get("is_active"))
        critical_alerts = sum(1 for a in alerts if a.get("severity") == "critical")

        bandwidth_chart_data = []
        for point in bandwidth_timeline[-60:]:
            ts = point.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts)
                time_label = dt.strftime("%H:%M")
            except (ValueError, TypeError):
                time_label = ts[:5] if ts else ""
            bandwidth_chart_data.append({
                "time": time_label,
                "bytes_in": point.get("bytes_per_sec", 0),
                "bytes_out": point.get("bytes_per_sec", 0),
            })

        proto_chart_data = []
        for proto, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True):
            proto_chart_data.append({"protocol": proto, "count": count})

        recent_dns = []
        for log in dns_logs[:50]:
            recent_dns.append({
                "timestamp": log.get("timestamp", "")[:19].replace("T", " "),
                "src_ip": log.get("src_ip", ""),
                "query_name": log.get("query_name", ""),
                "query_type": log.get("query_type", ""),
                "response_code": log.get("response_code", ""),
            })

        recent_tls = []
        for tls in tls_metadata[:50]:
            recent_tls.append({
                "timestamp": tls.get("timestamp", "")[:19].replace("T", " "),
                "src_ip": tls.get("src_ip", ""),
                "dst_ip": tls.get("dst_ip", ""),
                "sni": tls.get("sni", ""),
                "issuer": tls.get("issuer", ""),
                "version": tls.get("version", ""),
            })

        recent_alerts = []
        for alert in alerts[:50]:
            recent_alerts.append({
                "timestamp": alert.get("timestamp", "")[:19].replace("T", " "),
                "severity": alert.get("severity", ""),
                "name": alert.get("name", ""),
                "message": alert.get("message", ""),
                "source_ip": alert.get("source_ip", ""),
            })

        device_list = []
        for device in devices[:100]:
            device_list.append({
                "mac": device.get("mac", ""),
                "ip": device.get("ip", ""),
                "hostname": device.get("hostname", ""),
                "vendor": device.get("vendor", "Unknown"),
                "os_fingerprint": device.get("os_fingerprint", "Unknown"),
                "is_active": device.get("is_active", False),
                "last_seen": device.get("last_seen", "")[:19].replace("T", " "),
            })

        top_talkers_data = []
        for talker in top_talkers:
            top_talkers_data.append({
                "ip": talker.get("ip", ""),
                "total_bytes": talker.get("total_bytes", 0),
                "total_bytes_human": human_readable_bytes(talker.get("total_bytes", 0)),
            })

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range_hours": hours,
            "summary": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "total_bytes_human": human_readable_bytes(total_bytes),
                "total_devices": len(devices),
                "active_devices": active_devices,
                "total_alerts": len(alerts),
                "critical_alerts": critical_alerts,
                "total_dns_queries": len(dns_logs),
                "total_tls_sessions": len(tls_metadata),
                "total_sessions": len(sessions),
            },
            "bandwidth_chart": bandwidth_chart_data,
            "protocol_distribution": proto_chart_data,
            "top_talkers": top_talkers_data,
            "dns_queries": recent_dns,
            "tls_sessions": recent_tls,
            "alerts": recent_alerts,
            "devices": device_list,
        }

    def _render_html(self, data: dict[str, Any]) -> str:
        """Render the HTML report using the Jinja2 template.

        Args:
            data: Report data dictionary.

        Returns:
            Rendered HTML string.
        """
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )
        template = env.get_template("report.html")
        return template.render(**data)

    def generate_html(self, hours: int = 24) -> str:
        """Generate an HTML report with interactive charts.

        Args:
            hours: Number of hours of data to include.

        Returns:
            Path to the generated HTML file.
        """
        data = self._collect_data(hours)
        html_content = self._render_html(data)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"netsentinel_report_{timestamp}.html"
        filepath = self._output_dir / filename

        filepath.write_text(html_content, encoding="utf-8")
        logger.info("HTML report generated: %s", filepath)
        return str(filepath)

    def _render_pdf(self, html_content: str) -> str:
        """Render a PDF from HTML content using WeasyPrint.

        Args:
            html_content: HTML string to convert to PDF.

        Returns:
            Path to the generated PDF file.
        """
        try:
            from weasyprint import HTML

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"netsentinel_report_{timestamp}.pdf"
            filepath = self._output_dir / filename

            HTML(string=html_content).write_pdf(str(filepath))
            logger.info("PDF report generated: %s", filepath)
            return str(filepath)
        except ImportError:
            logger.error("WeasyPrint is required for PDF generation")
            raise
        except Exception as e:
            logger.error("PDF generation failed: %s", e)
            raise

    def generate_pdf(self, hours: int = 24) -> str:
        """Generate a PDF report.

        Args:
            hours: Number of hours of data to include.

        Returns:
            Path to the generated PDF file.
        """
        data = self._collect_data(hours)
        html_content = self._render_html(data)
        return self._render_pdf(html_content)

    def generate_json(self, hours: int = 24) -> str:
        """Generate a JSON report.

        Args:
            hours: Number of hours of data to include.

        Returns:
            Path to the generated JSON file.
        """
        data = self._collect_data(hours)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"netsentinel_report_{timestamp}.json"
        filepath = self._output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("JSON report generated: %s", filepath)
        return str(filepath)

    def generate_csv(self, hours: int = 24) -> str:
        """Generate a CSV report with multiple sections.

        Args:
            hours: Number of hours of data to include.

        Returns:
            Path to the generated CSV file.
        """
        data = self._collect_data(hours)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"netsentinel_report_{timestamp}.csv"
        filepath = self._output_dir / filename

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            writer.writerow(["=== SUMMARY ==="])
            for key, value in data["summary"].items():
                writer.writerow([key, value])
            writer.writerow([])

            writer.writerow(["=== PROTOCOL DISTRIBUTION ==="])
            writer.writerow(["Protocol", "Packet Count"])
            for proto in data["protocol_distribution"]:
                writer.writerow([proto["protocol"], proto["count"]])
            writer.writerow([])

            writer.writerow(["=== TOP TALKERS ==="])
            writer.writerow(["IP Address", "Total Bytes", "Total Bytes (Human)"])
            for talker in data["top_talkers"]:
                writer.writerow([talker["ip"], talker["total_bytes"], talker["total_bytes_human"]])
            writer.writerow([])

            writer.writerow(["=== DEVICES ==="])
            writer.writerow(["MAC", "IP", "Hostname", "Vendor", "OS", "Active", "Last Seen"])
            for device in data["devices"]:
                writer.writerow([
                    device["mac"], device["ip"], device["hostname"],
                    device["vendor"], device["os_fingerprint"],
                    device["is_active"], device["last_seen"],
                ])
            writer.writerow([])

            writer.writerow(["=== DNS QUERIES ==="])
            writer.writerow(["Timestamp", "Source IP", "Query Name", "Type", "Response Code"])
            for dns in data["dns_queries"]:
                writer.writerow([
                    dns["timestamp"], dns["src_ip"], dns["query_name"],
                    dns["query_type"], dns["response_code"],
                ])
            writer.writerow([])

            writer.writerow(["=== TLS SESSIONS ==="])
            writer.writerow(["Timestamp", "Source IP", "Destination IP", "SNI", "Issuer", "Version"])
            for tls in data["tls_sessions"]:
                writer.writerow([
                    tls["timestamp"], tls["src_ip"], tls["dst_ip"],
                    tls["sni"], tls["issuer"], tls["version"],
                ])
            writer.writerow([])

            writer.writerow(["=== ALERTS ==="])
            writer.writerow(["Timestamp", "Severity", "Name", "Message", "Source IP"])
            for alert in data["alerts"]:
                writer.writerow([
                    alert["timestamp"], alert["severity"], alert["name"],
                    alert["message"], alert["source_ip"],
                ])

        logger.info("CSV report generated: %s", filepath)
        return str(filepath)
