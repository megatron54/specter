"""Security report generator — exports scan results as an HTML report.

Generates a professional-looking dark-themed HTML report summarizing:
- Discovered devices
- Open ports and services
- Vulnerabilities found
- OS fingerprints
- Recommendations
"""

from datetime import datetime
from typing import Optional


def generate_report(
    devices: list[dict],
    vulnerabilities: Optional[dict[str, list]] = None,
    os_results: Optional[dict[str, dict]] = None,
    subnet: str = "Unknown",
) -> str:
    """Generate an HTML security assessment report.

    Args:
        devices: List of device dicts from scan.
        vulnerabilities: Dict mapping IP -> list of vuln dicts.
        os_results: Dict mapping IP -> OS fingerprint dict.
        subnet: Network subnet that was scanned.

    Returns:
        Complete HTML document as a string.
    """
    vulnerabilities = vulnerabilities or {}
    os_results = os_results or {}

    total_vulns = sum(len(v) for v in vulnerabilities.values())
    critical_count = sum(
        1 for vulns in vulnerabilities.values()
        for v in vulns if v.get("severity") == "critical"
    )
    high_count = sum(
        1 for vulns in vulnerabilities.values()
        for v in vulns if v.get("severity") == "high"
    )

    # Risk score
    if critical_count > 0:
        risk_level = "CRITICAL"
        risk_color = "#ff3b3b"
    elif high_count > 0:
        risk_level = "HIGH"
        risk_color = "#ff8c00"
    elif total_vulns > 0:
        risk_level = "MEDIUM"
        risk_color = "#ffd700"
    else:
        risk_level = "LOW"
        risk_color = "#00ff88"

    # Build device rows
    device_rows = ""
    for dev in devices:
        ports_str = ", ".join(str(p["port"]) for p in dev.get("open_ports", []))
        vuln_count = len(vulnerabilities.get(dev["ip"], []))
        os_info = os_results.get(dev["ip"], {})
        os_str = os_info.get("os_family", "Unknown")

        device_rows += f"""
        <tr>
            <td>{dev.get('name') or '-'}</td>
            <td class="mono">{dev['ip']}</td>
            <td class="mono">{dev['mac']}</td>
            <td>{dev.get('vendor', 'Unknown')}</td>
            <td>{dev.get('device_type', 'Unknown')}</td>
            <td>{os_str}</td>
            <td class="mono">{ports_str or '-'}</td>
            <td class="{'vuln-critical' if vuln_count > 0 else ''}">{vuln_count}</td>
        </tr>"""

    # Build vulnerability section
    vuln_section = ""
    for ip, vulns in vulnerabilities.items():
        if not vulns:
            continue
        dev_name = next((d.get("name") or d["ip"] for d in devices if d["ip"] == ip), ip)
        vuln_section += f'<h3>{dev_name} ({ip})</h3><div class="vuln-list">'
        for v in vulns:
            sev = v.get("severity", "info")
            vuln_section += f"""
            <div class="vuln-item vuln-{sev}">
                <div class="vuln-header">
                    <span class="severity-badge severity-{sev}">{sev.upper()}</span>
                    <span class="vuln-title">{v.get('title', '')}</span>
                    <span class="vuln-port">Port {v.get('port', '?')}</span>
                </div>
                <p>{v.get('description', '')}</p>
                {f'<p class="cve">CVE: {v["cve"]}</p>' if v.get('cve') else ''}
                <p class="remediation">Remediation: {v.get('remediation', 'N/A')}</p>
            </div>"""
        vuln_section += "</div>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Specter Security Report — {subnet}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #0a0a0f; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 40px; }}
        .mono {{ font-family: 'Consolas', 'JetBrains Mono', monospace; }}
        h1 {{ color: #fff; font-size: 2em; margin-bottom: 5px; }}
        h2 {{ color: #00bfff; margin: 30px 0 15px; padding-bottom: 8px; border-bottom: 1px solid #333; }}
        h3 {{ color: #ccc; margin: 20px 0 10px; }}
        .header {{ margin-bottom: 40px; }}
        .header .subtitle {{ color: #888; font-size: 0.9em; }}
        .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .meta-card {{ background: #12121a; border: 1px solid #333; border-radius: 8px; padding: 20px; text-align: center; }}
        .meta-card .value {{ font-size: 2em; font-weight: bold; }}
        .meta-card .label {{ color: #888; font-size: 0.85em; margin-top: 5px; }}
        .risk-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: #12121a; border-radius: 8px; overflow: hidden; }}
        th {{ background: #1a1a2e; color: #00bfff; text-align: left; padding: 12px 15px; font-size: 0.85em; text-transform: uppercase; }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #222; font-size: 0.9em; }}
        tr:hover {{ background: #1a1a2e; }}
        .vuln-list {{ margin: 10px 0; }}
        .vuln-item {{ background: #12121a; border-left: 3px solid #666; border-radius: 4px; padding: 12px 15px; margin: 8px 0; }}
        .vuln-critical {{ border-left-color: #ff3b3b; }}
        .vuln-high {{ border-left-color: #ff8c00; }}
        .vuln-medium {{ border-left-color: #ffd700; }}
        .vuln-low {{ border-left-color: #00bfff; }}
        .vuln-info {{ border-left-color: #888; }}
        .vuln-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .vuln-title {{ font-weight: 600; color: #fff; }}
        .vuln-port {{ color: #888; font-size: 0.85em; margin-left: auto; }}
        .severity-badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; }}
        .severity-critical {{ background: #ff3b3b33; color: #ff3b3b; }}
        .severity-high {{ background: #ff8c0033; color: #ff8c00; }}
        .severity-medium {{ background: #ffd70033; color: #ffd700; }}
        .severity-low {{ background: #00bfff33; color: #00bfff; }}
        .severity-info {{ background: #88888833; color: #888; }}
        .remediation {{ color: #00ff88; font-size: 0.85em; margin-top: 5px; }}
        .cve {{ color: #ff8c00; font-size: 0.85em; }}
        p {{ margin: 5px 0; line-height: 1.5; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #333; color: #555; font-size: 0.8em; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SPECTER Security Assessment Report</h1>
        <p class="subtitle">Network: {subnet} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="meta">
        <div class="meta-card">
            <div class="value">{len(devices)}</div>
            <div class="label">Devices Found</div>
        </div>
        <div class="meta-card">
            <div class="value">{total_vulns}</div>
            <div class="label">Vulnerabilities</div>
        </div>
        <div class="meta-card">
            <div class="value" style="color: {risk_color}">{risk_level}</div>
            <div class="label">Risk Level</div>
        </div>
        <div class="meta-card">
            <div class="value">{critical_count}</div>
            <div class="label">Critical Issues</div>
        </div>
    </div>

    <h2>Discovered Devices</h2>
    <table>
        <thead>
            <tr><th>Name</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>OS</th><th>Open Ports</th><th>Vulns</th></tr>
        </thead>
        <tbody>
            {device_rows}
        </tbody>
    </table>

    <h2>Vulnerability Assessment</h2>
    {vuln_section if vuln_section else '<p style="color: #888;">No vulnerabilities detected.</p>'}

    <h2>Recommendations</h2>
    <ul style="list-style: none; padding: 0;">
        {'<li style="margin: 8px 0; padding-left: 20px; position: relative;"><span style="position: absolute; left: 0; color: #ff3b3b;">●</span> Immediately address all CRITICAL vulnerabilities — they allow full device compromise.</li>' if critical_count > 0 else ''}
        {'<li style="margin: 8px 0; padding-left: 20px; position: relative;"><span style="position: absolute; left: 0; color: #ff8c00;">●</span> Remediate HIGH severity issues — unencrypted services expose credentials.</li>' if high_count > 0 else ''}
        <li style="margin: 8px 0; padding-left: 20px; position: relative;"><span style="position: absolute; left: 0; color: #00bfff;">●</span> Segment IoT devices onto a separate VLAN to limit lateral movement.</li>
        <li style="margin: 8px 0; padding-left: 20px; position: relative;"><span style="position: absolute; left: 0; color: #00bfff;">●</span> Disable unnecessary services and close unused ports.</li>
        <li style="margin: 8px 0; padding-left: 20px; position: relative;"><span style="position: absolute; left: 0; color: #00bfff;">●</span> Enable WPA3 on the wireless network and use strong passwords.</li>
        <li style="margin: 8px 0; padding-left: 20px; position: relative;"><span style="position: absolute; left: 0; color: #00bfff;">●</span> Keep firmware and software updated on all network devices.</li>
    </ul>

    <div class="footer">
        Generated by Specter Network Security Framework | For authorized security assessments only
    </div>
</body>
</html>"""

    return html
