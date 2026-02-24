"""Generate HTML capture reports with charts and security findings."""

import base64
import html
import io
from collections import Counter, defaultdict
from datetime import datetime


def generate_capture_report(
    metadata: dict,
    packets: list[dict],
    security_events: list[dict],
    geoip_data: dict[str, dict],
    top_talkers: list[dict],
) -> str:
    """Generate an HTML report from capture data.

    Returns a complete HTML string.
    """
    sections = [
        _header_section(metadata),
        _executive_summary(metadata, packets),
        _top_ips_section(packets),
        _top_connections_section(packets),
        _protocol_chart_section(metadata),
        _timeline_chart_section(packets),
        _security_findings_section(security_events),
        _geoip_summary_section(packets, geoip_data),
        _flagged_packets_section(packets),
        _recommendations_section(security_events, packets, geoip_data),
        _footer_section(),
    ]

    body = "\n".join(sections)
    return _wrap_html(body)


def _wrap_html(body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Network Capture Report</title>
<style>
  body {{
    font-family: 'Segoe UI', Consolas, monospace;
    background: #1e1e2e; color: #cdd6f4;
    margin: 0; padding: 20px;
  }}
  h1, h2, h3 {{ color: #89b4fa; }}
  table {{
    border-collapse: collapse; width: 100%; margin: 10px 0 20px 0;
  }}
  th, td {{
    border: 1px solid #45475a; padding: 8px 12px; text-align: left;
  }}
  th {{ background: #313244; color: #cdd6f4; }}
  td {{ background: #1e1e2e; }}
  .critical {{ color: #f38ba8; font-weight: bold; }}
  .warning {{ color: #f9e2af; }}
  .info {{ color: #94e2d5; }}
  .summary-box {{
    background: #313244; border: 1px solid #45475a;
    border-radius: 8px; padding: 16px; margin: 10px 0;
    display: inline-block; min-width: 150px; text-align: center;
  }}
  .summary-box .value {{
    font-size: 24px; font-weight: bold; color: #89b4fa;
  }}
  .summary-box .label {{ color: #a6adc8; font-size: 12px; }}
  .recommendation {{
    background: #313244; border-left: 4px solid #f9e2af;
    padding: 10px 16px; margin: 8px 0;
  }}
  img {{ max-width: 100%; margin: 10px 0; }}
  .footer {{
    text-align: center; color: #a6adc8;
    border-top: 1px solid #45475a; padding-top: 16px; margin-top: 32px;
  }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def _header_section(metadata: dict) -> str:
    start = metadata.get("start_time", "N/A")
    duration = metadata.get("duration_s", 0)
    bpf = metadata.get("filter", "") or "None"
    mins, secs = divmod(int(duration), 60)
    return f"""
<h1>Network Capture Report</h1>
<table>
<tr><th>Capture Start</th><td>{_esc(start)}</td></tr>
<tr><th>Duration</th><td>{mins}m {secs}s</td></tr>
<tr><th>BPF Filter</th><td>{_esc(bpf)}</td></tr>
</table>"""


def _executive_summary(metadata: dict, packets: list[dict]) -> str:
    total = metadata.get("total_packets", len(packets))
    total_bytes = metadata.get("total_bytes", sum(p.get("length", 0) for p in packets))
    duration = metadata.get("duration_s", 1) or 1
    pps = total / duration
    proto = metadata.get("proto_counts", {})
    tcp = proto.get("TCP", 0)
    udp = proto.get("UDP", 0)
    other = proto.get("Other", 0)

    def pct(n):
        return f"{(n / total * 100):.1f}%" if total > 0 else "0%"

    if total_bytes >= 1_000_000:
        bytes_str = f"{total_bytes / 1_000_000:.1f} MB"
    elif total_bytes >= 1_000:
        bytes_str = f"{total_bytes / 1_000:.1f} KB"
    else:
        bytes_str = f"{total_bytes} B"

    return f"""
<h2>Executive Summary</h2>
<div>
  <div class="summary-box"><div class="value">{total:,}</div><div class="label">Total Packets</div></div>
  <div class="summary-box"><div class="value">{bytes_str}</div><div class="label">Total Bytes</div></div>
  <div class="summary-box"><div class="value">{pps:.1f}</div><div class="label">Avg Packets/s</div></div>
  <div class="summary-box"><div class="value">{tcp:,} ({pct(tcp)})</div><div class="label">TCP</div></div>
  <div class="summary-box"><div class="value">{udp:,} ({pct(udp)})</div><div class="label">UDP</div></div>
  <div class="summary-box"><div class="value">{other:,} ({pct(other)})</div><div class="label">Other</div></div>
</div>"""


def _top_ips_section(packets: list[dict]) -> str:
    src_counter: Counter = Counter()
    dst_counter: Counter = Counter()
    src_bytes: dict[str, int] = defaultdict(int)
    dst_bytes: dict[str, int] = defaultdict(int)

    for p in packets:
        s, d = p.get("src", ""), p.get("dst", "")
        length = p.get("length", 0)
        if s:
            src_counter[s] += 1
            src_bytes[s] += length
        if d:
            dst_counter[d] += 1
            dst_bytes[d] += length

    def ip_table(title, counter, bytes_map):
        rows = ""
        for ip, count in counter.most_common(10):
            b = bytes_map.get(ip, 0)
            rows += f"<tr><td>{_esc(ip)}</td><td>{count:,}</td><td>{_fmt_bytes(b)}</td></tr>\n"
        return f"""
<h3>{title}</h3>
<table><tr><th>IP</th><th>Packets</th><th>Bytes</th></tr>
{rows}</table>"""

    return f"""
<h2>Top IPs</h2>
{ip_table("Top 10 Source IPs", src_counter, src_bytes)}
{ip_table("Top 10 Destination IPs", dst_counter, dst_bytes)}"""


def _top_connections_section(packets: list[dict]) -> str:
    conn_counter: Counter = Counter()
    conn_bytes: dict[str, int] = defaultdict(int)
    for p in packets:
        s = p.get("src", "")
        d = p.get("dst", "")
        sp = p.get("src_port")
        dp = p.get("dst_port")
        if s and d and sp and dp:
            key = f"{s}:{sp} -> {d}:{dp}"
            conn_counter[key] += 1
            conn_bytes[key] += p.get("length", 0)

    rows = ""
    for conn, count in conn_counter.most_common(10):
        rows += f"<tr><td>{_esc(conn)}</td><td>{count:,}</td><td>{_fmt_bytes(conn_bytes[conn])}</td></tr>\n"

    return f"""
<h2>Top 10 Connections</h2>
<table><tr><th>Connection</th><th>Packets</th><th>Bytes</th></tr>
{rows}</table>"""


def _protocol_chart_section(metadata: dict) -> str:
    proto = metadata.get("proto_counts", {})
    try:
        img = _make_pie_chart(proto)
        return f"""
<h2>Protocol Distribution</h2>
<img src="data:image/png;base64,{img}" alt="Protocol Distribution">"""
    except Exception:
        # matplotlib not available, fall back to text
        rows = "".join(
            f"<tr><td>{_esc(k)}</td><td>{v:,}</td></tr>" for k, v in proto.items()
        )
        return f"""
<h2>Protocol Distribution</h2>
<table><tr><th>Protocol</th><th>Count</th></tr>{rows}</table>"""


def _timeline_chart_section(packets: list[dict]) -> str:
    if not packets:
        return ""
    # Group packets by second
    time_counts: Counter = Counter()
    for p in packets:
        t = p.get("time", "")[:8]  # HH:MM:SS
        if t:
            time_counts[t] += 1

    try:
        img = _make_timeline_chart(time_counts)
        return f"""
<h2>Packets per Second Over Time</h2>
<img src="data:image/png;base64,{img}" alt="Packets/s Timeline">"""
    except Exception:
        return ""


def _security_findings_section(events: list[dict]) -> str:
    if not events:
        return "<h2>Security Findings</h2><p>No security events detected.</p>"

    rows = ""
    for e in events:
        sev = e.get("severity", "info")
        css = sev
        rows += (
            f'<tr><td>{_esc(e.get("timestamp", "")[:19])}</td>'
            f'<td class="{css}">{_esc(sev.upper())}</td>'
            f'<td>{_esc(e.get("event_type", ""))}</td>'
            f'<td>{_esc(e.get("source_ip", ""))}</td>'
            f'<td>{_esc(e.get("dest_ip", ""))}</td>'
            f'<td>{_esc(e.get("description", ""))}</td></tr>\n'
        )

    return f"""
<h2>Security Findings</h2>
<table>
<tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>Dest</th><th>Description</th></tr>
{rows}</table>"""


def _geoip_summary_section(packets: list[dict], geoip_data: dict) -> str:
    if not geoip_data:
        return ""

    # Aggregate stats per external IP
    ip_stats: dict[str, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for p in packets:
        for ip_key in ("src", "dst"):
            ip = p.get(ip_key, "")
            if ip in geoip_data:
                ip_stats[ip]["packets"] += 1
                ip_stats[ip]["bytes"] += p.get("length", 0)

    if not ip_stats:
        return ""

    rows = ""
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
    for ip, stats in sorted_ips[:20]:
        geo = geoip_data.get(ip, {})
        rows += (
            f"<tr><td>{_esc(ip)}</td>"
            f'<td>{_esc(geo.get("country_code", "?"))}</td>'
            f'<td>{_esc(geo.get("country_name", ""))}</td>'
            f'<td>{_esc(geo.get("city", ""))}</td>'
            f"<td>{stats['packets']:,}</td>"
            f"<td>{_fmt_bytes(stats['bytes'])}</td></tr>\n"
        )

    return f"""
<h2>GeoIP Summary</h2>
<table>
<tr><th>IP</th><th>Code</th><th>Country</th><th>City</th><th>Packets</th><th>Bytes</th></tr>
{rows}</table>"""


def _flagged_packets_section(packets: list[dict]) -> str:
    flagged = [p for p in packets if p.get("threat_level")]
    if not flagged:
        return "<h2>Flagged Packets</h2><p>No packets were flagged during this capture.</p>"

    rows = ""
    for p in flagged[:100]:  # Limit to 100
        sev = p.get("threat_level", "")
        rows += (
            f'<tr><td>{_esc(p.get("time", ""))}</td>'
            f'<td class="{sev}">{_esc(sev.upper())}</td>'
            f'<td>{_esc(p.get("src", ""))}</td>'
            f'<td>{_esc(p.get("dst", ""))}</td>'
            f'<td>{_esc(p.get("protocol", ""))}</td>'
            f'<td>{p.get("length", 0)}</td>'
            f'<td>{_esc(p.get("info", ""))}</td></tr>\n'
        )

    return f"""
<h2>Flagged Packets ({len(flagged)} total)</h2>
<table>
<tr><th>Time</th><th>Threat</th><th>Source</th><th>Dest</th><th>Protocol</th><th>Length</th><th>Info</th></tr>
{rows}</table>"""


def _recommendations_section(events: list[dict], packets: list[dict],
                             geoip_data: dict) -> str:
    recs = []
    event_types = {e.get("event_type") for e in events}

    # Check for telnet traffic
    if any(p.get("dst_port") == 23 or p.get("src_port") == 23 for p in packets):
        recs.append("Consider blocking port 23/Telnet traffic — use SSH instead")

    if "port_scan" in event_types:
        scanners = {e["source_ip"] for e in events if e.get("event_type") == "port_scan"}
        for ip in scanners:
            recs.append(f"Port scan detected from {ip} — consider firewall rules")

    if "arp_spoof" in event_types:
        for e in events:
            if e.get("event_type") == "arp_spoof":
                recs.append(f"ARP spoofing detected: {e.get('description', '')} — verify network devices")

    if "dns_tunnel" in event_types:
        domains = set()
        for e in events:
            if e.get("event_type") == "dns_tunnel":
                domains.add(e.get("source_ip", ""))
        for d in domains:
            recs.append(f"Investigate potential DNS tunneling from {d}")

    if "syn_flood" in event_types:
        recs.append("SYN flood activity detected — consider SYN cookies or rate limiting")

    if "malicious_port" in event_types:
        recs.append("Connections to known malicious ports detected — investigate immediately")

    # High-volume foreign IPs
    if geoip_data:
        ip_bytes: dict[str, int] = defaultdict(int)
        for p in packets:
            for key in ("src", "dst"):
                ip = p.get(key, "")
                if ip in geoip_data:
                    ip_bytes[ip] += p.get("length", 0)
        for ip, total in sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:3]:
            geo = geoip_data.get(ip, {})
            country = geo.get("country_name", "Unknown")
            if total > 1_000_000:
                recs.append(
                    f"Investigate high-volume connection to {ip} in {country} "
                    f"({_fmt_bytes(total)})"
                )

    if not recs:
        return "<h2>Recommendations</h2><p>No specific recommendations based on this capture.</p>"

    items = "".join(f'<div class="recommendation">{_esc(r)}</div>' for r in recs)
    return f"<h2>Recommendations</h2>{items}"


def _footer_section() -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
<div class="footer">
  <p>Generated by Network Real-Time Monitor &mdash; {now}</p>
</div>"""


# ── Chart helpers ───────────────────────────────────────────


def _make_pie_chart(proto_counts: dict) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = list(proto_counts.keys())
    sizes = list(proto_counts.values())
    colors = ["#89b4fa", "#a6e3a1", "#f9e2af", "#f38ba8", "#cba6f7"]

    fig, ax = plt.subplots(figsize=(5, 4), facecolor="#1e1e2e")
    ax.set_facecolor("#1e1e2e")
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct="%1.1f%%",
        colors=colors[:len(labels)],
        textprops={"color": "#cdd6f4"},
    )
    for t in autotexts:
        t.set_color("#1e1e2e")
        t.set_fontweight("bold")
    ax.set_title("Protocol Distribution", color="#cdd6f4")

    return _fig_to_base64(fig)


def _make_timeline_chart(time_counts: Counter) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sorted_times = sorted(time_counts.keys())
    values = [time_counts[t] for t in sorted_times]

    # Subsample if too many points
    if len(sorted_times) > 300:
        step = len(sorted_times) // 300
        sorted_times = sorted_times[::step]
        values = values[::step]

    fig, ax = plt.subplots(figsize=(10, 3), facecolor="#1e1e2e")
    ax.set_facecolor("#1e1e2e")
    ax.fill_between(range(len(values)), values, color="#89b4fa", alpha=0.4)
    ax.plot(range(len(values)), values, color="#89b4fa", linewidth=1)
    ax.set_ylabel("Packets/s", color="#cdd6f4")
    ax.tick_params(colors="#a6adc8")

    # Show a few time labels
    if len(sorted_times) > 6:
        step = len(sorted_times) // 6
        ax.set_xticks(range(0, len(sorted_times), step))
        ax.set_xticklabels(sorted_times[::step], rotation=45, fontsize=8)
    else:
        ax.set_xticks(range(len(sorted_times)))
        ax.set_xticklabels(sorted_times, rotation=45, fontsize=8)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#45475a")
    ax.spines["left"].set_color("#45475a")
    fig.tight_layout()

    return _fig_to_base64(fig)


def _fig_to_base64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", facecolor=fig.get_facecolor())
    buf.seek(0)
    import matplotlib.pyplot as plt
    plt.close(fig)
    return base64.b64encode(buf.read()).decode("utf-8")


# ── Formatting helpers ──────────────────────────────────────


def _esc(s: str) -> str:
    return html.escape(str(s))


def _fmt_bytes(b: int) -> str:
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    elif b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b} B"
