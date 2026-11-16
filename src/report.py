from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime
from html import escape
import csv

# NetSentry - Security Report Generator

CAPTURE_FILE = Path("data/first_capture.pcapng")
REPORT_DIR = Path("reports")


def generate_report():

    if not CAPTURE_FILE.exists():
        print("Capture file not found:", CAPTURE_FILE)
        return

    REPORT_DIR.mkdir(exist_ok=True)

    print("\nNetSentry Report Generator")
    print("=" * 35)

    packets = rdpcap(str(CAPTURE_FILE))

    protocol_counts = Counter()
    source_counts = Counter()
    destination_counts = Counter()

    dns_count = 0
    packet_rows = []

    # Store TCP SYN attempts for anomaly detection
    scan_attempts = defaultdict(set)

    for packet in packets:

        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).isoformat(timespec="seconds")

        src_ip = ""
        dst_ip = ""
        src_port = ""
        dst_port = ""
        protocol = "OTHER"

        if packet.haslayer(ARP):
            protocol = "ARP"

        elif packet.haslayer(IP):

            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst

            source_counts[src_ip] += 1
            destination_counts[dst_ip] += 1

            if packet.haslayer(TCP):

                tcp = packet[TCP]
                protocol = "TCP"

                src_port = tcp.sport
                dst_port = tcp.dport

                # SYN set, ACK not set:
                # an initial TCP connection attempt
                flags = int(tcp.flags)

                if (flags & 0x02) and not (flags & 0x10):

                    time_bucket = int(float(packet.time) // 60)

                    key = (src_ip, dst_ip, time_bucket)

                    scan_attempts[key].add(tcp.dport)

            elif packet.haslayer(UDP):

                udp = packet[UDP]
                protocol = "UDP"

                src_port = udp.sport
                dst_port = udp.dport

            elif packet.haslayer(ICMP):

                protocol = "ICMP"

            else:
                protocol = "OTHER IP"

            if packet.haslayer(DNS):
                dns_count += 1

        elif packet.haslayer(ARP):
            protocol = "ARP"

        protocol_counts[protocol] += 1

        packet_rows.append({
            "Timestamp": timestamp,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Packet Length": len(packet)
        })

    # Generate CSV file
    csv_file = REPORT_DIR / "packet_details.csv"

    fieldnames = [
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Packet Length"
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(packet_rows)

    # Detect possible port scanning patterns
    anomalies = []

    for (src, dst, bucket), ports in scan_attempts.items():

        if len(ports) >= 15:

            anomalies.append({
                "source": src,
                "destination": dst,
                "time_bucket": bucket,
                "port_count": len(ports),
                "ports": sorted(ports)
            })

    # Prepare HTML tables
    protocol_rows = ""

    for protocol, count in protocol_counts.most_common():

        protocol_rows += (
            f"<tr><td>{escape(protocol)}</td>"
            f"<td>{count}</td></tr>"
        )

    source_rows = ""

    for ip, count in source_counts.most_common(5):

        source_rows += (
            f"<tr><td>{escape(ip)}</td>"
            f"<td>{count}</td></tr>"
        )

    anomaly_rows = ""

    for item in anomalies:

        anomaly_rows += (
            "<tr>"
            f"<td>{escape(item['source'])}</td>"
            f"<td>{escape(item['destination'])}</td>"
            f"<td>{item['port_count']}</td>"
            f"<td>{escape(str(item['ports']))}</td>"
            "</tr>"
        )

    if not anomalies:

        anomaly_rows = (
            "<tr><td colspan='4'>"
            "No activity matched the current detection rule."
            "</td></tr>"
        )

    # Generate HTML report
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>NetSentry Security Report</title>

        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f2f5fa;
                padding: 30px;
                color: #202b3c;
            }}

            h1 {{ color: #164b85; }}

            .card {{
                background: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
            }}

            th, td {{
                padding: 12px;
                border-bottom: 1px solid #ddd;
                text-align: left;
            }}

            th {{
                background: #164b85;
                color: white;
            }}
        </style>
    </head>

    <body>

        <h1>NetSentry Security Report</h1>

        <div class="card">
            <h2>Capture Overview</h2>
            <p>Total packets: {len(packets)}</p>
            <p>DNS packets identified: {dns_count}</p>
            <p>Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="card">
            <h2>Protocol Distribution</h2>
            <table>
                <tr><th>Protocol</th><th>Packets</th></tr>
                {protocol_rows}
            </table>
        </div>

        <div class="card">
            <h2>Top Source IP Addresses</h2>
            <table>
                <tr><th>IP Address</th><th>Packets</th></tr>
                {source_rows}
            </table>
        </div>

        <div class="card">
            <h2>Potential Port Scanning Activity</h2>
            <p>
                Rule: At least 15 distinct destination ports
                receiving initial TCP SYN attempts from the same
                source to the same destination in a 60-second bucket.
            </p>
            <table>
                <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Unique Ports</th>
                    <th>Ports</th>
                </tr>
                {anomaly_rows}
            </table>
            <p>These are heuristic alerts, not confirmed attacks.</p>
        </div>

    </body>
    </html>
    """

    html_file = REPORT_DIR / "security_report.html"

    html_file.write_text(html_content, encoding="utf-8")

    print("\nAnalysis complete!")
    print("Total packets:", len(packets))
    print("DNS packets:", dns_count)
    print("Potential port scanning alerts:", len(anomalies))

    print("\nFiles generated:")
    print(csv_file)
    print(html_file)


if __name__ == "__main__":
    generate_report()
