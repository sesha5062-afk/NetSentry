NetSentry – Network Traffic Analyzer

Overview

NetSentry is a Python-based network traffic analysis tool developed using Scapy. It reads PCAPNG files, analyses network packets, identifies protocols, extracts IP addresses and port information, and generates security analysis reports.

Features

- PCAPNG file analysis
- TCP, UDP, ICMP and ARP identification
- DNS packet identification
- Source and destination IP extraction
- Port extraction
- Protocol traffic statistics
- Top source IP analysis
- CSV packet report generation
- HTML security report generation
- Initial heuristic-based TCP port scanning detection

Technologies Used

- Python
- Scapy
- Wireshark
- Kali Linux
- CSV
- HTML and CSS
- Git and GitHub

Project Structure

- "src/analyzer.py" – Packet analysis
- "src/report.py" – Security report generation
- "data/" – Capture data directory
- "reports/" – Generated report directory
- "requirements.txt" – Python dependencies

Installation

Clone the repository:

git clone https://github.com/sesha5062-afk/NetSentry
cd NetSentry

Create a virtual environment:

python3 -m venv venv
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Place your own authorized PCAPNG capture at:

"data/first_capture.pcapng"

Run the analyzer:

python src/analyzer.py

Generate reports:

python src/report.py

Detection Logic

NetSentry includes an initial heuristic that identifies potential TCP port scanning when at least 15 distinct destination ports receive initial TCP SYN attempts from the same source to the same destination within a 60-second time bucket.

Alerts require manual investigation and do not confirm malicious activity.

Project Status

Initial packet analysis and CSV/HTML report generation implemented. Further detection rules and dashboard improvements are planned.

Disclaimer

This project is intended for educational and authorized network security analysis only.
