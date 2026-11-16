from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, ARP
from collections import Counter
from pathlib import Path
CAPTURE_FILE = Path("data/first_capture.pcapng")
def analyze_packets():
	print("\n=====================================")
	print("       Network       Analyzer")
	print("=====================================\n")
	if not CAPTURE_FILE.exists():
		print("ERROR: Capture fle not found")
		print("Expected location:", CAPTURE_FILE)
		return
	packets=rdpcap(str(CAPTURE_FILE))
	print("Capture file:",CAPTURE_FILE)
	print("Total packets:",len(packets))
	protocols=Counter()
	layers=Counter()
	source_ips=Counter()
	destination_ips=Counter()
	ports=Counter()
	for packet in packets:
		if packet.haslayer(ARP):
			protocols["ARP"] +=1
			layers["ARP"] +=1
		if packet.haslayer(IP):
			ip=packet[IP]
			source_ips[ip.src]+=1
			destination_ips[ip.dst]+=1
			layers["IP"]+=1
			if packet.haslayer(TCP):
				tcp=packet[TCP]
				layers["TCP"]+=1
				ports[tcp.dport]+=1
				protocols["TCP"]+=1
			elif packet.haslayer(UDP):
				udp=packet[UDP]
				layers["UDP"]+=1
				ports[udp.dport]+=1
				protocols["UDP"]+=1
			elif packet.haslayer(ICMP):
				layers["ICMP"]+=1
				protocols["ICMP"]+=1
			else:
				protocols["OTHER IP"]+=1
			if packet.haslayer(DNS):
				layers["DNS"]+=1
	print("\n======= PROTOCOL SUMMARY =======")
	for protocol, count in protocols.most_common():
		print(f"{protocol}: {count}")
	print("\n======= NETWORK LAYERS ========")
	for layer, count in layers.most_common():
		print(f"{layer}: {count}")
	print("\n======= TOP SOURCE IPs ========")
	for ip, count in source_ips.most_common(5):
		print(f"{ip}:{count} packets")
	print("\n======= TOP DESTINATION PORTS ========")
	for port, count in ports.most_common(10):
		print(f"Port {port}: {count} packets")
print("\n======================================")
print("          Analysis          Completed!")
print("======================================\n")
if __name__ == "__main__":
	analyze_packets()
