# PRODIGY_NT5
# Packet Sniffer Tool

## Overview
The `packet_sniffer.py` is a Python-based network packet sniffing tool developed using the `scapy` library. This tool captures and analyzes network packets, displaying relevant information such as:

- Source IP address
- Destination IP address
- Protocol (TCP/UDP/Other)
- Payload data (if available for TCP packets)

The tool is designed for educational purposes to help users learn about network traffic and protocol analysis. **It should only be used on networks you own or have explicit permission to monitor.**

## Features
- Captures and analyzes IP packets.
- Displays key details such as source/destination IP addresses and protocols.
- Decodes and prints payload data for TCP packets (if available).
- Error handling for graceful operation.

## Prerequisites
1. Python 3.x installed on your system.
2. The `scapy` library. Install it using pip:
   ```bash
   pip install scapy
   ```
3. Administrative/root permissions to run the script.

## Usage
1. Save the script as `packet_sniffer.py`.
2. Run the script with administrator/root privileges:
   ```bash
   sudo python3 packet_sniffer.py
   ```
3. The tool will start capturing packets on the default network interface. Press `Ctrl+C` to stop sniffing.

## Example Output
```
Starting packet sniffer... (Press Ctrl+C to stop)
[+] Protocol: TCP | Source IP: 192.168.1.10 -> Destination IP: 192.168.1.1
Payload: GET / HTTP/1.1\nHost: example.com\n
[+] Protocol: UDP | Source IP: 192.168.1.15 -> Destination IP: 8.8.8.8
[+] Protocol: OTHER | Source IP: 10.0.0.5 -> Destination IP: 10.0.0.1
```

## Ethical Use
This tool is intended strictly for educational purposes. Users must ensure:
- They have explicit permission to monitor and capture traffic on the network they are analyzing.
- They do not use this tool for malicious purposes or unauthorized data collection.

## Notes
- The tool uses the `sniff()` function from `scapy` to capture packets.
- By default, it captures only IP packets. You can modify the `filter` parameter to capture other types of packets (e.g., ARP, ICMP).
- Ensure you have the necessary permissions to run the script; otherwise, you may encounter a `PermissionError`.

## License
This project is open-source and available for educational use. The author is not responsible for any misuse of this tool.
