from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            protocol = "OTHER"

            # Determine protocol type
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"

            # Extract packet details
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore') if protocol == "TCP" else None

            # Display captured information
            print(f"[+] Protocol: {protocol} | Source IP: {src_ip} -> Destination IP: {dst_ip}")
            if payload:
                print(f"Payload: {payload}\n")

    except Exception as e:
        # Handle unexpected errors gracefully
        print(f"[!] Error processing packet: {e}")

def main():
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    try:
        # Start sniffing on the network interface
        sniff(filter="ip", prn=packet_callback, store=False)
    except PermissionError:
        print("[!] Permission denied. Please run the script as administrator/root.")
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")

if __name__ == "__main__":
    main()
