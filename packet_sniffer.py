import scapy.all as scapy

def sniff_packets(interface, filter=None):
    scapy.sniff(iface=interface, store=False, prn=process_packet, filter=filter)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport  # Fixed typo here
            print(f"TCP packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port}")
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport  # Fixed typo here
            print(f"UDP packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port}")
        else:
            print(f"IP packet {ip_src} --> {ip_dst}, protocol: {protocol}")

def main():
    interface = input("Enter the interface to sniff on: ")
    filter = input("Enter BPF filter (press Enter to skip): ")
    print("Starting packet sniff...")
    sniff_packets(interface, filter if filter else None)  # Now it runs the sniffer

if __name__ == "__main__":
    main()
