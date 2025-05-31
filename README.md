# Packet_Sniffer
This is a Python-based Packet Sniffer which captures and analyzes network traffic in real-time. The program prompts the user to specify a network interface and an optional BPF (Berkeley Packet Filter) expression to filter specific types of packets (e.g., only TCP or UDP). 

### WORKING
It monitors packets on the selected interface and processes each one to extract and display critical information, including source and destination IP addresses, protocols, and port numbers for TCP and UDP packets. 

### WARNING
This tool is intended strictly for educational and authorized testing environments.
Do not use it to intercept traffic without permission, as that may violate privacy laws and network policies.

### REQUIREMENTS
install scapy
>pip install scapy

run
>sudo python packet_sniffer.py

interfaces could be
 - eth0 (Ethernet)
 - wlan0 or wlp3s0 (Wi-Fi)
 - en0 (on macOS)
 - lo (loopback – avoid using this)
