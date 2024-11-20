# Network-Packet-Analyser

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto  # protocol number (e.g., 6 for TCP, 17 for UDP)
        
        # Extract additional protocol information
        if TCP in packet:
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol_name = "Other"
            src_port = None
            dst_port = None

        # Display packet details
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name} (Proto Num: {protocol})")
        if src_port and dst_port:
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        
        # Display payload data (if available)
        if packet.haslayer('Raw'):
            payload_data = packet['Raw'].load
            print(f"Payload Data: {payload_data}\n")
        else:
            print("No Payload Data\n")

# Sniff packets (limit=0 means unlimited; count parameter can limit capture)
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
